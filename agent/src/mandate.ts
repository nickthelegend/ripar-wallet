// Mandate intake (POST /mandate): the signed MetaMask Delegation the user's device produced (ripar-mandate-req ->
// eth-signature), relayed by the companion. The agent accepts it only when it can actually use it and it is what the
// device's policy allows:
//   - delegate == this agent (never ANY_DELEGATE), delegator = the canonical Ripar vault of the signer,
//   - ROOT authority,
//   - exactly one PulseCosignEnforcer caveat (the deployment's), strict 288-byte terms with sane values,
//     every other caveat a MetaMask enforcer the device can decode,
//   - a 65-byte K1 signature (v 27/28, low-s) over the Delegation digest of the canonical DelegationManager, whose
//     signer's canonical vault (smart-accounts-kit Hybrid counterfactual, deployParams [K1,[],[],[]], salt 0) is the
//     delegator.
import {
  ANY_DELEGATE,
  DELEGATION_MANAGER,
  SECP256K1_N,
  bytesToBigInt,
  caveatDump,
  computeVaultAddress,
  decodePulseTerms,
  decodeRequest,
  enforcerKind,
  hashDelegation,
  isLowS,
  k1RecoverAddress,
  keyIdOf,
  mandateDigest,
  p256OnCurve,
  parseResponse,
  readRequest,
  signedDelegation,
  toChecksumAddress,
  toHex,
  type Delegation,
  type MandateRequest,
  type RiparDeployment,
} from '@ripar/protocol';
import type { Address, Hex } from 'viem';
import { ApiError } from './errors.js';
import type { DelegationJson, StoredMandate } from './types.js';
import { checksum, isHexBytes, sameAddress, ZERO_ADDRESS } from './util.js';

const ROOT: Hex = `0x${'ff'.repeat(32)}`;

export class MandateError extends ApiError {
  constructor(message: string) {
    super(422, 'bad_mandate', message);
  }
}

export interface MandateContext {
  /** this agent's address (must be the delegate) */
  agent: Address;
  chainId: number;
  deployment: RiparDeployment;
}

export type ValidatedMandate = Omit<StoredMandate, 'receivedAt' | 'status'>;

/** the body of POST /mandate */
export interface MandateInput {
  /** a framework Delegation (JSON: salt as a decimal / 0x string, signature 65-byte hex) */
  delegation?: unknown;
  /** or: the ripar-mandate-req the device signed (UR, multipart parts joined by whitespace, or CBOR hex) ... */
  request?: string;
  /** ... and the device's eth-signature (UR) or the 65-byte r‖s‖v hex */
  signature?: string;
  /** ERC-8004 agent id (a request's key 10 wins) */
  agentId?: string | number;
  label?: string;
}

function fail(msg: string): never {
  throw new MandateError(msg);
}

function delegationFromJson(x: unknown): Delegation {
  if (!x || typeof x !== 'object' || Array.isArray(x)) fail('delegation: expected an object');
  const o = x as Record<string, unknown>;
  const addr = (k: string): Address => {
    try {
      return checksum(o[k], `delegation.${k}`);
    } catch (e) {
      fail((e as Error).message);
    }
  };
  if (!isHexBytes(o.authority, 32)) fail('delegation.authority: expected 32 bytes of hex');
  if (!Array.isArray(o.caveats)) fail('delegation.caveats: expected an array');
  const caveats = o.caveats.map((c, i) => {
    const r = c as Record<string, unknown>;
    if (!r || typeof r !== 'object') fail(`delegation.caveats[${i}]: expected an object`);
    let enforcer: Address;
    try {
      enforcer = checksum(r.enforcer, `delegation.caveats[${i}].enforcer`);
    } catch (e) {
      fail((e as Error).message);
    }
    if (!isHexBytes(r.terms)) fail(`delegation.caveats[${i}].terms: expected hex`);
    const args = r.args === undefined || r.args === null ? '0x' : r.args;
    if (!isHexBytes(args)) fail(`delegation.caveats[${i}].args: expected hex`);
    if (args !== '0x') fail(`delegation.caveats[${i}].args: must be empty in a stored mandate (args are set per redemption)`);
    return { enforcer, terms: (r.terms as string).toLowerCase() as Hex, args: '0x' as Hex };
  });
  let salt: bigint;
  if (typeof o.salt === 'bigint') salt = o.salt;
  else if (typeof o.salt === 'number' && Number.isSafeInteger(o.salt) && o.salt >= 0) salt = BigInt(o.salt);
  else if (typeof o.salt === 'string' && /^(0x[0-9a-fA-F]{1,64}|\d{1,78})$/.test(o.salt)) salt = BigInt(o.salt);
  else fail('delegation.salt: expected a uint256 (decimal or 0x string)');
  if (salt >= 1n << 256n) fail('delegation.salt: does not fit uint256');
  if (o.signature === undefined || o.signature === null || o.signature === '0x') fail('delegation.signature: missing (the device must sign the mandate)');
  if (!isHexBytes(o.signature, 65)) fail('delegation.signature: expected 65 bytes r‖s‖v');
  return {
    delegate: addr('delegate'),
    delegator: addr('delegator'),
    authority: (o.authority as string).toLowerCase() as Hex,
    caveats,
    salt,
    signature: (o.signature as string).toLowerCase() as Hex,
  };
}

/** turns the POST /mandate body into a Delegation (+ the device request when it came as QR data) */
export function mandateFromInput(input: MandateInput, chainId: number): { delegation: Delegation; request?: MandateRequest } {
  if (!input || typeof input !== 'object') fail('expected a JSON object');
  if (input.delegation !== undefined) {
    if (input.request !== undefined) fail('give either delegation or request + signature, not both');
    return { delegation: delegationFromJson(input.delegation) };
  }
  if (typeof input.request !== 'string' || typeof input.signature !== 'string') {
    fail('give {delegation} or {request: ripar-mandate-req, signature: eth-signature}');
  }
  let q: MandateRequest;
  try {
    const { kind, cbor } = readRequest(input.request);
    if (kind !== 'mandate') fail(`request: expected a ripar-mandate-req, got ${kind}`);
    const r = decodeRequest('mandate', cbor);
    if (r.kind !== 'mandate') fail('request: not a mandate');
    q = r;
  } catch (e) {
    if (e instanceof MandateError) throw e;
    fail(`request: ${(e as Error).message}`);
  }
  if (Number(q.chainId) !== chainId) fail(`request: chain ${q.chainId}, the agent runs on ${chainId}`);
  let rsv: Hex;
  const sig = input.signature.trim();
  if (/^0x[0-9a-fA-F]{130}$/.test(sig)) rsv = sig.toLowerCase() as Hex;
  else {
    let rep;
    try {
      rep = parseResponse(sig);
    } catch (e) {
      fail(`signature: ${(e as Error).message}`);
    }
    if (rep.type !== 'eth-signature') fail(`signature: expected an eth-signature response, got ${rep.type}`);
    rsv = rep.fields.rsv;
  }
  return { delegation: signedDelegation(q, rsv), request: q };
}

/** full validation; returns the mandate to store (throws MandateError) */
export function validateMandate(d: Delegation, ctx: MandateContext, request?: MandateRequest): ValidatedMandate {
  const dep = ctx.deployment;
  const warnings: string[] = [];
  if (!sameAddress(dep.delegationManager, DELEGATION_MANAGER)) {
    fail(`the deployment's DelegationManager ${dep.delegationManager} is not the canonical ${DELEGATION_MANAGER}`);
  }
  if (sameAddress(d.delegate, ANY_DELEGATE)) fail('delegate: ANY_DELEGATE is refused');
  if (!sameAddress(d.delegate, ctx.agent)) fail(`delegate ${d.delegate} is not this agent (${ctx.agent})`);
  if (sameAddress(d.delegator, ZERO_ADDRESS)) fail('delegator: zero address');
  if (d.authority.toLowerCase() !== ROOT) fail('authority: must be ROOT_AUTHORITY (a root mandate from the vault)');
  if (d.caveats.length < 1 || d.caveats.length > 16) fail('caveats: 1 to 16 entries');

  const pulseIdx = d.caveats.map((c, i) => (sameAddress(c.enforcer, dep.enforcer) ? i : -1)).filter((i) => i >= 0);
  if (pulseIdx.length !== 1) {
    fail(`exactly one PulseCosignEnforcer (${dep.enforcer}) caveat is required, found ${pulseIdx.length}`);
  }
  const otherCaveats: StoredMandate['otherCaveats'] = [];
  for (const c of d.caveats) {
    const dump = caveatDump(ctx.chainId, c.enforcer, c.terms, ctx.chainId, dep.enforcer);
    if (dump === null) fail(`caveat ${c.enforcer}: terms the device cannot decode (or an unsupported enforcer)`);
    if (!sameAddress(c.enforcer, dep.enforcer)) {
      otherCaveats.push({ enforcer: toChecksumAddress(c.enforcer), kind: enforcerKind(c.enforcer) ?? 'unknown', terms: c.terms });
    }
  }
  const pc = d.caveats[pulseIdx[0]!]!;
  let t;
  try {
    t = decodePulseTerms(pc.terms);
  } catch (e) {
    fail(`pulse terms: ${(e as Error).message}`);
  }
  if (!p256OnCurve(t.p1Key)) fail('pulse terms: the device key (px, py) is not a P-256 point');
  if (t.perTxAutoCap > t.periodAutoCap) fail('pulse terms: perTxAutoCap is above periodAutoCap');
  if (!sameAddress(t.sentinel, ZERO_ADDRESS) && !sameAddress(t.sentinel, dep.sentinel)) {
    fail(`pulse terms: sentinel ${t.sentinel} is not the deployment's RiparSentinel ${dep.sentinel}`);
  }
  if (sameAddress(t.sentinel, ZERO_ADDRESS)) warnings.push('no sentinel: the AUTO lane cannot be closed by the risk monitor');
  if (!t.newPayeeNeedsHuman) warnings.push('newPayeeNeedsHuman is off: AUTO can pay any payee inside the caps');
  if (t.periodAutoCap === 0n) warnings.push('periodAutoCap is 0: every payment needs the device');
  if (!sameAddress(t.token, ZERO_ADDRESS) && !sameAddress(t.token, dep.mockUsd)) {
    warnings.push(`metered token ${t.token} is not the deployment's MockUSD`);
  }

  // the K1 signature: v, low-s, recovery, canonical vault
  const sig = Buffer.from(d.signature.slice(2), 'hex');
  const v = sig[64]!;
  const r = bytesToBigInt(sig.subarray(0, 32));
  const s = bytesToBigInt(sig.subarray(32, 64));
  if (v !== 27 && v !== 28) fail('signature: v must be 27 or 28');
  if (!isLowS(s, SECP256K1_N)) fail('signature: high-s (the device always signs low-s)');
  const digest = mandateDigest(ctx.chainId, dep.delegationManager, d);
  const who = k1RecoverAddress(digest, r, s, v - 27);
  if (!who) fail('signature: does not recover a signer');
  const owner = toChecksumAddress(who);
  const canonical = computeVaultAddress(owner);
  if (!sameAddress(canonical, d.delegator)) {
    fail(`delegator ${d.delegator} is not the canonical Ripar vault ${canonical} of the signer ${owner}`);
  }

  const delegation: DelegationJson = {
    delegate: toChecksumAddress(d.delegate),
    delegator: toChecksumAddress(d.delegator),
    authority: d.authority,
    caveats: d.caveats.map((c) => ({ enforcer: toChecksumAddress(c.enforcer), terms: c.terms, args: '0x' as Hex })),
    salt: d.salt.toString(),
    signature: d.signature,
  };
  const agentId = request?.agentId ?? null;
  return {
    delegation,
    delegationHash: hashDelegation(d),
    vault: toChecksumAddress(d.delegator),
    owner,
    pulse: {
      enforcer: toChecksumAddress(pc.enforcer),
      terms: pc.terms,
      px: t.px,
      py: t.py,
      p1Key: t.p1Key,
      keyId: toHex(keyIdOf(t.p1Key)),
      token: t.token,
      perTxAutoCap: t.perTxAutoCap.toString(),
      periodAutoCap: t.periodAutoCap.toString(),
      period: Number(t.period),
      epoch: t.epoch.toString(),
      newPayeeNeedsHuman: t.newPayeeNeedsHuman,
      sentinel: t.sentinel,
    },
    otherCaveats,
    ...(agentId !== null ? { agentId: agentId.toString() } : {}),
    ...(request?.label ? { label: request.label } : {}),
    source: request ? 'device-qr' : 'delegation',
    warnings,
  };
}

/** the framework Delegation of a stored mandate (args empty) */
export function delegationOf(m: StoredMandate): Delegation {
  const d = m.delegation;
  return {
    delegate: d.delegate,
    delegator: d.delegator,
    authority: d.authority,
    caveats: d.caveats.map((c) => ({ ...c, args: '0x' as Hex })),
    salt: BigInt(d.salt),
    signature: d.signature,
  };
}
