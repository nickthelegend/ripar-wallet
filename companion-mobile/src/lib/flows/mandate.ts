// Ported unchanged from companion/src/lib/flows/mandate.ts.
// The mandate: a MetaMask Delegation from the vault to the agent whose one PulseCosignEnforcer caveat names this
// device's P1 key, the AUTO caps, the device's panic floor as epoch and the pinned sentinel (docs/PROTOCOL.md §4
// mandate policy). K1 signs it on the device (eth-signature); the signed delegation is handed to the agent.
import {
  type BuiltRequest,
  type CaveatSpec,
  type MandateRequest,
  ProtoError,
  buildRequest,
  decodeRequest,
  encodePermissionContext,
  encodePulseTerms,
  expectVerified,
  hashDelegation,
  parseResponse,
  randomBytes,
  bytesToBigInt,
  signedDelegation,
  toChecksumAddress,
  toHex,
  isValidAddress,
  ANY_DELEGATE,
} from '@ripar/protocol';
import type { AgentMandate } from '../agent';
import { parseUnits } from '../format';
import type { DelegationJson, MandateRecord, PairedDevice } from '../store';

type Hex = `0x${string}`;
const ZERO = '0x0000000000000000000000000000000000000000' as const;

export interface MandateForm {
  agent: string;
  agentId: string;
  label: string;
  /** metered asset: 'native' or an ERC-20 address */
  token: string;
  tokenDecimals: number;
  tokenSymbol: string | null;
  /** human units, e.g. "5" */
  perTxAutoCap: string;
  periodAutoCap: string;
  /** seconds; 0 = lifetime cap */
  period: number;
  newPayeeNeedsHuman: boolean;
  /** add a RedeemerEnforcer caveat: only the agent may redeem (no re-delegation) */
  redeemerOnly: boolean;
  /** add a TimestampEnforcer caveat ending at this unix time (null = no end) */
  validUntil: number | null;
}

export interface MandatePlan {
  request: BuiltRequest;
  decoded: MandateRequest;
  pulseTerms: Hex;
  perTxAutoCap: bigint;
  periodAutoCap: bigint;
  token: `0x${string}`;
}

/** validates the form and builds the ripar-mandate-req (throws Error with a user-facing message) */
export function planMandate(
  form: MandateForm,
  device: PairedDevice,
  epoch: bigint,
  opts: { fragLen?: number; salt?: bigint } = {},
): MandatePlan {
  const p = device.pinned;
  if (!isValidAddress(form.agent.trim())) throw new Error('Agent address: not a valid address (check the EIP-55 checksum)');
  const agent = toChecksumAddress(form.agent.trim());
  if (agent === ZERO || agent.toLowerCase() === ANY_DELEGATE.toLowerCase()) throw new Error('Agent address: not the zero address or ANY_DELEGATE');
  if (/^0x0{40}$/i.test(p.enforcer)) throw new Error('The device has no PulseCosignEnforcer pinned: pair again with a deployment');
  const native = form.token === 'native';
  if (!native && !isValidAddress(form.token)) throw new Error('Token: not a valid address');
  const token = native ? ZERO : toChecksumAddress(form.token);
  const dec = native ? 18 : form.tokenDecimals;
  let perTx: bigint;
  let perPeriod: bigint;
  try {
    perTx = parseUnits(form.perTxAutoCap, dec);
    perPeriod = parseUnits(form.periodAutoCap, dec);
  } catch (e) {
    throw new Error(`Caps: ${(e as Error).message}`);
  }
  const U128 = 1n << 128n;
  if (perTx >= U128 || perPeriod >= U128) throw new Error('Caps: too large (uint128)');
  if (perTx > perPeriod) throw new Error('Caps: the per-transaction cap exceeds the period cap');
  if (!Number.isInteger(form.period) || form.period < 0 || form.period >= 2 ** 32) throw new Error('Period: 0 .. 2^32-1 seconds');
  let agentId: bigint | undefined;
  if (form.agentId.trim()) {
    if (!/^\d{1,20}$/.test(form.agentId.trim())) throw new Error('Agent id: a whole number (ERC-8004 agentId)');
    agentId = BigInt(form.agentId.trim());
    if (agentId >= 1n << 64n) throw new Error('Agent id: must fit 64 bits for the device');
  }
  const label = form.label.trim();
  if (new TextEncoder().encode(label).length > 64) throw new Error('Label: at most 64 bytes');
  if (/[\u0000-\u001f\u007f]/.test(label)) throw new Error('Label: no control characters');

  const pulse = {
    kind: 'pulse' as const,
    enforcer: p.enforcer,
    p1Key: device.p1Key,
    token,
    perTxAutoCap: perTx,
    periodAutoCap: perPeriod,
    period: form.period,
    epoch,
    newPayeeNeedsHuman: form.newPayeeNeedsHuman,
    // the device refuses any sentinel but the pinned one (or zero when none is pinned)
    sentinel: p.sentinel,
  };
  const caveats: CaveatSpec[] = [pulse];
  if (form.redeemerOnly) caveats.push({ kind: 'redeemer', addresses: [agent] });
  if (form.validUntil !== null) {
    if (!Number.isInteger(form.validUntil) || form.validUntil <= Math.floor(Date.now() / 1000)) throw new Error('Valid until: a future time');
    caveats.push({ kind: 'timestamp', after: 0, before: form.validUntil });
  }
  const salt = opts.salt ?? bytesToBigInt(randomBytes(8));
  const request = buildRequest(
    'mandate',
    {
      chainId: p.chainId,
      manager: p.manager,
      delegate: agent,
      delegator: p.vault,
      caveats,
      salt,
      ...(label ? { label } : {}),
      ...(agentId !== undefined ? { agentId } : {}),
    },
    { frag: opts.fragLen ?? 70 },
  );
  const decoded = decodeRequest('mandate', request.cbor) as MandateRequest;
  const pulseTerms = toHex(
    encodePulseTerms({
      px: device.px,
      py: device.py,
      token,
      perTxAutoCap: perTx,
      periodAutoCap: perPeriod,
      period: form.period,
      epoch,
      newPayeeNeedsHuman: form.newPayeeNeedsHuman,
      sentinel: p.sentinel,
    }),
  );
  return { request, decoded, pulseTerms, perTxAutoCap: perTx, periodAutoCap: perPeriod, token };
}

/** accept() filter: an eth-signature echoing the request's req-id */
export function answersMandate(ur: string, request: BuiltRequest): boolean {
  try {
    const rep = parseResponse(ur);
    return rep.type === 'eth-signature' && rep.fields.reqId.toLowerCase() === request.reqId.toLowerCase();
  } catch {
    return false;
  }
}

export function delegationToJson(d: ReturnType<typeof signedDelegation>): DelegationJson {
  return {
    delegate: d.delegate,
    delegator: d.delegator,
    authority: d.authority,
    caveats: d.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: c.args })),
    salt: d.salt.toString(),
    signature: d.signature,
  };
}

export function delegationFromJson(j: DelegationJson): ReturnType<typeof signedDelegation> {
  return { ...j, salt: BigInt(j.salt), caveats: j.caveats.map((c) => ({ ...c })) };
}

/** verifies the device's eth-signature (K1 recovers to the paired K1 over this request) -> the mandate record */
export function acceptMandate(
  ur: string,
  plan: MandatePlan,
  form: MandateForm,
  device: PairedDevice,
  now = Date.now(),
): MandateRecord {
  const rep = expectVerified(parseResponse(ur, { request: plan.request, k1Address: device.k1Address }));
  if (rep.type !== 'eth-signature') throw new ProtoError(`expected eth-signature, got ${rep.type}`);
  const d = signedDelegation(plan.decoded, rep.fields.rsv);
  const dh = hashDelegation(d);
  if (rep.fields.delegationHash && rep.fields.delegationHash.toLowerCase() !== dh.toLowerCase()) {
    throw new ProtoError('delegation hash mismatch');
  }
  return {
    delegation: delegationToJson(d),
    delegationHash: dh,
    pulseTerms: plan.pulseTerms,
    agent: d.delegate,
    agentId: plan.decoded.agentId !== null ? plan.decoded.agentId.toString() : null,
    label: plan.decoded.label ?? '',
    token: plan.token,
    tokenSymbol: form.token === 'native' ? 'MON' : form.tokenSymbol,
    tokenDecimals: form.token === 'native' ? 18 : form.tokenDecimals,
    epoch: decodePulseEpoch(plan.pulseTerms).toString(),
    requestUr: plan.request.ur,
    signatureUr: ur.trim().toUpperCase(),
    signedAt: now,
  };
}

function decodePulseEpoch(terms: Hex): bigint {
  return BigInt(`0x${terms.slice(2 + 6 * 64, 2 + 7 * 64)}`);
}

/**
 * What the agent receives (POST /mandate): the request the device reviewed and its eth-signature, so the agent rebuilds
 * the delegation and recovers K1 itself instead of trusting a delegation this page assembled.
 */
export function mandateEnvelope(m: MandateRecord): AgentMandate {
  return {
    request: m.requestUr,
    signature: m.signatureUr,
    ...(m.agentId !== null ? { agentId: m.agentId } : {}),
    ...(m.label ? { label: m.label } : {}),
  };
}

/** the permission context the agent redeems with (abi.encode([delegation]), caveat args empty) */
export function permissionContextOf(m: MandateRecord): `0x${string}` {
  return encodePermissionContext([delegationFromJson(m.delegation)]);
}
