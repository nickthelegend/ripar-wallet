// Escalations -> co-sign requests -> device answers. The agent proposes; the companion checks the proposal against
// what the user pinned (refusing early what the device would refuse anyway), builds the ripar-cosign-req with a fresh
// single-use nonce and a short expiry, and turns the device's answer into either the HUMAN-path caveat args for the
// agent (ripar-cosign) or a denial to relay on-chain (ripar-deny, built by the device from a 2 s hold on the review).
import {
  type AutoBudget,
  type BuiltRequest,
  type CborMap,
  type CosignFields,
  type CosignRequest,
  ProtoError,
  REQ_TYPES,
  buildRequest,
  bytesEqual,
  cborDecode,
  cosignCaveatArgs,
  decodeErc20,
  decodeRequest,
  denyRequestHashOf,
  expectVerified,
  firmwareToken,
  parseResponse,
  readRequest,
  toAddr,
  toBytes,
  toHex,
  tokenCheck,
  urParts,
  urSingle,
} from '@ripar/protocol';
import type { CosignAnswer, DenyAnswer, Escalation } from '../agent';
import type { MandateRecord, PairedDevice } from '../store';

type Hex = `0x${string}`;

export interface EscalationCheck {
  /** the device would refuse, or the escalation is not for this vault: never build it */
  errors: string[];
  /** shown next to the request (the device shows them too) */
  warnings: string[];
}

export function checkEscalation(e: Escalation, device: PairedDevice | null, mandate: MandateRecord | null): EscalationCheck {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!device) return { errors: ['No paired device.'], warnings };
  const p = device.pinned;
  if (Number(e.chainId) !== p.chainId) errors.push(`Chain ${e.chainId} is not the pinned chain ${p.chainId}.`);
  if (e.enforcer !== p.enforcer) errors.push(`Enforcer ${e.enforcer} is not the pinned PulseCosignEnforcer.`);
  if (e.delegator !== p.vault) errors.push(`Delegator ${e.delegator} is not your vault ${p.vault}.`);
  const call = decodeErc20(e.call.callData);
  if (call.kind === 'unknown') errors.push('The call is not a native send or an ERC-20 transfer / approve / transferFrom: the device refuses UNKNOWN CALLDATA.');
  if (call.kind !== 'none' && call.kind !== 'unknown' && e.call.value !== 0n) errors.push('An ERC-20 call that also sends native value: the device refuses it.');
  if (!mandate) warnings.push('No mandate recorded in this companion: the device will flag UNKNOWN MANDATE.');
  else {
    if (mandate.delegationHash.toLowerCase() !== e.delegationHash.toLowerCase()) {
      warnings.push('Not the mandate this device signed last: the device will show UNKNOWN MANDATE.');
    }
    if (mandate.agent !== e.redeemer) warnings.push(`Redeemer ${e.redeemer} is not the mandate's agent ${mandate.agent}.`);
    if (e.agentId !== null && mandate.agentId !== null && e.agentId.toString() !== mandate.agentId) {
      warnings.push(`The escalation names agent ${e.agentId}; the mandate's agent id is ${mandate.agentId}.`);
    }
  }
  if (call.kind === 'approve') warnings.push('This is an APPROVE: it grants spending rights and never becomes an AUTO payee.');
  if (call.kind === 'transferFrom') warnings.push('This is a transferFrom: it never becomes an AUTO payee.');
  return { errors, warnings };
}

export interface CosignPlan {
  request: BuiltRequest;
  decoded: CosignRequest;
  nonce: bigint;
  expiry: bigint;
  /** the requestHash a device deny from this review signs */
  denyRequestHash: Hex;
}

export interface CosignContext {
  device: PairedDevice;
  nonce: bigint;
  /** unix seconds now */
  now: number;
  /** expiry = now + ttl (default 1 h; the device refuses more than 7 days after its own time) */
  ttlSeconds?: number;
  /** the enforcer's autoBudget for the mandate (shown as "Budget left (companion)") */
  budget?: AutoBudget | null;
  /** decimals / symbol the companion claims for an ERC-20 the firmware table does not list */
  tokenMeta?: { decimals: number | null; symbol: string | null } | null;
  fragLen?: number;
}

export function planCosign(e: Escalation, ctx: CosignContext): CosignPlan {
  const p = ctx.device.pinned;
  const ttl = ctx.ttlSeconds ?? 3600;
  if (ttl <= 0 || ttl > 7 * 86400) throw new ProtoError('expiry: 1 s .. 7 days ahead');
  const expiry = BigInt(ctx.now + ttl);
  const call = decodeErc20(e.call.callData);
  const listed = call.kind === 'none' || !!firmwareToken(p.chainId, e.call.target);
  const f: CosignFields = {
    chainId: p.chainId,
    enforcer: p.enforcer,
    delegationHash: e.delegationHash,
    delegator: e.delegator,
    redeemer: e.redeemer,
    target: e.call.target,
    value: e.call.value,
    nonce: ctx.nonce,
    expiry,
    calldata: e.call.callData,
  };
  if (e.note !== null || e.claims) {
    f.ai = { ...(e.note !== null ? { text: e.note } : {}), claims: e.claims ? { to: e.claims.to, token: e.claims.token, amount: e.claims.amount } : null };
  }
  if (e.risk) f.risk = { src: e.risk.src, category: e.risk.category, label: e.risk.label, ageDays: e.risk.ageDays };
  if (ctx.budget) f.budgetLeft = ctx.budget.remaining;
  // decimals / symbol are CLAIMS: only for an asset the firmware table does not list (a listed token's table wins,
  // and a contradicting claim is refused by the device)
  if (!listed && ctx.tokenMeta) {
    if (ctx.tokenMeta.decimals !== null && ctx.tokenMeta.decimals >= 0 && ctx.tokenMeta.decimals <= 77) f.decimals = ctx.tokenMeta.decimals;
    if (ctx.tokenMeta.symbol && /^[\x20-\x7e]{1,16}$/.test(ctx.tokenMeta.symbol)) f.symbol = ctx.tokenMeta.symbol;
  }
  const request = buildRequest('cosign', f, { frag: ctx.fragLen ?? 70 });
  const decoded = decodeRequest('cosign', request.cbor) as CosignRequest;
  tokenCheck(decoded); // throws for a claim the device would refuse
  return { request, decoded, nonce: ctx.nonce, expiry, denyRequestHash: denyRequestHashOf(decoded) };
}

/**
 * The agent's own prebuilt request (it verifies the device's answer against exactly these bytes). The companion
 * decodes it, checks it describes this escalation and the pinned context, that its expiry is sane and its nonce was
 * never used on-chain (`nonceUsed`), and re-cuts the verified CBOR into its own QR parts. Throws on any mismatch.
 */
export function adoptAgentRequest(
  e: Escalation,
  device: PairedDevice,
  opts: { now: number; fragLen?: number; nonceUsed?: boolean },
): CosignPlan {
  if (!e.request) throw new ProtoError('the escalation carries no prebuilt request');
  const { kind, cbor } = readRequest(e.request.ur);
  if (kind !== 'cosign') throw new ProtoError(`the agent sent a ${kind} request, not a co-sign`);
  const q = decodeRequest('cosign', cbor) as CosignRequest;
  const p = device.pinned;
  const same = (a: Uint8Array, b: string) => bytesEqual(a, toAddr(b));
  const bad: string[] = [];
  if (Number(q.chainId) !== p.chainId) bad.push('chain');
  if (!same(q.enforcer, p.enforcer)) bad.push('enforcer (not the pinned one)');
  if (!same(q.delegator, p.vault)) bad.push('delegator (not your vault)');
  if (!bytesEqual(q.delegationHash, toBytes(e.delegationHash, 32))) bad.push('mandate');
  if (!same(q.redeemer, e.redeemer)) bad.push('redeemer');
  if (!same(q.target, e.call.target)) bad.push('target');
  if (q.value !== e.call.value) bad.push('value');
  if (!bytesEqual(q.calldata, toBytes(e.call.callData))) bad.push('calldata');
  if (toHex(q.reqId).toLowerCase() !== e.request.reqId.toLowerCase()) bad.push('req-id');
  if (bad.length) throw new ProtoError(`the agent's request does not match its escalation: ${bad.join(', ')}`);
  if (q.expiry <= BigInt(opts.now)) throw new ProtoError("the agent's request has already expired");
  if (q.expiry > BigInt(opts.now + 7 * 86400)) throw new ProtoError("the agent's request expires more than 7 days ahead: the device refuses it");
  if (opts.nonceUsed) throw new ProtoError(`nonce ${q.nonce} was already used on-chain for this mandate: the redemption would revert (CosignReplayed)`);
  tokenCheck(q);
  const plan = planOfCbor(cbor, opts.fragLen);
  if (e.requestHash && e.requestHash.toLowerCase() !== plan.denyRequestHash.toLowerCase()) {
    throw new ProtoError("the agent's requestHash is not the hash of its own request");
  }
  return plan;
}

function planOfCbor(cbor: Uint8Array, fragLen = 70): CosignPlan {
  const q = decodeRequest('cosign', cbor) as CosignRequest;
  const type = REQ_TYPES.cosign;
  const request: BuiltRequest = {
    kind: 'cosign',
    type,
    reqId: toHex(q.reqId),
    map: cborDecode(cbor) as CborMap,
    cbor,
    ur: urSingle(type, cbor),
    parts: urParts(type, cbor, fragLen),
  };
  return { request, decoded: q, nonce: q.nonce, expiry: q.expiry, denyRequestHash: denyRequestHashOf(q) };
}

/**
 * The plan of a co-sign request shown earlier (persisted as its single-part UR), so a reload resumes the same round
 * with the same req-id and nonce. The escalation must still describe it (checked like the agent's own request).
 */
export function resumePlan(requestUr: string, e: Escalation, device: PairedDevice, fragLen = 70): CosignPlan {
  const { kind, cbor } = readRequest(requestUr);
  if (kind !== 'cosign') throw new ProtoError(`a stored ${kind} request, not a co-sign`);
  const plan = planOfCbor(cbor, fragLen);
  const q = plan.decoded;
  const p = device.pinned;
  const same = (a: Uint8Array, b: string) => bytesEqual(a, toAddr(b));
  if (
    Number(q.chainId) !== p.chainId ||
    !same(q.enforcer, p.enforcer) ||
    !same(q.delegator, p.vault) ||
    !bytesEqual(q.delegationHash, toBytes(e.delegationHash, 32)) ||
    !same(q.target, e.call.target) ||
    q.value !== e.call.value ||
    !bytesEqual(q.calldata, toBytes(e.call.callData))
  ) {
    throw new ProtoError('the stored request no longer matches this escalation or the pinned device');
  }
  return plan;
}

/**
 * May this escalation show a request with this nonce? A nonce the chain has used can never be redeemed. A nonce this
 * companion already handed out is fine for the SAME escalation (showing its request again after a reload or a
 * detour: at most one redemption can ever use it on chain) and refused for any other escalation.
 */
export function nonceConflict(
  escalationId: string,
  delegationHash: string,
  nonce: bigint,
  work: Record<string, { delegationHash: string; nonce: string }>,
): string | null {
  for (const [id, w] of Object.entries(work)) {
    if (id === escalationId) continue;
    if (w.delegationHash.toLowerCase() === delegationHash.toLowerCase() && w.nonce === nonce.toString()) {
      return `nonce ${nonce} was already handed out for escalation ${id} under this mandate: only one of them could ever be redeemed (CosignReplayed)`;
    }
  }
  return null;
}

/** accept() filter: a ripar-cosign or ripar-deny echoing the co-sign's req-id */
export function answersCosign(ur: string, request: BuiltRequest): boolean {
  try {
    const rep = parseResponse(ur);
    return (rep.type === 'ripar-cosign' || rep.type === 'ripar-deny') && rep.fields.reqId.toLowerCase() === request.reqId.toLowerCase();
  } catch {
    return false;
  }
}

export type CosignOutcome =
  | { kind: 'cosign'; answer: CosignAnswer; bpm: number; checks: { name: string; ok: boolean }[] }
  | {
      kind: 'deny';
      answer: Omit<DenyAnswer, 'attestTx'>;
      attest: { agentId: bigint; requestHash: Hex; presenceHash: Hex; rs: Hex };
      checks: { name: string; ok: boolean }[];
      /** set when the device filed the deny against another agent than the mandate this companion recorded */
      note: string | null;
    };

/** verifies the device's answer to a co-sign review against the request, the P1 key and the pinned relay */
export function acceptCosignAnswer(ur: string, plan: CosignPlan, device: PairedDevice, mandate: MandateRecord | null): CosignOutcome {
  const p = device.pinned;
  const rep = expectVerified(
    parseResponse(ur, {
      request: plan.request,
      p1Key: device.p1Key,
      pinned: { chainId: p.chainId, enforcer: p.enforcer, sentinel: p.sentinel, relay: p.relay },
    }),
  );
  if (rep.type === 'ripar-cosign') {
    const f = rep.fields;
    const caveatArgs = f.caveatArgs ?? cosignCaveatArgs(plan.nonce, plan.expiry, f.presenceHash, f.rs);
    return {
      kind: 'cosign',
      bpm: f.evidence.bpm,
      checks: rep.checks,
      answer: {
        ur: ur.trim().toUpperCase(),
        reqId: f.reqId,
        nonce: plan.nonce.toString(),
        expiry: plan.expiry.toString(),
        presenceHash: f.presenceHash,
        r: f.r,
        s: f.s,
        caveatArgs,
        approvalDigest: f.digest ?? null,
        emulator: device.emulator,
      },
    };
  }
  if (rep.type === 'ripar-deny') {
    const f = rep.fields;
    if (f.requestHash.toLowerCase() !== plan.denyRequestHash.toLowerCase()) throw new ProtoError('the deny names another request');
    const note =
      mandate?.agentId && f.agentId.toString() !== mandate.agentId
        ? `The device filed this deny against agent ${f.agentId}, not the recorded mandate's agent ${mandate.agentId}.`
        : null;
    return {
      kind: 'deny',
      checks: rep.checks,
      note,
      answer: { ur: ur.trim().toUpperCase(), requestHash: f.requestHash, agentId: f.agentId.toString(), presenceHash: f.presenceHash, emulator: device.emulator },
      attest: { agentId: f.agentId, requestHash: f.requestHash, presenceHash: f.presenceHash, rs: f.rs },
    };
  }
  throw new ProtoError(`unexpected ${rep.type}`);
}
