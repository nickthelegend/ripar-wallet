// The PulseCosignEnforcer AUTO path seen from an agent / companion (contracts/SPEC.md v1.2): the autoBudget view's
// result type, an offline mirror of its period rollover, and the AUTO-or-escalate decision in the enforcer's order
// (meterable call, sentinel lane, per-tx cap, known payee, period cap). The chain decides; these helpers predict it.
import { type BytesLike, type IntLike, bytesEqual, isZero, toAddr, toBytes, toInt } from './bytes.js';
import { type DecodedPulseTerms, decodePulseTerms } from './caveats.js';
import { decodeErc20 } from './erc20.js';

/** IPulseCosignEnforcer.autoBudget(manager, delegationHash, terms) */
export interface AutoBudget {
  /** AUTO spend in the current period (0 after an elapsed period) */
  spent: bigint;
  /** periodAutoCap - spent (0 when spent >= cap) */
  remaining: bigint;
  /** start of the current window (0 = no AUTO spend yet) */
  periodStart: bigint;
  /** end of the window; 0 when period == 0 (lifetime cap) or nothing was spent yet */
  periodEnd: bigint;
}

/** raw stored accounting: IPulseCosignEnforcer.periodSpent(manager, delegationHash) */
export interface StoredPeriod {
  spent: IntLike;
  start: IntLike;
}

const U64_MAX = (1n << 64n) - 1n;

/** the enforcer's _rollover: an elapsed window reads as spent 0 with the next aligned start */
export function rolloverPeriod(spent: bigint, start: bigint, period: bigint, now: bigint): { spent: bigint; start: bigint } {
  if (period !== 0n && start !== 0n && now >= start + period) {
    return { spent: 0n, start: start + ((now - start) / period) * period };
  }
  return { spent, start };
}

/** offline mirror of the autoBudget view at time `now` (unix s) from periodSpent() and the mandate's pulse terms */
export function computeAutoBudget(terms: BytesLike | DecodedPulseTerms, stored: StoredPeriod, now: IntLike): AutoBudget {
  const t = isDecoded(terms) ? terms : decodePulseTerms(terms);
  const r = rolloverPeriod(toInt(stored.spent), toInt(stored.start), t.period, toInt(now));
  const remaining = r.spent < t.periodAutoCap ? t.periodAutoCap - r.spent : 0n;
  let periodStart = 0n;
  let periodEnd = 0n;
  if (r.start !== 0n) {
    periodStart = r.start;
    if (t.period !== 0n) {
      const end = r.start + t.period;
      periodEnd = end > U64_MAX ? U64_MAX : end;
    }
  }
  return { spent: r.spent, remaining, periodStart, periodEnd };
}

function isDecoded(x: unknown): x is DecodedPulseTerms {
  return typeof x === 'object' && x !== null && !(x instanceof Uint8Array) && 'periodAutoCap' in x;
}

/** why a redemption cannot take the AUTO path and needs the device (HUMAN co-sign) instead */
export type EscalationReason =
  /** not a native send (terms.token = 0) / not a `transfer` of terms.token with no native value */
  | 'not-meterable'
  /** the sentinel closed the vault's lane (LaneClosed): a co-sign still works, a reopen needs the device */
  | 'lane-closed'
  /** amount > perTxAutoCap */
  | 'per-tx-cap'
  /** newPayeeNeedsHuman and the payee was never co-signed under this mandate */
  | 'new-payee'
  /** spent + amount > periodAutoCap */
  | 'period-cap';

export type AutoDecision =
  | { path: 'auto'; payee: Uint8Array; amount: bigint; budgetAfter: AutoBudget }
  | { path: 'human'; reason: EscalationReason; payee: Uint8Array; amount: bigint };

/** the single execution a redemption would run */
export interface ExecutionCall {
  target: BytesLike;
  value: IntLike;
  callData: BytesLike;
}

export interface AutoPathState {
  /** sentinel.laneOpen(delegator); ignored when terms.sentinel is zero. Default true */
  laneOpen?: boolean;
  /** enforcer.isKnownPayee(manager, delegationHash, payee) */
  payeeKnown: boolean;
  /** enforcer.periodSpent(manager, delegationHash) */
  stored: StoredPeriod;
  /** block time to evaluate at (unix s) */
  now: IntLike;
}

/**
 * Predicts the enforcer's AUTO path for one call (empty caveat args), in the enforcer's order. 'human' means the
 * enforcer would revert (HumanRequired / LaneClosed): ask the device for a co-sign (ripar-cosign-req) instead.
 */
export function autoPathDecision(terms: BytesLike | DecodedPulseTerms, call: ExecutionCall, st: AutoPathState): AutoDecision {
  const t = isDecoded(terms) ? terms : decodePulseTerms(terms);
  const target = toAddr(call.target, 'target');
  const value = toInt(call.value);
  const cd = toBytes(call.callData, null, 'callData');
  const dec = decodeErc20(cd);
  // the enforcer's payee / amount: native = (target, value); ERC-20 = decoded (transferFrom: to)
  const payee = dec.kind === 'none' ? target : dec.to;
  const amount = dec.kind === 'none' ? value : dec.amount;
  const token = toAddr(t.token, 'terms.token');
  const meterable = isZero(token)
    ? dec.kind === 'none' && value !== 0n
    : dec.kind === 'transfer' && bytesEqual(target, token) && value === 0n;
  if (!meterable) return { path: 'human', reason: 'not-meterable', payee, amount };
  if (!isZero(toAddr(t.sentinel, 'terms.sentinel')) && st.laneOpen === false) {
    return { path: 'human', reason: 'lane-closed', payee, amount };
  }
  if (amount > t.perTxAutoCap) return { path: 'human', reason: 'per-tx-cap', payee, amount };
  if (t.newPayeeNeedsHuman && !st.payeeKnown) return { path: 'human', reason: 'new-payee', payee, amount };
  const now = toInt(st.now);
  const r = rolloverPeriod(toInt(st.stored.spent), toInt(st.stored.start), t.period, now);
  const start = r.start === 0n ? now : r.start;
  const spent = r.spent + amount;
  if (spent > t.periodAutoCap) return { path: 'human', reason: 'period-cap', payee, amount };
  return { path: 'auto', payee, amount, budgetAfter: computeAutoBudget(t, { spent, start }, now) };
}

/**
 * What an agent hands a companion when the AUTO path is closed: enough to build a ripar-cosign-req
 * (buildRequest('cosign', ...)) for the device. The companion adds nonce (randomCosignNonce) and expiry.
 */
export interface EscalationRequest {
  chainId: IntLike;
  /** the PulseCosignEnforcer pinned at pairing */
  enforcer: BytesLike;
  delegationHash: BytesLike;
  /** the vault */
  delegator: BytesLike;
  /** the agent redeeming the delegation */
  redeemer: BytesLike;
  call: ExecutionCall;
  reason: EscalationReason;
  /** ERC-8004 agent id (a deny from the review is filed against the mandate's agent) */
  agentId?: IntLike;
  /** agent's explanation, shown as the AI line (<= 100 UTF-8 bytes after truncation) */
  note?: string;
}
