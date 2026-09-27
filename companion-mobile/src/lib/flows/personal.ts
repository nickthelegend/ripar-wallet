// Sending from the vault, co-signed by the device.
//
// The vault is a HybridDeleGator owned by the device's K1 alone, and K1 signs only mandates. So this phone pays from
// the vault the same way an agent does, under a mandate of its own: the PERSONAL MANDATE, a delegation from the vault
// to this phone's hot key whose one PulseCosignEnforcer caveat sets perTxAutoCap = 0 and periodAutoCap = 0. With both
// caps at 0 the enforcer's AUTO path refuses every payment (HumanRequired), so EVERY payment needs a fresh HUMAN
// co-sign: the device reviews that exact call, checks a live pulse, and SIGN produces the P-256 signature the enforcer
// verifies on-chain. The hot key only redeems (and pays the gas); on its own it cannot move anything. A
// RedeemerEnforcer caveat also pins the redeemer to the hot key.
//
//   set up once:  planPersonalMandate -> device signs (K1, pulse + SIGN) -> acceptMandate
//   every send:   planPayment (fresh single-use nonce) -> device co-signs -> acceptCosignAnswer -> redeemPaymentWrite
import {
  type Delegation,
  DELEGATION_MANAGER,
  CosignNonceTracker,
  encodeRedeemDelegations,
  readRequest,
  toChecksumAddress,
  withCaveatArgs,
} from '@ripar/protocol';
import { type Address, type Hex, encodeFunctionData, erc20Abi } from 'viem';
import type { Escalation } from '../agent';
import { GAS_LIMITS, type WriteRequest } from '../chain';
import type { MandateRecord, PairedDevice } from '../store';
import { type CosignPlan, planCosign, planOfCbor } from './cosign';
import { type MandateForm, type MandatePlan, delegationFromJson, planMandate } from './mandate';

export const PERSONAL_LABEL = 'Ripar phone: every payment co-signed';

/** the personal mandate form: vault -> hot key, native terms, AUTO caps 0, lifetime period, redeemer = hot key */
export function personalMandateForm(hotKey: Address): MandateForm {
  return {
    agent: hotKey,
    agentId: '',
    label: PERSONAL_LABEL,
    token: 'native',
    tokenDecimals: 18,
    tokenSymbol: 'MON',
    perTxAutoCap: '0',
    periodAutoCap: '0',
    period: 0,
    newPayeeNeedsHuman: true,
    redeemerOnly: true,
    validUntil: null,
  };
}

export function planPersonalMandate(hotKey: Address, device: PairedDevice, epoch: bigint, fragLen = 70): MandatePlan {
  return planMandate(personalMandateForm(hotKey), device, epoch, { fragLen });
}

/** true when a mandate record is a personal mandate for `hotKey` (AUTO caps 0, delegate = hot key) */
export function isPersonalMandate(m: MandateRecord, hotKey: Address): boolean {
  if (m.agent.toLowerCase() !== hotKey.toLowerCase()) return false;
  const t = m.pulseTerms.slice(2);
  // words 3 and 4 of the 288-byte terms: perTxAutoCap, periodAutoCap
  const perTx = BigInt(`0x${t.slice(3 * 64, 4 * 64)}`);
  const perPeriod = BigInt(`0x${t.slice(4 * 64, 5 * 64)}`);
  return perTx === 0n && perPeriod === 0n;
}

export interface PaymentDraft {
  to: Address;
  /** 'native' (MON) or an ERC-20 */
  asset: 'native' | Address;
  /** base units */
  amount: bigint;
}

/** the single call the vault makes: a native send, or an ERC-20 transfer (the only shapes the device decodes) */
export function paymentCall(d: PaymentDraft): { target: Address; value: bigint; callData: Hex } {
  if (d.amount <= 0n) throw new Error('The amount must be above 0.');
  const to = toChecksumAddress(d.to);
  if (/^0x0{40}$/i.test(to)) throw new Error('Not to the zero address.');
  if (d.asset === 'native') return { target: to, value: d.amount, callData: '0x' };
  return {
    target: toChecksumAddress(d.asset),
    value: 0n,
    callData: encodeFunctionData({ abi: erc20Abi, functionName: 'transfer', args: [to, d.amount] }),
  };
}

/** the payment as a co-sign "escalation" (the shape planCosign takes; no AI text, no claims: this is the user's own) */
export function paymentEscalation(d: PaymentDraft, device: PairedDevice, personal: MandateRecord, hotKey: Address): Escalation {
  const call = paymentCall(d);
  return {
    id: 'personal',
    status: 'pending',
    createdAt: Math.floor(Date.now() / 1000),
    reason: 'other',
    reasonText: null,
    chainId: BigInt(device.pinned.chainId),
    enforcer: device.pinned.enforcer,
    delegationHash: personal.delegationHash,
    delegator: device.pinned.vault,
    redeemer: toChecksumAddress(hotKey),
    call,
    agentId: null,
    note: null,
    claims: null,
    risk: null,
    request: null,
    requestHash: null,
    display: null,
  };
}

/**
 * The co-sign request of a payment, with a fresh single-use nonce that this app never handed out and the chain has not
 * seen (`usedOnChain` = enforcer.nonceUsed; fail closed: a nonce whose state cannot be read is never used).
 */
export async function planPayment(
  d: PaymentDraft,
  ctx: {
    device: PairedDevice;
    personal: MandateRecord;
    hotKey: Address;
    handedOut: string[];
    usedOnChain: (nonce: bigint) => Promise<boolean>;
    now: number;
    ttlSeconds?: number;
    fragLen?: number;
  },
): Promise<CosignPlan> {
  const dh = ctx.personal.delegationHash;
  const tracker = new CosignNonceTracker();
  for (const n of ctx.handedOut) tracker.markUsed(dh, n);
  const nonce = await tracker.nextUnused(dh, ctx.usedOnChain);
  return planCosign(paymentEscalation(d, ctx.device, ctx.personal, ctx.hotKey), {
    device: ctx.device,
    nonce,
    now: ctx.now,
    ttlSeconds: ctx.ttlSeconds ?? 900,
    fragLen: ctx.fragLen ?? 70,
  });
}

/**
 * DelegationManager.redeemDelegations of the co-signed payment, sent by the hot key: the personal mandate with the
 * device's 160-byte co-sign args on its pulse caveat (HUMAN path), one single-call execution.
 */
export function redeemPaymentWrite(
  personal: MandateRecord,
  plan: CosignPlan,
  caveatArgs: Hex,
  opts: { manager?: Address; enforcer: Address; gas?: bigint },
): WriteRequest {
  const d: Delegation = withCaveatArgs(delegationFromJson(personal.delegation), opts.enforcer, caveatArgs);
  const q = plan.decoded;
  const target = toChecksumAddress(q.target);
  const data = encodeRedeemDelegations([{ delegations: [d], target, value: q.value, callData: q.calldata }]);
  return {
    kind: 'redeem',
    to: toChecksumAddress(opts.manager ?? DELEGATION_MANAGER),
    data,
    value: 0n,
    gas: opts.gas ?? GAS_LIMITS.redeem,
    summary: `Pay from the vault (co-signed by the device): ${q.value > 0n ? 'native send' : 'token transfer'} via ${target}`,
  };
}

/** the plan of a payment request shown earlier (persisted as its single-part UR): same req-id, same nonce */
export function planFromRequestUr(requestUr: string, fragLen = 70): CosignPlan {
  const { kind, cbor } = readRequest(requestUr);
  if (kind !== 'cosign') throw new Error(`a stored ${kind} request, not a co-sign`);
  return planOfCbor(cbor, fragLen);
}
