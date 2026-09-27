// The agent service: mandate intake, payments (AUTO path) and escalations to the human (HUMAN path co-signed by the
// Ripar device through the companion). The planner (Qwen or scripted) only PROPOSES payments through payInvoice();
// this code decides what is sent, and the PulseCosignEnforcer on chain has the final word: the agent can never
// bypass it (a HUMAN redemption needs the device's P-256 signature over the exact call).
import {
  AUSD_10143,
  CosignNonceTracker,
  P256_N,
  aiTextTrunc,
  autoPathDecision,
  buildRequest,
  bytesToBigInt,
  cosignCaveatArgs,
  cosignDigest,
  decodeRequest,
  denyRequestHashOf,
  erc20Transfer,
  isLowS,
  p256Verify,
  parseResponse,
  presenceHash,
  toHex,
  tokenCheck,
  type AutoBudget,
  type CosignFields,
  type CosignRequest,
} from '@ripar/protocol';
import type { Address, Hex } from 'viem';
import { TxPendingError, type Execution, type RiparChain, type TxOutcome } from './chain.js';
import type { AgentConfig } from './config.js';
import { ApiError, ChainRevertError } from './errors.js';
import type { EventBus } from './events.js';
import { delegationOf, mandateFromInput, validateMandate, type MandateInput } from './mandate.js';
import type { AgentStore } from './store.js';
import type {
  CosignRequestJson,
  Escalation,
  EscalationWhy,
  Invoice,
  InvoiceState,
  PaymentRecord,
  StoredMandate,
} from './types.js';
import { checksum, errorMessage, fmtAmount, isHexBytes, Mutex, parseAmount, randomId, sameAddress, shortAddr, ZERO_ADDRESS } from './util.js';

export interface PayOptions {
  /** a destination other than the invoice's payee of record (e.g. an injected memo): always forced to the device */
  payTo?: string;
  /** the planner's short explanation, appended to the device's AI line */
  note?: string;
  /** who proposed it */
  planner?: string;
}

export type PayOutcome =
  | { outcome: 'paid'; path: 'auto'; invoiceId: string; payment: PaymentRecord }
  | { outcome: 'escalated'; invoiceId: string; escalation: Escalation }
  | { outcome: 'pending'; invoiceId: string; txHash: Hex }
  | { outcome: 'refused'; invoiceId: string; reason: string }
  | { outcome: 'failed'; invoiceId: string; error: { name: string; message: string } };

/** POST /escalations/:id/cosign: the device's ripar-cosign response, raw (UR) or as its fields */
export interface CosignSubmission {
  ur?: string;
  evidence12?: string;
  salt16?: string;
  r?: string;
  s?: string;
  rs?: string;
}

export interface InvoiceView extends Invoice {
  status: InvoiceState['status'];
  due: boolean;
  nextDueAt?: number;
  paidCount: number;
  escalationId?: string;
  lastError?: string;
  symbol?: string;
}

const WHY_SHORT: Record<EscalationWhy, string> = {
  'not-meterable': 'not an AUTO call',
  'lane-closed': 'AUTO lane closed',
  'per-tx-cap': 'over the per-tx cap',
  'new-payee': 'new payee',
  'period-cap': 'over the period cap',
  'payee-redirect': 'payee changed',
  'chain-human-required': 'chain requires a human',
  'chain-lane-closed': 'chain: lane closed',
};

const WHY_TEXT: Record<EscalationWhy, string> = {
  'not-meterable': 'the call is not an AUTO payment for this mandate (other asset or call): the device must co-sign',
  'lane-closed': 'the risk monitor closed the vault\'s AUTO lane: only device co-signs pay until the device reopens it',
  'per-tx-cap': 'the amount is above the mandate\'s per-transaction AUTO cap',
  'new-payee': 'the payee was never co-signed under this mandate (newPayeeNeedsHuman)',
  'period-cap': 'the amount would exceed the AUTO budget of the current period',
  'payee-redirect': 'the destination differs from the invoice\'s payee of record (the invoice memo asked for it): possible prompt injection',
  'chain-human-required': 'the enforcer refused the AUTO redemption (HumanRequired)',
  'chain-lane-closed': 'the enforcer refused the AUTO redemption (LaneClosed)',
};

function riskFor(why: EscalationWhy, vendor: string): NonNullable<CosignRequestJson['risk']> {
  const r = (category: string, label: string) => ({ src: 'agent', category, label: aiTextTrunc(label, 64), ageDays: 0 });
  switch (why) {
    case 'payee-redirect':
      return r('payee-redirect', `memo redirects the ${vendor} payment`);
    case 'new-payee':
      return r('new-payee', 'first payment to this address under this mandate');
    case 'per-tx-cap':
    case 'period-cap':
      return r('over-cap', 'amount above the AUTO caps');
    case 'lane-closed':
    case 'chain-lane-closed':
      return r('lane-closed', 'risk monitor closed the AUTO lane');
    case 'not-meterable':
      return r('not-auto', 'asset or call outside the AUTO terms');
    default:
      return r('human-required', 'the enforcer requires a device co-sign');
  }
}

export interface ServiceDeps {
  config: AgentConfig;
  chain: RiparChain;
  store: AgentStore;
  events: EventBus;
}

export class AgentService {
  readonly config: AgentConfig;
  readonly chain: RiparChain;
  readonly store: AgentStore;
  readonly events: EventBus;
  private readonly lock = new Mutex();
  private readonly nonces = new CosignNonceTracker(8);

  constructor(d: ServiceDeps) {
    this.config = d.config;
    this.chain = d.chain;
    this.store = d.store;
    this.events = d.events;
    for (const e of Object.values(this.store.escalations)) this.nonces.markUsed(e.cosign.delegationHash, BigInt(e.cosign.nonce));
  }

  get agent(): Address {
    return this.chain.agent;
  }

  /** start-up: an escalation left 'submitting' by a crash is resolved from the chain's nonceUsed view */
  async recover(): Promise<void> {
    for (const e of Object.values(this.store.escalations)) {
      // with a tx hash, settlePending() reads the receipt; without one the process died before the send returned
      if (e.status !== 'submitting' || e.submission?.txHash) continue;
      const used = await this.chain.nonceUsed(e.cosign.delegationHash, BigInt(e.cosign.nonce)).catch(() => null);
      if (used === null) continue;
      e.status = used ? 'executed' : 'pending';
      e.updatedAt = Date.now();
      if (used) {
        e.error = { name: 'Recovered', message: 'redeemed before a restart (transaction hash unknown)', at: Date.now() };
        const inv = e.invoiceId ? this.store.invoices.find((i) => i.id === e.invoiceId) : undefined;
        if (inv) this.invoicePaid(inv, `recovered:${e.id}`, Math.floor(Date.now() / 1000));
      }
    }
    this.store.saveEscalations();
  }

  // ------------------------------------------------------------------------------------------------ mandate
  mandate(): StoredMandate | null {
    return this.store.mandate;
  }

  private requireMandate(): StoredMandate {
    const m = this.store.mandate;
    if (!m) throw new ApiError(409, 'no_mandate', 'no mandate yet: the companion must POST /mandate with the device-signed delegation');
    if (m.status !== 'active') throw new ApiError(409, 'mandate_dead', `the mandate is dead: ${m.deadReason ?? 'revoked'}`);
    return m;
  }

  async acceptMandate(input: MandateInput): Promise<StoredMandate> {
    return this.lock.run(async () => {
      const { delegation, request } = mandateFromInput(input, this.config.chainId);
      const v = validateMandate(delegation, { agent: this.agent, chainId: this.config.chainId, deployment: this.config.deployment }, request);
      if (v.agentId === undefined && input.agentId !== undefined) {
        if (!/^\d{1,78}$/.test(String(input.agentId))) throw new ApiError(422, 'bad_mandate', 'agentId: expected an integer');
        v.agentId = String(input.agentId);
      }
      if (v.label === undefined && typeof input.label === 'string' && input.label.length <= 64) v.label = input.label;
      // on-chain liveness: not revoked / disabled, epoch not stale, vault owned by the signer
      const live = await this.chain.mandateLiveness(v.delegationHash, v.pulse.keyId);
      if (live.revoked) throw new ApiError(422, 'bad_mandate', 'the device already revoked this mandate');
      if (live.disabled) throw new ApiError(422, 'bad_mandate', 'the vault disabled this delegation');
      if (BigInt(v.pulse.epoch) < live.minEpoch) throw new ApiError(422, 'bad_mandate', `stale epoch ${v.pulse.epoch} < minEpoch ${live.minEpoch} (the device panicked)`);
      const owner = await this.chain.vaultOwner(v.vault);
      if (owner === null) v.warnings.push('the vault is not deployed yet: redemptions revert until it is');
      else if (!sameAddress(owner, v.owner)) throw new ApiError(422, 'bad_mandate', `the vault's owner is ${owner}, the mandate was signed by ${v.owner}`);
      if (this.config.agentId !== undefined && v.agentId !== undefined && BigInt(v.agentId) !== this.config.agentId) {
        v.warnings.push(`the mandate names agentId ${v.agentId} but AGENT_ID is ${this.config.agentId}`);
      }
      const prev = this.store.mandate;
      const m: StoredMandate = { ...v, receivedAt: Date.now(), status: 'active' };
      this.store.mandate = m;
      this.store.saveMandate();
      if (prev && prev.delegationHash !== m.delegationHash) {
        // escalations of the old mandate can never be redeemed with the new one
        for (const e of Object.values(this.store.escalations)) {
          if (e.status === 'pending' && e.cosign.delegationHash === prev.delegationHash) this.closeEscalation(e, 'expired', 'MandateReplaced', 'a new mandate replaced the one this co-sign was for');
        }
        this.store.saveEscalations();
      }
      this.events.emit('mandate', this.mandateSummary(m));
      this.events.log(`mandate accepted: ${m.delegationHash} from vault ${m.vault}`);
      return m;
    });
  }

  mandateSummary(m: StoredMandate): Record<string, unknown> {
    return {
      delegationHash: m.delegationHash,
      vault: m.vault,
      owner: m.owner,
      status: m.status,
      deadReason: m.deadReason,
      agentId: m.agentId,
      label: m.label,
      pulse: m.pulse,
      otherCaveats: m.otherCaveats,
      warnings: m.warnings,
      receivedAt: m.receivedAt,
    };
  }

  private markMandateDead(reason: string): void {
    const m = this.store.mandate;
    if (!m || m.status === 'dead') return;
    m.status = 'dead';
    m.deadReason = reason;
    this.store.saveMandate();
    this.events.emit('mandate', this.mandateSummary(m));
    this.events.log(`mandate is dead: ${reason}`);
  }

  // ------------------------------------------------------------------------------------------------ tokens
  resolveToken(t: string): Address {
    const s = t.trim();
    if (/^(native|mon)$/i.test(s)) return ZERO_ADDRESS;
    if (/^musd$/i.test(s)) {
      if (sameAddress(this.config.deployment.mockUsd, ZERO_ADDRESS)) throw new ApiError(422, 'bad_invoice', 'no MockUSD in this deployment');
      return this.config.deployment.mockUsd;
    }
    if (/^ausd$/i.test(s)) {
      if (this.config.chainId !== 10143) throw new ApiError(422, 'bad_invoice', 'AUSD is only known on 10143');
      return AUSD_10143;
    }
    try {
      return checksum(s, 'token');
    } catch {
      throw new ApiError(422, 'bad_invoice', `unknown token ${t}`);
    }
  }

  async tokenMeta(token: Address): Promise<{ decimals: number; symbol: string }> {
    if (sameAddress(token, ZERO_ADDRESS)) return { decimals: 18, symbol: 'MON' };
    return this.chain.tokenInfo(token);
  }

  // ------------------------------------------------------------------------------------------------ invoices
  private invState(id: string): InvoiceState {
    let s = this.store.invoiceState[id];
    if (!s) {
      s = { status: 'open', paidCount: 0, payments: [], updatedAt: Date.now() };
      this.store.invoiceState[id] = s;
    }
    return s;
  }

  private isDue(inv: Invoice, st: InvoiceState, now: number): boolean {
    if (st.status !== 'open' && st.status !== 'failed') return false;
    if (st.pendingTx) return false;
    const at = st.nextDueAt ?? inv.dueAt;
    return at === undefined || at <= now;
  }

  invoiceViews(now = Math.floor(Date.now() / 1000)): InvoiceView[] {
    return this.store.invoices.map((inv) => {
      const st = this.invState(inv.id);
      return {
        ...inv,
        status: st.status,
        due: this.isDue(inv, st, now),
        ...(st.nextDueAt !== undefined ? { nextDueAt: st.nextDueAt } : {}),
        paidCount: st.paidCount,
        ...(st.escalationId ? { escalationId: st.escalationId } : {}),
        ...(st.lastError ? { lastError: st.lastError } : {}),
      };
    });
  }

  private setInvoice(id: string, patch: Partial<InvoiceState>): void {
    const st = this.invState(id);
    Object.assign(st, patch, { updatedAt: Date.now() });
    this.store.saveInvoiceState();
    this.events.emit('invoice', { id, ...st });
  }

  private invoicePaid(inv: Invoice, paymentId: string, now: number): void {
    const st = this.invState(inv.id);
    const patch: Partial<InvoiceState> = {
      paidCount: st.paidCount + 1,
      payments: [...st.payments, paymentId],
      escalationId: undefined,
      lastError: undefined,
    };
    if (inv.recurring) {
      patch.status = 'open';
      patch.nextDueAt = now + inv.recurring.intervalSeconds;
    } else patch.status = 'paid';
    this.setInvoice(inv.id, patch);
  }

  // ------------------------------------------------------------------------------------------------ payments
  /** one payment proposal from the planner: AUTO when the enforcer allows it, otherwise an escalation */
  async payInvoice(invoiceId: string, opts: PayOptions = {}): Promise<PayOutcome> {
    return this.lock.run(() => this.payInvoiceLocked(invoiceId, opts));
  }

  private async payInvoiceLocked(invoiceId: string, opts: PayOptions): Promise<PayOutcome> {
    const m = this.requireMandate();
    const inv = this.store.invoices.find((i) => i.id === invoiceId);
    if (!inv) throw new ApiError(404, 'unknown_invoice', `no invoice ${invoiceId}`);
    await this.settlePending();
    const now = await this.chain.now();
    this.expireStale(now);
    const st = this.invState(inv.id);
    const refuse = (reason: string): PayOutcome => ({ outcome: 'refused', invoiceId, reason });
    if (st.pendingTx) return refuse(`transaction ${st.pendingTx.hash} is not confirmed yet`);
    if (st.status === 'escalated') return refuse(`waiting for the device: escalation ${st.escalationId}`);
    if (st.status === 'paid') return refuse('already paid');
    if (st.status === 'denied') return refuse('the human denied this payment on the device');
    if (!this.isDue(inv, st, Number(now))) return refuse(`not due before ${st.nextDueAt ?? inv.dueAt}`);

    const token = this.resolveToken(inv.token);
    const meta = await this.tokenMeta(token);
    let amount: bigint;
    try {
      amount = parseAmount(inv.amount, meta.decimals);
    } catch (e) {
      return refuse(errorMessage(e));
    }
    if (amount === 0n) return refuse('zero amount');
    let dest: Address = inv.payee;
    let redirectedFrom: Address | undefined;
    if (opts.payTo !== undefined && opts.payTo !== '') {
      try {
        dest = checksum(opts.payTo, 'pay_to');
      } catch (e) {
        return refuse(errorMessage(e));
      }
      if (!sameAddress(dest, inv.payee)) redirectedFrom = inv.payee;
    }
    if (sameAddress(dest, ZERO_ADDRESS) || sameAddress(dest, m.vault)) return refuse('refusing to pay the zero address or the vault itself');
    const exec: Execution = sameAddress(token, ZERO_ADDRESS)
      ? { target: dest, value: amount, callData: '0x' }
      : { target: token, value: 0n, callData: toHex(erc20Transfer(dest, amount)) };

    const balance = sameAddress(token, ZERO_ADDRESS) ? await this.chain.nativeBalance(m.vault) : await this.chain.tokenBalance(token, m.vault);
    if (balance < amount) {
      const why = `vault balance ${fmtAmount(balance, meta.decimals)} ${meta.symbol} < ${inv.amount}`;
      this.setInvoice(inv.id, { lastError: why });
      return refuse(why);
    }

    const ctx = { m, inv, exec, token, meta, amount, dest, now, redirectedFrom, opts };
    if (redirectedFrom) return this.escalate(ctx, 'payee-redirect');

    const dh = m.delegationHash;
    const laneCheck = sameAddress(m.pulse.sentinel, ZERO_ADDRESS) ? Promise.resolve(true) : this.chain.laneOpen(m.pulse.sentinel, m.vault);
    const [laneOpen, payeeKnown, stored] = await Promise.all([laneCheck, this.chain.isKnownPayee(dh, dest), this.chain.periodSpent(dh)]);
    const decision = autoPathDecision(m.pulse.terms, exec, { laneOpen, payeeKnown, stored, now });
    if (decision.path === 'human') return this.escalate(ctx, decision.reason);

    // AUTO: the enforcer decides; HumanRequired / LaneClosed at estimation means escalate instead
    try {
      const tx = await this.chain.redeem(delegationOf(m), exec, '0x');
      const payment: PaymentRecord = {
        id: randomId('pay'),
        invoiceId: inv.id,
        path: 'auto',
        txHash: tx.hash,
        gasUsed: tx.gasUsed.toString(),
        gasLimit: tx.gasLimit.toString(),
        blockNumber: tx.blockNumber.toString(),
        to: dest,
        token,
        amount: amount.toString(),
        at: Date.now(),
      };
      this.store.payments.push(payment);
      this.store.savePayments();
      this.invoicePaid(inv, payment.id, Number(now));
      this.events.emit('payment', payment);
      this.events.log(`AUTO paid ${inv.id}: ${inv.amount} ${meta.symbol} to ${dest} (${tx.hash})`);
      return { outcome: 'paid', path: 'auto', invoiceId: inv.id, payment };
    } catch (e) {
      if (e instanceof TxPendingError) {
        // sent, outcome unknown: never pay this invoice again before the receipt settles it (settlePending)
        this.setInvoice(inv.id, {
          pendingTx: { hash: e.hash, gasLimit: e.gasLimit.toString(), to: dest, token, amount: amount.toString(), at: Date.now() },
          lastError: e.message,
        });
        this.events.log(`AUTO payment of ${inv.id} sent (${e.hash}) but not confirmed yet`);
        return { outcome: 'pending', invoiceId: inv.id, txHash: e.hash };
      }
      if (e instanceof ChainRevertError) {
        if (e.escalate) return this.escalate(ctx, e.revert.name === 'LaneClosed' ? 'chain-lane-closed' : 'chain-human-required');
        if (e.mandateDead) this.markMandateDead(`${e.revert.name}: ${e.revert.message}`);
        this.setInvoice(inv.id, { status: 'failed', lastError: `${e.revert.name}: ${e.revert.message}` });
        return { outcome: 'failed', invoiceId: inv.id, error: { name: e.revert.name, message: e.revert.message } };
      }
      const msg = errorMessage(e);
      this.setInvoice(inv.id, { lastError: msg });
      return { outcome: 'failed', invoiceId: inv.id, error: { name: 'Error', message: msg } };
    }
  }

  private async escalate(
    c: {
      m: StoredMandate;
      inv: Invoice;
      exec: Execution;
      token: Address;
      meta: { decimals: number; symbol: string };
      amount: bigint;
      dest: Address;
      now: bigint;
      redirectedFrom?: Address;
      opts: PayOptions;
    },
    why: EscalationWhy,
  ): Promise<PayOutcome> {
    const { m, inv, exec, token, meta, amount, dest, now } = c;
    const dh = m.delegationHash;
    const nonce = await this.nonces.nextUnused(dh, (n) => this.chain.nonceUsed(dh, n));
    const expiry = Number(now) + Math.min(this.config.cosignTtlSeconds, 7 * 24 * 3600);
    let budget: AutoBudget;
    try {
      budget = await this.chain.autoBudget(dh, m.pulse.terms);
    } catch {
      budget = { spent: 0n, remaining: 0n, periodStart: 0n, periodEnd: 0n };
    }
    const amountText = fmtAmount(amount, meta.decimals);
    const base =
      why === 'payee-redirect'
        ? `REDIRECT ${inv.id}: memo says pay ${shortAddr(dest)}, not ${inv.vendor}; ${amountText} ${meta.symbol}`
        : `${inv.id} ${inv.vendor}: ${amountText} ${meta.symbol} (${WHY_SHORT[why]})`;
    const note = c.opts.note ? aiTextTrunc(c.opts.note, 100).trim() : '';
    const text = aiTextTrunc(note ? `${base}. ${note}` : base, 100);
    // The claims are what the agent's task says it pays: the invoice of record (payee, token, amount). The device
    // checks them against its own decode of the calldata. A redirected destination (pay_to, e.g. from an injected
    // memo) therefore shows "AI claims: MISMATCH" in red on the device, never a green MATCH on the attacker's address.
    const claims = {
      to: c.redirectedFrom ?? dest,
      token: sameAddress(token, ZERO_ADDRESS) ? ZERO_ADDRESS : token,
      amount: amount.toString(),
    };
    const cosign: CosignRequestJson = {
      chainId: this.config.chainId,
      enforcer: m.pulse.enforcer,
      delegationHash: dh,
      delegator: m.vault,
      redeemer: this.agent,
      target: exec.target,
      value: exec.value.toString(),
      calldata: exec.callData,
      nonce: nonce.toString(),
      expiry,
      risk: riskFor(why, inv.vendor),
      ai: { text, claims },
      budgetLeft: budget.remaining.toString(),
      decimals: meta.decimals,
      symbol: aiTextTrunc(meta.symbol, 16),
    };
    // the token claims (keys 15 / 16) must agree with the firmware table, otherwise the device refuses the request
    let built = buildRequest('cosign', cosign as unknown as CosignFields);
    try {
      tokenCheck(decodeRequest('cosign', built.cbor) as CosignRequest);
    } catch {
      delete cosign.decimals;
      delete cosign.symbol;
      built = buildRequest('cosign', cosign as unknown as CosignFields);
    }
    const q = decodeRequest('cosign', built.cbor) as CosignRequest;
    const esc: Escalation = {
      id: randomId('esc'),
      status: 'pending',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      invoiceId: inv.id,
      reason: why,
      reasonText: WHY_TEXT[why],
      execution: { target: exec.target, value: exec.value.toString(), callData: exec.callData },
      cosign,
      request: { type: 'ripar-cosign-req', reqId: built.reqId, ur: built.ur, parts: built.parts },
      requestHash: denyRequestHashOf(q),
      display: {
        vendor: inv.vendor,
        payee: dest,
        amount: amountText,
        symbol: meta.symbol,
        token,
        ...(inv.memo !== undefined ? { memo: inv.memo } : {}),
        ...(c.redirectedFrom ? { redirectedFrom: c.redirectedFrom } : {}),
      },
      ...(c.opts.planner ? { planner: c.opts.planner } : {}),
    };
    this.store.escalations[esc.id] = esc;
    this.store.saveEscalations();
    this.setInvoice(inv.id, { status: 'escalated', escalationId: esc.id, lastError: undefined });
    this.events.emit('escalation', esc);
    this.events.log(`escalated ${inv.id} to the device: ${WHY_TEXT[why]}`, { escalationId: esc.id });
    return { outcome: 'escalated', invoiceId: inv.id, escalation: esc };
  }

  /** pending escalations whose co-sign expired: expired, their invoice re-opens (a new escalation gets a new nonce) */
  expireStale(now: bigint): void {
    let changed = false;
    for (const e of Object.values(this.store.escalations)) {
      if (e.status === 'pending' && BigInt(e.cosign.expiry) < now) {
        this.closeEscalation(e, 'expired', 'CosignExpired', 'the co-sign window passed');
        changed = true;
      }
    }
    if (changed) this.store.saveEscalations();
  }

  private closeEscalation(e: Escalation, status: 'expired' | 'failed', name: string, message: string): void {
    e.status = status;
    e.error = { name, message, at: Date.now() };
    e.updatedAt = Date.now();
    if (e.invoiceId && this.store.invoiceState[e.invoiceId]?.escalationId === e.id) {
      this.setInvoice(e.invoiceId, { status: status === 'expired' ? 'open' : 'failed', escalationId: undefined, lastError: `${name}: ${message}` });
    }
    this.events.emit('escalation', e);
  }

  // ------------------------------------------------------------------------------------------------ escalations
  escalations(): Escalation[] {
    return Object.values(this.store.escalations).sort((a, b) => b.createdAt - a.createdAt);
  }

  escalation(id: string): Escalation {
    const e = this.store.escalations[id];
    if (!e) throw new ApiError(404, 'unknown_escalation', `no escalation ${id}`);
    return e;
  }

  /** the device's co-sign for an escalation: verified locally against the mandate's P-256 key, then the HUMAN redemption */
  async submitCosign(id: string, body: CosignSubmission): Promise<{ escalation: Escalation; payment: PaymentRecord }> {
    return this.lock.run(() => this.submitCosignLocked(id, body));
  }

  private async submitCosignLocked(id: string, body: CosignSubmission): Promise<{ escalation: Escalation; payment: PaymentRecord }> {
    const e = this.escalation(id);
    if (e.status === 'executed') throw new ApiError(409, 'already_executed', `escalation ${id} was already redeemed (${e.result?.txHash ?? 'tx unknown'})`);
    if (e.status === 'denied') throw new ApiError(409, 'denied', `escalation ${id} was denied`);
    if (e.status === 'expired') throw new ApiError(410, 'expired', `escalation ${id} expired: ${e.error?.message ?? ''}`);
    if (e.status === 'submitting') throw new ApiError(409, 'in_progress', `escalation ${id} is being redeemed`);
    if (e.status === 'failed') throw new ApiError(409, 'failed', `escalation ${id} failed: ${e.error?.name ?? ''} ${e.error?.message ?? ''}`);
    const m = this.requireMandate();
    if (m.delegationHash !== e.cosign.delegationHash) throw new ApiError(409, 'mandate_changed', 'the mandate changed since this escalation');

    const sig = parseCosignSubmission(body);
    const c = e.cosign;
    const ph = presenceHash(sig.evidence12, sig.salt16);
    const digest = cosignDigest(
      {
        chainId: c.chainId,
        enforcer: c.enforcer,
        delegationHash: c.delegationHash,
        delegator: c.delegator,
        redeemer: c.redeemer,
        target: c.target,
        value: BigInt(c.value),
        calldata: c.calldata,
        nonce: BigInt(c.nonce),
        expiry: c.expiry,
      },
      ph,
    );
    const r = bytesToBigInt(sig.rs.subarray(0, 32));
    const s = bytesToBigInt(sig.rs.subarray(32, 64));
    if (!isLowS(s, P256_N)) throw new ApiError(400, 'bad_cosign', 'high-s signature (the enforcer rejects it)');
    if (!p256Verify(m.pulse.p1Key, digest, r, s)) {
      throw new ApiError(400, 'bad_cosign', 'the P-256 signature does not verify against the mandate\'s device key for this exact call');
    }
    const now = await this.chain.now();
    if (now > BigInt(c.expiry)) {
      this.closeEscalation(e, 'expired', 'CosignExpired', 'the co-sign expired before it was redeemed');
      this.store.saveEscalations();
      throw new ApiError(410, 'expired', 'the co-sign expired');
    }
    if (await this.chain.nonceUsed(c.delegationHash, BigInt(c.nonce))) {
      this.closeEscalation(e, 'failed', 'CosignReplayed', 'the nonce of this co-sign is already used on chain');
      this.store.saveEscalations();
      throw new ApiError(409, 'replayed', 'CosignReplayed: this co-sign nonce was already used');
    }
    const args = cosignCaveatArgs(BigInt(c.nonce), c.expiry, ph, sig.rs);
    const exec: Execution = { target: e.execution.target, value: BigInt(e.execution.value), callData: e.execution.callData };
    e.status = 'submitting';
    e.updatedAt = Date.now();
    e.submission = { approvalDigest: toHex(digest), presenceHash: toHex(ph), at: Date.now() };
    this.store.saveEscalations();
    let tx: TxOutcome;
    try {
      tx = await this.chain.redeem(delegationOf(m), exec, args);
    } catch (err) {
      if (err instanceof TxPendingError) {
        // sent, outcome unknown: stays 'submitting' until settlePending() reads the receipt
        e.submission.txHash = err.hash;
        e.submission.gasLimit = err.gasLimit.toString();
        e.error = { name: 'TxPending', message: err.message, at: Date.now() };
        this.store.saveEscalations();
        this.events.emit('escalation', e);
        throw new ApiError(504, 'tx_pending', `${err.message}; GET /escalations/${e.id} shows the outcome once it settles`, { txHash: err.hash });
      }
      if (err instanceof ChainRevertError) {
        const name = err.revert.name;
        if (name === 'CosignExpired') this.closeEscalation(e, 'expired', name, err.revert.message);
        else if (['CosignReplayed', 'BadCosign', 'InvalidArgs'].includes(name) || err.mandateDead) {
          this.closeEscalation(e, 'failed', name, err.revert.message);
          if (err.mandateDead) this.markMandateDead(`${name}: ${err.revert.message}`);
        } else {
          // e.g. an empty vault or a paused DelegationManager: the co-sign is still unused, it can be submitted again
          e.status = 'pending';
          e.error = { name, message: err.revert.message, at: Date.now() };
          e.updatedAt = Date.now();
        }
        this.store.saveEscalations();
        this.events.emit('escalation', e);
        throw new ApiError(502, 'chain_revert', `${name}: ${err.revert.message}`, { revert: err.revert, phase: err.phase, txHash: err.txHash });
      }
      e.status = 'pending';
      e.error = { name: 'Error', message: errorMessage(err), at: Date.now() };
      e.updatedAt = Date.now();
      this.store.saveEscalations();
      throw new ApiError(502, 'chain_error', errorMessage(err));
    }
    const payment = await this.finalizeHuman(e, tx, toHex(digest), toHex(ph), now);
    return { escalation: e, payment };
  }

  /** a HUMAN redemption landed: payment record, invoice, then attestApproval (ERC-8004) when an agentId is known */
  private async finalizeHuman(e: Escalation, tx: TxOutcome, digest: Hex, ph: Hex, now: bigint): Promise<PaymentRecord> {
    const c = e.cosign;
    const payment: PaymentRecord = {
      id: randomId('pay'),
      ...(e.invoiceId ? { invoiceId: e.invoiceId } : {}),
      escalationId: e.id,
      path: 'human',
      txHash: tx.hash,
      gasUsed: tx.gasUsed.toString(),
      gasLimit: tx.gasLimit.toString(),
      blockNumber: tx.blockNumber.toString(),
      // what was actually paid (the claims describe the invoice of record, which a redirect does not pay)
      to: e.display.payee ?? c.ai.claims.to,
      token: e.display.token ?? c.ai.claims.token,
      amount: c.ai.claims.amount,
      at: Date.now(),
    };
    this.store.payments.push(payment);
    this.store.savePayments();
    e.status = 'executed';
    e.error = undefined;
    e.updatedAt = Date.now();
    e.result = {
      txHash: tx.hash,
      gasUsed: tx.gasUsed.toString(),
      gasLimit: tx.gasLimit.toString(),
      blockNumber: tx.blockNumber.toString(),
      approvalDigest: digest,
      presenceHash: ph,
      paymentId: payment.id,
    };
    this.store.saveEscalations();
    const inv = e.invoiceId ? this.store.invoices.find((i) => i.id === e.invoiceId) : undefined;
    if (inv) this.invoicePaid(inv, payment.id, Number(now));
    this.events.emit('payment', payment);
    this.events.log(`HUMAN paid ${e.invoiceId ?? e.id} with the device co-sign (${tx.hash})`);

    // ERC-8004 reputation: only the redeemer (this agent) can attest its approval
    const m = this.store.mandate;
    const agentId = this.config.agentId ?? (m?.agentId !== undefined ? BigInt(m.agentId) : undefined);
    if (agentId !== undefined) {
      try {
        const at = await this.chain.attestApproval(this.config.deployment.relay, agentId, digest);
        e.result.attest = { txHash: at.hash };
        this.events.log(`attested approval for agent ${agentId} (${at.hash})`);
      } catch (err) {
        e.result.attest = {
          ...(err instanceof TxPendingError ? { txHash: err.hash } : {}),
          error: err instanceof ChainRevertError ? `${err.revert.name}: ${err.revert.message}` : errorMessage(err),
        };
        this.events.log(`attestApproval failed: ${e.result.attest.error}`);
      }
      this.store.saveEscalations();
    }
    this.events.emit('escalation', e);
    return payment;
  }

  /**
   * Settles transactions that were sent but whose receipt could not be read (TxPendingError): an AUTO payment is
   * recorded (or released after a revert), a HUMAN redemption is finalized (or its escalation re-opened: a reverted
   * redemption does not consume the co-sign). Runs under the service lock.
   */
  private async settlePending(): Promise<void> {
    let now: bigint | null = null;
    const chainNow = async (): Promise<bigint> => (now ??= await this.chain.now());
    for (const inv of this.store.invoices) {
      const p = this.store.invoiceState[inv.id]?.pendingTx;
      if (!p) continue;
      const r = await this.chain.txStatus(p.hash);
      if (r.status === 'pending') continue;
      if (r.status === 'reverted') {
        this.setInvoice(inv.id, { pendingTx: undefined, lastError: `transaction ${p.hash} reverted` });
        continue;
      }
      const payment: PaymentRecord = {
        id: randomId('pay'),
        invoiceId: inv.id,
        path: 'auto',
        txHash: p.hash,
        gasUsed: (r.gasUsed ?? 0n).toString(),
        gasLimit: p.gasLimit,
        blockNumber: (r.blockNumber ?? 0n).toString(),
        to: p.to,
        token: p.token,
        amount: p.amount,
        at: Date.now(),
      };
      this.store.payments.push(payment);
      this.store.savePayments();
      this.setInvoice(inv.id, { pendingTx: undefined });
      this.invoicePaid(inv, payment.id, Number(await chainNow()));
      this.events.emit('payment', payment);
      this.events.log(`AUTO payment of ${inv.id} confirmed (${p.hash})`);
    }
    for (const e of Object.values(this.store.escalations)) {
      const sub = e.submission;
      if (e.status !== 'submitting' || !sub?.txHash) continue;
      const r = await this.chain.txStatus(sub.txHash);
      if (r.status === 'pending') continue;
      if (r.status === 'success') {
        await this.finalizeHuman(
          e,
          { hash: sub.txHash, gasUsed: r.gasUsed ?? 0n, gasLimit: BigInt(sub.gasLimit ?? '0'), blockNumber: r.blockNumber ?? 0n },
          sub.approvalDigest,
          sub.presenceHash,
          await chainNow(),
        );
      } else {
        e.status = 'pending';
        e.error = { name: 'Reverted', message: `redemption ${sub.txHash} reverted; the co-sign was not consumed`, at: Date.now() };
        e.updatedAt = Date.now();
        this.store.saveEscalations();
        this.events.emit('escalation', e);
      }
    }
  }

  /** the user denied on the device; the companion relays the deny (RiparReputationRelay.attestDenial) and tells us */
  async deny(id: string, body: { ur?: string; note?: string } = {}): Promise<Escalation> {
    return this.lock.run(async () => {
      const e = this.escalation(id);
      if (e.status === 'executed') throw new ApiError(409, 'already_executed', 'already redeemed: a deny can no longer stop it');
      if (e.status === 'submitting') throw new ApiError(409, 'in_progress', 'being redeemed right now');
      if (e.status === 'denied') return e;
      let verified = false;
      let requestHash: Hex | undefined;
      if (body.ur !== undefined) {
        if (typeof body.ur !== 'string') throw new ApiError(400, 'bad_request', 'ur: expected a string');
        let rep;
        try {
          rep = parseResponse(body.ur, {
            request: e.request.ur,
            p1Key: this.store.mandate?.pulse.p1Key ?? null,
            chainId: this.config.chainId,
            contract: this.config.deployment.relay,
          });
        } catch (err) {
          throw new ApiError(400, 'bad_deny', `not a ripar-deny response: ${errorMessage(err)}`);
        }
        if (rep.type !== 'ripar-deny') throw new ApiError(400, 'bad_deny', `expected ripar-deny, got ${rep.type}`);
        requestHash = rep.fields.requestHash;
        const sigOk = rep.checks.some((x) => /P-256 signature/.test(x.name) && x.ok) && rep.checks.filter((x) => /P-256|low-s/.test(x.name)).every((x) => x.ok);
        const mandateAgent = this.store.mandate?.agentId;
        const agentOk = mandateAgent === undefined || BigInt(mandateAgent) === rep.fields.agentId;
        verified = sigOk && agentOk && requestHash.toLowerCase() === e.requestHash.toLowerCase();
      }
      e.status = 'denied';
      e.updatedAt = Date.now();
      e.deny = {
        at: Date.now(),
        verified,
        ...(requestHash ? { requestHash } : {}),
        ...(typeof body.note === 'string' ? { note: body.note.slice(0, 200) } : {}),
      };
      this.store.saveEscalations();
      if (e.invoiceId) this.setInvoice(e.invoiceId, { status: 'denied', escalationId: e.id, lastError: 'denied on the device' });
      this.events.emit('escalation', e);
      this.events.log(`escalation ${e.id} denied by the human${verified ? ' (device deny verified)' : ''}`);
      return e;
    });
  }

  // ------------------------------------------------------------------------------------------------ state
  async state(): Promise<Record<string, unknown>> {
    const m = this.store.mandate;
    const out: Record<string, unknown> = {
      agent: { address: this.agent, chainId: this.config.chainId, agentId: this.config.agentId?.toString() ?? m?.agentId ?? null },
      deployment: {
        enforcer: this.config.deployment.enforcer,
        sentinel: this.config.deployment.sentinel,
        relay: this.config.deployment.relay,
        registry: this.config.deployment.registry,
        mockUsd: this.config.deployment.mockUsd,
        delegationManager: this.config.deployment.delegationManager,
      },
      mandate: m ? this.mandateSummary(m) : null,
    };
    let now: bigint | null = null;
    try {
      await this.lock.run(() => this.settlePending());
      now = await this.chain.now();
      out.chainTime = Number(now);
      this.expireStale(now);
    } catch (e) {
      out.chainError = errorMessage(e);
    }
    if (m && now !== null) {
      try {
        const token = m.pulse.token;
        const meta = await this.tokenMeta(token);
        const [native, tokenBal, budget, laneOpen, owner, live] = await Promise.all([
          this.chain.nativeBalance(m.vault),
          sameAddress(token, ZERO_ADDRESS) ? Promise.resolve(null) : this.chain.tokenBalance(token, m.vault),
          this.chain.autoBudget(m.delegationHash, m.pulse.terms),
          sameAddress(m.pulse.sentinel, ZERO_ADDRESS) ? Promise.resolve(true) : this.chain.laneOpen(m.pulse.sentinel, m.vault),
          this.chain.vaultOwner(m.vault),
          this.chain.mandateLiveness(m.delegationHash, m.pulse.keyId),
        ]);
        // native + the metered token + the deployment's MockUSD (demo stablecoin)
        const balances = [{ token: ZERO_ADDRESS as Address, symbol: 'MON', decimals: 18, balance: native.toString(), formatted: fmtAmount(native, 18) }];
        if (tokenBal !== null) balances.push({ token, symbol: meta.symbol, decimals: meta.decimals, balance: tokenBal.toString(), formatted: fmtAmount(tokenBal, meta.decimals) });
        const musd = this.config.deployment.mockUsd;
        if (!sameAddress(musd, ZERO_ADDRESS) && !sameAddress(musd, token)) {
          try {
            const [mi, mb] = await Promise.all([this.chain.tokenInfo(musd), this.chain.tokenBalance(musd, m.vault)]);
            balances.push({ token: musd, symbol: mi.symbol, decimals: mi.decimals, balance: mb.toString(), formatted: fmtAmount(mb, mi.decimals) });
          } catch {
            /* MockUSD not deployed on this chain */
          }
        }
        out.vault = {
          address: m.vault,
          deployed: owner !== null,
          owner,
          native: balances[0],
          ...(tokenBal !== null ? { token: balances[1] } : {}),
          balances,
        };
        out.budget = {
          token,
          symbol: meta.symbol,
          spent: budget.spent.toString(),
          remaining: budget.remaining.toString(),
          remainingFormatted: fmtAmount(budget.remaining, meta.decimals),
          perTxAutoCap: m.pulse.perTxAutoCap,
          perTxAutoCapFormatted: fmtAmount(BigInt(m.pulse.perTxAutoCap), meta.decimals),
          periodAutoCap: m.pulse.periodAutoCap,
          periodStart: Number(budget.periodStart),
          periodEnd: Number(budget.periodEnd),
          period: m.pulse.period,
        };
        out.laneOpen = laneOpen;
        out.liveness = { revoked: live.revoked, disabled: live.disabled, minEpoch: live.minEpoch.toString(), stale: BigInt(m.pulse.epoch) < live.minEpoch };
        if (m.status === 'active' && (live.revoked || live.disabled || BigInt(m.pulse.epoch) < live.minEpoch)) {
          this.markMandateDead(live.revoked ? 'revoked by the device' : live.disabled ? 'disabled by the vault' : 'panic: stale epoch');
        }
      } catch (e) {
        out.chainError = errorMessage(e);
      }
    }
    out.invoices = this.invoiceViews(now !== null ? Number(now) : undefined);
    out.escalations = this.escalations().map(escalationSummary);
    out.payments = this.store.payments.slice(-50).reverse();
    return out;
  }
}

export function escalationSummary(e: Escalation): Record<string, unknown> {
  return {
    id: e.id,
    status: e.status,
    invoiceId: e.invoiceId,
    reason: e.reason,
    reasonText: e.reasonText,
    display: e.display,
    expiry: e.cosign.expiry,
    nonce: e.cosign.nonce,
    createdAt: e.createdAt,
    updatedAt: e.updatedAt,
    ...(e.result ? { txHash: e.result.txHash } : {}),
    ...(e.error ? { error: e.error } : {}),
  };
}

/** the device's ripar-cosign as raw UR or as {evidence12, salt16, r, s} / {evidence12, salt16, rs} */
export function parseCosignSubmission(body: CosignSubmission): { rs: Uint8Array; evidence12: Uint8Array; salt16: Uint8Array; reqId?: Hex } {
  const hexBytes = (v: unknown, n: number, what: string): Uint8Array => {
    if (!isHexBytes(v, n)) throw new ApiError(400, 'bad_cosign', `${what}: expected ${n} bytes of 0x-hex`);
    return Uint8Array.from(Buffer.from(v.slice(2), 'hex'));
  };
  if (!body || typeof body !== 'object') throw new ApiError(400, 'bad_cosign', 'expected a JSON object');
  if (body.ur !== undefined) {
    if (typeof body.ur !== 'string') throw new ApiError(400, 'bad_cosign', 'ur: expected a string');
    let rep;
    try {
      rep = parseResponse(body.ur);
    } catch (e) {
      throw new ApiError(400, 'bad_cosign', `not a device response: ${errorMessage(e)}`);
    }
    if (rep.type !== 'ripar-cosign') throw new ApiError(400, 'bad_cosign', `expected a ripar-cosign response, got ${rep.type}`);
    return {
      rs: hexBytes(rep.fields.rs, 64, 'rs'),
      evidence12: hexBytes(rep.fields.evidence12, 12, 'evidence12'),
      salt16: hexBytes(rep.fields.salt16, 16, 'salt16'),
      reqId: rep.fields.reqId,
    };
  }
  const evidence12 = hexBytes(body.evidence12, 12, 'evidence12');
  const salt16 = hexBytes(body.salt16, 16, 'salt16');
  let rs: Uint8Array;
  if (body.rs !== undefined) rs = hexBytes(body.rs, 64, 'rs');
  else {
    const r = hexBytes(body.r, 32, 'r');
    const s = hexBytes(body.s, 32, 's');
    rs = new Uint8Array(64);
    rs.set(r, 0);
    rs.set(s, 32);
  }
  return { rs, evidence12, salt16 };
}
