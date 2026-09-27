// AgentService against the fake chain + a software device: AUTO path, escalations (fields per PROTOCOL.md
// ripar-cosign-req), local P-256 verification before sending, HUMAN redemption, replay, deny, expiry, prompt injection.
import { beforeEach, describe, expect, it } from 'vitest';
import {
  aiMatches,
  decodeRequest,
  denyRequestHashOf,
  hashDelegation,
  readRequest,
  tokenCheck,
  type CosignRequest,
} from '@ripar/protocol';
import { ApiError, ChainRevertError } from '../src/errors.js';
import { delegationOf } from '../src/mandate.js';
import type { Escalation } from '../src/types.js';
import { ZERO_ADDRESS } from '../src/util.js';
import { ATTACKER, CLOUDNEST, LABELWORKS, MUSD, RELAY, STUDIO_ARC, makeFixture, type Fixture } from './helpers/fixture.js';
import { cosignEscalation, delegationJson, denyEscalation, newSoftDevice } from './helpers/soft-device.js';

async function escalated(f: Fixture, id: string, opts = {}): Promise<Escalation> {
  const out = await f.svc.payInvoice(id, opts);
  if (out.outcome !== 'escalated') throw new Error(`${id}: ${JSON.stringify(out)}`);
  return out.escalation;
}

async function apiError(p: Promise<unknown>): Promise<ApiError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof ApiError) return e;
    throw e;
  }
  throw new Error('expected an ApiError');
}

let f: Fixture;
beforeEach(async () => {
  f = makeFixture();
  await f.svc.acceptMandate({ delegation: delegationJson(f.mandate) });
});

describe('mandate', () => {
  it('stores the validated mandate', () => {
    const m = f.svc.mandate()!;
    expect(m.delegationHash).toBe(hashDelegation(f.mandate));
    expect(m.vault).toBe(f.dev.vault);
    expect(m.owner).toBe(f.dev.k1);
    expect(m.pulse.p1Key).toBe(f.dev.p1Key);
    expect(m.pulse.perTxAutoCap).toBe('5000000');
    expect(m.status).toBe('active');
  });

  it('refuses payments before a mandate', async () => {
    const g = makeFixture();
    const e = await apiError(g.svc.payInvoice('INV-001'));
    expect(e.code).toBe('no_mandate');
  });
});

describe('escalation: new payee (first payment of a recurring invoice)', () => {
  it('builds a complete ripar-cosign-req the device accepts', async () => {
    const e = await escalated(f, 'INV-001');
    expect(e.status).toBe('pending');
    expect(e.reason).toBe('new-payee');
    const c = e.cosign;
    expect(c.chainId).toBe(10143);
    expect(c.enforcer).toBe(f.config.deployment.enforcer);
    expect(c.delegationHash).toBe(hashDelegation(f.mandate));
    expect(c.delegator).toBe(f.dev.vault);
    expect(c.redeemer).toBe(f.agent);
    expect(c.target).toBe(MUSD);
    expect(c.value).toBe('0');
    expect(BigInt(c.nonce)).toBeGreaterThan(0n);
    expect(c.expiry).toBe(Number(f.chain.time) + 3600);
    expect(Buffer.byteLength(c.ai.text, 'utf8')).toBeLessThanOrEqual(100);
    expect(c.ai.text).toContain('INV-001');
    expect(c.ai.claims).toEqual({ to: CLOUDNEST, token: MUSD, amount: '2500000' });
    expect(c.budgetLeft).toBe('20000000');
    expect(c.risk).toMatchObject({ src: 'agent', category: 'new-payee' });
    expect(c.decimals).toBe(6);
    expect(c.symbol).toBe('mUSD');
    // the prebuilt request decodes to the same fields; the device's own checks pass
    const { kind, cbor } = readRequest(e.request.ur);
    expect(kind).toBe('cosign');
    const q = decodeRequest('cosign', cbor) as CosignRequest;
    expect(q.nonce).toBe(BigInt(c.nonce));
    expect(q.expiry).toBe(BigInt(c.expiry));
    expect(Buffer.from(q.calldata).toString('hex')).toBe(c.calldata.slice(2));
    expect(aiMatches(q)).toBe(true);
    expect(() => tokenCheck(q)).not.toThrow();
    expect(e.requestHash).toBe(denyRequestHashOf(q));
    expect(e.request.parts.length).toBeGreaterThan(1);
    expect(f.chain.redeems).toHaveLength(0);
    // the invoice waits for the device
    expect(f.svc.invoiceViews().find((i) => i.id === 'INV-001')!.status).toBe('escalated');
    expect((await f.svc.payInvoice('INV-001')).outcome).toBe('refused');
  });

  it('device co-sign -> verified locally -> HUMAN redemption; the payee becomes known; the next one is AUTO', async () => {
    const e = await escalated(f, 'INV-001');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    const { escalation, payment } = await f.svc.submitCosign(e.id, { evidence12: sig.evidence12, salt16: sig.salt16, r: sig.r, s: sig.s });
    expect(escalation.status).toBe('executed');
    expect(escalation.result!.approvalDigest).toBe(sig.digest);
    expect(payment.path).toBe('human');
    expect(f.chain.redeems.map((r) => r.path)).toEqual(['human']);
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(2_500_000n);
    expect(await f.chain.isKnownPayee(e.cosign.delegationHash, CLOUDNEST)).toBe(true);
    // resubmitting the same co-sign is refused by the agent...
    expect((await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }))).code).toBe('already_executed');
    // ...and by the chain (CosignReplayed), should anyone relay the args again
    const args = f.chain.redeems[0]!.args;
    await expect(f.chain.redeem(delegationOf(f.svc.mandate()!), f.chain.redeems[0]!.execution, args)).rejects.toMatchObject({
      revert: { name: 'CosignReplayed' },
    });
    // recurring: due again after 60 s, now on the AUTO path
    const inv = f.svc.invoiceViews().find((i) => i.id === 'INV-001')!;
    expect(inv.status).toBe('open');
    expect(inv.paidCount).toBe(1);
    expect((await f.svc.payInvoice('INV-001')).outcome).toBe('refused'); // not due yet
    f.chain.time += 61n;
    const auto = await f.svc.payInvoice('INV-001');
    expect(auto.outcome).toBe('paid');
    expect(f.chain.redeems.map((r) => r.path)).toEqual(['human', 'auto']);
    expect(f.chain.redeems[1]!.args).toBe('0x');
    const b = await f.chain.autoBudget(e.cosign.delegationHash, f.svc.mandate()!.pulse.terms);
    expect(b.spent).toBe(2_500_000n);
  });

  it('accepts the raw ripar-cosign UR too', async () => {
    const e = await escalated(f, 'INV-003');
    expect(e.reason).toBe('new-payee');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    const r = await f.svc.submitCosign(e.id, { ur: sig.ur });
    expect(r.escalation.status).toBe('executed');
    expect(f.chain.balance(MUSD, LABELWORKS)).toBe(3_000_000n);
  });

  it('refuses a signature that does not verify BEFORE sending anything', async () => {
    const e = await escalated(f, 'INV-001');
    const other = newSoftDevice();
    const bad = cosignEscalation(other, e.cosign, e.request.reqId);
    const err = await apiError(f.svc.submitCosign(e.id, { ur: bad.ur }));
    expect(err.status).toBe(400);
    expect(err.code).toBe('bad_cosign');
    // a signature over another nonce (the device signed a different request)
    const wrong = cosignEscalation(f.dev, { ...e.cosign, nonce: (BigInt(e.cosign.nonce) + 1n).toString() }, e.request.reqId);
    expect((await apiError(f.svc.submitCosign(e.id, { ur: wrong.ur }))).code).toBe('bad_cosign');
    // malformed
    expect((await apiError(f.svc.submitCosign(e.id, { evidence12: '0x00', salt16: '0x00', rs: '0x00' }))).code).toBe('bad_cosign');
    expect(f.chain.redeems).toHaveLength(0);
    expect(f.svc.escalation(e.id).status).toBe('pending');
  });
});

describe('escalation reasons', () => {
  it('over the per-tx cap', async () => {
    const e = await escalated(f, 'INV-002');
    expect(e.reason).toBe('per-tx-cap');
    expect(e.cosign.ai.claims).toEqual({ to: STUDIO_ARC, token: MUSD, amount: '45000000' });
    expect(e.cosign.risk?.category).toBe('over-cap');
  });

  it('lane closed by the sentinel', async () => {
    f.chain.lane = false;
    const e = await escalated(f, 'INV-001');
    expect(e.reason).toBe('lane-closed');
  });

  it('the chain refuses an AUTO the planner predicted (HumanRequired at estimation) -> escalation, nothing sent', async () => {
    await payInv001Human(f);
    f.chain.time += 61n;
    f.chain.failNext = { name: 'HumanRequired' };
    const e = await escalated(f, 'INV-001');
    expect(e.reason).toBe('chain-human-required');
    expect(f.chain.redeems).toHaveLength(1);
  });

  it('prompt injection: a memo redirect is ALWAYS escalated and the device sees the AI claim MISMATCH', async () => {
    await payInv001Human(f); // CloudNest becomes a known payee: INV-004 alone would be AUTO
    const e = await escalated(f, 'INV-004', { payTo: ATTACKER, note: 'vendor changed bank details' });
    expect(e.reason).toBe('payee-redirect');
    // the claims are the invoice of record (CloudNest); the calldata pays the attacker
    expect(e.cosign.ai.claims).toEqual({ to: CLOUDNEST, token: MUSD, amount: '4000000' });
    expect(e.display.payee).toBe(ATTACKER);
    expect(e.cosign.ai.text.startsWith('REDIRECT INV-004')).toBe(true);
    expect(Buffer.byteLength(e.cosign.ai.text, 'utf8')).toBeLessThanOrEqual(100);
    expect(e.cosign.risk).toMatchObject({ src: 'agent', category: 'payee-redirect' });
    expect(e.display.redirectedFrom).toBe(CLOUDNEST);
    const q = decodeRequest('cosign', readRequest(e.request.ur).cbor) as CosignRequest;
    expect(aiMatches(q)).toBe(false); // the device shows "AI claims: MISMATCH" next to the attacker's address
    expect(f.chain.redeems).toHaveLength(1);
  });

  it('the same invoice without the redirect goes AUTO once the payee is known', async () => {
    await payInv001Human(f);
    const out = await f.svc.payInvoice('INV-004');
    expect(out.outcome).toBe('paid');
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(6_500_000n);
  });

  it('refuses when the vault cannot pay, pays nothing to the zero address or the vault', async () => {
    f.chain.setBalance(MUSD, f.dev.vault, 1n);
    const out = await f.svc.payInvoice('INV-001');
    expect(out).toMatchObject({ outcome: 'refused' });
    f.chain.setBalance(MUSD, f.dev.vault, 100_000_000n);
    expect(await f.svc.payInvoice('INV-001', { payTo: ZERO_ADDRESS })).toMatchObject({ outcome: 'refused' });
    expect(await f.svc.payInvoice('INV-001', { payTo: f.dev.vault })).toMatchObject({ outcome: 'refused' });
    expect(await f.svc.payInvoice('INV-001', { payTo: '0xnot-an-address' })).toMatchObject({ outcome: 'refused' });
    expect((await apiError(f.svc.payInvoice('INV-999'))).status).toBe(404);
  });
});

async function payInv001Human(fx: Fixture): Promise<void> {
  const e = await escalated(fx, 'INV-001');
  const sig = cosignEscalation(fx.dev, e.cosign, e.request.reqId);
  await fx.svc.submitCosign(e.id, { ur: sig.ur });
}

describe('nonces, expiry, replay, deny, failures', () => {
  it('every escalation gets a fresh nonce, also after a restart', async () => {
    const a = await escalated(f, 'INV-001');
    const b = await escalated(f, 'INV-002');
    const c = await escalated(f, 'INV-003');
    const svc2 = f.restart();
    expect(svc2.escalations()).toHaveLength(3);
    expect(svc2.mandate()!.delegationHash).toBe(a.cosign.delegationHash);
    const d = (await svc2.payInvoice('INV-004')) as { escalation?: Escalation };
    // INV-004 to CloudNest (not yet known) escalates as a new payee
    const nonces = new Set([a, b, c, d.escalation!].map((e) => e.cosign.nonce));
    expect(nonces.size).toBe(4);
  });

  it('a nonce already used on chain is caught before sending (CosignReplayed); the invoice gets a new escalation', async () => {
    const e = await escalated(f, 'INV-001');
    f.chain.nonces.add(`${e.cosign.delegationHash}:${e.cosign.nonce}`.toLowerCase());
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    const err = await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }));
    expect(err.code).toBe('replayed');
    expect(f.svc.escalation(e.id).status).toBe('failed');
    expect(f.chain.redeems).toHaveLength(0);
    const e2 = await escalated(f, 'INV-001');
    expect(e2.cosign.nonce).not.toBe(e.cosign.nonce);
  });

  it('expired co-signs: marked expired, the invoice re-opens, a late submission is refused (410)', async () => {
    const e = await escalated(f, 'INV-001');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    f.chain.time += 3601n;
    const err = await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }));
    expect(err.status).toBe(410);
    expect(f.svc.escalation(e.id).status).toBe('expired');
    expect(f.svc.invoiceViews().find((i) => i.id === 'INV-001')!.status).toBe('open');
    const e2 = await escalated(f, 'INV-001');
    expect(e2.cosign.expiry).toBe(Number(f.chain.time) + 3600);
  });

  it('the chain refuses at estimation (CosignExpired race) -> expired, nothing sent', async () => {
    const e = await escalated(f, 'INV-001');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    f.chain.failNext = { name: 'CosignExpired' };
    const err = await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }));
    expect(err.status).toBe(502);
    expect(f.svc.escalation(e.id).status).toBe('expired');
  });

  it('a transient failure (network) keeps the escalation pending: the same co-sign can be submitted again', async () => {
    const e = await escalated(f, 'INV-001');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    f.chain.networkDown = true;
    expect((await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }))).code).toBe('chain_error');
    expect(f.svc.escalation(e.id).status).toBe('pending');
    f.chain.networkDown = false;
    expect((await f.svc.submitCosign(e.id, { ur: sig.ur })).escalation.status).toBe('executed');
  });

  it('deny: a verified device deny marks the escalation and the invoice denied', async () => {
    const e = await escalated(f, 'INV-004', { payTo: ATTACKER });
    const ur = denyEscalation(f.dev, e, RELAY, 7n);
    const d = await f.svc.deny(e.id, { ur });
    expect(d.status).toBe('denied');
    expect(d.deny!.verified).toBe(true);
    expect(d.deny!.requestHash).toBe(e.requestHash);
    expect(f.svc.invoiceViews().find((i) => i.id === 'INV-004')!.status).toBe('denied');
    expect(await f.svc.payInvoice('INV-004')).toMatchObject({ outcome: 'refused' });
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    expect((await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }))).code).toBe('denied');
    expect(f.chain.redeems).toHaveLength(0);
  });

  it('deny without a UR (the companion relayed it) and a deny signed by another key (not verified, still denied)', async () => {
    const e1 = await escalated(f, 'INV-002');
    expect((await f.svc.deny(e1.id, {})).deny!.verified).toBe(false);
    const e2 = await escalated(f, 'INV-003');
    const d2 = await f.svc.deny(e2.id, { ur: denyEscalation(newSoftDevice(), e2, RELAY, 7n) });
    expect(d2.status).toBe('denied');
    expect(d2.deny!.verified).toBe(false);
    // a deny of a denied escalation is a no-op; garbage instead of a deny UR is refused and changes nothing
    expect((await f.svc.deny(e2.id, { ur: 'UR:NOT-A-DENY/xyz' })).status).toBe('denied');
    const e3 = await escalated(f, 'INV-001');
    expect((await apiError(f.svc.deny(e3.id, { ur: 'UR:NOT-A-DENY/xyz' }))).status).toBe(400);
    expect(f.svc.escalation(e3.id).status).toBe('pending');
  });

  it('a revoked mandate: the redemption fails DelegationRevoked and the mandate is marked dead', async () => {
    await payInv001Human(f);
    const m = f.svc.mandate()!;
    f.chain.revoked.add(`${m.pulse.keyId}:${m.delegationHash}`.toLowerCase());
    f.chain.time += 61n;
    const out = await f.svc.payInvoice('INV-001');
    expect(out).toMatchObject({ outcome: 'failed', error: { name: 'DelegationRevoked' } });
    expect(f.svc.mandate()!.status).toBe('dead');
    expect((await apiError(f.svc.payInvoice('INV-002'))).code).toBe('mandate_dead');
  });

  it('an AUTO payment sent but not confirmed is never paid twice; the receipt settles it', async () => {
    await payInv001Human(f);
    f.chain.time += 61n;
    f.chain.unconfirmedNext = 'success';
    const out = await f.svc.payInvoice('INV-001');
    expect(out.outcome).toBe('pending');
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(5_000_000n); // it did land
    expect(f.svc.invoiceViews().find((i) => i.id === 'INV-001')!.due).toBe(false);
    expect(await f.svc.payInvoice('INV-001')).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/not confirmed/) });
    expect(f.chain.redeems).toHaveLength(2);
    f.chain.confirmAll();
    const again = await f.svc.payInvoice('INV-001'); // settles first: recorded, the recurring invoice is not due yet
    expect(again).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/not due/) });
    expect(f.chain.redeems).toHaveLength(2);
    expect(f.store.payments.map((p) => p.path)).toEqual(['human', 'auto']);
    expect(f.svc.invoiceViews().find((i) => i.id === 'INV-001')!.paidCount).toBe(2);
  });

  it('an unconfirmed AUTO payment that reverted releases the invoice', async () => {
    await payInv001Human(f);
    f.chain.time += 61n;
    f.chain.unconfirmedNext = 'reverted';
    expect((await f.svc.payInvoice('INV-001')).outcome).toBe('pending');
    f.chain.confirmAll();
    const out = await f.svc.payInvoice('INV-001');
    expect(out.outcome).toBe('paid');
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(5_000_000n);
  });

  it('a HUMAN redemption sent but not confirmed stays submitting until the receipt settles it', async () => {
    const e = await escalated(f, 'INV-001');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    f.chain.unconfirmedNext = 'success';
    const err = await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }));
    expect(err.code).toBe('tx_pending');
    expect(f.svc.escalation(e.id).status).toBe('submitting');
    expect((await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }))).code).toBe('in_progress');
    f.chain.confirmAll();
    await f.svc.state();
    const done = f.svc.escalation(e.id);
    expect(done.status).toBe('executed');
    expect(done.result!.approvalDigest).toBe(sig.digest);
    expect(f.store.payments).toHaveLength(1);
    expect(f.svc.invoiceViews().find((i) => i.id === 'INV-001')!.paidCount).toBe(1);
  });

  it('restart recovery: an escalation left submitting (no tx hash) is resolved from nonceUsed', async () => {
    const a = await escalated(f, 'INV-001');
    const b = await escalated(f, 'INV-003');
    for (const e of [a, b]) {
      f.store.escalations[e.id]!.status = 'submitting';
    }
    f.store.saveEscalations();
    f.chain.nonces.add(`${a.cosign.delegationHash}:${a.cosign.nonce}`.toLowerCase()); // a landed, b did not
    const svc2 = f.restart();
    await svc2.recover();
    expect(svc2.escalation(a.id).status).toBe('executed');
    expect(svc2.escalation(b.id).status).toBe('pending');
    expect(svc2.invoiceViews().find((i) => i.id === 'INV-001')!.paidCount).toBe(1);
  });

  it('attestApproval after a HUMAN redemption when AGENT_ID is configured', async () => {
    const g = makeFixture({ AGENT_ID: '1939' });
    await g.svc.acceptMandate({ delegation: delegationJson(g.mandate) });
    const e = await escalated(g, 'INV-001');
    const sig = cosignEscalation(g.dev, e.cosign, e.request.reqId);
    const r = await g.svc.submitCosign(e.id, { ur: sig.ur });
    expect(g.chain.attests).toEqual([{ relay: RELAY, agentId: 1939n, digest: sig.digest }]);
    expect(r.escalation.result!.attest!.txHash).toMatch(/^0x/);
  });

  it('state() reports the budget, lane, vault and invoices', async () => {
    const s = (await f.svc.state()) as Record<string, any>;
    expect(s.mandate.delegationHash).toBe(hashDelegation(f.mandate));
    expect(s.budget.remaining).toBe('20000000');
    expect(s.budget.perTxAutoCapFormatted).toBe('5');
    expect(s.laneOpen).toBe(true);
    expect(s.vault.token.formatted).toBe('100');
    expect(s.invoices).toHaveLength(4);
    expect(s.escalations).toEqual([]);
  });

  it('ChainRevertError flags', async () => {
    f.chain.failNext = { name: 'LaneClosed' };
    const err = (await f.chain.redeem(delegationOf(f.svc.mandate()!), { target: MUSD, value: 0n, callData: '0x' }, '0x').catch((e: unknown) => e)) as ChainRevertError;
    expect(err).toBeInstanceOf(ChainRevertError);
    expect(err.escalate).toBe(true);
    expect(err.mandateDead).toBe(false);
    f.chain.failNext = { name: 'StaleEpoch' };
    const dead = (await f.chain.redeem(delegationOf(f.svc.mandate()!), { target: MUSD, value: 0n, callData: '0x' }, '0x').catch((e: unknown) => e)) as ChainRevertError;
    expect(dead.mandateDead).toBe(true);
    expect(dead.escalate).toBe(false);
  });
});
