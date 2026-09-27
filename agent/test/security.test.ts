// Security review fixes, service level (fake chain + software device): prototype-safe id lookups, bounded device
// payloads, idempotent AUTO / HUMAN sends (a broadcast error never leads to a second payment), undeployed vaults,
// nonceUsed failing closed, hostile token symbols, and the deny contract (device-verified or operator only).
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { decodeRequest, readRequest, type CosignRequest } from '@ripar/protocol';
import { getAddress, keccak256, type Address } from 'viem';
import { generatePrivateKey, privateKeyToAddress } from 'viem/accounts';
import { configWarnings, loadConfig, publicConfig } from '../src/config.js';
import { ApiError, MAX_QR_FIELD } from '../src/errors.js';
import { EventBus } from '../src/events.js';
import { AgentService } from '../src/service.js';
import { AgentStore } from '../src/store.js';
import type { Escalation } from '../src/types.js';
import { CLOUDNEST, DEP, LABELWORKS, MUSD, RELAY, makeFixture, type Fixture } from './helpers/fixture.js';
import { cosignEscalation, delegationJson, denyEscalation } from './helpers/soft-device.js';

async function apiError(p: Promise<unknown> | (() => unknown)): Promise<ApiError> {
  try {
    await (typeof p === 'function' ? Promise.resolve().then(p) : p);
  } catch (e) {
    if (e instanceof ApiError) return e;
    throw e;
  }
  throw new Error('expected an ApiError');
}

async function escalated(fx: Fixture, id: string): Promise<Escalation> {
  const out = await fx.svc.payInvoice(id);
  if (out.outcome !== 'escalated') throw new Error(`${id}: ${JSON.stringify(out)}`);
  return out.escalation;
}

/** INV-001 paid through the HUMAN path: CloudNest becomes a known payee, INV-001 is due again (AUTO) after 61 s */
async function payInv001Human(fx: Fixture): Promise<void> {
  const e = await escalated(fx, 'INV-001');
  await fx.svc.submitCosign(e.id, { ur: cosignEscalation(fx.dev, e.cosign, e.request.reqId).ur });
  fx.chain.time += 61n;
}

const inv = (fx: Fixture, id: string) => fx.svc.invoiceViews().find((i) => i.id === id)!;
const autoRedeems = (fx: Fixture) => fx.chain.redeems.filter((r) => r.path === 'auto').length;

let f: Fixture;
beforeEach(async () => {
  f = makeFixture();
  await f.svc.acceptMandate({ delegation: delegationJson(f.mandate) });
});

describe('1. prototype pollution through ids', () => {
  it('__proto__ / constructor never resolve to Object.prototype members', async () => {
    for (const id of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'esc_zz', 'esc_0123456789abcdef']) {
      expect((await apiError(() => f.svc.escalation(id))).code).toBe('unknown_escalation');
      expect((await apiError(f.svc.deny(id, { operator: true, note: 'x' }))).code).toBe('unknown_escalation');
      expect((await apiError(f.svc.submitCosign(id, {}))).code).toBe('unknown_escalation');
    }
    expect(({} as Record<string, unknown>).status).toBeUndefined();
    expect(({} as Record<string, unknown>).deny).toBeUndefined();
    expect(Object.getPrototypeOf(f.store.escalations)).toBeNull();
    expect(Object.getPrototypeOf(f.store.invoiceState)).toBeNull();
  });

  it('invoices named __proto__ / constructor get their own state (nothing is written onto Object)', async () => {
    const extra = [
      { id: '__proto__', vendor: 'Proto', payee: LABELWORKS, token: 'mUSD', amount: '1' },
      { id: 'constructor', vendor: 'Ctor', payee: LABELWORKS, token: 'mUSD', amount: '1' },
    ];
    f.store.setInvoices([...f.store.invoices, ...extra]);
    expect(inv(f, '__proto__').status).toBe('open');
    expect((await f.svc.payInvoice('__proto__')).outcome).toBe('escalated');
    expect((await f.svc.payInvoice('constructor')).outcome).toBe('escalated');
    expect(inv(f, '__proto__').status).toBe('escalated');
    expect(({} as Record<string, unknown>).status).toBeUndefined();
    expect((Object as unknown as Record<string, unknown>).status).toBeUndefined();
    // written and read back as own entries
    const svc2 = f.restart();
    expect(svc2.invoiceViews().find((i) => i.id === '__proto__')!.status).toBe('escalated');
    expect(Object.getPrototypeOf(svc2.store.invoiceState)).toBeNull();
  });

  it('state files with __proto__ keys load as own entries of a prototype-less record', () => {
    const e = { id: 'esc_0000000000000001', status: 'pending', cosign: { delegationHash: '0x' + '11'.repeat(32), nonce: '1' } };
    writeFileSync(join(f.dataDir, 'escalations.json'), `{"__proto__": ${JSON.stringify(e)}}`);
    writeFileSync(join(f.dataDir, 'invoice-state.json'), '{"__proto__": {"status": "paid"}, "constructor": {"status": "paid"}}');
    const store = new AgentStore(f.config.dataDir, f.config.invoicesPath, f.config.invoicesExamplePath);
    expect(Object.getPrototypeOf(store.escalations)).toBeNull();
    expect(Object.keys(store.invoiceState).sort()).toEqual(['__proto__', 'constructor']);
    const svc = new AgentService({ config: f.config, chain: f.chain, store, events: new EventBus() });
    expect(() => svc.escalation('__proto__')).toThrow(ApiError);
    expect(({} as Record<string, unknown>).status).toBeUndefined();
  });
});

describe('2. bounded device payloads', () => {
  it('a ur longer than 16 KiB is refused (413) before decoding, nothing changes', async () => {
    const e = await escalated(f, 'INV-001');
    const long = 'UR:RIPAR-DENY/' + 'A'.repeat(MAX_QR_FIELD);
    expect(await apiError(f.svc.deny(e.id, { ur: long }))).toMatchObject({ status: 413, code: 'field_too_large' });
    expect(await apiError(f.svc.submitCosign(e.id, { ur: long }))).toMatchObject({ status: 413, code: 'field_too_large' });
    expect(f.svc.escalation(e.id).status).toBe('pending');
  });
});

describe('3. idempotent sends: a broadcast error never pays twice', () => {
  it('AUTO: the node accepted it although the broadcast errored -> pending, never re-sent, paid once when mined', async () => {
    await payInv001Human(f);
    const signedBefore = f.chain.signed.size;
    f.chain.broadcastErrorNext = 'accepted';
    const out = await f.svc.payInvoice('INV-001');
    expect(out.outcome).toBe('pending');
    const hash = (out as { txHash: string }).txHash;
    const st = f.store.invoiceState['INV-001']!.pendingTx!;
    expect(st.hash).toBe(hash);
    expect(st.nonce).toBe(1);
    expect(keccak256(st.raw!)).toBe(hash);
    // the next proposals (planner steps) do not sign or send anything new
    expect(await f.svc.payInvoice('INV-001')).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/not confirmed/) });
    const step = await f.svc.payInvoice('INV-001');
    expect(step.outcome).toBe('refused');
    expect(f.chain.signed.size).toBe(signedBefore + 1);
    expect(autoRedeems(f)).toBe(0);
    // the re-broadcast of the same bytes is "already known" (ignored)
    expect(f.chain.rebroadcasts.every((r) => keccak256(r) === hash)).toBe(true);
    f.chain.mineAll();
    const after = await f.svc.payInvoice('INV-001');
    expect(after).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/not due/) });
    expect(autoRedeems(f)).toBe(1);
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(5_000_000n);
    expect(f.store.payments.map((p) => [p.path, p.txHash])).toEqual([
      ['human', f.chain.redeems[0]!.hash],
      ['auto', hash],
    ]);
    expect(inv(f, 'INV-001').paidCount).toBe(2);
  });

  it('AUTO: write-ahead: a crash after signing, before the broadcast, never pays twice after a restart', async () => {
    await payInv001Human(f);
    f.chain.crashAfterSignNext = true;
    const out = await f.svc.payInvoice('INV-001');
    expect(out.outcome).toBe('pending'); // the signed transaction was recorded before anything left the process
    const hash = (out as { txHash: string }).txHash;
    // "restart": a new service on the same data directory reads the recorded transaction back
    const svc2 = f.restart();
    const st2 = (svc2 as unknown as { store: AgentStore }).store;
    expect(st2.invoiceState['INV-001']!.pendingTx!.hash).toBe(hash);
    expect(await svc2.payInvoice('INV-001')).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/not confirmed/) });
    expect(f.chain.rebroadcasts.map((r) => keccak256(r))).toEqual([hash]); // the same bytes, never a new nonce
    f.chain.mineAll();
    await svc2.state();
    expect(autoRedeems(f)).toBe(1);
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(5_000_000n);
    expect(st2.payments.at(-1)!.txHash).toBe(hash);
  });

  it('AUTO: a transaction whose nonce was used by another transaction is dropped: the invoice is released', async () => {
    await payInv001Human(f);
    f.chain.broadcastErrorNext = 'rejected';
    const out = await f.svc.payInvoice('INV-001');
    expect(out.outcome).toBe('pending');
    const hash = (out as { txHash: string }).txHash;
    f.chain.useNonceElsewhere(); // nonce 1 is mined by another transaction of the agent's key
    await f.svc.state(); // settles
    const v = inv(f, 'INV-001');
    expect(v.lastError).toBe(`transaction ${hash} was dropped (nonce 1 used by another transaction)`);
    expect(v.due).toBe(true);
    expect(f.store.invoiceState['INV-001']!.pendingTx).toBeUndefined();
    // paid once, with a new transaction
    const again = await f.svc.payInvoice('INV-001');
    expect(again.outcome).toBe('paid');
    expect(autoRedeems(f)).toBe(1);
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(5_000_000n);
  });

  it('AUTO: a transaction the node never saw is re-broadcast unchanged (same hash) and paid once', async () => {
    await payInv001Human(f);
    f.chain.broadcastErrorNext = 'rejected';
    const out = await f.svc.payInvoice('INV-001');
    const hash = (out as { txHash: string }).txHash;
    expect(f.chain.txs.some((t) => t.hash === hash)).toBe(false);
    await f.svc.state(); // nonce not used: re-broadcast
    expect(f.chain.rebroadcasts).toHaveLength(1);
    expect(keccak256(f.chain.rebroadcasts[0]!)).toBe(hash);
    expect(f.chain.txs.find((t) => t.hash === hash)!.state).toBe('mempool');
    await f.svc.state(); // throttled: not re-sent at once
    expect(f.chain.rebroadcasts).toHaveLength(1);
    f.chain.mineAll();
    await f.svc.state();
    expect(inv(f, 'INV-001').paidCount).toBe(2);
    expect(f.store.payments.at(-1)!.txHash).toBe(hash);
    expect(autoRedeems(f)).toBe(1);
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(5_000_000n);
  });

  it('AUTO: failed reads (receipt unknown, nonce unreadable) keep it pending, never release it', async () => {
    await payInv001Human(f);
    f.chain.broadcastErrorNext = 'rejected';
    expect((await f.svc.payInvoice('INV-001')).outcome).toBe('pending');
    f.chain.useNonceElsewhere(); // really dropped, but only readable evidence may release the invoice
    const realNonce = f.chain.accountNonce.bind(f.chain);
    f.chain.accountNonce = async () => {
      throw new Error('rpc down (fake)');
    };
    expect(await f.svc.payInvoice('INV-001')).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/not confirmed/) });
    f.chain.accountNonce = realNonce;
    const realStatus = f.chain.txStatus.bind(f.chain);
    f.chain.txStatus = async () => ({ status: 'unknown' });
    expect(await f.svc.payInvoice('INV-001')).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/not confirmed/) });
    f.chain.txStatus = realStatus;
    expect(f.store.invoiceState['INV-001']!.pendingTx).toBeDefined();
    expect(autoRedeems(f)).toBe(0);
    // readable again: dropped, released, paid once
    expect((await f.svc.payInvoice('INV-001')).outcome).toBe('paid');
    expect(autoRedeems(f)).toBe(1);
  });

  it('HUMAN: a broadcast error leaves the escalation submitting with the tx; settled once mined', async () => {
    const e = await escalated(f, 'INV-001');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    f.chain.broadcastErrorNext = 'accepted';
    const err = await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }));
    expect(err.code).toBe('tx_pending');
    const sub = f.svc.escalation(e.id).submission!;
    expect(f.svc.escalation(e.id).status).toBe('submitting');
    expect(sub.nonce).toBe(0);
    expect(keccak256(sub.raw!)).toBe(sub.txHash);
    expect((await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }))).code).toBe('in_progress');
    f.chain.mineAll();
    await f.svc.state();
    expect(f.svc.escalation(e.id).status).toBe('executed');
    expect(f.store.payments).toHaveLength(1);
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(2_500_000n);
  });

  it('HUMAN: a dropped redemption re-opens the escalation (the co-sign was not consumed)', async () => {
    const e = await escalated(f, 'INV-001');
    const sig = cosignEscalation(f.dev, e.cosign, e.request.reqId);
    f.chain.broadcastErrorNext = 'rejected';
    expect((await apiError(f.svc.submitCosign(e.id, { ur: sig.ur }))).code).toBe('tx_pending');
    f.chain.useNonceElsewhere();
    await f.svc.state();
    expect(f.svc.escalation(e.id)).toMatchObject({ status: 'pending', error: { name: 'Dropped' } });
    expect((await f.svc.submitCosign(e.id, { ur: sig.ur })).escalation.status).toBe('executed');
    expect(f.chain.balance(MUSD, CLOUDNEST)).toBe(2_500_000n);
  });
});

describe('4. funded but undeployed vault', () => {
  it('refuses to pay without marking the mandate dead or escalating; pays once deployed', async () => {
    const owner = f.chain.owners.get(f.dev.vault.toLowerCase())!;
    f.chain.owners.delete(f.dev.vault.toLowerCase());
    const out = await f.svc.payInvoice('INV-001');
    expect(out).toMatchObject({ outcome: 'refused', reason: expect.stringMatching(/vault is not deployed yet/) });
    expect(inv(f, 'INV-001')).toMatchObject({ status: 'open', lastError: expect.stringMatching(/deploy it \(companion Vault page\)/) });
    expect(f.svc.mandate()!.status).toBe('active');
    expect(f.svc.escalations()).toHaveLength(0);
    expect(f.chain.redeems).toHaveLength(0);
    f.chain.owners.set(f.dev.vault.toLowerCase(), owner);
    expect((await f.svc.payInvoice('INV-001')).outcome).toBe('escalated');
  });

  it('submitCosign refuses 409 vault_not_deployed before sending', async () => {
    const e = await escalated(f, 'INV-001');
    f.chain.owners.delete(f.dev.vault.toLowerCase());
    const err = await apiError(f.svc.submitCosign(e.id, { ur: cosignEscalation(f.dev, e.cosign, e.request.reqId).ur }));
    expect(err).toMatchObject({ status: 409, code: 'vault_not_deployed' });
    expect(f.svc.escalation(e.id).status).toBe('pending');
    expect(f.chain.signed.size).toBe(0);
  });

  it('InvalidEOASignature kills the mandate only when the vault has code', async () => {
    await payInv001Human(f);
    // the vault loses its code between the pre-check and the revert handler (the revert came from an EOA check)
    const realHasCode = f.chain.hasCode.bind(f.chain);
    let calls = 0;
    f.chain.hasCode = async (a: Address) => (++calls === 1 ? realHasCode(a) : false);
    f.chain.failNext = { name: 'InvalidEOASignature' };
    expect(await f.svc.payInvoice('INV-001')).toMatchObject({ outcome: 'failed', error: { name: 'InvalidEOASignature' } });
    expect(f.svc.mandate()!.status).toBe('active');
    f.chain.hasCode = realHasCode;
    // with code, it is a real signature failure: dead
    f.store.invoiceState['INV-001']!.status = 'open';
    f.chain.failNext = { name: 'InvalidEOASignature' };
    expect((await f.svc.payInvoice('INV-001')).outcome).toBe('failed');
    expect(f.svc.mandate()!.status).toBe('dead');
  });
});

describe('7. nonceUsed failures fail closed', () => {
  it('escalate: no escalation without a checked nonce', async () => {
    f.chain.nonceUsed = async () => {
      throw new Error('rpc down (fake)');
    };
    const out = await f.svc.payInvoice('INV-001');
    expect(out).toMatchObject({ outcome: 'failed', error: { name: 'NonceCheckFailed' } });
    expect(f.svc.escalations()).toHaveLength(0);
    expect(inv(f, 'INV-001').lastError).toMatch(/nonce could not be checked/);
  });

  it('submitCosign: nothing is sent when nonceUsed cannot be read', async () => {
    const e = await escalated(f, 'INV-001');
    f.chain.nonceUsed = async () => {
      throw new Error('rpc down (fake)');
    };
    const err = await apiError(f.svc.submitCosign(e.id, { ur: cosignEscalation(f.dev, e.cosign, e.request.reqId).ur }));
    expect(err).toMatchObject({ status: 502, code: 'chain_error' });
    expect(f.svc.escalation(e.id).status).toBe('pending');
    expect(f.chain.redeems).toHaveLength(0);
  });
});

describe('8. hostile token symbols', () => {
  for (const symbol of ['EVIL\u0000‮\u{1F600}', 'A'.repeat(17), '', 'x\u0007y']) {
    it(`escalates a token whose symbol() is ${JSON.stringify(symbol)} without keys 15 / 16`, async () => {
      const token = getAddress(privateKeyToAddress(generatePrivateKey()));
      f.chain.tokens.set(token.toLowerCase(), { decimals: 6, symbol });
      f.chain.setBalance(token, f.dev.vault, 10_000_000n);
      f.store.setInvoices([...f.store.invoices, { id: 'INV-EVIL', vendor: 'Evil Co', payee: LABELWORKS, token, amount: '1.5' }]);
      const e = await escalated(f, 'INV-EVIL');
      expect(e.cosign.symbol).toBeUndefined();
      expect(e.cosign.decimals).toBeUndefined();
      expect(e.display.symbol).toBe('?');
      expect(e.cosign.ai.text).toMatch(/^[\x20-\x7e]*$/);
      const q = decodeRequest('cosign', readRequest(e.request.ur).cbor) as CosignRequest;
      expect(q.hasSymbol).toBe(false);
    });
  }

  it('a printable symbol is still carried', async () => {
    const token = getAddress(privateKeyToAddress(generatePrivateKey()));
    f.chain.tokens.set(token.toLowerCase(), { decimals: 6, symbol: 'GOOD' });
    f.chain.setBalance(token, f.dev.vault, 10_000_000n);
    f.store.setInvoices([...f.store.invoices, { id: 'INV-GOOD', vendor: 'Good Co', payee: LABELWORKS, token, amount: '1.5' }]);
    const e = await escalated(f, 'INV-GOOD');
    expect(e.cosign.symbol).toBe('GOOD');
    expect(e.cosign.decimals).toBe(6);
  });
});

describe('6. deny contract', () => {
  it('a verified deny, then the same deny again with attestTx (the companion relays twice)', async () => {
    const e = await escalated(f, 'INV-002');
    const ur = denyEscalation(f.dev, e, RELAY, 7n);
    const d1 = await f.svc.deny(e.id, { ur, note: 'not this one' });
    expect(d1.deny).toMatchObject({ verified: true, requestHash: e.requestHash, note: 'not this one' });
    expect(d1.deny!.attestTx).toBeUndefined();
    const attestTx = `0x${'ab'.repeat(32)}`;
    const d2 = await f.svc.deny(e.id, { ur, note: 'not this one', attestTx });
    expect(d2.status).toBe('denied');
    expect(d2.deny).toMatchObject({ verified: true, attestTx });
    // recorded once: a later attestTx (even without a ur, the deny being verified) does not replace it
    const d3 = await f.svc.deny(e.id, { attestTx: `0x${'cd'.repeat(32)}` });
    expect(d3.deny!.attestTx).toBe(attestTx);
    // a bad attestTx or a forged ur on the denied escalation is refused
    expect((await apiError(f.svc.deny(e.id, { attestTx: '0x1234' }))).code).toBe('bad_request');
    expect((await apiError(f.svc.deny(e.id, { ur: 'UR:NOT-A-DENY/xyz' }))).code).toBe('bad_deny');
    expect(inv(f, 'INV-002').status).toBe('denied');
  });

  it('attestTx without a ur is stored only on a verified deny', async () => {
    const e = await escalated(f, 'INV-002');
    await f.svc.deny(e.id, { ur: denyEscalation(f.dev, e, RELAY, 7n) });
    const tx = `0x${'12'.repeat(32)}`;
    expect((await f.svc.deny(e.id, { attestTx: tx })).deny!.attestTx).toBe(tx);
  });

  it('an operator deny needs AGENT_API_TOKEN and {operator: true}; a device deny later upgrades it', async () => {
    const g = makeFixture({ AGENT_API_TOKEN: 'operator-token-123' });
    await g.svc.acceptMandate({ delegation: delegationJson(g.mandate) });
    const e = await escalated(g, 'INV-002');
    expect((await apiError(g.svc.deny(e.id, {}))).code).toBe('deny_needs_device');
    const d = await g.svc.deny(e.id, { operator: true, note: 'ops' });
    expect(d.deny).toMatchObject({ verified: false, operator: true, note: 'ops' });
    expect(g.svc.invoiceViews().find((i) => i.id === 'INV-002')!.status).toBe('denied');
    // no attestTx on an unverified deny without a device ur
    expect((await g.svc.deny(e.id, { attestTx: `0x${'ef'.repeat(32)}` })).deny!.attestTx).toBeUndefined();
    const up = await g.svc.deny(e.id, { ur: denyEscalation(g.dev, e, RELAY, 7n), attestTx: `0x${'ef'.repeat(32)}` });
    expect(up.deny).toMatchObject({ verified: true, requestHash: e.requestHash, attestTx: `0x${'ef'.repeat(32)}` });
  });

  it('the deny must name the configured agent (AGENT_ID)', async () => {
    const g = makeFixture({ AGENT_ID: '1939' });
    await g.svc.acceptMandate({ delegation: delegationJson(g.mandate) });
    const e = await escalated(g, 'INV-002');
    expect((await apiError(g.svc.deny(e.id, { ur: denyEscalation(g.dev, e, RELAY, 7n) }))).code).toBe('bad_deny');
    expect(g.svc.escalation(e.id).status).toBe('pending');
    expect((await g.svc.deny(e.id, { ur: denyEscalation(g.dev, e, RELAY, 1939n) })).deny!.verified).toBe(true);
  });
});

describe('5. configuration: RPC URL redaction and bind warnings', () => {
  const base = (env: Record<string, string> = {}) =>
    loadConfig({ RPC_URL: 'http://127.0.0.1:8545', CHAIN_ID: '10143', AGENT_PRIVATE_KEY: generatePrivateKey(), ...env }, { deploymentJson: { ...DEP } });

  it('publicConfig echoes only the RPC origin', () => {
    const c = base({ RPC_URL: 'https://user:pw@rpc.example:8443/v2/SECRETKEY?apikey=Q#frag' });
    const pub = publicConfig(c);
    expect(pub.rpcUrl).toBe('https://rpc.example:8443');
    expect(pub.rpcUrlRedacted).toBe(true);
    expect(JSON.stringify(pub)).not.toMatch(/SECRETKEY|apikey|user|pw|frag/);
    expect(publicConfig(base({ RPC_URL: 'http://127.0.0.1:8545' }))).toMatchObject({ rpcUrl: 'http://127.0.0.1:8545', rpcUrlRedacted: false });
  });

  it('binds to 127.0.0.1 by default; warns for any other bind, with or without a token', () => {
    const c = base();
    expect(c.host).toBe('127.0.0.1');
    expect(configWarnings(c).join()).not.toMatch(/listening on/);
    expect(configWarnings(base({ HOST: '0.0.0.0' })).join()).toMatch(/without AGENT_API_TOKEN/);
    expect(configWarnings(base({ HOST: '0.0.0.0', AGENT_API_TOKEN: 't' })).join()).toMatch(/reachable from the network/);
    expect(configWarnings(base({ HOST: '::1' })).join()).not.toMatch(/listening on/);
  });

  it('AGENT_ALLOWED_HOSTS takes host names only', () => {
    expect(base({ AGENT_ALLOWED_HOSTS: 'Agent.LAN, ripar.test' }).allowedHosts).toEqual(['agent.lan', 'ripar.test']);
    expect(() => base({ AGENT_ALLOWED_HOSTS: 'http://agent.lan' })).toThrow(/AGENT_ALLOWED_HOSTS/);
    expect(() => base({ AGENT_ALLOWED_HOSTS: 'agent.lan:8787' })).toThrow(/AGENT_ALLOWED_HOSTS/);
  });
});
