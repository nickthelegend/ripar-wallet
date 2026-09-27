// End-to-end device flows over the DeviceTransport with the WASM emulator in Node (test mode, demo seed): the same
// frames the animated QR would show are fed to the emulated camera, and the response is read from its LCD. Covers
// the keys-only + full pairing, the mandate (with the predicted review compared line by line to the device's own),
// co-signs (ERC-20 + native), a deny from the co-sign review, and the kill switch (revoke, reopen, PANIC).
import { beforeAll, describe, expect, it } from 'vitest';
import { decodeFunctionData } from 'viem';
import {
  type RiparDeployment,
  DELEGATION_MANAGER,
  buildRequest,
  denyRequestHashOf,
  decodeRequest,
  toHex,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_DEVICE_REGISTRY_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
  decodePermissionContext,
  erc20Transfer,
  hashDelegation,
} from '@ripar/protocol';
import { parseEscalation } from '../src/lib/agent';
import { GAS_LIMITS, attestDenialWrite, registerDeviceWrite } from '../src/lib/chain';
import { acceptCosignAnswer, adoptAgentRequest, answersCosign, checkEscalation, planCosign } from '../src/lib/flows/cosign';
import { acceptKillSwitch, KILL_TYPES } from '../src/lib/flows/killswitch';
import { type MandateForm, acceptMandate, answersMandate, delegationFromJson, mandateEnvelope, permissionContextOf, planMandate } from '../src/lib/flows/mandate';
import { acceptPairing, answersRequest, isKeysOnlyPair, planPairing, readKeysOnly } from '../src/lib/flows/pairing';
import { deriveVault } from '../src/lib/flows/vault';
import { previewCosign, previewMandate } from '../src/lib/review-preview';
import type { KeysOnly, MandateRecord, PairedDevice } from '../src/lib/store';
import { DeviceExchange } from '../src/device/transport';
import { AGENT, DEMO_K1, DEMO_VAULT, DEP, MOCK_USD, NOW, PAYEE, Rig, loadEmu, tickPromises, track } from './helpers';

let rig: Rig;
let keys: KeysOnly;
let device: PairedDevice;
let mandate: MandateRecord;
const dep: RiparDeployment = DEP;

function linesOf(s: ReturnType<Rig['run']>) {
  return s.review!.lines.map((l) => ({ label: l.label, value: l.value, tone: l.tone }));
}

beforeAll(async () => {
  const mod = await loadEmu();
  rig = new Rig(await mod.RiparEmulator.create({ test: true }));
});

describe('pairing over the emulator transport', () => {
  it('reads the keys-only pairing QR (HOME: hold 2 s, release) and labels the EMULATOR', async () => {
    const ex = new DeviceExchange(rig.transport, { parts: [], expect: ['ripar-pair'], accept: isKeysOnlyPair }, rig.sched);
    const got = track(ex);
    rig.emu.keyDown();
    rig.run((s) => s.screen === 'homeHold', 3000);
    rig.emu.keyUp();
    rig.run((s) => s.screen === 'pairQr', 1000);
    await tickPromises();
    expect(got.value()).toMatch(/^UR:RIPAR-PAIR\//);
    keys = readKeysOnly(got.value()!, 1);
    expect(keys.k1Address).toBe(DEMO_K1);
    expect(keys.emulator).toBe(true);
    expect(keys.firmwareId).toBe('0x7bc44601d30720f1');
    rig.home();
  });

  it('derives the canonical vault: @ripar/protocol = smart-accounts-kit (demo K1)', async () => {
    const v = await deriveVault(keys.k1Address, 10143);
    expect(v.address).toBe(DEMO_VAULT);
    expect(v.kitAddress).toBe(DEMO_VAULT);
    expect(v.matches).toBe(true);
    expect(v.factoryData).toBe(v.protocolFactoryData);
  });

  it('pairs with the full request (multipart frames), verifies BindDevice and builds registerDevice', async () => {
    const plan = planPairing(dep, keys.k1Address, { now: NOW, fragLen: 70 });
    expect(plan.vault).toBe(DEMO_VAULT);
    expect(plan.request.parts.length).toBeGreaterThan(1);
    expect(plan.pinned).toMatchObject({ chainId: 10143, enforcer: dep.enforcer, sentinel: dep.sentinel, relay: dep.relay, vault: DEMO_VAULT });
    const ex = new DeviceExchange(
      rig.transport,
      { parts: plan.request.parts, expect: ['ripar-pair'], accept: (u) => answersRequest(u, plan.request), frameMs: 300 },
      rig.sched,
    );
    const frames: number[] = [];
    ex.on((e) => e.kind === 'frame' && frames.push(e.index));
    const got = track(ex);
    const s = rig.scanRequest();
    expect(s.screen).toBe('review');
    expect(s.review!.ok).toBe(true);
    expect(new Set(frames).size).toBe(plan.request.parts.length); // every part was shown
    rig.pageToEnd();
    rig.pulseAndSign();
    await tickPromises();
    expect(got.value()).toMatch(/^UR:RIPAR-PAIR\//);
    device = acceptPairing(got.value()!, plan, keys);
    expect(device.emulator).toBe(true);
    expect(device.pinned.vault).toBe(DEMO_VAULT);
    expect(rig.state.context.paired).toBe(true);
    const w = registerDeviceWrite(dep.registry, device);
    expect(w.to).toBe(dep.registry);
    expect(w.gas).toBe(GAS_LIMITS.registerDevice);
    const call = decodeFunctionData({ abi: RIPAR_DEVICE_REGISTRY_ABI, data: w.data });
    expect(call.functionName).toBe('registerDevice');
    expect(call.args[0]).toBe(DEMO_K1);
    expect(call.args[5]).toBe(device.k1Signature);
    rig.home();
  });
});

const form: MandateForm = {
  agent: AGENT,
  agentId: '42',
  label: 'treasury agent',
  token: MOCK_USD,
  tokenDecimals: 6,
  tokenSymbol: 'mUSD',
  perTxAutoCap: '5',
  periodAutoCap: '20',
  period: 86400,
  newPayeeNeedsHuman: true,
  redeemerOnly: true,
  validUntil: null,
};

describe('mandate', () => {
  it('predicts the device review line by line, gets K1 to sign, and builds the agent envelope', async () => {
    const plan = planMandate(form, device, 0n, { salt: 7n });
    const preview = previewMandate(plan.decoded, { p1Key: device.p1Key, vault: DEMO_VAULT, sentinel: dep.sentinel, minEpoch: 0n });
    const ex = new DeviceExchange(
      rig.transport,
      { parts: plan.request.parts, expect: ['eth-signature'], accept: (u) => answersMandate(u, plan.request) },
      rig.sched,
    );
    const got = track(ex);
    const s = rig.scanRequest();
    expect(s.screen).toBe('review');
    expect(s.review!.ok, s.review!.refusal).toBe(true);
    expect(s.review!.title).toBe(preview.title);
    expect(preview.lines).toEqual(linesOf(s));
    rig.pageToEnd();
    rig.pulseAndSign();
    await tickPromises();
    mandate = acceptMandate(got.value()!, plan, form, device, 2);
    expect(mandate.delegationHash).toBe(rig.state.context.lastDelegationHash);
    expect(mandate.agent).toBe(AGENT);
    expect(mandate.agentId).toBe('42');
    // what the agent gets: the request the device reviewed + its eth-signature (the agent recovers K1 itself)
    const env = mandateEnvelope(mandate);
    expect(env.request).toBe(plan.request.ur);
    expect(env.signature).toBe(got.value());
    expect(env.agentId).toBe('42');
    const [d] = decodePermissionContext(permissionContextOf(mandate));
    expect(hashDelegation(d!)).toBe(mandate.delegationHash);
    expect(d!.delegator).toBe(DEMO_VAULT);
    void DELEGATION_MANAGER;
    expect(delegationFromJson(mandate.delegation).salt).toBe(7n);
    rig.home();
  });

  it('refuses a form the device would refuse, before any QR', () => {
    expect(() => planMandate({ ...form, agent: '0x0000000000000000000000000000000000000a11' }, device, 0n)).toThrow(/ANY_DELEGATE/);
    expect(() => planMandate({ ...form, perTxAutoCap: '30' }, device, 0n)).toThrow(/exceeds the period cap/);
    expect(() => planMandate({ ...form, perTxAutoCap: '1.1234567' }, device, 0n)).toThrow(/decimal places/);
  });
});

function escalation(over: Record<string, unknown> = {}) {
  return parseEscalation({
    id: 'esc-1',
    chainId: 10143,
    enforcer: dep.enforcer,
    delegationHash: mandate.delegationHash,
    delegator: DEMO_VAULT,
    redeemer: AGENT,
    call: { target: MOCK_USD, value: '0', callData: `0x${Buffer.from(erc20Transfer(PAYEE, 25_000_000n)).toString('hex')}` },
    reason: 'new-payee',
    agentId: '42',
    note: 'pay invoice 17',
    claims: { to: PAYEE, token: MOCK_USD, amount: '25000000' },
    risk: { src: 'nansen', category: 'new', label: 'unlabelled EOA', ageDays: 3 },
    ...over,
  });
}

describe('co-sign and deny', () => {
  it('ERC-20 transfer: preview = device review, pulse + SIGN -> HUMAN caveat args for the agent', async () => {
    const e = escalation();
    expect(checkEscalation(e, device, mandate).errors).toEqual([]);
    const budget = { spent: 0n, remaining: 20_000_000n, periodStart: 0n, periodEnd: 0n };
    const plan = planCosign(e, { device, nonce: 1234567n, now: NOW, budget, tokenMeta: { decimals: 6, symbol: 'mUSD' } });
    const preview = previewCosign(plan.decoded, {
      p1Key: device.p1Key,
      vault: DEMO_VAULT,
      sentinel: dep.sentinel,
      minEpoch: 0n,
      lastDelegationHash: mandate.delegationHash,
    });
    const ex = new DeviceExchange(
      rig.transport,
      { parts: plan.request.parts, expect: ['ripar-cosign', 'ripar-deny'], accept: (u) => answersCosign(u, plan.request) },
      rig.sched,
    );
    const got = track(ex);
    const s = rig.scanRequest();
    expect(s.screen).toBe('review');
    expect(s.review!.ok, s.review!.refusal).toBe(true);
    expect(preview.lines).toEqual(linesOf(s));
    rig.pageToEnd();
    rig.pulseAndSign();
    await tickPromises();
    const out = acceptCosignAnswer(got.value()!, plan, device, mandate);
    expect(out.kind).toBe('cosign');
    if (out.kind !== 'cosign') return;
    expect(out.answer.caveatArgs.length).toBe(2 + 2 * 160);
    expect(out.answer.nonce).toBe('1234567');
    expect(out.answer.emulator).toBe(true);
    rig.home();
  });

  it('native send: the device shows MON from its own table', async () => {
    const e = escalation({ id: 'esc-2', call: { target: PAYEE, value: '1500000000000000000', callData: '0x' }, claims: { to: PAYEE, token: null, amount: '1500000000000000000' } });
    const plan = planCosign(e, { device, nonce: 99n, now: NOW });
    const preview = previewCosign(plan.decoded, { p1Key: device.p1Key, vault: DEMO_VAULT, sentinel: dep.sentinel, minEpoch: 0n, lastDelegationHash: mandate.delegationHash });
    expect(preview.lines[1]).toEqual({ label: 'Amount', value: '1.5 MON', tone: 'normal' });
    const ex = new DeviceExchange(rig.transport, { parts: plan.request.parts, expect: ['ripar-cosign', 'ripar-deny'], accept: (u) => answersCosign(u, plan.request) }, rig.sched);
    const got = track(ex);
    const s = rig.scanRequest();
    expect(preview.lines).toEqual(linesOf(s));
    rig.pageToEnd();
    rig.pulseAndSign();
    await tickPromises();
    expect(acceptCosignAnswer(got.value()!, plan, device, mandate).kind).toBe('cosign');
    rig.home();
  });

  it('deny from the review (hold 2 s): the device builds the deny, the companion relays attestDenial', async () => {
    const e = escalation({ id: 'esc-3' });
    const plan = planCosign(e, { device, nonce: 555n, now: NOW });
    const ex = new DeviceExchange(rig.transport, { parts: plan.request.parts, expect: ['ripar-cosign', 'ripar-deny'], accept: (u) => answersCosign(u, plan.request) }, rig.sched);
    const got = track(ex);
    rig.scanRequest();
    let s = rig.key('hold2');
    expect(s.screen).toBe('review');
    expect(s.review!.job).toBe('deny');
    s = rig.pageToEnd();
    s = rig.key('press'); // a short press signs the deny (no pulse)
    expect(s.screen).toBe('qr');
    await tickPromises();
    const out = acceptCosignAnswer(got.value()!, plan, device, mandate);
    expect(out.kind).toBe('deny');
    if (out.kind !== 'deny') return;
    expect(out.attest.requestHash).toBe(plan.denyRequestHash);
    expect(out.attest.agentId).toBe(42n);
    expect(out.note).toBeNull();
    const w = attestDenialWrite(dep.relay, { ...out.attest, px: device.px, py: device.py });
    expect(w.gas).toBe(GAS_LIMITS.attestDenial);
    const call = decodeFunctionData({ abi: RIPAR_REPUTATION_RELAY_ABI, data: w.data });
    expect(call.functionName).toBe('attestDenial');
    expect(call.args[0]).toBe(42n);
    rig.home();
  });

  /** an escalation exactly as agent/src/service.ts publishes it: cosign fields + the request it prebuilt */
  function agentEscalation(over: Record<string, unknown> = {}, reqOver: Record<string, unknown> = {}) {
    const cosign = {
      chainId: 10143,
      enforcer: dep.enforcer,
      delegationHash: mandate.delegationHash,
      delegator: DEMO_VAULT,
      redeemer: AGENT,
      target: MOCK_USD,
      value: '0',
      calldata: toHex(erc20Transfer(PAYEE, 12_000_000n)),
      nonce: '777000111',
      expiry: NOW + 1800,
      ai: { text: 'invoice 18: hosting', claims: { to: PAYEE, token: MOCK_USD, amount: '12000000' } },
      budgetLeft: '15000000',
      decimals: 6,
      symbol: 'mUSD',
      ...over,
    };
    const req = buildRequest('cosign', { ...cosign, ...reqOver } as never);
    const q = decodeRequest('cosign', req.cbor);
    return parseEscalation({
      id: 'agent-esc-1',
      status: 'pending',
      createdAt: NOW * 1000,
      reason: 'new-payee',
      reasonText: 'new payee',
      execution: { target: cosign.target, value: cosign.value, callData: cosign.calldata },
      cosign,
      request: { type: 'ripar-cosign-req', reqId: req.reqId, ur: req.ur, parts: req.parts },
      requestHash: denyRequestHashOf(q as never),
      display: { payee: PAYEE, amount: '12', symbol: 'mUSD', token: MOCK_USD, vendor: 'Hosting Co' },
    });
  }

  it("relays the agent's own prebuilt request (after checking it) and answers with the device's UR", async () => {
    const e = agentEscalation();
    expect(e.createdAt).toBe(NOW);
    expect(e.request).not.toBeNull();
    const plan = adoptAgentRequest(e, device, { now: NOW, fragLen: 60 });
    expect(plan.request.reqId).toBe(e.request!.reqId);
    expect(plan.nonce).toBe(777000111n);
    const ex = new DeviceExchange(rig.transport, { parts: plan.request.parts, expect: ['ripar-cosign', 'ripar-deny'], accept: (u) => answersCosign(u, plan.request) }, rig.sched);
    const got = track(ex);
    const s = rig.scanRequest();
    expect(s.review!.ok, s.review!.refusal).toBe(true);
    rig.pageToEnd();
    rig.pulseAndSign();
    await tickPromises();
    const out = acceptCosignAnswer(got.value()!, plan, device, mandate);
    expect(out.kind).toBe('cosign');
    // the agent verifies this UR against e.request.ur: same req-id, same digest inputs
    expect(out.answer.ur).toMatch(/^UR:RIPAR-COSIGN\//);
    rig.home();
  });

  it("refuses an agent request that does not match its escalation, is expired, or reuses a nonce", () => {
    expect(() => adoptAgentRequest(agentEscalation({}, { calldata: toHex(erc20Transfer(AGENT, 12_000_000n)) }), device, { now: NOW })).toThrow(/calldata/);
    expect(() => adoptAgentRequest(agentEscalation({}, { delegator: PAYEE }), device, { now: NOW })).toThrow(/delegator/);
    expect(() => adoptAgentRequest(agentEscalation({ expiry: NOW - 5 }), device, { now: NOW })).toThrow(/expired/);
    expect(() => adoptAgentRequest(agentEscalation({ expiry: NOW + 8 * 86400 }), device, { now: NOW })).toThrow(/7 days/);
    expect(() => adoptAgentRequest(agentEscalation(), device, { now: NOW, nonceUsed: true })).toThrow(/CosignReplayed/);
  });

  it('refuses escalations for another vault / chain / calldata the device cannot decode', () => {
    expect(checkEscalation(escalation({ delegator: PAYEE }), device, mandate).errors.join()).toMatch(/not your vault/);
    expect(checkEscalation(escalation({ chainId: 143 }), device, mandate).errors.join()).toMatch(/pinned chain/);
    expect(checkEscalation(escalation({ call: { target: MOCK_USD, value: '0', callData: '0xdeadbeef' } }), device, mandate).errors.join()).toMatch(
      /UNKNOWN CALLDATA/,
    );
    // a decimals claim that contradicts the firmware table for AUSD is refused before the QR
    const ausd = '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC';
    const e = escalation({ call: { target: ausd, value: '0', callData: `0x${Buffer.from(erc20Transfer(PAYEE, 1n)).toString('hex')}` } });
    expect(planCosign(e, { device, nonce: 1n, now: NOW, tokenMeta: { decimals: 18, symbol: 'AUSD' } }).decoded.hasDecimals).toBe(false);
  });
});

describe('kill switch (device-initiated)', () => {
  const read = async (drive: () => void) => {
    const ex = new DeviceExchange(rig.transport, { parts: [], expect: [...KILL_TYPES] }, rig.sched);
    const got = track(ex);
    drive();
    await tickPromises();
    return got.value();
  };

  it('REVOKE from the device menu -> revoke(px, py, delegationHash, r, s)', async () => {
    const ur = await read(() => {
      rig.emu.keyDown();
      rig.run((s) => s.screen === 'homeHold', 3000);
      rig.emu.keyUp();
      rig.run((s) => s.screen === 'pairQr', 1000);
      expect(rig.key('hold2').screen).toBe('menu');
      const s = rig.key('hold2');
      expect(s.review!.title).toBe('REVOKE MANDATE');
      rig.pageToEnd();
      rig.pulseAndSign();
    });
    const k = acceptKillSwitch(ur!, device);
    expect(k.type).toBe('ripar-revoke');
    const call = decodeFunctionData({ abi: PULSE_COSIGN_ENFORCER_ABI, data: k.write.data });
    expect(call.functionName).toBe('revoke');
    expect(call.args[2]).toBe(mandate.delegationHash);
    expect(k.write.gas).toBe(GAS_LIMITS.revoke);
    rig.home();
  });

  it('REOPEN from the device menu -> sentinel.reopen(vault, nonce, r, s)', async () => {
    const ur = await read(() => {
      rig.emu.keyDown();
      rig.run((s) => s.screen === 'homeHold', 3000);
      rig.emu.keyUp();
      rig.run((s) => s.screen === 'pairQr', 1000);
      rig.key('hold2');
      rig.key('press'); // -> REOPEN
      const s = rig.key('hold2');
      expect(s.review!.title).toMatch(/REOPEN/);
      rig.pageToEnd();
      rig.pulseAndSign();
    });
    const k = acceptKillSwitch(ur!, device);
    expect(k.type).toBe('ripar-reopen');
    const call = decodeFunctionData({ abi: RIPAR_SENTINEL_ABI, data: k.write.data });
    expect(call.args[0]).toBe(DEMO_VAULT);
    expect(call.args[1]).toBe(1n);
    rig.home();
  });

  it('PANIC (HOME: hold 5 s) -> panic(px, py, minEpoch + 1, r, s)', async () => {
    const ur = await read(() => {
      rig.emu.keyDown();
      rig.run((s) => s.screen === 'qr', 6000);
      rig.emu.keyUp();
      rig.run(() => false, 200);
    });
    const k = acceptKillSwitch(ur!, device);
    expect(k.type).toBe('ripar-panic');
    const call = decodeFunctionData({ abi: PULSE_COSIGN_ENFORCER_ABI, data: k.write.data });
    expect(call.functionName).toBe('panic');
    expect(call.args[2]).toBe(1n);
    rig.home();
  });

  it('a kill-switch QR from another device does not verify', async () => {
    const mod = await loadEmu();
    const other = new Rig(await mod.RiparEmulator.create({ test: { seed: '11'.repeat(32) } }));
    // an unpaired device refuses to panic, so pair it quickly with the same contracts
    const keysEx = new DeviceExchange(other.transport, { parts: [], expect: ['ripar-pair'], accept: isKeysOnlyPair }, other.sched);
    const kg = track(keysEx);
    other.emu.keyDown();
    other.run((s) => s.screen === 'homeHold', 3000);
    other.emu.keyUp();
    other.run((s) => s.screen === 'pairQr', 1000);
    await tickPromises();
    const k2 = readKeysOnly(kg.value()!);
    other.home();
    const plan = planPairing(dep, k2.k1Address, { now: NOW });
    const pe = new DeviceExchange(other.transport, { parts: plan.request.parts, expect: ['ripar-pair'], accept: (u) => answersRequest(u, plan.request) }, other.sched);
    track(pe);
    other.scanRequest();
    other.pageToEnd();
    other.pulseAndSign();
    other.home();
    const ex = new DeviceExchange(other.transport, { parts: [], expect: [...KILL_TYPES] }, other.sched);
    const got = track(ex);
    other.emu.keyDown();
    other.run((s) => s.screen === 'qr', 6000);
    other.emu.keyUp();
    await tickPromises();
    expect(() => acceptKillSwitch(got.value()!, device)).toThrow(/FAIL/);
    other.emu.destroy();
  });
});
