// The personal-mandate payment flow end to end against the emulated Ripar (the device's own firmware as WASM):
// pair, sign the personal mandate (AUTO caps 0, redeemer = the phone key), co-sign one payment, and build the
// redeemDelegations call the phone key sends. No chain: the calldata is decoded and checked instead.
import { describe, expect, it } from 'vitest';
import { type Hex, decodeFunctionData, encodeFunctionData, erc20Abi } from 'viem';
import {
  DELEGATION_MANAGER,
  PULSE_COSIGN_ENFORCER,
  REDEEM_DELEGATIONS_ABI,
  cosignCaveatArgs,
  decodePermissionContext,
  decodePulseTerms,
  toHex,
} from '@ripar/protocol';
import { requestAndVerify, verifierOf } from '../src/device/link';
import { QrLink } from '../src/device/qr-link';
import { applyKey } from '../src/lib/keypad';
import { type CosignOutcome, acceptCosignAnswer, answersCosign } from '../src/lib/flows/cosign';
import { acceptMandate, answersMandate } from '../src/lib/flows/mandate';
import { acceptPairing, answersRequest, planPairing } from '../src/lib/flows/pairing';
import {
  isPersonalMandate,
  paymentCall,
  personalMandateForm,
  planFromRequestUr,
  planPayment,
  planPersonalMandate,
  redeemPaymentWrite,
} from '../src/lib/flows/personal';
import type { FeedItem } from '../src/lib/feed';
import { insightsOf } from '../src/lib/insights';
import { DEMO_K1, DEMO_VAULT, DEP, FakeRipar, HOT_KEY, MOCK_USD, NOW, PAYEE, approveOnDevice, newEmu } from './helpers';

/** one round over the QR link: the device's camera sees the looped frames, this phone's camera the answer */
async function qrRound<T>(dev: FakeRipar, q: QrLink, request: Parameters<typeof requestAndVerify>[1], v: Parameters<typeof requestAndVerify<T>>[2]) {
  const round = requestAndVerify(q, request, v);
  await new Promise((r) => setTimeout(r, 0));
  if (dev.emu.state().screen !== 'scan') dev.key('press');
  const parts = q.frames.get()!.parts;
  for (let i = 0; i < parts.length * 3 && dev.emu.state().screen === 'scan'; i++) {
    dev.emu.scan(parts[i % parts.length]!);
    dev.tick(300);
  }
  approveOnDevice(dev);
  const s = dev.emu.state();
  expect(s.screen).toBe('qr');
  q.cameraRead(s.qr!.text);
  const out = await round;
  dev.key('press'); // done -> Home
  return out;
}

describe('personal mandate + co-signed payment (emulated Ripar)', () => {
  it('pairs, signs a mandate the phone key can only redeem with a co-sign, and pays', async () => {
    const dev = new FakeRipar(await newEmu());
    const q = new QrLink(300, 70);

    // pairing (keys already known: the demo device)
    const pp = planPairing(DEP, DEMO_K1, { now: NOW, fragLen: 70 });
    const { result: device } = await qrRound(dev, q, pp.request, verifierOf(['ripar-pair'], (ur) => acceptPairing(ur, pp, null), (ur) => answersRequest(ur, pp.request)));
    expect(device.pinned.vault).toBe(DEMO_VAULT);

    // the personal mandate: native terms, caps 0, lifetime, new payees need a human, redeemer = the phone key
    const mp = planPersonalMandate(HOT_KEY, device, 0n, 70);
    const terms = decodePulseTerms(mp.decoded.caveats.find((c) => toHex(c.enforcer).toLowerCase() === PULSE_COSIGN_ENFORCER.toLowerCase())!.terms);
    expect(terms.perTxAutoCap).toBe(0n);
    expect(terms.periodAutoCap).toBe(0n);
    expect(mp.decoded.caveats).toHaveLength(2); // pulse + redeemer
    const { result: personal } = await qrRound(
      dev,
      q,
      mp.request,
      verifierOf(['eth-signature'], (ur) => acceptMandate(ur, mp, personalMandateForm(HOT_KEY), device), (ur) => answersMandate(ur, mp.request)),
    );
    expect(personal.agent).toBe(HOT_KEY);
    expect(personal.delegation.delegator).toBe(DEMO_VAULT);
    expect(isPersonalMandate(personal, HOT_KEY)).toBe(true);

    // one payment: 12.5 mUSD to PAYEE, fresh nonce never handed out, never used on chain
    const amount = 12_500_000n;
    const handedOut = ['7'];
    const plan = await planPayment(
      { to: PAYEE, asset: MOCK_USD, amount },
      { device, personal, hotKey: HOT_KEY, handedOut, usedOnChain: async () => false, now: NOW, fragLen: 70 },
    );
    expect(plan.nonce).not.toBe(7n);
    expect(toHex(plan.decoded.redeemer).toLowerCase()).toBe(HOT_KEY.toLowerCase());
    expect(planFromRequestUr(plan.request.ur).nonce).toBe(plan.nonce);
    const { result: outcome } = await qrRound<CosignOutcome>(
      dev,
      q,
      plan.request,
      verifierOf(['ripar-cosign', 'ripar-deny'], (ur) => acceptCosignAnswer(ur, plan, device, personal), (ur) => answersCosign(ur, plan.request)),
    );
    expect(outcome.kind).toBe('cosign');
    if (outcome.kind !== 'cosign') return;
    expect(outcome.bpm).toBeGreaterThan(40);

    // what the phone key sends: redeemDelegations with the co-sign args on the pulse caveat, one transfer
    const w = redeemPaymentWrite(personal, plan, outcome.answer.caveatArgs, { enforcer: device.pinned.enforcer });
    expect(w.to).toBe(DELEGATION_MANAGER);
    const call = decodeFunctionData({ abi: REDEEM_DELEGATIONS_ABI, data: w.data });
    const [contexts, modes, execs] = call.args as [Hex[], Hex[], Hex[]];
    expect(modes).toEqual([`0x${'00'.repeat(32)}`]);
    const [d] = decodePermissionContext(contexts[0]!);
    const pulse = d!.caveats.find((c) => c.enforcer.toLowerCase() === device.pinned.enforcer.toLowerCase())!;
    expect(pulse.args).toBe(cosignCaveatArgs(plan.nonce, plan.expiry, outcome.answer.presenceHash, `${outcome.answer.r}${outcome.answer.s.slice(2)}` as Hex));
    expect(pulse.args.length).toBe(2 + 160 * 2);
    const transfer = encodeFunctionData({ abi: erc20Abi, functionName: 'transfer', args: [PAYEE, amount] });
    expect(execs[0]!.toLowerCase()).toBe(`${MOCK_USD.toLowerCase()}${'0'.repeat(64)}${transfer.slice(2)}`);
    dev.emu.destroy();
  });

  it('builds the calls the device can decode, and refuses nonsense', () => {
    expect(paymentCall({ to: PAYEE, asset: 'native', amount: 5n })).toEqual({ target: PAYEE, value: 5n, callData: '0x' });
    expect(paymentCall({ to: PAYEE, asset: MOCK_USD, amount: 5n }).callData.slice(0, 10)).toBe('0xa9059cbb');
    expect(() => paymentCall({ to: PAYEE, asset: 'native', amount: 0n })).toThrow();
    expect(() => paymentCall({ to: '0x0000000000000000000000000000000000000000', asset: 'native', amount: 1n })).toThrow();
  });
});

describe('keypad and insights', () => {
  it('edits an amount like a phone keypad', () => {
    let v = '0';
    for (const k of ['1', '2', '.', '5', '0', '0', '0', '0', '0', '0', '1']) v = applyKey(v, k, 6);
    expect(v).toBe('12.500000');
    expect(applyKey('0', '.', 0)).toBe('0');
    expect(applyKey('12.5', 'del', 6)).toBe('12.');
    expect(applyKey('1', 'del', 6)).toBe('0');
    expect(applyKey('1.', '.', 6)).toBe('1.');
  });

  it('counts payments per day and per actor, never summing across assets', () => {
    const now = 2_000_000_000;
    const item = (kind: FeedItem['kind'], actor: FeedItem['actor'], daysAgo: number, subtitle = ''): FeedItem => ({
      id: `${kind}${daysAgo}${actor}`,
      kind,
      actor,
      title: '',
      subtitle,
      amount: null,
      at: now - daysAgo * 86400 - 10,
      block: null,
      tx: null,
      fields: [],
    });
    const ins = insightsOf(
      [
        item('Payment', 'you', 0, 'Co-signed on your Ripar'),
        item('Payment', 'you', 1, 'Denied on the device'),
        item('AutoSpend', 'agent', 1),
        item('HumanCosigned', 'agent', 3),
        item('TransferIn', 'network', 0),
        item('AutoSpend', 'agent', 30),
      ],
      now,
    );
    expect(ins.total).toBe(3);
    expect(ins.byActor).toEqual({ you: 1, agentAuto: 1, agentCosigned: 1, denied: 0 });
    expect(ins.daily[13]).toBe(1);
    expect(ins.daily[12]).toBe(1);
    expect(ins.daily[10]).toBe(1);
  });
});
