// Round trips with the WASM device emulator (firmware/emu/dist, the real firmware C++ in deterministic test mode):
// TS builds every request -> the emulator scans it (multipart QR parts, also fountain-mixed parts) -> review ->
// pulse + SIGN (or the hold gestures) -> the response QR text -> TS parses and verifies it. Includes refusals.
// The emulator is always labelled EMULATOR: its pairing carries the emulator firmware id.
import { pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import type * as EmuModule from '../../../firmware/emu/dist/ripar-emu.js';
import {
  type BuiltRequest,
  type DeviceIdentity,
  AUSD_10143,
  DELEGATION_MANAGER,
  EMULATOR_FIRMWARE_ID,
  FIRMWARE_REGISTRY,
  FIRMWARE_RELAY,
  MM_ENFORCERS,
  PULSE_COSIGN_ENFORCER,
  computeVaultAddress,
  cosignCaveatArgs,
  decodePermissionContext,
  decodeRequest,
  denyRequestHashOf,
  encodePermissionContext,
  encodeRedeemDelegations,
  expectVerified,
  firmwareRefusal,
  hashDelegation,
  parseResponse,
  privyParse,
  randomCosignNonce,
  signedDelegation,
  tokenCheck,
  urParts,
  verifyPairing,
  withCaveatArgs,
  buildRequest,
} from '../src/index.js';
import { DEMO_K1, DEMO_P1, DEMO_VAULT } from './helpers/demo-device.js';
import { EMULATOR_PATH, hexToBytes } from './helpers/env.js';

type Emu = EmuModule.RiparEmulator;
type EmuState = EmuModule.EmuState;

const CHAIN = 10143;
const NOW = 1790500000; // 2026-09-27 09:06:40 UTC (> the firmware time floor)
const EXP = NOW + 3600;
// firmware v1.2: the Ripar contracts compiled into the firmware (a pairing may only name these); the sentinel is not
// compiled in (pinned as given)
const REGISTRY = FIRMWARE_REGISTRY['10143']!;
const ENFORCER = PULSE_COSIGN_ENFORCER;
const RELAY = FIRMWARE_RELAY['10143']!;
const SENTINEL = '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0';
const OTHER = '0x5FbDB2315678afecb367f032d93F642f64180aa3'; // an address the firmware does not pin
const AGENT = '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707';
const PAYEE = '0x0165878A594ca255338adfa4d48449f69242Eb8F';
const AGENT_ID = 42;
const salt = (n: number): string => n.toString(16).padStart(2, '0').repeat(16);

let emu: Emu;
let identity: DeviceIdentity;
let mandate: BuiltRequest;
let mandateSig: string;
let mandateDh: string;
let lastRefusal = '';

// ------------------------------------------------------------------------------------------------ driving helpers
function toScan(): EmuState {
  let s = emu.state();
  if (s.screen !== 'scan') s = emu.key('press');
  expect(s.screen).toBe('scan');
  return s;
}

function scanAll(parts: string[]): EmuModule.ScanResult {
  toScan();
  let r: EmuModule.ScanResult | null = null;
  for (const p of parts) {
    r = emu.scan(p);
    if (r.result === 'complete') break;
    expect(['accepted', 'ignored'], `${r.result} ${r.hint}`).toContain(r.result);
  }
  return r!;
}

function pageToEnd(): EmuState {
  let s = emu.state();
  for (let i = 0; i < 80 && s.screen === 'review' && !s.review!.allSeen; i++) s = emu.key('press');
  return s;
}

/** last review page -> PULSE -> thumb -> ARMED -> (TRNG salt) -> SIGN -> the response QR */
function pulseAndSign(saltHex?: string): EmuState {
  let s = emu.key('press');
  expect(s.screen).toBe('pulse');
  emu.finger({ on: true, bpm: 72 });
  s = emu.tickUntil((x) => x.screen === 'armed', { maxMs: 20000, stepMs: 20 });
  expect(s.screen).toBe('armed');
  if (saltHex) emu.injectTrng(saltHex);
  s = emu.key('press');
  expect(s.screen).toBe('qr');
  expect(s.qr?.signed).toBe(true);
  emu.finger({ on: false });
  return s;
}

function home(): void {
  const s = emu.key('press');
  expect(s.screen).toBe('home');
}

function reviewOf(req: BuiltRequest, multipart = true): EmuState {
  const r = scanAll(multipart ? req.parts : [req.ur]);
  expect(r.result).toBe('complete');
  const s = emu.state();
  expect(s.screen, JSON.stringify(s.message)).toBe('review');
  return s;
}

function expectRefused(req: BuiltRequest, prefix: string): void {
  const s = reviewOf(req, false);
  expect(s.review!.ok).toBe(false);
  expect(s.review!.refusal.startsWith(prefix), s.review!.refusal).toBe(true);
  lastRefusal = s.review!.refusal;
  pageToEnd();
  const sigs = emu.state().signatures;
  const h = emu.key('press');
  expect(h.screen).toBe('home');
  expect(h.signatures).toBe(sigs);
}

/** a request the device refuses while parsing it: message screen (no review), nothing signed */
function expectParseRefused(req: BuiltRequest, title: string, reason: string): void {
  const r = scanAll([req.ur]);
  expect(r.result).toBe('complete');
  const s = emu.state();
  expect(s.screen).toBe('message');
  expect(s.message!.title).toBe(title);
  expect(s.message!.body, s.message!.body).toContain(reason);
  const sigs = s.signatures;
  const h = emu.key('press');
  expect(h.screen).toBe('home');
  expect(h.signatures).toBe(sigs);
}

const cosignFields = (over: Record<string, unknown>) => ({
  chainId: CHAIN,
  enforcer: ENFORCER,
  delegationHash: mandateDh,
  delegator: DEMO_VAULT,
  redeemer: AGENT,
  target: AUSD_10143,
  value: 0,
  nonce: randomCosignNonce(),
  expiry: EXP,
  ...over,
});

// ------------------------------------------------------------------------------------------------ the scenario
beforeAll(async () => {
  const mod = (await import(pathToFileURL(EMULATOR_PATH).href)) as typeof EmuModule;
  emu = await mod.RiparEmulator.create({ test: true });
});

describe('emulator round trips (test mode, demo seed)', () => {
  it('powers on as the demo device, labelled EMULATOR', () => {
    const s = emu.state();
    expect(s.emulator).toBe(true);
    expect(s.emulatorId).toBe('ripar-emulator v1');
    expect('0x' + s.firmwareId).toBe(EMULATOR_FIRMWARE_ID);
    expect(s.k1).toBe(DEMO_K1);
    expect('0x' + s.p1).toBe(DEMO_P1);
    expect(computeVaultAddress(s.k1)).toBe(DEMO_VAULT);
  });

  it('refusal before pairing: a co-sign is NOT PAIRED', () => {
    mandateDh = '0x' + '11'.repeat(32);
    expectRefused(buildRequest('cosign', cosignFields({ transfer: { to: PAYEE, amount: 1 } })), 'NOT PAIRED');
  });

  it('refusals: a pairing that names other contracts than the compiled-in ones, or another vault (key 8)', () => {
    for (const [over, prefix] of [
      [{ registry: OTHER }, 'WRONG REGISTRY'],
      [{ enforcer: OTHER }, 'WRONG PULSE CO-SIGN ENFORCER'],
      [{ relay: OTHER }, 'WRONG REPUTATION RELAY'],
      [{ manager: OTHER }, 'WRONG DELEGATION MANAGER'],
      [{ vault: OTHER }, "VAULT IS NOT THIS DEVICE'S VAULT"],
    ] as const) {
      const req = buildRequest('pair', { chainId: CHAIN, sentinel: SENTINEL, now: NOW, ...over });
      // the library refuses early with the same headline (make_request firmware_refusal)
      expect(firmwareRefusal(decodeRequest('pair', req.cbor), DEMO_K1)?.startsWith(prefix)).toBe(true);
      expectRefused(req, prefix);
      if (prefix.startsWith('VAULT')) expect(lastRefusal).toContain(DEMO_VAULT);
      else expect(lastRefusal).toContain('Monad testnet (10143)');
    }
    expect(emu.state().paired).toBe(false);
  });

  it('pair (multipart, 70-byte fragments, no key 8) -> ripar-pair verified with both BindDevice signatures', () => {
    const req = buildRequest('pair', {
      chainId: CHAIN,
      registry: REGISTRY,
      manager: DELEGATION_MANAGER,
      enforcer: ENFORCER,
      sentinel: SENTINEL,
      relay: RELAY,
      now: NOW,
    });
    expect(req.map.has(8)).toBe(false);
    expect(req.parts.length).toBeGreaterThan(1);
    const s0 = reviewOf(req);
    expect(s0.review!.title).toBe('PAIR DEVICE');
    expect(s0.review!.ok).toBe(true);
    pageToEnd();
    const s = pulseAndSign();
    expect(s.qr!.title).toBe('PAIRED');
    identity = verifyPairing(s.qr!.text, req);
    expect(identity.emulator).toBe(true);
    expect(identity.firmwareId).toBe(EMULATOR_FIRMWARE_ID);
    expect(identity.k1Address).toBe(DEMO_K1);
    expect(identity.p1Key).toBe(DEMO_P1);
    const rep = expectVerified(parseResponse(s.qr!.text, { request: req }));
    if (rep.type !== 'ripar-pair') throw new Error(rep.type);
    expect(rep.fields.vault).toBe(DEMO_VAULT); // the vault the device pinned: derived from K1
    expect(rep.checks.map((c) => c.name)).toContain("pair request names only the firmware's pinned contracts");
    expect(s.context.vault).toBe(DEMO_VAULT);
    expect(s.vault).toBe(DEMO_VAULT);
    expect(s.context.pulseCosignEnforcer).toBe(ENFORCER);
    expect(s.context.registry).toBe(REGISTRY);
    expect(s.context.relay).toBe(RELAY);
    home();
  });

  it('keys-only pairing QR: parsed, but verifyPairing refuses it (no BindDevice signatures)', () => {
    const s = emu.key('hold2');
    expect(s.screen).toBe('pairQr');
    const rep = parseResponse(s.qr!.text);
    expect(rep.type).toBe('ripar-pair');
    if (rep.type !== 'ripar-pair') return;
    expect(rep.fields.k1Address).toBe(DEMO_K1);
    expect(rep.fields.emulator).toBe(true);
    expect(rep.fields.reqId).toBeUndefined();
    expect(rep.fields.vault).toBe(DEMO_VAULT); // the companion derives the vault from key 2 (docs/PROTOCOL.md 4)
    expect(() => verifyPairing(s.qr!.text, buildRequest('pair', { chainId: CHAIN, now: NOW }))).toThrow();
    emu.key('hold2'); // menu
    emu.key('press');
    emu.key('press');
    expect(emu.key('hold2').screen).toBe('home'); // BACK
  });

  it('refusal: a mandate without the pulse co-sign caveat', () => {
    const req = buildRequest('mandate', {
      chainId: CHAIN,
      manager: DELEGATION_MANAGER,
      delegate: AGENT,
      delegator: DEMO_VAULT,
      salt: 2,
      caveats: [{ kind: 'erc20TransferAmount', token: AUSD_10143, amount: 1_000_000 }],
    });
    expectRefused(req, 'MANDATE WITHOUT PULSE CO-SIGN');
  });

  it('mandate (typed caveats, multipart) -> eth-signature verified against the paired K1; Delegation assembled', () => {
    mandate = buildRequest(
      'mandate',
      {
        chainId: CHAIN,
        manager: DELEGATION_MANAGER,
        delegate: AGENT,
        delegator: DEMO_VAULT,
        salt: 20260927,
        label: 'Ripar TS round trip',
        agentId: AGENT_ID,
        caveats: [
          { kind: 'timestamp', after: 0, before: NOW + 30 * 86400 },
          {
            kind: 'pulse',
            enforcer: ENFORCER,
            p1Key: identity.p1Key,
            token: AUSD_10143,
            perTxAutoCap: 5_000_000,
            periodAutoCap: 20_000_000,
            period: 86400,
            epoch: 0,
            newPayeeNeedsHuman: true,
            sentinel: SENTINEL,
          },
          { kind: 'redeemer', addresses: [AGENT] },
        ],
      },
      { frag: 60 },
    );
    const s0 = reviewOf(mandate);
    expect(s0.review!.title).toBe('SIGN MANDATE');
    expect(s0.review!.ok, s0.review!.refusal).toBe(true);
    pageToEnd();
    const s = pulseAndSign();
    expect(s.qr!.title).toBe('MANDATE SIGNED');
    const rep = expectVerified(parseResponse(s.qr!.text, { request: mandate, k1Address: identity.k1Address }));
    if (rep.type !== 'eth-signature') throw new Error(rep.type);
    expect(rep.fields.delegationHash).toBe(s.context.lastDelegationHash);
    mandateDh = rep.fields.delegationHash!;
    mandateSig = rep.fields.rsv;
    // the framework Delegation for redeemDelegations
    const q = decodeRequest('mandate', mandate.cbor);
    if (q.kind !== 'mandate') throw new Error('kind');
    const d = signedDelegation(q, mandateSig);
    expect(hashDelegation(d)).toBe(mandateDh);
    expect(decodePermissionContext(encodePermissionContext([d]))).toEqual([d]);
    home();
  });

  it("refusals: another vault as delegator (mandate, co-sign): NOT THIS DEVICE'S VAULT", () => {
    const m = buildRequest('mandate', {
      chainId: CHAIN,
      manager: DELEGATION_MANAGER,
      delegate: AGENT,
      delegator: OTHER,
      salt: 4,
      caveats: [{ kind: 'pulse', p1Key: identity.p1Key, token: AUSD_10143, perTxAutoCap: 1, periodAutoCap: 1, period: 0, sentinel: SENTINEL }],
    });
    expect(firmwareRefusal(decodeRequest('mandate', m.cbor), identity.k1Address)).toMatch(/^NOT THIS DEVICE'S VAULT/);
    expectRefused(m, "NOT THIS DEVICE'S VAULT");
    const c = buildRequest('cosign', cosignFields({ delegator: OTHER, transfer: { to: PAYEE, amount: 1 } }));
    expect(firmwareRefusal(decodeRequest('cosign', c.cbor), identity.k1Address)).toMatch(/^NOT THIS DEVICE'S VAULT/);
    expectRefused(c, "NOT THIS DEVICE'S VAULT");
  });

  it('refusals: wrong chain, unknown calldata, lying token claims', () => {
    expectRefused(buildRequest('cosign', cosignFields({ chainId: 143, transfer: { to: PAYEE, amount: 1 } })), 'WRONG CHAIN');
    expectRefused(buildRequest('cosign', cosignFields({ calldata: '0xdeadbeef00' })), 'UNKNOWN CALLDATA');
    // the token table is checked while parsing: a message screen, with make_request's (and tokenCheck's) wording
    const lying = buildRequest('cosign', cosignFields({ transfer: { to: PAYEE, amount: 1 }, decimals: 18 }));
    const q = decodeRequest('cosign', lying.cbor);
    if (q.kind !== 'cosign') throw new Error('kind');
    let why = '';
    try {
      tokenCheck(q);
    } catch (e) {
      why = (e as Error).message;
    }
    expect(why).toContain('disagrees with the firmware token table');
    expectParseRefused(lying, 'CO-SIGN REFUSED', why);
  });

  let cosignErc20: BuiltRequest;
  it('co-sign ERC-20 transfer -> ripar-cosign verified; HUMAN caveat args; redeemDelegations calldata', () => {
    cosignErc20 = buildRequest(
      'cosign',
      cosignFields({
        transfer: { to: PAYEE, amount: 25_000_000 },
        ai: { text: 'pay invoice 17', claims: { to: PAYEE, token: AUSD_10143, amount: 25_000_000 } },
        decimals: 6,
        symbol: 'AUSD',
      }),
    );
    const s0 = reviewOf(cosignErc20);
    expect(s0.review!.title).toBe('CO-SIGN PAYMENT');
    expect(s0.review!.ok, s0.review!.refusal).toBe(true);
    pageToEnd();
    // the remembered mandate sets newPayeeNeedsHuman: the review says the payee becomes an AUTO payee (firmware v1.2)
    expect(s0.review!.lines.some((l) => /becomes an AUTO payee of this mandate/.test(JSON.stringify(l)))).toBe(true);
    const s = pulseAndSign(salt(0xa1));
    expect(s.qr!.title).toBe('CO-SIGNED');
    const rep = expectVerified(
      parseResponse(s.qr!.text, { request: cosignErc20, p1Key: identity.p1Key, k1Address: identity.k1Address }),
    );
    expect(rep.checks.map((c) => c.name)).toContain('delegator is the vault derived from the paired K1');
    if (rep.type !== 'ripar-cosign') throw new Error(rep.type);
    expect(rep.fields.salt16).toBe('0x' + salt(0xa1));
    expect(rep.fields.evidence.version).toBe(1);
    expect(Math.abs(rep.fields.evidence.bpm - 72)).toBeLessThan(12);
    const q = decodeRequest('cosign', cosignErc20.cbor);
    if (q.kind !== 'cosign') throw new Error('kind');
    expect(rep.fields.caveatArgs).toBe(cosignCaveatArgs(q.nonce, q.expiry, rep.fields.presenceHash, rep.fields.rs));
    expect(hexToBytes(rep.fields.caveatArgs!).length).toBe(160);
    const m = decodeRequest('mandate', mandate.cbor);
    if (m.kind !== 'mandate') throw new Error('kind');
    const d = withCaveatArgs(signedDelegation(m, mandateSig), ENFORCER, rep.fields.caveatArgs!);
    const data = encodeRedeemDelegations([{ delegations: [d], target: q.target, value: q.value, callData: q.calldata }]);
    expect(data.startsWith('0xcef6d209')).toBe(true); // redeemDelegations(bytes[],bytes32[],bytes[])
    home();
  });

  it('co-sign native send -> verified; the same response fails against another request', () => {
    const req = buildRequest('cosign', cosignFields({ target: PAYEE, value: 1_500_000_000_000_000_000n }));
    reviewOf(req, false);
    pageToEnd();
    const s = pulseAndSign(salt(0xa2));
    expectVerified(parseResponse(s.qr!.text, { request: req, p1Key: identity.p1Key }));
    const wrong = parseResponse(s.qr!.text, { request: cosignErc20, p1Key: identity.p1Key });
    expect(wrong.result).toBe('FAIL');
    home();
  });

  it('deny built by the device from a co-sign review (hold 2 s, no pulse)', () => {
    const req = buildRequest('cosign', cosignFields({ transfer: { to: '0x000000000000000000000000000000000000dEaD', amount: 999_000_000 } }));
    reviewOf(req, false);
    let s = emu.key('hold2');
    expect(s.job).toBe('deny');
    expect(s.review!.title).toBe('DENY + REPORT AGENT');
    pageToEnd();
    emu.injectTrng(salt(0xb1));
    s = emu.key('press');
    expect(s.screen).toBe('qr');
    const rep = expectVerified(parseResponse(s.qr!.text, { request: req, contract: RELAY, p1Key: identity.p1Key }));
    if (rep.type !== 'ripar-deny') throw new Error(rep.type);
    const q = decodeRequest('cosign', req.cbor);
    if (q.kind !== 'cosign') throw new Error('kind');
    expect(rep.fields.requestHash).toBe(denyRequestHashOf(q));
    expect(rep.fields.agentId).toBe(BigInt(AGENT_ID));
    expect(rep.fields.evidence12).toBe('0x' + '00'.repeat(12));
    // wrong relay domain -> FAIL
    expect(parseResponse(s.qr!.text, { request: req, contract: REGISTRY, p1Key: identity.p1Key }).result).toBe('FAIL');
    home();
  });

  it('companion deny request -> verified; another agent is refused', () => {
    expectRefused(
      buildRequest('deny', { chainId: CHAIN, relay: RELAY, agentId: 7, requestHash: '0x' + '77'.repeat(32) }),
      'NOT THE PINNED AGENT',
    );
    const req = buildRequest('deny', { chainId: CHAIN, relay: RELAY, agentId: AGENT_ID, requestHash: '0x' + '77'.repeat(32) });
    reviewOf(req, false);
    pageToEnd();
    emu.injectTrng(salt(0xb2));
    const s = emu.key('press');
    expect(s.screen).toBe('qr');
    expectVerified(parseResponse(s.qr!.text, { request: req, p1Key: identity.p1Key }));
    home();
  });

  it('Privy authorization (canonical JSON; fed as pure + fountain-mixed parts) -> DER signature verified', () => {
    const json = {
      version: 1,
      method: 'PATCH',
      url: 'https://api.privy.io/v1/wallets/wl8yz4c2rq0q1cdz2q8a4',
      body: { additional_signers: [{ signer_id: 'kq7ks9z3n1v2lq4d7w0p8m3y', override_policy_ids: ['pol9x2'] }] },
      headers: { 'privy-app-id': 'cm0appid1234' },
    };
    const req = buildRequest('privy', { json }, { frag: 30 });
    const pq = decodeRequest('privy', req.cbor);
    if (pq.kind !== 'privy') throw new Error('kind');
    expect(privyParse(pq.json).signers?.[0]?.signerId).toBe('kq7ks9z3n1v2lq4d7w0p8m3y'); // the companion's preview
    // the first pure part is never shown: the device must solve the message from the mixed parts
    const all = urParts(req.type, req.cbor, 30, 60);
    const seqLen = req.parts.length;
    const feed = [...all.slice(1, seqLen), ...all.slice(seqLen)];
    const r = scanAll(feed);
    expect(r.result).toBe('complete');
    const s0 = emu.state();
    expect(s0.review!.title).toBe('PRIVY AUTHORIZATION');
    expect(s0.review!.ok, s0.review!.refusal).toBe(true);
    pageToEnd();
    const s = pulseAndSign();
    const rep = expectVerified(parseResponse(s.qr!.text, { request: req, p1Key: identity.p1Key }));
    if (rep.type !== 'ripar-der-sig') throw new Error(rep.type);
    expect(Buffer.from(rep.fields.derBase64, 'base64').toString('hex')).toBe(rep.fields.der.slice(2));
    home();
  });

  it('refusal: a Privy /rpc request (outside the allow-list), which privyParse refuses too', () => {
    const json = {
      version: 1,
      method: 'POST',
      url: 'https://api.privy.io/v1/wallets/w1/rpc',
      body: { method: 'eth_sendTransaction' },
      headers: { 'privy-app-id': 'app1' },
    };
    const req = buildRequest('privy', { json });
    let why = '';
    try {
      privyParse(JSON.stringify(json));
    } catch (e) {
      why = (e as Error).message;
    }
    expect(why).toBe('method must be PATCH');
    expectParseRefused(req, 'PRIVY REQUEST REFUSED', 'method must be PATCH');
  });

  it('revoke (device menu) -> ripar-revoke verified in the pinned enforcer domain', () => {
    emu.key('hold2'); // pairing QR
    emu.key('hold2'); // menu
    let s = emu.key('hold2'); // REVOKE
    expect(s.job).toBe('revoke');
    pageToEnd();
    s = pulseAndSign();
    expect(s.qr!.title).toBe('REVOKE SIGNED');
    const rep = expectVerified(parseResponse(s.qr!.text, { chainId: CHAIN, contract: ENFORCER, p1Key: identity.p1Key }));
    if (rep.type !== 'ripar-revoke') throw new Error(rep.type);
    expect(rep.fields.delegationHash).toBe(mandateDh);
    // without a contract: the PulseCosignEnforcer compiled in for the chain
    expectVerified(parseResponse(s.qr!.text, { chainId: CHAIN, p1Key: identity.p1Key }));
    expect(parseResponse(s.qr!.text, { chainId: CHAIN, contract: SENTINEL, p1Key: identity.p1Key }).result).toBe('FAIL');
    expect(parseResponse(s.qr!.text, { chainId: 143, contract: ENFORCER, p1Key: identity.p1Key }).result).toBe('FAIL');
    home();
  });

  it('refusal: re-pairing to Monad (143) while a mandate is live and not covered by a panic: PANIC FIRST', () => {
    expect(emu.state().context.unpanickedMandates).toBe(true); // a revoke does not clear it
    const req = buildRequest('pair', { chainId: 143, sentinel: SENTINEL, now: NOW });
    expect(firmwareRefusal(decodeRequest('pair', req.cbor), DEMO_K1)).toBeNull(); // only the device knows its context
    expectRefused(req, 'PANIC FIRST');
    expect(emu.state().context.chainId).toBe(String(CHAIN));
  });

  it('PANIC (hold 5 s on HOME) -> ripar-panic verified, minEpoch 1', () => {
    const s = emu.key('hold5');
    expect(s.screen).toBe('qr');
    const rep = expectVerified(parseResponse(s.qr!.text, { chainId: CHAIN, contract: ENFORCER, p1Key: identity.p1Key }));
    if (rep.type !== 'ripar-panic') throw new Error(rep.type);
    expect(rep.fields.minEpoch).toBe(1n);
    expectVerified(parseResponse(s.qr!.text, { chainId: CHAIN, p1Key: identity.p1Key })); // compiled-in enforcer
    expect(emu.state().context.unpanickedMandates).toBe(false);
    home();
  });

  it('reopen (device menu) -> ripar-reopen verified in the sentinel domain, nonce 1, the pinned vault', () => {
    emu.key('hold2');
    emu.key('hold2');
    emu.key('press'); // REOPEN
    let s = emu.key('hold2');
    expect(s.job).toBe('reopen');
    pageToEnd();
    s = pulseAndSign();
    const rep = expectVerified(
      parseResponse(s.qr!.text, { chainId: CHAIN, contract: SENTINEL, p1Key: identity.p1Key, k1Address: identity.k1Address }),
    );
    if (rep.type !== 'ripar-reopen') throw new Error(rep.type);
    expect(rep.fields.vault).toBe(DEMO_VAULT);
    expect(rep.checks[0]!.name).toBe('reopen vault is the vault derived from the paired K1');
    expect(rep.fields.nonce).toBe(1n);
    expect(parseResponse(s.qr!.text, { chainId: CHAIN, contract: ENFORCER, p1Key: identity.p1Key }).result).toBe('FAIL');
    home();
  });

  it('refusal: a mandate at the stale epoch 0 after the panic', () => {
    const req = buildRequest('mandate', {
      chainId: CHAIN,
      manager: DELEGATION_MANAGER,
      delegate: AGENT,
      delegator: DEMO_VAULT,
      salt: 3,
      agentId: AGENT_ID,
      caveats: [
        {
          kind: 'pulse',
          enforcer: ENFORCER,
          p1Key: identity.p1Key,
          token: AUSD_10143,
          perTxAutoCap: 1,
          periodAutoCap: 1,
          period: 86400,
          epoch: 0,
          sentinel: SENTINEL,
        },
        { kind: 'limitedCalls', enforcer: MM_ENFORCERS.LimitedCallsEnforcer, amount: 5 },
      ],
    });
    expectRefused(req, 'RULE 1: STALE EPOCH 0');
  });
});
