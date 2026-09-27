// End-to-end tests of the Ripar device emulator (emu/dist, built by emu/build.sh). Node 18+, no npm dependencies.
//
//   node emu/test/run_tests.mjs            (python on PATH, or RIPAR_PYTHON=<python>)
//
// Every request is built by tools/make_request.py (emu/test/oracle.py build). The emulator runs in deterministic
// test mode (seed = DEMO_SEED, injected salts). Every signed response the emulator shows is then checked by
// emu/test/oracle.py verify: (a) `make_request.py parse` exits 0 (all signatures verified), (b) the response is
// byte-identical to make_request.py's simulate() for the same request, seed, salt and evidence (and, for the salt-free
// mandate / Privy responses, to the stdout of the `make_request.py simulate` CLI). Finally the parity audits
// (audit_key_window.mjs, audit_scan_repeat.mjs, audit_pulse_faults.mjs) run as child processes and must exit 0.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { RiparEmulator } from '../dist/ripar-emu.mjs';

const ORACLE = fileURLToPath(new URL('./oracle.py', import.meta.url));
const PY = process.env.RIPAR_PYTHON || 'python';

// ------------------------------------------------------------------------------------------------ tiny harness
let passed = 0;
let failed = 0;
let section = '';
function sect(name) {
  section = name;
  console.log('-- ' + name);
}
function check(name, cond, info) {
  if (cond) {
    passed++;
    return true;
  }
  failed++;
  console.log(`   FAIL [${section}] ${name}` + (info !== undefined ? `\n        ${typeof info === 'string' ? info : JSON.stringify(info)}` : ''));
  return false;
}
function fatal(msg) {
  console.log('FATAL: ' + msg);
  process.exit(2);
}

function oracle(mode, input) {
  const p = spawnSync(PY, [ORACLE, mode], { input: JSON.stringify(input), maxBuffer: 64 << 20, encoding: 'utf8' });
  if (p.error) fatal(`cannot run ${PY}: ${p.error.message}`);
  if (p.status !== 0) fatal(`oracle ${mode} failed (${p.status}):\n${p.stderr}\n${p.stdout}`);
  return JSON.parse(p.stdout);
}

// ------------------------------------------------------------------------------------------------ fixtures
// firmware v1.2: the Ripar contracts are compiled in (src/enforcers.cpp, CREATE2 addresses of the bytecode frozen for
// contracts v1.2) and the vault is derived from K1 (src/vault.cpp); a pairing may only name those
const DM = '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3'; // MetaMask DelegationManager v1.3.0 (compiled in)
const AUSD = '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC'; // listed token on 10143 (6 decimals)
const MUSD = '0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a'; // MockUSD (mUSD, 6 decimals), listed on 10143 since v1.2
const REGISTRY = '0xA08a47c9d645926615CF04D69b7a048133F68c9f'; // RiparDeviceRegistry (compiled in, 10143 + 143)
const ENFORCER = '0x64d61fe5438981DC803ED61250FEf024617ae7eE'; // PulseCosignEnforcer (compiled in, 10143 + 143)
const RELAY = '0xE433dCA75CA6cd730b1006F51A26208B000eA9E2'; // RiparReputationRelay compiled in on 10143
const RELAY_143 = '0x108BA102F7D0915f51c93F128b96Bd24F647f06d'; // ... and on 143 (firmware v1.2 review)
const SENTINEL = '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0'; // RiparSentinel: never compiled in, pinned as given
const AGENT = '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707';
const PAYEE = '0x0165878A594ca255338adfa4d48449f69242Eb8F';
const DEAD = '0x000000000000000000000000000000000000dEaD';
const ZERO = '0x0000000000000000000000000000000000000000';
// the v1.1 fixtures: contracts / vault the v1.2 firmware must refuse
const OTHER_REGISTRY = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
const OTHER_ENFORCER = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512';
const OTHER_RELAY = '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9';
const OTHER_MANAGER = '0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6';
const OTHER_VAULT = '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9';
const NOW = 1790500000; // 2026-09-27 09:06:40 UTC
const EXP = NOW + 3600;
const CHAIN = 10143;
const AGENT_ID = 42;
// the P1 key of the demo seed (the emulator's key in test mode; also checked against state().p1 below)
const DEMO_P1 = '5cbcd94e72c801fc1b1167ef6f648a5b998d41819020703610637bca5d182765b8f1fb687dc1ceb07f52f98cf80292b23d7583879c75689c4cf35393b67bd954';
const DEMO_K1 = '0x753454832754c071704be47915d4DeC6339624Eb';
// the demo K1's vault: MetaMask SimpleFactory CREATE2 (salt 0) of the HybridDeleGator proxy (docs/PROTOCOL.md 2.1),
// checked on Monad testnet; the emulator derives it (vault.cpp), make_request.py independently (oracle.py vault)
const VAULT = '0xc36F625D426eBa8f1e0129276B284a939CD3A57D';
const ONE_MON = '1000000000000000000';

const rid = (n) => n.toString(16).padStart(2, '0').repeat(16);
// no enforcer given: make_request.py fills in the PulseCosignEnforcer compiled in for the chain
const pulseCaveat = (epoch, over = {}) => ({ kind: 'pulse', p1Key: DEMO_P1, token: AUSD, perTxAutoCap: 5000000,
  periodAutoCap: 20000000, period: 86400, epoch, newPayeeNeedsHuman: true, sentinel: SENTINEL, ...over });
// keys 4 / 5 / 7 equal to the compiled-in contracts, no key 8 (the device pins the vault it derives from K1)
const pairFields = { chainId: CHAIN, registry: REGISTRY, manager: DM, enforcer: ENFORCER, sentinel: SENTINEL, relay: RELAY,
  now: NOW };
const cosignBase = { chainId: CHAIN, enforcer: ENFORCER, delegationHash: '$dh:mandate_ok', delegator: VAULT, redeemer: AGENT,
  target: AUSD, value: 0, expiry: EXP };
const PRIVY_JSON = { version: 1, method: 'PATCH', url: 'https://api.privy.io/v1/wallets/wl8yz4c2rq0q1cdz2q8a4',
  body: { additional_signers: [{ signer_id: 'kq7ks9z3n1v2lq4d7w0p8m3y', override_policy_ids: ['pol9x2'] }] },
  headers: { 'privy-app-id': 'cm0appid1234' } };
const mandateBase = { chainId: CHAIN, manager: DM, delegate: AGENT, delegator: VAULT };

const SPECS = [
  { name: 'pair', kind: 'pair', reqid: rid(1), frag: 40, fields: pairFields },
  // key 8 present and equal to the derived vault (it can only confirm it)
  { name: 'repair_same', kind: 'pair', reqid: rid(3), fields: { ...pairFields, vault: VAULT, now: NOW + 60 } },
  { name: 'mandate_ok', kind: 'mandate', reqid: rid(4), frag: 60, fields: { ...mandateBase, salt: 1, agentId: AGENT_ID,
    label: 'demo agent', caveats: [pulseCaveat(0)] } },
  { name: 'mandate_nopulse', kind: 'mandate', reqid: rid(5), fields: { ...mandateBase, salt: 2,
    caveats: [{ kind: 'erc20TransferAmount', token: AUSD, amount: 1000000 }] } },
  { name: 'mandate_stale', kind: 'mandate', reqid: rid(6), fields: { ...mandateBase, salt: 3, agentId: AGENT_ID,
    caveats: [pulseCaveat(0)] } },
  { name: 'cosign_erc20', kind: 'cosign', reqid: rid(7), fields: { ...cosignBase, nonce: 1,
    transfer: { to: PAYEE, amount: 25000000 },
    ai: { text: 'pay invoice 17', claims: { to: PAYEE, token: AUSD, amount: 25000000 } } } },
  { name: 'cosign_native', kind: 'cosign', reqid: rid(8), fields: { ...cosignBase, target: PAYEE, value: '1500000000000000000', nonce: 2 } },
  { name: 'cosign_for_deny', kind: 'cosign', reqid: rid(9), fields: { ...cosignBase, nonce: 3,
    transfer: { to: DEAD, amount: 999000000 } } },
  { name: 'cosign_wrong_chain', kind: 'cosign', reqid: rid(10), fields: { ...cosignBase, chainId: 143, nonce: 4,
    transfer: { to: PAYEE, amount: 1 } } },
  { name: 'cosign_unknown_calldata', kind: 'cosign', reqid: rid(11), fields: { ...cosignBase, nonce: 5, calldata: '0xdeadbeef00' } },
  { name: 'cosign_expiry_far', kind: 'cosign', reqid: rid(12), fields: { ...cosignBase, nonce: 6, expiry: NOW + 9 * 86400,
    transfer: { to: PAYEE, amount: 1 } } },
  { name: 'deny_req', kind: 'deny', reqid: rid(13), fields: { chainId: CHAIN, relay: RELAY, agentId: AGENT_ID,
    requestHash: '0x' + '77'.repeat(32) } },
  { name: 'deny_req_wrong_agent', kind: 'deny', reqid: rid(14), fields: { chainId: CHAIN, relay: RELAY, agentId: 7,
    requestHash: '0x' + '77'.repeat(32) } },
  { name: 'privy', kind: 'privy', reqid: rid(15), fields: { json: PRIVY_JSON } },
  { name: 'mandate_epoch1', kind: 'mandate', reqid: rid(16), fields: { ...mandateBase, salt: 4, agentId: AGENT_ID,
    caveats: [pulseCaveat(1)] } },
  { name: 'cosign_later', kind: 'cosign', reqid: rid(17), fields: { ...cosignBase, delegationHash: '$dh:mandate_epoch1',
    nonce: 7, expiry: NOW + 2 * 86400, transfer: { to: PAYEE, amount: 5000000 } } },
  // ---- v1.2 pairing: the compiled-in contracts and the vault derived from K1 are the only ones a pairing may name
  { name: 'pair_wrong_vault', kind: 'pair', reqid: rid(20), fields: { ...pairFields, vault: OTHER_VAULT } },
  { name: 'pair_wrong_registry', kind: 'pair', reqid: rid(21), fields: { ...pairFields, registry: OTHER_REGISTRY } },
  { name: 'pair_wrong_manager', kind: 'pair', reqid: rid(22), fields: { ...pairFields, manager: OTHER_MANAGER } },
  { name: 'pair_wrong_enforcer', kind: 'pair', reqid: rid(23), fields: { ...pairFields, enforcer: OTHER_ENFORCER } },
  { name: 'pair_wrong_relay', kind: 'pair', reqid: rid(24), fields: { ...pairFields, relay: OTHER_RELAY } },
  // minimal: keys 1, 2, 3, 6, 9 only (no DelegationManager / enforcer / relay / vault: the device fills them in)
  { name: 'pair_min', kind: 'pair', reqid: rid(25), fields: { chainId: CHAIN, registry: REGISTRY, sentinel: SENTINEL, now: NOW } },
  // a move to Monad (143): the chain changes, so PANIC FIRST applies while mandates signed since the last panic exist
  { name: 'repair_143', kind: 'pair', reqid: rid(26), fields: { chainId: 143, registry: REGISTRY, sentinel: SENTINEL,
    now: NOW + 120 } },
  { name: 'mandate_other_vault', kind: 'mandate', reqid: rid(27), fields: { ...mandateBase, delegator: OTHER_VAULT, salt: 5,
    agentId: AGENT_ID, caveats: [pulseCaveat(0)] } },
  { name: 'cosign_other_vault', kind: 'cosign', reqid: rid(28), fields: { ...cosignBase, delegator: OTHER_VAULT, nonce: 8,
    transfer: { to: PAYEE, amount: 1 } } },
  // ---- the co-sign AUTO payee line against mandate_ok (token terms: AUSD, newPayeeNeedsHuman, 5 / 20 AUSD per 1 d)
  { name: 'auto_approve', kind: 'cosign', reqid: rid(30), fields: { ...cosignBase, nonce: 30,
    approve: { spender: PAYEE, amount: 1000000 } } },
  { name: 'auto_transfer_from', kind: 'cosign', reqid: rid(31), fields: { ...cosignBase, nonce: 31,
    transferFrom: { from: VAULT, to: PAYEE, amount: 1000000 } } },
  { name: 'auto_zero_amount', kind: 'cosign', reqid: rid(32), fields: { ...cosignBase, nonce: 32, transfer: { to: PAYEE, amount: 0 } } },
  { name: 'auto_zero_payee', kind: 'cosign', reqid: rid(33), fields: { ...cosignBase, nonce: 33, transfer: { to: ZERO, amount: 5 } } },
  { name: 'auto_musd', kind: 'cosign', reqid: rid(34), fields: { ...cosignBase, target: MUSD, nonce: 34,
    transfer: { to: PAYEE, amount: 1234567 } } },
  { name: 'auto_unknown_mandate', kind: 'cosign', reqid: rid(35), fields: { ...cosignBase, delegationHash: '0x' + '11'.repeat(32),
    nonce: 35, transfer: { to: PAYEE, amount: 1000000 } } },
  { name: 'auto_value_attached', kind: 'cosign', reqid: rid(36), fields: { ...cosignBase, value: 1, nonce: 36,
    transfer: { to: PAYEE, amount: 1000000 } } },
  // ---- a second device (minimal pairing): native terms with a lifetime cap, then a mandate without newPayeeNeedsHuman
  { name: 'mandate_native', kind: 'mandate', reqid: rid(40), fields: { ...mandateBase, salt: 40, agentId: 7,
    caveats: [pulseCaveat(0, { token: ZERO, perTxAutoCap: ONE_MON, periodAutoCap: '3000000000000000000', period: 0 })] } },
  { name: 'nat_send', kind: 'cosign', reqid: rid(41), fields: { ...cosignBase, delegationHash: '$dh:mandate_native',
    target: PAYEE, value: '500000000000000000', nonce: 41 } },
  { name: 'nat_zero_value', kind: 'cosign', reqid: rid(42), fields: { ...cosignBase, delegationHash: '$dh:mandate_native',
    target: PAYEE, value: 0, nonce: 42 } },
  { name: 'nat_erc20', kind: 'cosign', reqid: rid(43), fields: { ...cosignBase, delegationHash: '$dh:mandate_native',
    nonce: 43, transfer: { to: PAYEE, amount: 1000000 } } },
  { name: 'mandate_nohuman', kind: 'mandate', reqid: rid(44), fields: { ...mandateBase, salt: 44, agentId: 7,
    caveats: [pulseCaveat(0, { newPayeeNeedsHuman: false })] } },
  { name: 'nohuman_transfer', kind: 'cosign', reqid: rid(45), fields: { ...cosignBase, delegationHash: '$dh:mandate_nohuman',
    nonce: 45, transfer: { to: PAYEE, amount: 1000000 } } },
  { name: 'nat_send_forgotten', kind: 'cosign', reqid: rid(46), fields: { ...cosignBase, delegationHash: '$dh:mandate_native',
    target: PAYEE, value: '500000000000000000', nonce: 46 } },
];

// review line helpers (review.cpp texts)
const autoLines = (s) => (s.review ? s.review.lines : []).filter((l) => l.label === '' &&
  l.value.includes(' becomes an AUTO payee of this mandate'));
// the exact AUTO payee line (review.cpp review_cosign; caps with the token table of the mandate's asset)
const autoText = (payee, perTx, cap, periodText) => `${payee} becomes an AUTO payee of this mandate: the agent can then ` +
  `pay it without a pulse, up to ${perTx} per payment and ${cap}` +
  (periodText === null ? ' in total (lifetime cap)' : ` per ${periodText} window (fixed windows from the first AUTO spend)`);
const line = (s, label) => (s.review ? s.review.lines : []).find((l) => l.label === label);
const lines = (s, label) => (s.review ? s.review.lines : []).filter((l) => l.label === label);
const PANIC_LINE = 'this device signed a PANIC after this mandate: once that PANIC is relayed, the chain refuses it';
// the co-sign line for a mandate the device does not remember (review.cpp review_cosign, v1.2 review)
const mayLines = (s) => (s.review ? s.review.lines : []).filter((l) => l.label === '' &&
  l.value.includes(' may become an AUTO payee of mandate '));
const mayText = (payee, dh) => `${payee} may become an AUTO payee of mandate ${dh}: the agent could then pay it ` +
  'without a pulse, up to caps this device does not know';
function expectMay(emu, req, name, want) {
  return reviewOnly(emu, req, (s) => {
    const got = mayLines(s);
    if (want === null) check(`${name}: no 'may become an AUTO payee' line`, got.length === 0, got);
    else check(`${name}: exactly one 'may become an AUTO payee' line, in amber`, got.length === 1 && got[0].value === want &&
      got[0].tone === 'warn', { got, want });
  });
}
const panicFirst = (chain) => `PANIC FIRST: mandates signed on ${chain} (PulseCosignEnforcer ${ENFORCER}, vault ${VAULT}) ` +
  'would not be covered by PANIC after re-pairing. Sign a PANIC (home: hold 5 s) and relay it, then pair again';

const JOBS = []; // signed responses to verify with the oracle
const salt = (n) => n.toString(16).padStart(2, '0').repeat(16);
// zlib CRC-32 (context.cpp crc32), big-endian 4 bytes
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32be(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 255] ^ (c >>> 8);
  const out = Buffer.alloc(4);
  out.writeUInt32BE((c ^ 0xffffffff) >>> 0);
  return out;
}

// ------------------------------------------------------------------------------------------------ driving helpers
const TEST_OPTS = { test: true };

function scanRequest(emu, req, { multipart = false } = {}) {
  let s = emu.state();
  if (s.screen !== 'scan') s = emu.key('press');
  if (s.screen !== 'scan') throw new Error('not on SCAN: ' + s.screen);
  let r = null;
  for (const part of multipart ? req.parts : [req.ur]) r = emu.scan(part);
  return { r, s: emu.state() };
}

function pageToEnd(emu) {
  let s = emu.state();
  for (let i = 0; i < 60 && s.screen === 'review' && !s.review.allSeen; i++) s = emu.key('press');
  return s;
}

// on the last page of a pulse review: press -> PULSE, thumb on, wait for ARMED, (salt), press SIGN
function pulseAndSign(emu, saltHex) {
  let s = emu.key('press');
  check('review -> PULSE', s.screen === 'pulse', s.screen);
  emu.finger({ on: true, bpm: 72 });
  s = emu.tickUntil((x) => x.screen === 'armed', { maxMs: 20000, stepMs: 20 });
  check('pulse passes -> ARMED', s.screen === 'armed', s.pulse);
  if (saltHex) emu.injectTrng(saltHex);
  s = emu.key('press');
  check('SIGN -> QR', s.screen === 'qr' && s.qr && s.qr.signed, s.message || s.screen);
  emu.finger({ on: false });
  return s;
}

function done(emu) {
  const s = emu.key('press');
  check('done -> HOME', s.screen === 'home', s.screen);
  return s;
}

function expectRefusedReview(emu, req, prefix, { cosign = false, inspect = null } = {}) {
  scanRequest(emu, req);
  let s = emu.state();
  check(`${prefix}: review opened`, s.screen === 'review', s.screen);
  check(`${prefix}: policy refused`, s.review && s.review.ok === false, s.review && s.review.refusal);
  check(`${prefix}: refusal text`, s.review && s.review.refusal.startsWith(prefix), s.review && s.review.refusal);
  if (inspect) inspect(s);
  const first = s.display.rows[0] || {};
  check(`${prefix}: first line REFUSED in red`, first.label === 'REFUSED' && first.color === 'bad', first);
  s = pageToEnd(emu);
  check(`${prefix}: refused footer`, s.display.footer === (cosign ? 'REFUSED: press = home | 2s = DENY' : 'REFUSED: press = home'),
    s.display.footer);
  const sigs = s.signatures;
  s = emu.key('press');
  check(`${prefix}: press -> HOME, nothing signed, no pulse`, s.screen === 'home' && s.signatures === sigs && !s.pulse.sensorOn, s.screen);
  return s;
}

// scan a request, hand its review (as opened) to inspect(), then leave it without signing: hold 2 s cancels a review
// (on a co-sign review it opens the deny review first, whose hold 2 s cancels); a message is dismissed by a press
function reviewOnly(emu, req, inspect) {
  scanRequest(emu, req);
  const s = emu.state();
  const sigs = s.signatures;
  inspect(s);
  let x = emu.state();
  for (let i = 0; i < 4 && x.screen !== 'home'; i++) x = emu.key(x.screen === 'message' ? 'press' : 'hold2');
  check('review left without signing', x.screen === 'home' && x.signatures === sigs && !x.pulse.sensorOn, x.screen);
  return s;
}

// the review of a co-sign: exactly `want` AUTO payee lines (0 or the one text given)
function expectAuto(emu, req, name, want, { ok = true } = {}) {
  return reviewOnly(emu, req, (s) => {
    check(`${name}: review ${ok ? 'ok' : 'refused'}`, s.review && s.review.ok === ok, s.review && s.review.refusal);
    const got = autoLines(s);
    if (want === null) check(`${name}: no AUTO payee line`, got.length === 0, got);
    else check(`${name}: exactly one AUTO payee line, in amber`, got.length === 1 && got[0].value === want && got[0].tone === 'warn',
      { got, want });
  });
}

// ================================================================================================ main
const t0 = Date.now();
sect('requests from make_request.py build');
const REQ = oracle('build', SPECS);
check('all requests built', SPECS.every((sp) => REQ[sp.name] && REQ[sp.name].ur), Object.keys(REQ));
check('pair request is multipart', REQ.pair.parts.length >= 3, REQ.pair.parts.length);

sect('power-on (test mode)');
const emu = await RiparEmulator.create(TEST_OPTS);
let s = emu.state();
const FWID = createHash('sha256').update('ripar-emulator v1').digest('hex').slice(0, 16);
check('emulator flag', s.emulator === true && s.emulatorId === 'ripar-emulator v1');
check('firmware id = sha256("ripar-emulator v1")[:8]', s.firmwareId === FWID, s.firmwareId);
check('self-test passed', s.selftest.passed && /SELFTEST PASS/.test(s.selftest.report));
check('K1 = demo K1', s.k1 === DEMO_K1, s.k1);
check('P1 = demo P1', s.p1 === DEMO_P1);
check('HOME, NOT PAIRED', s.screen === 'home' && s.display.kind === 'home' && s.display.badge === 'NOT PAIRED', s.display);
check('k1Short on HOME', s.display.k1Short === '0x7534...24Eb', s.display.k1Short);
{
  const indep = oracle('vault', [DEMO_K1])[DEMO_K1];
  check('state().vault = the vault derived from K1 (make_request.py vault_address, independently)', s.vault === VAULT &&
    indep === VAULT, { emulator: s.vault, makeRequest: indep, want: VAULT });
  check('serial log names K1 and its vault', s.serial.includes(`ripar: K1 ${DEMO_K1}, vault ${VAULT}, not paired`), s.serial);
  const c = emu.exportContext();
  check('context layout v3, 256 bytes, v3 fields exported', c.version === 3 && c.hex.length === 512 &&
    c.unpanickedMandates === false && c.newPayeeNeedsHuman === false && c.pulseToken === ZERO && c.perTxAutoCap === '0' &&
    c.periodAutoCap === '0' && c.period === 0, c);
}

sect('key semantics on HOME');
s = emu.hold(1500);
check('release between 1 s and 2 s does nothing', s.screen === 'home', s.screen);
s = emu.key('press');
check('press -> SCAN', s.screen === 'scan' && s.scan.active && s.display.kind === 'scan', s.screen);
s = emu.key('hold2');
check('hold 2 s on SCAN = cancel -> HOME', s.screen === 'home', s.screen);
s = emu.key('hold5');
check('unpaired PANIC is refused', s.screen === 'message' && s.message.title === 'PANIC REFUSED' && /NOT PAIRED/.test(s.message.body), s.message);
s = done(emu);
check('camera off outside SCAN', emu.scan(REQ.pair.ur).result === 'camera-off');

sect('refusal: unpaired co-sign');
expectRefusedReview(emu, REQ.cosign_erc20, 'NOT PAIRED', { cosign: true });
scanRequest(emu, REQ.cosign_erc20);
pageToEnd(emu);
s = emu.key('hold2');
check('deny from an unpaired co-sign is not possible', s.screen === 'message' && s.message.title === 'DENY NOT POSSIBLE', s.message);
done(emu);

sect('pairing refusals (v1.2): only the compiled-in contracts and the vault derived from K1');
{
  const fwErr = (what, key, given, contract, fw) => `WRONG ${what}: key ${key} = ${given} is not the ${contract} this firmware ` +
    `pins on Monad testnet (10143): ${fw}`;
  expectRefusedReview(emu, REQ.pair_wrong_vault, "VAULT IS NOT THIS DEVICE'S VAULT", { inspect: (x) => {
    check('wrong key 8: exact refusal', x.review.refusal === `VAULT IS NOT THIS DEVICE'S VAULT: key 8 = ${OTHER_VAULT}, but this ` +
      `device's K1 ${DEMO_K1} owns the vault ${VAULT} (MetaMask SimpleFactory CREATE2, salt 0; leave key 8 out to pin it)`,
    x.review.refusal);
    const v = line(x, 'Vault');
    check('wrong key 8: the derived vault in green', v && v.value === `${VAULT} (derived from this device)` && v.tone === 'good', v);
    const k8 = line(x, 'Key 8 vault');
    check('wrong key 8: key 8 in red', k8 && k8.value === `${OTHER_VAULT} (NOT THIS DEVICE'S VAULT)` && k8.tone === 'bad', k8);
  } });
  expectRefusedReview(emu, REQ.pair_wrong_registry, 'WRONG REGISTRY', { inspect: (x) => check('wrong registry: exact refusal',
    x.review.refusal === fwErr('REGISTRY', 3, OTHER_REGISTRY, 'RiparDeviceRegistry', REGISTRY), x.review.refusal) });
  expectRefusedReview(emu, REQ.pair_wrong_manager, 'WRONG DELEGATION MANAGER', { inspect: (x) => check('wrong manager: exact refusal',
    x.review.refusal === fwErr('DELEGATION MANAGER', 4, OTHER_MANAGER, 'MetaMask DelegationManager', DM), x.review.refusal) });
  expectRefusedReview(emu, REQ.pair_wrong_enforcer, 'WRONG PULSE CO-SIGN ENFORCER', { inspect: (x) => check(
    'wrong enforcer: exact refusal', x.review.refusal === fwErr('PULSE CO-SIGN ENFORCER', 5, OTHER_ENFORCER, 'PulseCosignEnforcer',
      ENFORCER), x.review.refusal) });
  expectRefusedReview(emu, REQ.pair_wrong_relay, 'WRONG REPUTATION RELAY', { inspect: (x) => check('wrong relay: exact refusal',
    x.review.refusal === fwErr('REPUTATION RELAY', 7, OTHER_RELAY, 'RiparReputationRelay', RELAY), x.review.refusal) });
  check('nothing pinned by a refused pairing', !emu.state().paired && emu.state().store.saves === 0, emu.state().context);
}

sect('pairing (multipart scan) -> BindDevice');
{
  emu.key('press');
  const n = REQ.pair.parts.length;
  let r;
  for (let i = 0; i < n; i++) {
    r = emu.scan(REQ.pair.parts[i]);
    if (i < n - 1) check(`part ${i + 1}/${n} accepted`, r.result === 'accepted' && r.seqLen === n && r.received === i + 1, r);
  }
  check('last part completes the UR', r.result === 'complete' && r.screen === 'review', r);
  s = emu.state();
  check('PAIR DEVICE review', s.review.title === 'PAIR DEVICE' && s.review.ok && s.job === 'pair', s.review.refusal);
  {
    const want = { Registry: `${REGISTRY} (firmware table)`, Manager: `${DM} (MetaMask v1.3.0)`,
      'Co-sign': `${ENFORCER} (firmware table)`, Relay: `${RELAY} (firmware table)`, Vault: `${VAULT} (derived from this device)` };
    for (const [label, value] of Object.entries(want)) {
      const l = line(s, label);
      check(`pair review: ${label} = ${value}, green`, l && l.value === value && l.tone === 'good', l);
    }
    check('pair review: no key 8 line (key 8 absent)', !line(s, 'Key 8 vault'), s.review.lines);
  }
  check('9 visible rows, paged', s.display.rowsShown === 9 && s.display.totalRows > 9 && s.display.moreBelow, s.display);
  check('footer = more while rows are hidden', s.display.footer === 'press = more | hold 2s = cancel', s.display.footer);
  const firsts = [s.display.firstRow];
  while (!s.review.allSeen) {
    s = emu.key('press');
    firsts.push(s.display.firstRow);
  }
  const total = s.display.totalRows;
  const want = [];
  for (let f = 0; ; f += 8) {
    const c = Math.min(f, total - 9);
    want.push(c);
    if (c + 9 >= total) break;
  }
  check('pages move by 8 rows (1 overlap), last page clamped', JSON.stringify(firsts) === JSON.stringify(want), { firsts, want });
  check('last page footer', s.display.footer === 'press = PULSE + SIGN | 2s = cancel', s.display.footer);
  s = emu.key('press');
  check('PULSE screen, sensor on', s.screen === 'pulse' && s.pulse.sensorOn && s.display.kind === 'pulse', s.screen);
  s = emu.key('press');
  check('press while measuring is ignored', s.screen === 'pulse', s.screen);
  emu.finger({ on: true, bpm: 72 });
  s = emu.tickUntil((x) => x.screen === 'armed', { maxMs: 20000, stepMs: 20 });
  check('ARMED after a live pulse', s.screen === 'armed' && s.pulse.passed && s.pulse.beats >= 5, s.pulse);
  check('ARMED title', s.display.title === 'ARMED: press SIGN (PAIR DEVICE)', s.display.title);
  check('pulse bpm near 72', Math.abs(s.pulse.bpm - 72) < 10, s.pulse.bpm);
  s = emu.key('press');
  check('PAIRED QR', s.screen === 'qr' && s.qr.title === 'PAIRED' && s.qr.text.startsWith('UR:RIPAR-PAIR/'), s.message || s.qr);
  check('context pinned + saved', s.paired && s.context.pulseCosignEnforcer === ENFORCER && s.context.vault === VAULT &&
    s.context.notBefore === String(NOW) && s.store.saves === 1, s.context);
  check('pinned: compiled-in contracts, the derived vault (no key 8 sent), no PANIC FIRST flag', s.context.registry === REGISTRY &&
    s.context.delegationManager === DM && s.context.relay === RELAY && s.context.sentinel === SENTINEL &&
    s.context.vault === s.vault && !s.context.unpanickedMandates, s.context);
  check('QR version / ECC reported', s.qr.fits && s.qr.version >= 1 && (s.qr.ecc === 'M' || s.qr.ecc === 'L'), s.qr);
  var PAIR_UR = s.qr.text;
  JOBS.push({ name: 'pair', kind: 'pair', resp: PAIR_UR, req: REQ.pair.ur });
  emu.finger({ on: false });
  s = done(emu);
  check('HOME shows PAIRED', s.display.badge === 'PAIRED', s.display);
}

sect('pairing QR (keys only) and the device menu');
s = emu.key('hold2');
check('hold 2 s + release on HOME -> keys-only pairing QR', s.screen === 'pairQr' && s.qr && !s.qr.signed &&
  s.qr.title === 'PAIR: keys only (nothing pinned)', s.screen);
JOBS.push({ name: 'pair-keys', kind: 'pair-keys', resp: s.qr.text });
s = emu.key('hold2');
check('hold 2 s on the pairing QR -> menu', s.screen === 'menu' && s.menu.index === 0 && s.display.title === 'DEVICE ACTIONS', s.screen);
s = emu.key('press');
check('press = next item', s.menu.index === 1 && s.display.rows[1].value === '> REOPEN the agent lane', s.display.rows);
s = emu.key('press');
s = emu.key('hold2');
check('BACK -> HOME', s.screen === 'home', s.screen);

sect('mandate refusal: no pulse co-sign caveat');
expectRefusedReview(emu, REQ.mandate_nopulse, 'MANDATE WITHOUT PULSE CO-SIGN');

sect("mandate refusal: a delegator that is not this device's vault");
expectRefusedReview(emu, REQ.mandate_other_vault, "NOT THIS DEVICE'S VAULT", { inspect: (x) => {
  check('exact refusal', x.review.refusal === `NOT THIS DEVICE'S VAULT: delegator ${OTHER_VAULT} is not the vault ${VAULT} ` +
    "derived from this device's K1", x.review.refusal);
  const v = line(x, 'Vault');
  check('vault line in red, not marked derived', v && v.value === OTHER_VAULT && v.tone === 'bad', v);
} });

sect('mandate (K1 signs the delegation)');
scanRequest(emu, REQ.mandate_ok, { multipart: true });
s = emu.state();
check('SIGN MANDATE review ok', s.review.title === 'SIGN MANDATE' && s.review.ok, s.review.refusal);
{
  const want = { 'Agent id': ['42 (companion)', 'normal'], Vault: [`${VAULT} (derived from this device)`, 'good'],
    Period: ['86400 s = 1 d (fixed windows from the first AUTO spend)', 'normal'], 'Auto per tx': ['5 AUSD', 'normal'],
    'Auto per period': ['20 AUSD', 'normal'], 'New payees': ['need a pulse co-sign', 'good'], Enforcer: [ENFORCER, 'dim'] };
  for (const [label, [value, tone]] of Object.entries(want)) {
    const l = line(s, label);
    check(`mandate review: ${label} = ${value}`, l && l.value === value && l.tone === tone, l);
  }
}
pageToEnd(emu);
s = pulseAndSign(emu);
check('MANDATE SIGNED eth-signature', s.qr.title === 'MANDATE SIGNED' && s.qr.text.startsWith('UR:ETH-SIGNATURE/'), s.qr);
check('lastDelegationHash + agent remembered', s.context.lastDelegationHash !== null && s.context.agentId === '42' &&
  s.context.hasAgentId, s.context);
check('its pulse terms remembered + PANIC FIRST flag set (context v3)', s.context.pulseToken === AUSD &&
  s.context.perTxAutoCap === '5000000' && s.context.periodAutoCap === '20000000' && s.context.period === 86400 &&
  s.context.newPayeeNeedsHuman === true && s.context.unpanickedMandates === true, s.context);
const MANDATE_DH = s.context.lastDelegationHash;
JOBS.push({ name: 'mandate', kind: 'mandate', resp: s.qr.text, req: REQ.mandate_ok.ur, pair: PAIR_UR, expectDh: MANDATE_DH });
done(emu);

sect('re-pairing to another chain while the mandate may be live: PANIC FIRST');
expectRefusedReview(emu, REQ.repair_143, 'PANIC FIRST', { inspect: (x) => {
  check('exact refusal', x.review.refusal === panicFirst('Monad testnet (10143)'), x.review.refusal);
  const f = lines(x, 'CHANGES').find((l) => l.value.startsWith('FORGETS mandate'));
  check('CHANGES: FORGETS mandate ... (still live: PANIC first), red', f && f.value === `FORGETS mandate ${MANDATE_DH} (still live: ` +
    'PANIC first)' && f.tone === 'bad', lines(x, 'CHANGES'));
} });
sect('a re-pairing that names another enforcer: refused by the firmware table (before PANIC FIRST)');
expectRefusedReview(emu, REQ.pair_wrong_enforcer, 'WRONG PULSE CO-SIGN ENFORCER');

sect('co-sign refusals');
expectRefusedReview(emu, REQ.cosign_wrong_chain, 'WRONG CHAIN', { cosign: true });
expectRefusedReview(emu, REQ.cosign_unknown_calldata, 'UNKNOWN CALLDATA', { cosign: true });
expectRefusedReview(emu, REQ.cosign_expiry_far, 'EXPIRY TOO FAR', { cosign: true });
expectRefusedReview(emu, REQ.cosign_other_vault, "NOT THIS DEVICE'S VAULT", { cosign: true, inspect: (x) => {
  check('exact refusal', x.review.refusal === `NOT THIS DEVICE'S VAULT: delegator ${OTHER_VAULT} is not the vault ${VAULT} ` +
    "derived from this device's K1", x.review.refusal);
  // v1.2 review: a refused co-sign signs nothing, so it whitelists nothing - no AUTO payee line of either kind
  check('refused co-sign: no AUTO payee line', autoLines(x).length === 0 && mayLines(x).length === 0, x.review.lines);
} });

sect("co-sign 'becomes an AUTO payee' line: exactly the PulseCosignEnforcer v1.2 predicate (token terms)");
{
  const AUSD_AUTO = (payee) => autoText(payee, '5 AUSD', '20 AUSD', '86400 s = 1 d');
  expectAuto(emu, REQ.cosign_erc20, 'transfer of the mandate token to a payee', AUSD_AUTO(PAYEE));
  expectAuto(emu, REQ.cosign_for_deny, 'transfer to another payee', AUSD_AUTO(DEAD));
  expectAuto(emu, REQ.cosign_native, 'native send (not the mandate asset)', null);
  expectAuto(emu, REQ.auto_approve, 'approve', null);
  expectAuto(emu, REQ.auto_transfer_from, 'transferFrom', null);
  expectAuto(emu, REQ.auto_zero_amount, 'transfer of 0', null);
  expectAuto(emu, REQ.auto_zero_payee, 'transfer to the zero address', null);
  expectAuto(emu, REQ.auto_unknown_mandate, 'UNKNOWN MANDATE', null);
  expectMay(emu, REQ.auto_unknown_mandate, 'UNKNOWN MANDATE (transfer of 1 AUSD)', mayText(PAYEE, '0x' + '11'.repeat(32)));
  expectMay(emu, REQ.cosign_erc20, 'the remembered mandate', null);
  expectMay(emu, REQ.auto_value_attached, 'refused (native value on an ERC-20 call)', null);
  expectAuto(emu, REQ.auto_value_attached, 'ERC-20 call with native value (refused)', null, { ok: false });
  reviewOnly(emu, REQ.auto_musd, (x) => {
    check('MockUSD (another token): review ok, no AUTO payee line', x.review.ok && autoLines(x).length === 0, x.review);
    const a = line(x, 'Amount');
    const t = line(x, 'Token');
    check('MockUSD from the v1.2 token table: 1.234567 mUSD', a && a.value === '1.234567 mUSD' && t &&
      t.value === 'mUSD - MockUSD (Ripar demo)' && t.tone === 'good', { a, t });
  });
  reviewOnly(emu, REQ.cosign_erc20, (x) => {
    const v = line(x, 'Vault');
    check('co-sign vault line: derived from this device, green', v && v.value === `${VAULT} (derived from this device)` &&
      v.tone === 'good', v);
    check('no panic line while the mandate is unpanicked', !x.review.lines.some((l) => l.value === PANIC_LINE));
    const i = x.review.lines.findIndex((l) => l.label === 'Mandate');
    check('the AUTO payee line follows the Mandate line', i >= 0 && autoLines(x)[0] === x.review.lines[i + 1], x.review.lines);
  });
}

sect('co-sign: ERC-20 transfer (P1 HumanApproval, presenceHash of the evidence + salt)');
scanRequest(emu, REQ.cosign_erc20);
s = emu.state();
check('CO-SIGN PAYMENT review ok', s.review.title === 'CO-SIGN PAYMENT' && s.review.ok, s.review.refusal);
check('amount shown with the token table', s.review.lines.some((l) => /25 AUSD/.test(l.value)), s.review.lines);
pageToEnd(emu);
s = pulseAndSign(emu, salt(0xa1));
check('CO-SIGNED', s.qr.title === 'CO-SIGNED' && s.qr.text.startsWith('UR:RIPAR-COSIGN/'), s.qr);
check('device time advanced to the expiry', s.context.notBefore === String(EXP), s.context.notBefore);
JOBS.push({ name: 'cosign_erc20', kind: 'cosign', resp: s.qr.text, req: REQ.cosign_erc20.ur, pair: PAIR_UR, salt: salt(0xa1) });
done(emu);

sect('co-sign: native transfer');
scanRequest(emu, REQ.cosign_native);
s = emu.state();
check('native review ok', s.review.ok && s.review.lines.some((l) => /1\.5 MON/.test(l.value)), s.review.refusal || s.review.lines);
pageToEnd(emu);
s = pulseAndSign(emu, salt(0xa2));
JOBS.push({ name: 'cosign_native', kind: 'cosign', resp: s.qr.text, req: REQ.cosign_native.ur, pair: PAIR_UR, salt: salt(0xa2) });
done(emu);

sect('deny built on the device from a co-sign review (hold 2 s, no pulse)');
scanRequest(emu, REQ.cosign_for_deny);
s = emu.key('hold2');
check('DENY review (built by the device)', s.screen === 'review' && s.job === 'deny' && s.review.title === 'DENY + REPORT AGENT' &&
  s.review.ok, s.review);
s = pageToEnd(emu);
check('deny footer: no pulse', s.display.footer === 'press = SIGN (no pulse) | 2s = cancel', s.display.footer);
emu.injectTrng(salt(0xb1));
s = emu.key('press');
check('DENY SIGNED without pulse', s.screen === 'qr' && s.qr.title === 'DENY SIGNED (agent 42)' && !s.pulse.sensorOn, s.qr || s.message);
JOBS.push({ name: 'deny_from_cosign', kind: 'deny-from-cosign', resp: s.qr.text, req: REQ.cosign_for_deny.ur, pair: PAIR_UR,
  chain: CHAIN, contract: RELAY, relay: RELAY, agentId: AGENT_ID, salt: salt(0xb1), zeroEvidence: true });
done(emu);

sect('companion deny request');
expectRefusedReview(emu, REQ.deny_req_wrong_agent, 'NOT THE PINNED AGENT');
scanRequest(emu, REQ.deny_req);
s = pageToEnd(emu);
check('deny-req review ok', s.review.ok && s.job === 'deny', s.review.refusal);
emu.injectTrng(salt(0xb2));
s = emu.key('press');
check('deny-req signed', s.screen === 'qr' && s.qr.text.startsWith('UR:RIPAR-DENY/'), s.message);
JOBS.push({ name: 'deny_req', kind: 'deny', resp: s.qr.text, req: REQ.deny_req.ur, pair: PAIR_UR, salt: salt(0xb2), zeroEvidence: true });
done(emu);

sect('Privy authorization (P1, DER)');
scanRequest(emu, REQ.privy);
s = emu.state();
check('PRIVY AUTHORIZATION review ok', s.review.title === 'PRIVY AUTHORIZATION' && s.review.ok, s.review.refusal);
pageToEnd(emu);
s = pulseAndSign(emu);
check('PRIVY REQUEST SIGNED', s.qr.title === 'PRIVY REQUEST SIGNED' && s.qr.text.startsWith('UR:RIPAR-DER-SIG/'), s.qr);
JOBS.push({ name: 'privy', kind: 'privy', resp: s.qr.text, req: REQ.privy.ur, pair: PAIR_UR });
done(emu);

sect('key semantics: a press belongs to the screen it began on');
{
  let sigs = emu.state().signatures;
  const epoch = emu.state().context.minEpoch;
  emu.key('press'); // SCAN
  emu.keyDown();
  s = emu.tick(2100);
  check('hold on SCAN cancels at 2 s', s.screen === 'home', s.screen);
  s = emu.tick(4000);
  check('... and never panics at 5 s+ on HOME', s.screen === 'home' && s.signatures === sigs && s.context.minEpoch === epoch, s.screen);
  emu.keyUp();
  s = emu.tick(60);
  check('... nor does its release do anything', s.screen === 'home', s.screen);

  scanRequest(emu, REQ.mandate_ok); // a review; hold -> cancel at 2 s, then on to 6 s
  emu.keyDown();
  s = emu.tick(6000);
  emu.keyUp();
  s = emu.tick(60);
  check('a cancel-hold on a review that reaches 5 s on HOME never panics', s.screen === 'home' && s.signatures === sigs &&
    s.context.minEpoch === epoch, s.screen);

  emu.key('press'); // SCAN, then the co-sign arrives while the key is held
  emu.keyDown();
  s = emu.tick(300);
  emu.scan(REQ.cosign_for_deny.ur);
  s = emu.tick(2500);
  check('a hold carried into a co-sign review never files a deny', s.screen === 'review' && s.job === 'cosign' && s.review.row === 0,
    s.job);
  emu.keyUp();
  s = emu.tick(60);
  s = emu.key('press');
  check('... and a fresh press pages the review', s.screen === 'review' && s.review.row > 0, s.review.row);
  s = emu.hold(1500);
  check('release between 1 s and 2 s on a review does nothing', s.screen === 'review' && s.job === 'cosign', s.screen);
  s = emu.key('hold2');
  check('hold 2 s on the co-sign review = DENY review', s.job === 'deny', s.job);
  s = emu.key('hold2');
  check('hold 2 s on the deny review = cancel', s.screen === 'home' && s.signatures === sigs, s.screen);
}

sect('pulse gate: spoofs, lifted thumb, timeouts');
{
  scanRequest(emu, REQ.cosign_erc20);
  pageToEnd(emu);
  s = emu.key('press');
  emu.finger({ on: true, bpm: 66, shape: 'square' });
  s = emu.tickUntil((x) => x.screen === 'armed', { maxMs: 15000, stepMs: 20 });
  check('square-wave spoof never arms SIGN', s.screen === 'pulse' && s.pulse.finger && !s.pulse.passed, s.pulse);
  emu.finger({ on: false });
  emu.tick(500);
  emu.finger({ on: true, bpm: 72, shape: 'sine' });
  s = emu.tickUntil((x) => x.screen === 'armed', { maxMs: 15000, stepMs: 20 });
  check('sine spoof (too regular) never arms SIGN', s.screen === 'pulse' && s.pulse.finger && s.pulse.beats >= 5, s.pulse);
  emu.finger({ on: false });
  s = emu.tick(1000);
  emu.finger({ on: true, bpm: 80, shape: 'ppg' });
  s = emu.tickUntil((x) => x.screen === 'armed', { maxMs: 20000, stepMs: 20 });
  check('a real-shaped pulse arms SIGN', s.screen === 'armed', s.pulse);
  emu.finger({ on: false });
  s = emu.tick(500);
  check('thumb lifted: ARMED -> PULSE (never signs)', s.screen === 'pulse' && !s.pulse.passed, s.screen);
  const errs = s.buzz.err;
  s = emu.tick(120000);
  check('120 s without a key: PULSE -> HOME (timeout, error beep)', s.screen === 'home' && s.buzz.err === errs + 1 && !s.pulse.sensorOn,
    s.screen);
  emu.key('press');
  s = emu.tick(119000);
  check('SCAN stays before 120 s', s.screen === 'scan', s.screen);
  s = emu.tick(1100);
  check('SCAN times out after 120 s', s.screen === 'home', s.screen);
  scanRequest(emu, REQ.privy);
  s = emu.tick(121000);
  check('REVIEW times out after 120 s', s.screen === 'home', s.screen);
  s = emu.tick(300000);
  check('HOME never times out', s.screen === 'home', s.screen);
}

sect('a SIGN press that began on PULSE never signs (deterministic replay)');
{
  // two identical emulators driven identically reach ARMED at the same millisecond
  const drive = async () => {
    const e = await RiparEmulator.create(TEST_OPTS);
    e.key('press');
    e.scan(REQ.pair.ur);
    for (let i = 0; i < 40 && !e.state().review.allSeen; i++) e.key('press');
    e.key('press');
    e.finger({ on: true, bpm: 72 });
    return e;
  };
  const a = await drive();
  const tStartA = a.state().nowMs;
  const sa = a.tickUntil((x) => x.screen === 'armed', { maxMs: 20000, stepMs: 5 });
  const tArmed = sa.nowMs;
  check('the ARMED frame is being pushed to the LCD (31 ms)', sa.app.busy && sa.app.busyUntilMs === tArmed + 31 &&
    sa.display.drawnAtMs === tArmed, sa.app);
  a.destroy();
  // 300 ms before: debounced on PULSE, swallowed by the drain on the screen change. 20 / 5 ms before: still inside the
  // 30 ms debounce when ARMED is drawn (FsmIn::keyDown false), stable by the time the 31 ms frame push is done; the
  // post-draw drain swallows it (flows.cpp app_loop, io.cpp io_flush)
  for (const lead of [300, 20, 5]) {
    const b = await drive();
    check(`lead ${lead}: replay starts at the same millisecond`, b.state().nowMs === tStartA, { a: tStartA, b: b.state().nowMs });
    b.tick(tArmed - lead - b.state().nowMs);
    check(`lead ${lead}: still measuring before the press`, b.state().screen === 'pulse', b.state().screen);
    b.keyDown();
    let sb = b.tick(lead + 200); // ARMED appears while the key is down
    check(`lead ${lead}: ARMED appeared during the press`, sb.screen === 'armed' && sb.keyDown, sb.screen);
    b.keyUp();
    sb = b.tick(100);
    check(`lead ${lead}: its release (< 1 s) does not sign`, sb.screen === 'armed' && sb.signatures === 0, sb.screen);
    if (lead === 300) {
      sb = b.key('press');
      check('a press that begins on ARMED signs', sb.screen === 'qr' && sb.qr.title === 'PAIRED', sb.screen);
    }
    b.destroy();
  }
  // a press that begins right after the ARMED pass (its frame still being pushed) belongs to ARMED
  const c = await drive();
  let sc = c.tick(tArmed - c.state().nowMs);
  check('ARMED at the same millisecond in the replay', sc.screen === 'armed' && sc.app.busy, sc.screen);
  sc = c.key('press');
  check('a press that begins as ARMED is drawn signs', sc.screen === 'qr' && sc.qr.title === 'PAIRED', sc.screen);
  c.destroy();
}

sect('camera handoff: an identical QR is delivered at most once per second (qrscan.cpp)');
{
  const BAD1 = 'UR:RIPAR-PAIR-REQ/LPADAXAEAEAE';
  const BAD2 = 'UR:RIPAR-COSIGN-REQ/LPADAXAEAEAE';
  s = emu.key('press');
  check('on SCAN', s.screen === 'scan', s.screen);
  const err0 = s.buzz.err;
  let r = emu.scan(BAD1);
  check('first decode is delivered (bad QR part, error beep)', r.result === 'error' && emu.state().buzz.err === err0 + 1, r);
  const hint = r.hint;
  r = emu.scan(BAD1);
  check('the same payload again at once is not delivered (no second beep)', r.result === 'repeat' && r.hint === hint &&
    emu.state().buzz.err === err0 + 1, r);
  emu.tick(500);
  check('... nor 0.5 s later', emu.scan(BAD1).result === 'repeat');
  r = emu.scan(BAD2);
  check('a different payload is delivered at once', r.result === 'error' && emu.state().buzz.err === err0 + 2, r);
  r = emu.scan(BAD1);
  check('the filter only holds the payload delivered last', r.result === 'error' && emu.state().buzz.err === err0 + 3, r);
  emu.tick(1000);
  r = emu.scan(BAD1);
  check('after 1 s the same payload is delivered again', r.result === 'error' && emu.state().buzz.err === err0 + 4, r);
  check('an empty payload is ignored', emu.scan('').result === 'empty' && emu.state().buzz.err === err0 + 4);
  // a hold that began on SCAN cancels it at 2 s; BAD1 delivered just before; SCAN again 0.5 s later: qrscan_start()
  // restarts the filter, so the same payload is delivered at once
  emu.keyDown();
  emu.tick(1800);
  r = emu.scan(BAD1);
  check('delivered during the cancel hold', r.result === 'error', r);
  s = emu.tick(300);
  check('... the hold cancels SCAN', s.screen === 'home', s.screen);
  emu.keyUp();
  emu.tick(60);
  s = emu.key('press');
  r = emu.scan(BAD1);
  check('back on SCAN within 1 s: the same payload is delivered at once (the filter restarts with the camera)',
    s.screen === 'scan' && r.result === 'error', r);
  r = emu.scan(REQ.mandate_ok.parts[0]);
  check('multipart part 1 accepted', r.result === 'accepted' && r.received === 1, r);
  r = emu.scan(REQ.mandate_ok.parts[0]);
  check('the same part again within 1 s is not re-delivered', r.result === 'repeat' && r.received === 1, r);
  s = emu.key('hold2');
  check('cancel -> HOME', s.screen === 'home', s.screen);
}

sect('revoke (device menu, pulse)');
emu.key('hold2'); // pairing QR
emu.key('hold2'); // menu
s = emu.key('hold2'); // select REVOKE
check('REVOKE MANDATE review', s.screen === 'review' && s.job === 'revoke' && s.review.ok, s.review);
pageToEnd(emu);
s = pulseAndSign(emu);
check('REVOKE SIGNED', s.qr.title === 'REVOKE SIGNED' && s.qr.text.startsWith('UR:RIPAR-REVOKE/'), s.qr);
check('the revoked mandate is forgotten', s.context.lastDelegationHash === null && s.context.agentId === '42', s.context);
check('... with its pulse terms; the PANIC FIRST flag stays set', s.context.pulseToken === ZERO && s.context.perTxAutoCap === '0' &&
  s.context.periodAutoCap === '0' && s.context.period === 0 && !s.context.newPayeeNeedsHuman && s.context.unpanickedMandates, s.context);
JOBS.push({ name: 'revoke', kind: 'revoke', resp: s.qr.text, pair: PAIR_UR, chain: CHAIN, contract: ENFORCER, delegationHash: MANDATE_DH });
done(emu);

sect('a revoke does not unlock a chain change (PANIC FIRST)');
expectRefusedReview(emu, REQ.repair_143, 'PANIC FIRST', { inspect: (x) => {
  check('exact refusal', x.review.refusal === panicFirst('Monad testnet (10143)'), x.review.refusal);
  check('no FORGETS line (the revoked mandate is no longer remembered)',
    !lines(x, 'CHANGES').some((l) => l.value.startsWith('FORGETS')), lines(x, 'CHANGES'));
} });
expectAuto(emu, REQ.cosign_erc20, 'co-sign for the revoked mandate (UNKNOWN MANDATE)', null);
expectMay(emu, REQ.cosign_erc20, 'co-sign for the revoked (maybe unrelayed) mandate', mayText(PAYEE, MANDATE_DH));

sect('PANIC (hold 5 s on HOME, no pulse)');
s = emu.key('hold5');
check('PANIC QR', s.screen === 'qr' && s.qr.title === 'PANIC: min epoch 1' && s.qr.text.startsWith('UR:RIPAR-PANIC/'), s.qr || s.message);
check('min epoch 1 stored', s.context.minEpoch === '1' && !s.pulse.sensorOn, s.context);
check('the panic clears the PANIC FIRST flag (saved)', s.context.unpanickedMandates === false &&
  emu.exportContext().stored === emu.exportContext().hex, s.context);
JOBS.push({ name: 'panic1', kind: 'panic', resp: s.qr.text, pair: PAIR_UR, chain: CHAIN, contract: ENFORCER, epoch: 1 });
done(emu);

sect('after the panic a chain change may be paired (reviewed, not signed here)');
reviewOnly(emu, REQ.repair_143, (x) => {
  check('repair to 143: review ok', x.review.ok, x.review.refusal);
  const ch = lines(x, 'CHANGES').map((l) => l.value);
  check('CHANGES: chain and relay (the one compiled in for 143), nothing forgotten',
    ch.includes('Chain: Monad testnet (10143) -> Monad (143)') && ch.includes(`Relay: ${RELAY} -> ${RELAY_143}`) &&
    !ch.some((v) => v.startsWith('FORGETS')), ch);
  const r = line(x, 'Relay');
  check('143 relay from the firmware table, green', r && r.value === `${RELAY_143} (firmware table)` && r.tone === 'good', r);
  const pl = line(x, 'PANIC');
  check('the chain move after a panic: red PANIC line (the device cannot see whether it was relayed)', pl &&
    pl.tone === 'bad' && pl.value === `mandates signed on Monad testnet (10143) die only once this device's PANIC (min ` +
    'epoch 1) is relayed there - this device cannot check that. Confirm only if the on-chain min epoch of this device ' +
    'key is >= 1', pl);
  const v = line(x, 'Vault');
  check('same derived vault on 143', v && v.value === `${VAULT} (derived from this device)`, v);
});
check('... still paired to 10143', emu.state().context.chainId === String(CHAIN), emu.state().context);

sect('mandate refusal: stale epoch after the panic');
expectRefusedReview(emu, REQ.mandate_stale, 'RULE 1: STALE EPOCH 0');

sect('reopen (device menu, pulse)');
emu.key('hold2');
emu.key('hold2');
emu.key('press'); // REOPEN
s = emu.key('hold2');
check('REOPEN review', s.screen === 'review' && s.job === 'reopen' && s.review.ok, s.review);
pageToEnd(emu);
s = pulseAndSign(emu);
check('REOPEN SIGNED (nonce 1)', s.qr.title === 'REOPEN SIGNED (nonce 1)' && s.context.reopenNonce === '1', s.qr);
JOBS.push({ name: 'reopen', kind: 'reopen', resp: s.qr.text, pair: PAIR_UR, chain: CHAIN, contract: SENTINEL, vault: VAULT, nonce: 1 });
done(emu);

sect('mandate at the new panic floor (epoch 1)');
scanRequest(emu, REQ.mandate_epoch1);
s = pageToEnd(emu);
check('epoch 1 mandate allowed after PANIC(1)', s.review.ok, s.review.refusal);
s = pulseAndSign(emu);
const MANDATE1_DH = s.context.lastDelegationHash;
check('a mandate after the panic sets the PANIC FIRST flag again', s.context.unpanickedMandates === true, s.context);
JOBS.push({ name: 'mandate_epoch1', kind: 'mandate', resp: s.qr.text, req: REQ.mandate_epoch1.ur, pair: PAIR_UR, expectDh: MANDATE1_DH });
done(emu);

sect('Save rules when NVS fails (respond.h Save)');
{
  emu.setNvsFail(true);
  const before = emu.state();
  scanRequest(emu, REQ.repair_same);
  s = emu.state();
  check('key 8 = the derived vault: accepted, no key 8 line', s.review.ok && !line(s, 'Key 8 vault') &&
    line(s, 'Vault').value === `${VAULT} (derived from this device)`, s.review.refusal || s.review.lines);
  check('... no pinned contract changes', s.review.lines.some((l) => l.value === 'no pinned contract changes'), s.review.lines);
  s = pageToEnd(emu);
  check('re-pairing that keeps the mandate scope is allowed (while unpanicked)', s.review.ok, s.review.refusal);
  emu.key('press');
  emu.finger({ on: true, bpm: 72 });
  emu.tickUntil((x) => x.screen === 'armed', { maxMs: 20000, stepMs: 20 });
  s = emu.key('press');
  emu.finger({ on: false });
  check('Required: pairing withheld', s.screen === 'message' && s.message.title === 'NOT SIGNED' &&
    /signature withheld/.test(s.message.body) && s.signatures === before.signatures, s.message);
  check('... and the context is unchanged', s.context.notBefore === before.context.notBefore, s.context);
  done(emu);

  scanRequest(emu, REQ.cosign_later);
  s = pageToEnd(emu);
  check('co-sign 2 days ahead allowed', s.review.ok, s.review.refusal);
  s = pulseAndSign(emu, salt(0xa3));
  check('BestEffort: co-sign still shown, normal footer', s.qr.title === 'CO-SIGNED' &&
    s.qr.footer === 'Scan this with the companion. press = done', s.qr);
  check('... RAM keeps the OLD device time (stricter)', s.context.notBefore === before.context.notBefore, s.context.notBefore);
  JOBS.push({ name: 'cosign_later', kind: 'cosign', resp: s.qr.text, req: REQ.cosign_later.ur, pair: PAIR_UR, salt: salt(0xa3) });
  done(emu);

  emu.key('hold2');
  emu.key('hold2');
  s = emu.key('hold2');
  pageToEnd(emu);
  s = pulseAndSign(emu);
  check('BestEffort: revoke still shown, with the warning', s.qr.title === 'REVOKE SIGNED' &&
    s.qr.footer === 'WARNING: not saved - device still lists the mandate. press = done', s.qr);
  check('... RAM still lists the mandate', s.context.lastDelegationHash === MANDATE1_DH, s.context);
  JOBS.push({ name: 'revoke_unsaved', kind: 'revoke', resp: s.qr.text, pair: PAIR_UR, chain: CHAIN, contract: ENFORCER,
    delegationHash: MANDATE1_DH });
  done(emu);

  s = emu.key('hold5');
  check('Restrict: PANIC still shown, with the warning', s.screen === 'qr' && s.qr.title === 'PANIC: min epoch 2' &&
    s.qr.footer === 'Relay NOW. WARNING: epoch not saved (lost on restart). press = done', s.qr);
  check('... RAM follows (epoch 2), NVS keeps epoch 1', s.context.minEpoch === '2' && s.store.saves === before.store.saves, s.context);
  check('... RAM: PANIC FIRST flag cleared', s.context.unpanickedMandates === false, s.context);
  JOBS.push({ name: 'panic2', kind: 'panic', resp: s.qr.text, pair: PAIR_UR, chain: CHAIN, contract: ENFORCER, epoch: 2 });
  done(emu);
  emu.setNvsFail(false);
}

sect('persistence: the companion keeps the emulated NVS');
{
  const nvs = emu.exportNvs();
  const ctx = emu.exportContext();
  check('exportNvs', nvs.emulator === true && nvs.seed && nvs.context === ctx.stored, nvs);
  const e2 = await RiparEmulator.create({ ...TEST_OPTS, seed: nvs.seed, context: nvs.context });
  const s2 = e2.state();
  check('restored: same K1, paired, stored epoch 1 (the unsaved panic is lost on restart)', s2.k1 === DEMO_K1 && s2.paired &&
    s2.context.minEpoch === '1' && s2.context.reopenNonce === '1', s2.context);
  check('... and the stored context still lists the mandate (the unsaved revoke)', s2.context.lastDelegationHash === MANDATE1_DH,
    s2.context);
  check('... and still has the PANIC FIRST flag (the unsaved panic is lost)', s2.context.unpanickedMandates === true &&
    s2.context.pulseToken === AUSD && s2.context.newPayeeNeedsHuman === true, s2.context);
  check('... serial log: K1, vault, chain', s2.serial.includes(`ripar: K1 ${DEMO_K1}, vault ${VAULT}, Monad testnet (10143)`), s2.serial);
  e2.key('press');
  e2.scan(REQ.repair_143.ur);
  const s2r = e2.state();
  check('... so a chain change is refused after the restart: PANIC FIRST', s2r.review && !s2r.review.ok &&
    s2r.review.refusal === panicFirst('Monad testnet (10143)'), s2r.review && s2r.review.refusal);
  e2.destroy();
  const lost = async (name, hex, opts = TEST_OPTS) => {
    const e = await RiparEmulator.create({ ...opts, context: hex });
    const x = e.state();
    check(`${name}: PAIRING LOST, unpaired`, x.screen === 'message' && x.message.title === 'PAIRING LOST' && !x.paired &&
      /older firmware layout, or corrupt/.test(x.message.body) && x.serial.some((l) => /PAIRING LOST$/.test(l)), x.message);
    e.destroy();
  };
  await lost('corrupt stored context', 'ff'.repeat(198));
  // a v2 blob (firmware v1.1 layout: 194-byte body + CRC) with a valid CRC: an older layout is never loaded
  const v2 = Buffer.alloc(194);
  v2[0] = 2;
  v2.writeBigUInt64BE(10143n, 1);
  await lost('v2 context (firmware v1.1 layout, valid CRC)', Buffer.concat([v2, crc32be(v2)]).toString('hex'));
  // a v3 blob whose unpanickedMandates byte is 2 (valid CRC)
  const v3 = Buffer.from(ctx.stored, 'hex');
  check('stored blob is v3, 256 bytes', v3.length === 256 && v3[0] === 3, v3.length);
  const bad = Buffer.from(v3.subarray(0, 252));
  bad[251] = 2;
  await lost('v3 context with a flag byte of 2', Buffer.concat([bad, crc32be(bad)]).toString('hex'));
  const good = Buffer.from(v3.subarray(0, 252));
  check('control: the same blob re-CRC-ed unchanged is the stored one', Buffer.concat([good, crc32be(good)]).toString('hex') === ctx.stored);
  const ver2 = Buffer.from(good);
  ver2[0] = 2;
  await lost('a 256-byte blob with version 2 (valid CRC)', Buffer.concat([ver2, crc32be(ver2)]).toString('hex'));
}

sect('self-test failure: nothing is ever signed');
{
  const e = await RiparEmulator.create({ test: { selftestFault: true } });
  let sf = e.state();
  check('SELFTEST FAIL screen', sf.screen === 'fail' && sf.message.title === 'SELFTEST FAIL' && /SIGNING IS DISABLED/.test(sf.message.body) &&
    /FAIL P-256 ecdsa_sign == RFC6979 vector/.test(sf.message.body), sf.message);
  sf = e.key('press');
  check('keys do nothing', sf.screen === 'fail', sf.screen);
  sf = e.key('hold5');
  check('no panic either', sf.screen === 'fail' && sf.signatures === 0, sf.screen);
  check('no scanning', e.scan(REQ.pair.ur).result === 'camera-off');
  e.destroy();
}

sect('missing hardware (the device boots without camera / pulse sensor)');
{
  const e = await RiparEmulator.create({ test: true, hardware: { camera: false } });
  let sh = e.key('press');
  check('no camera: SCAN says so', sh.screen === 'scan' && sh.display.hint === 'NO CAMERA DETECTED - hold 2 s = back' && !sh.hardware.camera,
    sh.display);
  check('no camera: nothing is read', e.scan(REQ.pair.ur).result === 'camera-off');
  e.destroy();
  const p = await RiparEmulator.create({ test: true, hardware: { pulseSensor: false } });
  p.key('press');
  p.scan(REQ.pair.ur);
  for (let i = 0; i < 40 && !p.state().review.allSeen; i++) p.key('press');
  sh = p.key('press');
  check('no pulse sensor: PULSE title', sh.screen === 'pulse' && sh.display.title === 'NO PULSE SENSOR - cannot sign', sh.display.title);
  p.finger({ on: true, bpm: 72 });
  sh = p.tickUntil((x) => x.screen === 'armed', { maxMs: 15000 });
  check('no pulse sensor: SIGN is never armed', sh.screen === 'pulse' && !sh.pulse.passed, sh.screen);
  p.destroy();
}

sect('normal mode: keys from companion entropy');
{
  const ent = new Uint8Array(64).map((_, i) => (i * 37 + 11) & 255);
  const e = await RiparEmulator.create({ entropy: ent });
  const s1 = e.state();
  const seedHex = createHash('sha256').update(Buffer.from(ent)).digest('hex');
  check('new device keys, self-test passed, not test mode', !s1.testMode && s1.selftest.passed && s1.k1 !== DEMO_K1, s1.k1);
  check('seed = sha256(entropy pool)', e.exportNvs().seed === seedHex);
  let saved = null;
  e.onContextSaved = (nvs) => { saved = nvs; };
  e.key('press');
  e.scan(REQ.pair.ur);
  for (let i = 0; i < 40 && !e.state().review.allSeen; i++) e.key('press');
  e.key('press');
  e.finger({ on: true, bpm: 64 });
  e.tickUntil((x) => x.screen === 'armed', { maxMs: 20000 });
  const sq = e.key('press');
  check('non-test device pairs', sq.screen === 'qr' && sq.qr.title === 'PAIRED', sq.screen);
  const indep = oracle('vault', [s1.k1])[s1.k1];
  check('its own derived vault is pinned (make_request.py vault_address agrees)', sq.vault === indep && sq.context.vault === indep &&
    indep !== VAULT, { emulator: sq.vault, pinned: sq.context.vault, makeRequest: indep });
  check('onContextSaved fired with the new context', saved && saved.context === sq.store.contextHex, saved);
  JOBS.push({ name: 'pair_random_device', kind: 'pair', resp: sq.qr.text, req: REQ.pair.ur, notDemo: true });
  const e2 = await RiparEmulator.create({ entropy: new Uint8Array(32).fill(1), seed: saved.seed, context: saved.context });
  check('restore from exportNvs()', e2.state().k1 === s1.k1 && e2.state().paired);
  // the same context under another K1 (the demo seed): its pinned vault is not that device's vault -> fail closed
  const e4 = await RiparEmulator.create({ ...TEST_OPTS, context: saved.context });
  const s4 = e4.state();
  check("another device's context (vault not derived from this K1): PAIRING LOST", s4.screen === 'message' &&
    s4.message.title === 'PAIRING LOST' && !s4.paired && s4.k1 === DEMO_K1, s4.message);
  e4.destroy();
  e.destroy();
  e2.destroy();
  let threw = false;
  try {
    await RiparEmulator.create({ entropy: new Uint8Array(8) });
  } catch (err) {
    threw = /entropy/.test(err.message);
  }
  check('too little entropy is refused', threw);
}

sect('pulse gate (v1.2 detector): spoofs switched with the thumb kept on never arm SIGN');
{
  // the emulator finding against the v1.1 detector: square 66 bpm, switched to sine 72 bpm at 5 s without lifting the
  // thumb, armed SIGN about 6 s after the switch (ppg seeds 1 / 2 / 3). finger() without `on` keeps the thumb on, so the
  // synthetic sensor sees no new landing; the sine / square phase jumps at the switch (ppg_synth.cpp absolute phase).
  const cases = [
    { seed: 1, from: { bpm: 66, shape: 'square' }, to: { bpm: 72, shape: 'sine' } },
    { seed: 2, from: { bpm: 66, shape: 'square' }, to: { bpm: 72, shape: 'sine' } },
    { seed: 3, from: { bpm: 66, shape: 'square' }, to: { bpm: 72, shape: 'sine' } },
    { seed: 1, from: { bpm: 72, shape: 'flat' }, to: { bpm: 72, shape: 'sine' } },
    { seed: 1, from: { bpm: 60, shape: 'sine' }, to: { bpm: 72, shape: 'sine' } },
    { seed: 1, from: { bpm: 72, shape: 'sine' }, to: { bpm: 66, shape: 'square' } },
  ];
  for (const c of cases) {
    const tag = `${c.from.shape} ${c.from.bpm} -> ${c.to.shape} ${c.to.bpm} (ppg seed ${c.seed})`;
    const e = await RiparEmulator.create({ test: { ppgSeed: c.seed } });
    e.key('press');
    e.scan(REQ.pair.ur);
    for (let i = 0; i < 40 && !e.state().review.allSeen; i++) e.key('press');
    let x = e.key('press');
    check(`${tag}: PULSE`, x.screen === 'pulse' && x.pulse.sensorOn, x.screen);
    e.finger({ on: true, ...c.from });
    x = e.tickUntil((y) => y.screen === 'armed', { maxMs: 5000, stepMs: 20 });
    check(`${tag}: first 5 s not armed`, x.screen === 'pulse', x.pulse);
    const f = e.finger(c.to);
    check(`${tag}: switched with the thumb kept on`, f.on === true && f.shape === c.to.shape && f.bpm === c.to.bpm, f);
    x = e.tickUntil((y) => y.screen === 'armed', { maxMs: 25000, stepMs: 20 });
    check(`${tag}: 25 s after the switch SIGN was never armed`, x.screen === 'pulse' && x.pulse.finger && !x.pulse.passed &&
      x.signatures === 0, x.pulse);
    // control: the gate itself still opens for a real-shaped pulse (thumb lifted and placed again)
    e.finger({ on: false });
    e.tick(1000);
    e.finger({ on: true, bpm: 72, shape: 'ppg' });
    x = e.tickUntil((y) => y.screen === 'armed', { maxMs: 20000, stepMs: 20 });
    check(`${tag}: control: a real-shaped pulse then arms SIGN`, x.screen === 'armed' && x.pulse.passed, x.pulse);
    e.destroy();
  }
}

sect('second device: a minimal pairing pins the compiled-in contracts and the vault derived from K1');
const dev2 = await RiparEmulator.create(TEST_OPTS);
let PAIR2_UR = null;
let NAT_DH = null;
let NOHUMAN_DH = null;
{
  scanRequest(dev2, REQ.pair_min);
  let x = dev2.state();
  check('minimal pairing (keys 1, 2, 3, 6, 9) review ok', x.review.ok, x.review.refusal);
  const want = { Manager: `${DM} (MetaMask v1.3.0)`, 'Co-sign': `${ENFORCER} (firmware table)`,
    Relay: `${RELAY} (firmware table)`, Vault: `${VAULT} (derived from this device)` };
  for (const [label, value] of Object.entries(want)) {
    const l = line(x, label);
    check(`minimal pairing: ${label} filled in = ${value}, green`, l && l.value === value && l.tone === 'good', l);
  }
  pageToEnd(dev2);
  x = pulseAndSign(dev2);
  check('PAIRED', x.qr.title === 'PAIRED', x.qr);
  check('pinned: compiled-in manager / enforcer / relay, registry, sentinel, derived vault', x.context.chainId === String(CHAIN) &&
    x.context.delegationManager === DM && x.context.pulseCosignEnforcer === ENFORCER && x.context.relay === RELAY &&
    x.context.registry === REGISTRY && x.context.sentinel === SENTINEL && x.context.vault === VAULT, x.context);
  PAIR2_UR = x.qr.text;
  JOBS.push({ name: 'pair_min', kind: 'pair', resp: PAIR2_UR, req: REQ.pair_min.ur });
  done(dev2);
  reviewOnly(dev2, REQ.repair_143, (y) => check('no mandate signed yet: a chain change may be paired', y.review.ok, y.review.refusal));
}

sect('second device: a native-terms mandate with a lifetime AUTO cap');
{
  scanRequest(dev2, REQ.mandate_native);
  let x = dev2.state();
  check('native-terms mandate review ok', x.review.ok, x.review.refusal);
  const want = { Period: 'never resets (lifetime cap)', 'Auto per tx': '1 MON', 'Auto per period': '3 MON',
    'Agent id': '7 (companion)' };
  for (const [label, value] of Object.entries(want)) {
    const l = line(x, label);
    check(`native mandate review: ${label} = ${value}`, l && l.value === value, l);
  }
  pageToEnd(dev2);
  x = pulseAndSign(dev2);
  check('MANDATE SIGNED', x.qr.title === 'MANDATE SIGNED', x.qr);
  check('native terms remembered (token 0, 1 / 3 MON, period 0), PANIC FIRST flag set', x.context.pulseToken === ZERO &&
    x.context.perTxAutoCap === ONE_MON && x.context.periodAutoCap === '3000000000000000000' && x.context.period === 0 &&
    x.context.newPayeeNeedsHuman === true && x.context.unpanickedMandates === true, x.context);
  NAT_DH = x.context.lastDelegationHash;
  JOBS.push({ name: 'mandate_native', kind: 'mandate', resp: x.qr.text, req: REQ.mandate_native.ur, pair: PAIR2_UR, expectDh: NAT_DH });
  done(dev2);
}

sect("second device: the 'becomes an AUTO payee' line for native terms");
{
  const NAT_AUTO = autoText(PAYEE, '1 MON', '3 MON', null);
  expectAuto(dev2, REQ.nat_zero_value, 'native send of value 0', null);
  expectAuto(dev2, REQ.nat_erc20, 'ERC-20 transfer (not the mandate asset)', null);
  scanRequest(dev2, REQ.nat_send);
  let x = dev2.state();
  const got = autoLines(x);
  check('native send of 0.5 MON: exactly one AUTO payee line (lifetime cap)', x.review.ok && got.length === 1 &&
    got[0].value === NAT_AUTO && got[0].tone === 'warn', { got, want: NAT_AUTO });
  pageToEnd(dev2);
  x = pulseAndSign(dev2, salt(0xc1));
  check('CO-SIGNED (the payee becomes an AUTO payee on chain)', x.qr.title === 'CO-SIGNED', x.qr);
  JOBS.push({ name: 'cosign_native_auto', kind: 'cosign', resp: x.qr.text, req: REQ.nat_send.ur, pair: PAIR2_UR, salt: salt(0xc1) });
  done(dev2);
}

sect('second device: PANIC FIRST until a panic, then the chain change is signed');
{
  expectRefusedReview(dev2, REQ.repair_143, 'PANIC FIRST', { inspect: (y) => {
    check('exact refusal', y.review.refusal === panicFirst('Monad testnet (10143)'), y.review.refusal);
    const f = lines(y, 'CHANGES').find((l) => l.value.startsWith('FORGETS'));
    check('FORGETS mandate (still live: PANIC first)', f && f.value === `FORGETS mandate ${NAT_DH} (still live: PANIC first)`, f);
  } });
  dev2.key('hold2');
  dev2.key('hold2');
  let x = dev2.key('hold2');
  check('REVOKE review', x.screen === 'review' && x.job === 'revoke' && x.review.ok, x.review);
  pageToEnd(dev2);
  x = pulseAndSign(dev2);
  check('REVOKE SIGNED; the flag stays set', x.qr.title === 'REVOKE SIGNED' && x.context.lastDelegationHash === null &&
    x.context.unpanickedMandates === true, x.context);
  JOBS.push({ name: 'revoke_native', kind: 'revoke', resp: x.qr.text, pair: PAIR2_UR, chain: CHAIN, contract: ENFORCER,
    delegationHash: NAT_DH });
  done(dev2);
  expectRefusedReview(dev2, REQ.repair_143, 'PANIC FIRST');

  scanRequest(dev2, REQ.mandate_nohuman);
  x = dev2.state();
  const np = line(x, 'New payees');
  check('mandate without newPayeeNeedsHuman: review ok, "AUTO path allowed"', x.review.ok && np && np.value === 'AUTO path allowed',
    np || x.review.refusal);
  pageToEnd(dev2);
  x = pulseAndSign(dev2);
  NOHUMAN_DH = x.context.lastDelegationHash;
  check('signed; newPayeeNeedsHuman false remembered', x.qr.title === 'MANDATE SIGNED' && x.context.newPayeeNeedsHuman === false &&
    x.context.pulseToken === AUSD, x.context);
  JOBS.push({ name: 'mandate_nohuman', kind: 'mandate', resp: x.qr.text, req: REQ.mandate_nohuman.ur, pair: PAIR2_UR,
    expectDh: NOHUMAN_DH });
  done(dev2);
  expectAuto(dev2, REQ.nohuman_transfer, 'newPayeeNeedsHuman false (every payee may use AUTO anyway)', null);
  expectAuto(dev2, REQ.nat_send_forgotten, 'co-sign for the earlier mandate (UNKNOWN MANDATE)', null);
  expectMay(dev2, REQ.nat_send_forgotten, 'co-sign for the earlier mandate (native send)', mayText(PAYEE, NAT_DH));

  x = dev2.key('hold5');
  check('PANIC: min epoch 1, flag cleared', x.screen === 'qr' && x.qr.title === 'PANIC: min epoch 1' &&
    x.context.unpanickedMandates === false && x.context.lastDelegationHash === NOHUMAN_DH, x.context);
  JOBS.push({ name: 'panic_dev2', kind: 'panic', resp: x.qr.text, pair: PAIR2_UR, chain: CHAIN, contract: ENFORCER, epoch: 1 });
  done(dev2);
  reviewOnly(dev2, REQ.nohuman_transfer, (y) => {
    const p = y.review.lines.find((l) => l.value === PANIC_LINE);
    check('co-sign for a mandate signed before the panic: the PANIC line, in amber', y.review.ok && p && p.tone === 'warn' &&
      autoLines(y).length === 0, y.review.lines);
  });

  scanRequest(dev2, REQ.repair_143);
  x = dev2.state();
  check('after the panic the chain change is allowed', x.review.ok, x.review.refusal);
  const f = lines(x, 'CHANGES').find((l) => l.value.startsWith('FORGETS'));
  check("FORGETS mandate ... (killed once this device's last PANIC is relayed)", f &&
    f.value === `FORGETS mandate ${NOHUMAN_DH} (killed once this device's last PANIC is relayed)` && f.tone === 'bad', f);
  pageToEnd(dev2);
  x = pulseAndSign(dev2);
  check('PAIRED on Monad (143)', x.qr.title === 'PAIRED' && x.context.chainId === '143', x.context);
  check('143: compiled-in enforcer / manager / registry / relay, same derived vault, mandate forgotten, epoch kept',
    x.context.pulseCosignEnforcer === ENFORCER && x.context.delegationManager === DM && x.context.registry === REGISTRY &&
    x.context.relay === RELAY_143 && x.context.vault === VAULT && x.context.lastDelegationHash === null &&
    x.context.pulseToken === ZERO && x.context.minEpoch === '1' && !x.context.unpanickedMandates, x.context);
  JOBS.push({ name: 'repair_143', kind: 'pair', resp: x.qr.text, req: REQ.repair_143.ur });
  done(dev2);
  reviewOnly(dev2, REQ.pair_min, (y) => check('and back to 10143 (no mandate since the panic): allowed', y.review.ok, y.review.refusal));
  dev2.destroy();
}

sect('make_request.py verifies every response (parse exit 0, byte-identical to simulate)');
{
  // negative control: the oracle must catch a response that does not belong to its request
  const cosignJob = JOBS.find((j) => j.name === 'cosign_erc20');
  JOBS.push({ ...cosignJob, name: 'control_wrong_request', req: REQ.cosign_native.ur, control: true });
  const jobs = JOBS.filter((j) => !j.notDemo);
  const res = oracle('verify', jobs);
  for (const r of res) {
    const job = jobs.find((j) => j.name === r.name);
    console.log(`   ${r.name.padEnd(22)} parse exit ${r.parseExit} (${r.parseResult}), identical ${r.identical}` +
      (r.cliIdentical !== undefined ? `, CLI simulate identical ${r.cliIdentical}` : ''));
    if (job.control) {
      check('negative control: parse fails', r.parseExit !== 0, r);
      check('negative control: not identical', r.identical === false, r);
      continue;
    }
    check(`${r.name}: parse exit 0 (${r.parseResult})`, r.parseExit === 0, r.parseError || r);
    check(`${r.name}: byte-identical to simulate()`, r.identical === true, r.expectError || { got: job.resp, want: r.expectedUr });
    if (job.kind === 'mandate' || job.kind === 'privy') check(`${r.name}: byte-identical to the simulate CLI`, r.cliIdentical === true);
    if (job.expectDh) check(`${r.name}: delegation hash = the device's lastDelegationHash`,
      r.parseFields.delegationHash === job.expectDh.slice(2), r.parseFields);
  }
  // salts / evidence actually carried by the responses
  for (const job of jobs.filter((j) => j.salt && !j.control)) {
    const r = res.find((x) => x.name === job.name);
    check(`${job.name}: salt = the injected TRNG bytes`, r.parseFields.salt16 === job.salt, r.parseFields);
    if (job.zeroEvidence) {
      check(`${job.name}: all-zero evidence (no pulse for a deny)`, r.parseFields.evidence12 === '00'.repeat(12), r.parseFields);
    } else {
      const ev = r.parseFields.evidence || {};
      check(`${job.name}: pulse evidence v1, ~72 bpm, >= 5 beats, DC levels`, ev.version === 1 && Math.abs(ev.bpm - 72) <= 10 &&
        ev.beats >= 5 && ev.irDC > 100000 && ev.redDC > 70000, ev);
    }
  }
  // the random-seed device: its signatures are checked (its keys are not the demo keys, so no simulate() comparison)
  const rnd = JOBS.find((j) => j.name === 'pair_random_device');
  const r2 = oracle('verify', [rnd])[0];
  check('random device pairing: parse exit 0 (BindDevice by its own K1 + P1)', r2.parseExit === 0, r2);
  check('random device pairing: firmware id = the emulator id', r2.parseFields.firmwareId === FWID, r2.parseFields);
}

sect('parity audits (emulator vs flows.cpp / io.cpp / qrscan.cpp / pulse.cpp)');
for (const f of ['audit_key_window.mjs', 'audit_scan_repeat.mjs', 'audit_pulse_faults.mjs']) {
  const p = spawnSync(process.execPath, [fileURLToPath(new URL('./' + f, import.meta.url))], { encoding: 'utf8',
    maxBuffer: 64 << 20 });
  const out = (p.stdout || '') + (p.stderr || '');
  console.log('   ' + (out.trim().split(/\r?\n/).pop() || f));
  check(`${f} exits 0`, p.status === 0, out);
}

console.log(`== emulator tests: ${passed} checks passed, ${failed} failed (${((Date.now() - t0) / 1000).toFixed(1)} s) -> ${failed ? 'FAIL' : 'PASS'}`);
process.exit(failed ? 1 : 0);
