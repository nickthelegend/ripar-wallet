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
const DM = '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3'; // MetaMask DelegationManager v1.3.0 (compiled in)
const AUSD = '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC'; // listed token on 10143 (6 decimals)
const REGISTRY = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
const ENFORCER = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512';
const ENFORCER2 = '0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6';
const SENTINEL = '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0';
const RELAY = '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9';
const VAULT = '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9';
const AGENT = '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707';
const PAYEE = '0x0165878A594ca255338adfa4d48449f69242Eb8F';
const NOW = 1790500000; // 2026-09-27 09:06:40 UTC
const EXP = NOW + 3600;
const CHAIN = 10143;
const AGENT_ID = 42;
// the P1 key of the demo seed (the emulator's key in test mode; also checked against state().p1 below)
const DEMO_P1 = '5cbcd94e72c801fc1b1167ef6f648a5b998d41819020703610637bca5d182765b8f1fb687dc1ceb07f52f98cf80292b23d7583879c75689c4cf35393b67bd954';
const DEMO_K1 = '0x753454832754c071704be47915d4DeC6339624Eb';

const rid = (n) => n.toString(16).padStart(2, '0').repeat(16);
const pulseCaveat = (epoch) => ({ kind: 'pulse', enforcer: ENFORCER, p1Key: DEMO_P1, token: AUSD, perTxAutoCap: 5000000,
  periodAutoCap: 20000000, period: 86400, epoch, newPayeeNeedsHuman: true, sentinel: SENTINEL });
const pairFields = { chainId: CHAIN, registry: REGISTRY, manager: DM, enforcer: ENFORCER, sentinel: SENTINEL, relay: RELAY,
  vault: VAULT, now: NOW };
const cosignBase = { chainId: CHAIN, enforcer: ENFORCER, delegationHash: '$dh:mandate_ok', delegator: VAULT, redeemer: AGENT,
  target: AUSD, value: 0, expiry: EXP };
const PRIVY_JSON = { version: 1, method: 'PATCH', url: 'https://api.privy.io/v1/wallets/wl8yz4c2rq0q1cdz2q8a4',
  body: { additional_signers: [{ signer_id: 'kq7ks9z3n1v2lq4d7w0p8m3y', override_policy_ids: ['pol9x2'] }] },
  headers: { 'privy-app-id': 'cm0appid1234' } };

const SPECS = [
  { name: 'pair', kind: 'pair', reqid: rid(1), frag: 40, fields: pairFields },
  { name: 'repair_enforcer', kind: 'pair', reqid: rid(2), fields: { ...pairFields, enforcer: ENFORCER2 } },
  { name: 'repair_same', kind: 'pair', reqid: rid(3), fields: { ...pairFields, now: NOW + 60 } },
  { name: 'mandate_ok', kind: 'mandate', reqid: rid(4), frag: 60, fields: { chainId: CHAIN, manager: DM, delegate: AGENT,
    delegator: VAULT, salt: 1, agentId: AGENT_ID, label: 'demo agent', caveats: [pulseCaveat(0)] } },
  { name: 'mandate_nopulse', kind: 'mandate', reqid: rid(5), fields: { chainId: CHAIN, manager: DM, delegate: AGENT,
    delegator: VAULT, salt: 2, caveats: [{ kind: 'erc20TransferAmount', token: AUSD, amount: 1000000 }] } },
  { name: 'mandate_stale', kind: 'mandate', reqid: rid(6), fields: { chainId: CHAIN, manager: DM, delegate: AGENT,
    delegator: VAULT, salt: 3, agentId: AGENT_ID, caveats: [pulseCaveat(0)] } },
  { name: 'cosign_erc20', kind: 'cosign', reqid: rid(7), fields: { ...cosignBase, nonce: 1,
    transfer: { to: PAYEE, amount: 25000000 },
    ai: { text: 'pay invoice 17', claims: { to: PAYEE, token: AUSD, amount: 25000000 } } } },
  { name: 'cosign_native', kind: 'cosign', reqid: rid(8), fields: { ...cosignBase, target: PAYEE, value: '1500000000000000000', nonce: 2 } },
  { name: 'cosign_for_deny', kind: 'cosign', reqid: rid(9), fields: { ...cosignBase, nonce: 3,
    transfer: { to: '0x000000000000000000000000000000000000dEaD', amount: 999000000 } } },
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
  { name: 'mandate_epoch1', kind: 'mandate', reqid: rid(16), fields: { chainId: CHAIN, manager: DM, delegate: AGENT,
    delegator: VAULT, salt: 4, agentId: AGENT_ID, caveats: [pulseCaveat(1)] } },
  { name: 'cosign_later', kind: 'cosign', reqid: rid(17), fields: { ...cosignBase, delegationHash: '$dh:mandate_epoch1',
    nonce: 7, expiry: NOW + 2 * 86400, transfer: { to: PAYEE, amount: 5000000 } } },
];

const JOBS = []; // signed responses to verify with the oracle
const salt = (n) => n.toString(16).padStart(2, '0').repeat(16);

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

function expectRefusedReview(emu, req, prefix, { cosign = false } = {}) {
  scanRequest(emu, req);
  let s = emu.state();
  check(`${prefix}: review opened`, s.screen === 'review', s.screen);
  check(`${prefix}: policy refused`, s.review && s.review.ok === false, s.review && s.review.refusal);
  check(`${prefix}: refusal text`, s.review && s.review.refusal.startsWith(prefix), s.review && s.review.refusal);
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

sect('mandate (K1 signs the delegation)');
scanRequest(emu, REQ.mandate_ok, { multipart: true });
s = emu.state();
check('SIGN MANDATE review ok', s.review.title === 'SIGN MANDATE' && s.review.ok, s.review.refusal);
pageToEnd(emu);
s = pulseAndSign(emu);
check('MANDATE SIGNED eth-signature', s.qr.title === 'MANDATE SIGNED' && s.qr.text.startsWith('UR:ETH-SIGNATURE/'), s.qr);
check('lastDelegationHash + agent remembered', s.context.lastDelegationHash !== null && s.context.agentId === '42' &&
  s.context.hasAgentId, s.context);
const MANDATE_DH = s.context.lastDelegationHash;
JOBS.push({ name: 'mandate', kind: 'mandate', resp: s.qr.text, req: REQ.mandate_ok.ur, pair: PAIR_UR, expectDh: MANDATE_DH });
done(emu);

sect('re-pairing that would abandon the mandate: REVOKE FIRST');
expectRefusedReview(emu, REQ.repair_enforcer, 'REVOKE FIRST');

sect('co-sign refusals');
expectRefusedReview(emu, REQ.cosign_wrong_chain, 'WRONG CHAIN', { cosign: true });
expectRefusedReview(emu, REQ.cosign_unknown_calldata, 'UNKNOWN CALLDATA', { cosign: true });
expectRefusedReview(emu, REQ.cosign_expiry_far, 'EXPIRY TOO FAR', { cosign: true });

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
JOBS.push({ name: 'revoke', kind: 'revoke', resp: s.qr.text, pair: PAIR_UR, chain: CHAIN, contract: ENFORCER, delegationHash: MANDATE_DH });
done(emu);

sect('PANIC (hold 5 s on HOME, no pulse)');
s = emu.key('hold5');
check('PANIC QR', s.screen === 'qr' && s.qr.title === 'PANIC: min epoch 1' && s.qr.text.startsWith('UR:RIPAR-PANIC/'), s.qr || s.message);
check('min epoch 1 stored', s.context.minEpoch === '1' && !s.pulse.sensorOn, s.context);
JOBS.push({ name: 'panic1', kind: 'panic', resp: s.qr.text, pair: PAIR_UR, chain: CHAIN, contract: ENFORCER, epoch: 1 });
done(emu);

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
JOBS.push({ name: 'mandate_epoch1', kind: 'mandate', resp: s.qr.text, req: REQ.mandate_epoch1.ur, pair: PAIR_UR, expectDh: MANDATE1_DH });
done(emu);

sect('Save rules when NVS fails (respond.h Save)');
{
  emu.setNvsFail(true);
  const before = emu.state();
  scanRequest(emu, REQ.repair_same);
  s = pageToEnd(emu);
  check('re-pairing that keeps the mandate scope is allowed', s.review.ok, s.review.refusal);
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
  e2.destroy();
  const e3 = await RiparEmulator.create({ ...TEST_OPTS, context: 'ff'.repeat(198) });
  const s3 = e3.state();
  check('corrupt stored context: PAIRING LOST, unpaired', s3.screen === 'message' && s3.message.title === 'PAIRING LOST' && !s3.paired,
    s3.message);
  e3.destroy();
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
  check('onContextSaved fired with the new context', saved && saved.context === sq.store.contextHex, saved);
  JOBS.push({ name: 'pair_random_device', kind: 'pair', resp: sq.qr.text, req: REQ.pair.ur, notDemo: true });
  const e2 = await RiparEmulator.create({ entropy: new Uint8Array(32).fill(1), seed: saved.seed, context: saved.context });
  check('restore from exportNvs()', e2.state().k1 === s1.k1 && e2.state().paired);
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
