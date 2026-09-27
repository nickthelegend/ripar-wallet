// Parity audit (emulator vs src/flows.cpp + src/io.cpp + src/ui.cpp): the "a press belongs to the screen on which it
// began" rule in the ~30 ms before a screen change.
//
//   node emu/test/audit_key_window.mjs         (python on PATH, or RIPAR_PYTHON=<python>; exit 1 = parity gap found)
//
// On the device, a screen change is followed IN THE SAME app_loop() pass by draw() and only then by the second
// drain_keys(true) (flows.cpp app_loop: on_change -> io_flush(true); draw(now); if (g_changed) io_flush(true)).
// Every screen is composed in a 320x240 RGB565 sprite and pushed over SPI at 40 MHz (ui.cpp flush(): 153,600 bytes
// = 30.7 ms minimum), while the 5 ms esp_timer key task keeps running (io.cpp). A press whose raw edge was detected
// just BEFORE the change (still inside the 30 ms debounce, so FsmIn::keyDown was false in the change pass) becomes
// "stable down" during that draw, and the post-draw io_flush(true) swallows it (g_armed = false): it produces no
// Short / Long2s / Hold5s on the new screen. docs/FIRMWARE.md section 5: "a SIGN press that began while the pulse was
// being measured does not sign when ARMED appears".
//
// The emulator used to run each pass in zero emulated time, so its post-draw flush came before the debounce completed
// and such a press acted on the new screen (3 GAPs here). It now keeps the loop busy for kFramePushMs = 31 ms after
// every frame it draws and runs the post-draw drain when that push is done (emu_core.cpp Device::step /
// draw_and_push), as the device does. The checks below state the DEVICE outcome; a GAP is the emulator deviating from
// it. Controls (a press ~40 ms before the change) show the parity that held before.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { RiparEmulator } from '../dist/ripar-emu.mjs';

const ORACLE = fileURLToPath(new URL('./oracle.py', import.meta.url));
const PY = process.env.RIPAR_PYTHON || 'python';

let passed = 0;
const gaps = [];
function check(name, cond, info) {
  if (cond) {
    passed++;
    console.log('   ok    ' + name);
  } else {
    gaps.push(name);
    console.log('   GAP   ' + name + (info !== undefined ? '\n         ' + JSON.stringify(info) : ''));
  }
}

function build(specs) {
  const p = spawnSync(PY, [ORACLE, 'build'], { input: JSON.stringify(specs), encoding: 'utf8', maxBuffer: 64 << 20 });
  if (p.status !== 0) throw new Error('oracle build failed: ' + p.stderr + p.stdout);
  return JSON.parse(p.stdout);
}

// same fixtures as run_tests.mjs (make_request.py builds the request)
const NOW = 1790500000;
const REQ = build([{ name: 'pair', kind: 'pair', reqid: '01'.repeat(16), fields: {
  chainId: 10143, registry: '0xA08a47c9d645926615CF04D69b7a048133F68c9f',
  manager: '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3', enforcer: '0x64d61fe5438981DC803ED61250FEf024617ae7eE',
  sentinel: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0', relay: '0xE433dCA75CA6cd730b1006F51A26208B000eA9E2',
  now: NOW } }]); // firmware v1.2: the compiled-in contracts; no key 8 (the device pins the vault derived from K1)

const STEP = 5;
function tickTo(e, t) {
  const n = e.state().nowMs;
  if (t < n) throw new Error(`tickTo ${t} < now ${n}`);
  return e.tick(t - n);
}
function firstTime(e, pred, maxMs) {
  let s = e.state();
  for (let i = 0; i < maxMs / STEP && !pred(s); i++) s = e.tick(STEP);
  if (!pred(s)) throw new Error('condition not reached');
  return s.nowMs;
}

// HOME -> SCAN -> pair review (all rows seen) -> PULSE with a live thumb; deterministic in test mode
async function toPulse() {
  const e = await RiparEmulator.create({ test: true });
  e.key('press');
  e.scan(REQ.pair.ur);
  for (let i = 0; i < 40 && !e.state().review.allSeen; i++) e.key('press');
  e.key('press');
  e.finger({ on: true, bpm: 72 });
  return e;
}

// ------------------------------------------------------------------------------------------------ 1. SIGN on ARMED
console.log('-- 1. SIGN press that began on PULSE, 20 ms before ARMED was drawn');
{
  const a = await toPulse();
  const tArmed = firstTime(a, (s) => s.screen === 'armed', 20000);
  a.destroy();
  const run = async (lead) => {
    const b = await toPulse();
    tickTo(b, tArmed - lead);
    const before = b.state();
    b.keyDown();
    let s = b.tick(lead + 100);
    const armedWhileDown = s.screen === 'armed';
    b.keyUp();
    s = b.tick(100);
    b.destroy();
    return { before: before.screen, armedWhileDown, screen: s.screen, signatures: s.signatures, title: s.qr && s.qr.title };
  };
  const r20 = await run(20);
  console.log(`   ARMED first drawn at ${tArmed} ms; press at ${tArmed - 20} ms (on ${r20.before}), released 120 ms later`);
  check('device: that press is swallowed by the post-draw io_flush -> nothing signed, still ARMED',
    r20.before === 'pulse' && r20.armedWhileDown && r20.screen === 'armed' && r20.signatures === 0, r20);
  const r40 = await run(40);
  check('control: a press 40 ms before ARMED (debounced on PULSE) never signs (emulator == device)',
    r40.before === 'pulse' && r40.screen === 'armed' && r40.signatures === 0, r40);
}

// ------------------------------------------------------------------------------------------------ 2. REVIEW cancel
console.log('-- 2. hold that began on SCAN 5 ms before the scanned request opened its review');
{
  const e = await RiparEmulator.create({ test: true });
  e.key('press');
  e.keyDown(); // on SCAN
  e.tick(STEP); // raw edge seen by the key timer
  const r = e.scan(REQ.pair.ur); // the request completes in the next pass -> REVIEW, drawn
  let s = e.state();
  const opened = r.result === 'complete' && s.screen === 'review';
  s = e.tick(2300); // hold on to 2.3 s
  e.keyUp();
  s = e.tick(100);
  check('device: the hold is swallowed (it began on SCAN) -> the PAIR DEVICE review stays open',
    opened && s.screen === 'review' && s.job === 'pair', { opened, screen: s.screen });
  e.destroy();

  const c = await RiparEmulator.create({ test: true });
  c.key('press');
  c.keyDown();
  c.tick(40); // debounced on SCAN before the request arrives
  c.scan(REQ.pair.ur);
  s = c.tick(2300);
  c.keyUp();
  s = c.tick(100);
  check('control: the same hold debounced on SCAN is ignored on the review (emulator == device)',
    s.screen === 'review' && s.job === 'pair', s.screen);
  c.destroy();
}

// ------------------------------------------------------------------------------------------------ 3. PANIC via timeout
console.log('-- 3. hold that began on SCAN 20 ms before the 120 s timeout drew HOME, held to 5 s (paired device)');
{
  const paired = async () => {
    const e = await toPulse();
    firstTime(e, (s) => s.screen === 'armed', 20000);
    let s = e.key('press');
    if (!(s.screen === 'qr' && s.qr.title === 'PAIRED')) throw new Error('pairing failed: ' + s.screen);
    e.finger({ on: false });
    e.key('press'); // done -> HOME
    e.key('press'); // -> SCAN
    return e;
  };
  const a = await paired();
  const tHome = firstTime(a, (s) => s.screen === 'home', 130000);
  a.destroy();
  const run = async (lead) => {
    const b = await paired();
    tickTo(b, tHome - lead);
    const before = b.state();
    b.keyDown();
    b.tick(lead + 5300);
    b.keyUp();
    const s = b.tick(100);
    b.destroy();
    return { before: before.screen, screen: s.screen, title: (s.qr && s.qr.title) || (s.message && s.message.title),
      minEpoch: s.context.minEpoch, signatures: s.signatures };
  };
  const r20 = await run(20);
  console.log(`   SCAN timed out to HOME at ${tHome} ms; press at ${tHome - 20} ms (on ${r20.before})`);
  check('device: a hold that began on SCAN never panics -> HOME, minEpoch 0, nothing signed',
    r20.before === 'scan' && r20.screen === 'home' && r20.minEpoch === '0' && r20.signatures === 1, r20);
  const r40 = await run(40);
  check('control: the same hold 40 ms before the timeout never panics (emulator == device)',
    r40.before === 'scan' && r40.screen === 'home' && r40.minEpoch === '0', r40);
}

console.log(`== audit_key_window: ${passed} parity checks ok, ${gaps.length} GAP(s)` + (gaps.length ? ' -> emulator != device' : ''));
process.exit(gaps.length ? 1 : 0);
