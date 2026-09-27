// Parity audit (emulator vs src/pulse.cpp + src/io.cpp + src/fsm.cpp): what happens when the pulse sensor or the
// firmware loop stops delivering, reached through the emulator's fault injection (setPulseFault / stallApp).
//
//   node emu/test/audit_pulse_faults.mjs        (python on PATH, or RIPAR_PYTHON=<python>; exit 1 = parity gap found)
//
// Device behaviour checked (each check states the DEVICE outcome; a GAP is the emulator deviating from it):
//   - pulse.cpp pulse_update(): no samples for more than kStaleMs = 250 ms (I2C fault, sensor unplugged) -> passed =
//     false, finger = false; fsm.cpp Armed: !pulsePassed -> back to Pulse ("thumb lifted / sensor stalled"), a SIGN
//     press there never signs.
//   - The MAX30102 keeps sampling into its 32-sample FIFO while nothing reads it (FIFO_ROLLOVER_EN, OVF_COUNTER
//     saturating at 31). The first read afterwards gets the 32 newest samples and the lost count; the sample clock is
//     advanced over the lost samples and re-synced to millis() after a stall longer than the FIFO, so PulseDetector
//     sees the timestamp gap (> 250 ms) and restarts the measurement: a stall can never produce a "passed" from
//     non-contiguous data. SIGN arms again only after a fresh measurement.
//   - fifo_read(): n = (WR - RD) & 0x1F, so a FIFO holding exactly 32 unread samples with OVF = 0 reads as 0 samples
//     (the next read, after the 33rd sample, gets 32 with OVF = 1).
//   - A sensor that lost power comes back in its reset state (MODE = 0): it samples nothing until pulse_start()
//     configures it again, i.e. the next measurement (a new review -> PULSE). pulse_start() itself fails while the bus
//     is faulted (g_running stays false: nothing is measured, SIGN never arms in that measurement).
//   - io.cpp pop_locked(): a key event older than kEventMaxAgeMs = 1000 ms when the loop polls it is dropped, so a
//     press made during a long loop stall never acts; a recent one does.
//   - qrscan.cpp: a QR decoded while the loop is stalled waits in the handoff slot and is read by the next pass.
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

const NOW = 1790500000;
const REQ = build([{ name: 'pair', kind: 'pair', reqid: '01'.repeat(16), fields: {
  chainId: 10143, registry: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
  manager: '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3', enforcer: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
  sentinel: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0', relay: '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9',
  vault: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9', now: NOW } }]);

const STEP = 5;
function until(e, pred, maxMs) {
  let s = e.state();
  for (let t = 0; t < maxMs && !pred(s); t += STEP) s = e.tick(STEP);
  return s;
}

// HOME -> SCAN -> pair review (all rows seen) -> PULSE, thumb on (deterministic test mode)
async function toPulse(e) {
  e = e || (await RiparEmulator.create({ test: true }));
  e.key('press');
  e.scan(REQ.pair.ur);
  for (let i = 0; i < 40 && !e.state().review.allSeen; i++) e.key('press');
  e.key('press');
  e.finger({ on: true, bpm: 72 });
  return e;
}
async function toArmed() {
  const e = await toPulse();
  const s = until(e, (x) => x.screen === 'armed', 20000);
  if (s.screen !== 'armed') throw new Error('never armed');
  return e;
}

// ------------------------------------------------------------------------------------------------ 1. I2C stall
console.log('-- 1. I2C bus stall on ARMED: stale after 250 ms, overflow + re-sync + fresh measurement afterwards');
{
  const e = await toArmed();
  let s = e.setPulseFault('stall');
  const t0 = s.nowMs;
  s = e.tick(200);
  check('device: 200 ms without samples -> still ARMED (the last result stands until 250 ms)',
    s.screen === 'armed' && s.pulse.passed && s.pulse.sensor.lastRead === 0 && s.pulse.sensor.sampling &&
      s.pulse.sensor.fifo >= 15, { screen: s.screen, sensor: s.pulse.sensor });
  s = until(e, (x) => x.screen !== 'armed', 400);
  const dt = s.nowMs - t0;
  check('device: > 250 ms without samples -> passed = false, finger = false, ARMED -> PULSE',
    s.screen === 'pulse' && !s.pulse.passed && !s.pulse.finger && dt > 200 && dt <= 320, { screen: s.screen, dt });
  const sigs = s.signatures;
  s = e.key('press');
  check('device: a SIGN press while the sensor is stalled never signs', s.screen === 'pulse' && s.signatures === sigs,
    { screen: s.screen, signatures: s.signatures });
  s = e.tick(800);
  check('device: the MAX30102 kept sampling: FIFO full (32), OVF counter saturated at 31',
    s.pulse.sensor.fifo === 32 && s.pulse.sensor.ovf === 31, s.pulse.sensor);
  const reads = s.pulse.sensor.reads;
  e.setPulseFault('none');
  s = until(e, (x) => x.pulse.sensor.lastRead > 0, 100);
  check('device: the first read after the stall gets the 32 newest samples and 31 lost (OVF), the rest is gone',
    s.pulse.sensor.lastRead === 32 && s.pulse.sensor.lastLost === 31 && s.pulse.sensor.fifo <= 1 &&
      s.pulse.sensor.reads > reads, s.pulse.sensor);
  check('device: the timestamp gap restarts the measurement (no beats, not passed)',
    s.screen === 'pulse' && !s.pulse.passed && s.pulse.beats === 0, s.pulse);
  s = until(e, (x) => x.screen === 'armed', 15000);
  check('device: SIGN arms again only after a fresh measurement', s.screen === 'armed' && s.pulse.beats >= 5, s.pulse);
  s = e.key('press');
  check('... and then signs', s.screen === 'qr' && s.qr.title === 'PAIRED', s.screen);
  e.destroy();
}

// ------------------------------------------------------------------------------------------------ 2. FIFO quirk
console.log('-- 2. fifo_read(): exactly 32 unread samples with OVF = 0 read as 0 samples');
{
  const e = await toPulse();
  until(e, (x) => x.pulse.finger, 2000);
  let seen = null;
  for (let attempt = 0; attempt < 20 && !seen; attempt++) {
    e.setPulseFault('stall');
    let s = until(e, (x) => x.pulse.sensor.fifo === 32, 400);
    const full = { fifo: s.pulse.sensor.fifo, ovf: s.pulse.sensor.ovf };
    // a loop pass runs in the next 5 ms step (the app is not pushing a frame then): it reads before the 33rd sample
    const passNext = !s.app.busy || s.app.busyUntilMs < s.nowMs + 2 * STEP;
    const reads = s.pulse.sensor.reads;
    e.setPulseFault('none');
    s = e.tick(STEP);
    if (!passNext) {
      e.tick(100);  // drained; try the next fill
      continue;
    }
    const first = { reads: s.pulse.sensor.reads - reads, lastRead: s.pulse.sensor.lastRead, fifo: s.pulse.sensor.fifo };
    s = until(e, (x) => x.pulse.sensor.lastRead > 0, 100);
    seen = { full, first, next: { lastRead: s.pulse.sensor.lastRead, lastLost: s.pulse.sensor.lastLost } };
  }
  check('device: FIFO full without overflow -> that read returns 0 samples (they stay in the FIFO)',
    seen && seen.full.fifo === 32 && seen.full.ovf === 0 && seen.first.reads === 1 && seen.first.lastRead === 0 &&
      seen.first.fifo === 32, seen);
  check('device: after the 33rd sample (OVF = 1) the next read gets 32 samples and 1+ lost',
    seen && seen.next.lastRead === 32 && seen.next.lastLost >= 1, seen);
  e.destroy();
}

// ------------------------------------------------------------------------------------------------ 3. unplug
console.log('-- 3. sensor unplugged on ARMED, plugged back: nothing until the next measurement starts');
{
  const e = await toArmed();
  let s = e.setPulseFault('unplug');
  check('device: power lost -> no sampling, FIFO gone', !s.pulse.sensor.sampling && s.pulse.sensor.fifo === 0,
    s.pulse.sensor);
  s = until(e, (x) => x.screen !== 'armed', 400);
  check('device: ARMED -> PULSE after 250 ms without samples', s.screen === 'pulse' && !s.pulse.passed, s.screen);
  e.setPulseFault('none');
  s = e.tick(3000);
  check('device: plugged back = reset state: still no samples, never armed in this measurement',
    s.screen === 'pulse' && !s.pulse.sensor.sampling && s.pulse.sensor.lastRead === 0 && !s.pulse.finger &&
      s.pulse.sensorOn, { screen: s.screen, sensor: s.pulse.sensor });
  s = e.key('hold2');
  check('hold 2 s on PULSE = cancel -> HOME', s.screen === 'home' && !s.pulse.sensorOn, s.screen);
  s = await toPulse(e).then((x) => x.state());
  check('device: the next measurement (pulse_start) configures the sensor again', s.screen === 'pulse' &&
    s.pulse.sensor.sampling && s.pulse.sensorOn, s.pulse.sensor);
  s = until(e, (x) => x.screen === 'armed', 15000);
  s = e.key('press');
  check('... and it arms and signs', s.screen === 'qr' && s.qr.title === 'PAIRED', s.screen);
  e.destroy();

  // pulse_start() while the bus is faulted
  const f = await RiparEmulator.create({ test: true });
  f.key('press');
  f.scan(REQ.pair.ur);
  for (let i = 0; i < 40 && !f.state().review.allSeen; i++) f.key('press');
  f.setPulseFault('stall');
  f.finger({ on: true, bpm: 72 });
  s = f.key('press');
  check('device: pulse_start() fails on a faulted bus -> not measuring', s.screen === 'pulse' && !s.pulse.sensorOn &&
    !s.pulse.sensor.sampling, s.pulse);
  f.setPulseFault('none');
  s = f.tick(8000);
  check('device: ... and it never arms in that measurement, even once the bus works again',
    s.screen === 'pulse' && !s.pulse.passed && !s.pulse.sensorOn, s.pulse);
  f.destroy();
}

// ------------------------------------------------------------------------------------------------ 4. loop stall
console.log('-- 4. firmware loop stalled for 1 s on ARMED (sensor + key timer keep running)');
{
  const e = await toArmed();
  let s = e.stallApp(1000);
  check('the loop is stalled', s.app.busy && s.app.stalled && s.app.busyUntilMs >= s.nowMs + 1000, s.app);
  const passes = s.app.passes;
  s = e.tick(900);
  check('no loop pass during the stall; the sensor filled its FIFO', s.app.passes === passes && s.pulse.sensor.fifo === 32 &&
    s.pulse.sensor.ovf > 0, { app: s.app, sensor: s.pulse.sensor });
  s = until(e, (x) => x.app.passes > passes, 200);
  check('device: first pass after the stall reads 32 samples, 31 lost, and the measurement restarts -> PULSE',
    s.pulse.sensor.lastRead === 32 && s.pulse.sensor.lastLost === 31 && s.screen === 'pulse' && !s.pulse.passed &&
      s.pulse.beats === 0, { screen: s.screen, pulse: s.pulse });
  s = until(e, (x) => x.screen === 'armed', 15000);
  check('... ARMED again after a fresh measurement', s.screen === 'armed', s.screen);
  e.destroy();
}

// ------------------------------------------------------------------------------------------------ 5. event age
console.log('-- 5. key events older than 1 s when the stalled loop polls them are dropped (io.cpp)');
{
  const e = await RiparEmulator.create({ test: true });
  let tEnd = e.stallApp(3000).app.busyUntilMs;
  e.tick(100);
  let s = e.key('press'); // its Short is queued ~0.3 s into the stall
  const errs = s.buzz.err;
  s = e.tick(tEnd + 50 - s.nowMs);
  check('device: a press made early in a 3 s stall does nothing (its event is > 1 s old when polled)',
    s.screen === 'home' && !s.app.stalled && s.buzz.err === errs, { screen: s.screen, app: s.app });
  tEnd = e.stallApp(3000).app.busyUntilMs;
  e.tick(2500);
  s = e.key('press'); // its Short is queued ~0.3 s before the stall ends
  s = e.tick(tEnd + 50 - s.nowMs);
  check('control: a press made in the last second of the stall acts once the loop runs (-> SCAN)', s.screen === 'scan',
    s.screen);
  e.destroy();
}

// ------------------------------------------------------------------------------------------------ 6. camera slot
console.log('-- 6. a QR decoded while the loop is stalled waits in the handoff slot');
{
  const e = await RiparEmulator.create({ test: true });
  e.key('press');
  const err0 = e.state().buzz.err;
  e.stallApp(500);
  const r = e.scan('UR:RIPAR-PAIR-REQ/LPADAXAEAEAE');
  let s = e.state();
  check('scan during the stall: pending, not read yet', r.result === 'pending' && s.buzz.err === err0, { r, err: s.buzz.err - err0 });
  s = e.tick(600);
  check('device: the next pass reads it (bad QR part, one error beep)', s.buzz.err === err0 + 1 &&
    /^bad QR part: /.test(s.scan.hint), { hint: s.scan.hint, err: s.buzz.err - err0 });
  e.destroy();
}

console.log(`== audit_pulse_faults: ${passed} parity checks ok, ${gaps.length} GAP(s)` + (gaps.length ? ' -> emulator != device' : ''));
process.exit(gaps.length ? 1 : 0);
