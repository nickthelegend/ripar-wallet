// Parity audit (emulator vs src/qrscan.cpp): repeat suppression of the camera handoff.
//
//   node emu/test/audit_scan_repeat.mjs         (exit 1 = parity gap found)
//
// On the device the decode task hands a payload to the app thread through qrscan.cpp deliver(): an identical payload is
// re-delivered at most once per kRepeatMs = 1000 ms (g_lastDelivered / g_lastDeliveredMs, cleared by qrscan_start()).
// So the same QR decoded again within 1 s never reaches UrDecoder::receive() in tick_scan(): no second "bad QR part"
// error beep, no second Accepted (no Fsm::touch()). The emulator's EmuCam::submit() used to deliver every scan() call
// (1 GAP here); it now applies the same filter (scan() result 'repeat'). The checks state the DEVICE outcome; a GAP is
// the emulator deviating from it.
import { RiparEmulator } from '../dist/ripar-emu.mjs';

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

const BAD = 'UR:RIPAR-PAIR-REQ/LPADAXAEAEAE'; // a UR whose bytewords / CRC do not decode -> UrDecoder::Error

console.log('-- the same undecodable request QR seen twice within 1 s (e.g. held in front of the camera)');
{
  const e = await RiparEmulator.create({ test: true });
  e.key('press');
  const err0 = e.state().buzz.err;
  const r1 = e.scan(BAD);
  e.tick(200);
  const r2 = e.scan(BAD);
  const s = e.state();
  console.log(`   1st scan: ${r1.result} (${r1.hint}); 2nd scan 205 ms later: ${r2.result}`);
  check('first decode is delivered: bad QR part + error beep (emulator == device)', r1.result === 'error' && /^bad QR part: /.test(r1.hint));
  check('device: the identical payload 205 ms later is not re-delivered (one error beep in total)',
    s.buzz.err === err0 + 1, { errBeeps: s.buzz.err - err0, second: r2.result });
  e.tick(1000);
  const r3 = e.scan(BAD);
  check('after 1 s the same payload is delivered again (emulator == device)', r3.result === 'error', r3);
  e.destroy();
}

console.log(`== audit_scan_repeat: ${passed} parity checks ok, ${gaps.length} GAP(s)` + (gaps.length ? ' -> emulator != device' : ''));
process.exit(gaps.length ? 1 : 0);
