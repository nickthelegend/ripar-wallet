# Ripar device emulator

The Ripar Wallet firmware compiled to WebAssembly, so the web companion can offer a faithful signer without the
hardware. It runs the **same portable C++ modules** as the ESP32-S3 (unchanged: `hashes util cbor ur eip712 abi crypto
protocol enforcers json_strict tokens policy review respond context fsm pulse_algo vault`), driven by
`src/emu_core.cpp`, a function-by-function port of the device driver `src/flows.cpp`. Every screen, key rule, refusal,
review line, signature and context change comes from the same code path as on the device.

The emulated device always says so: `state().emulator === true`, and the firmware id in every `ripar-pair` response
(key 6) is the first 8 bytes of `sha256("ripar-emulator v1")` = `7bc44601d30720f1`, never an app-image hash.

It emulates **firmware v1.2** (`docs/PROTOCOL.md` section 7): the Ripar contracts compiled in (a pairing may only name
them), the vault derived from K1 (`state().vault`, `src/vault.cpp`), the context layout v3 (the remembered mandate's
pulse terms and the PANIC FIRST flag), PANIC FIRST instead of REVOKE FIRST, the co-sign "becomes an AUTO payee" line (and,
for a mandate the device does not remember, "may become an AUTO payee"), the RiparReputationRelay compiled in on both
chains, and the v1.2 pulse gate (spoof statistics on foot-independent fiducials plus the IR / red cross-channel test,
`src/pulse_algo.cpp`).

## Files

| Path | What |
|---|---|
| `src/emu_core.h/.cpp` | the driver: `flows.cpp` ported function by function (each block names the function it mirrors; `EMULATOR:` marks the differences) |
| `src/emu_hw.h/.cpp` | emulated hardware: BOOT key timer + queue (`io.cpp`), MAX30102 FIFO + sample clock (`pulse.cpp`), camera (`qrscan.cpp`), NVS context blob (`store.cpp`), TRNG, keys + self-test (`keys.cpp`, over `crypto.cpp`) |
| `src/ppg_synth.h/.cpp` | synthetic 100 Hz IR / red PPG (the waveform model of `test/host/test_pulse.cpp`) |
| `src/emu_ui.h/.cpp`, `font_freesans9.h` | the screen model of `ui.cpp`: review rows wrapped with the real FreeSans9pt7b metrics, 9 visible rows, message rows, QR version / ECC (the `QR-CAPACITY` block of `ui.cpp`, extracted verbatim at build time) |
| `src/emu_state.cpp`, `json_out.h` | `state()` / context / NVS as JSON |
| `src/emu_api.cpp` | the C API (`extern "C"`, JSON in / out) |
| `js/ripar-emu.mjs`, `js/ripar-emu.d.ts` | the JavaScript class `RiparEmulator` and its types |
| `build.sh` | reproducible build → `dist/` |
| `dist/` | **commit this**: `ripar-emu.mjs` (wrapper), `ripar-emu-core.mjs` + `ripar-emu-core.wasm`, `ripar-emu.d.ts` |
| `test/run_tests.mjs`, `test/oracle.py` | end-to-end tests against `tools/make_request.py` |
| `test/run_wasm_host_tests.sh` | the firmware host tests (`test_fsm`, `test_pulse`, `test_vault`, ...) compiled to wasm and run under Node |

## Build

```bash
cd firmware
bash emu/build.sh                     # EMSDK defaults to F:/tools/emsdk (Emscripten 6.0.10)
EMU_SINGLE_FILE=1 bash emu/build.sh   # optional: the wasm embedded in ripar-emu-core.mjs (~567 KB, one file)
```

Flags: `-std=c++14 -O2 -sMODULARIZE -sEXPORT_ES6 -sENVIRONMENT=web,node -sALLOW_MEMORY_GROWTH -sINITIAL_MEMORY=8MB
-sSTACK_SIZE=1MB -sFILESYSTEM=0`, only the 11 `emu_*` functions and `cwrap` / `UTF8ToString` exported. Two builds of
the same sources give byte-identical `dist/` files. Output (firmware v1.2): `ripar-emu-core.wasm` about 505 KB (about
200 KB gzipped), `ripar-emu-core.mjs` 12 KB, `ripar-emu.mjs` 12 KB; with `EMU_SINGLE_FILE=1` one `ripar-emu-core.mjs` of
about 567 KB. The core finds its `.wasm` next to itself
(`new URL(..., import.meta.url)`), so serve both files from the same directory, or build with `EMU_SINGLE_FILE=1`.

## JavaScript API

```js
import { RiparEmulator } from './dist/ripar-emu.mjs';

const emu = await RiparEmulator.create();        // new device: 64 bytes of crypto.getRandomValues() -> seed = sha256(pool)
emu.onContextSaved = (nvs) => localStorage.ripar = JSON.stringify(nvs);   // emulated NVS: {seed, context}
// later: await RiparEmulator.create({ seed: nvs.seed, context: nvs.context })

emu.key('press');                                 // HOME -> SCAN
for (const part of parts) emu.scan(part);         // one QR per call -> {result, progress, received, seqLen, hint, screen}
while (!emu.state().review.allSeen) emu.key('press');   // page the review (9 rows, +8 per press)
emu.key('press');                                 // -> PULSE
emu.finger({ on: true, bpm: 72 });                // synthetic thumb
emu.tickUntil(s => s.screen === 'armed', { maxMs: 15000 });
emu.key('press');                                 // SIGN
const responseUr = emu.state().qr.text;           // the upper-cased UR the device shows as a QR
```

| Method | |
|---|---|
| `static create({entropy?, seed?, context?, test?, hardware?, clockMs?, battery?})` | powers on a device: self-test, first-run keys, context load, HOME (async, loads the wasm once) |
| `state()` | everything needed to draw the 320 x 240 screen, see below |
| `tick(ms)` | advances emulated time: every 5 ms the key timer ticks, the sensor samples, the firmware loop runs once (unless it is still pushing the last frame to the LCD, see Parity) |
| `tickUntil(pred, {maxMs, stepMs})` | ticks until `pred(state)` |
| `keyDown()` / `keyUp()` | the SIGN (BOOT) key, at the current emulated time (explicit clock: combine with `tick`) |
| `key('press' \| 'hold2' \| 'hold5')`, `hold(ms)` | down, tick, up, settle (press 120 ms, hold2 2.3 s, hold5 5.3 s) |
| `scan(text)` | the camera decodes one QR (single-part UR or one multipart part); only read on SCAN. The payload delivered last is not delivered again within 1 s (`result: 'repeat'`, as `qrscan.cpp`), so it may be called for every decoded camera frame. Time advances to the loop pass that reads it (5 to 35 ms) |
| `finger({on, bpm, amplitude, noise, hrv, shape})` | the synthetic PPG (`shape`: `ppg`, or the spoofs `sine` / `square` / `flat`) |
| `exportContext()`, `exportNvs()` | the pinned context (RAM + stored blob), the emulated NVS `{seed, context}` |
| `setNvsFail(bool)`, `setBattery(pct)` | fault injection (every NVS write fails), the fake battery level |
| `setPulseFault('none' \| 'stall' \| 'unplug')` | fault injection on the MAX30102 after power-on: I2C bus stall (nothing is read, the sensor keeps filling its FIFO), hot unplug (plugged back = reset state until the next measurement) |
| `stallApp(ms)` | fault injection: the firmware loop blocks for `ms` (key timer, camera handoff and sensor keep running); does not tick by itself |
| `injectTrng(bytes)` | test mode: the next TRNG bytes (e.g. the next co-sign / deny salt) |
| `addEntropy(bytes)`, `destroy()` | reseed the TRNG (also done on every `keyDown()`); free + wipe |

`state()` (types in `ripar-emu.d.ts`):

- `screen` (`home homeHold scan review pulse armed qr message pairQr menu fail`), `job`, `nowMs`, `keyDown`
- `app`: the firmware loop: `busy` / `busyUntilMs` (pushing the last frame, or stalled), `stalled`, `passes`
- `display`: the last frame drawn, per `kind`:
  - `home`: `k1Short`, `battery`, `badge` (PAIRED / NOT PAIRED), hints
  - `scan`: `hint`, `progress`
  - `review` (also the device menu): `title`, `rows` (`label`, `value`, `tone`, `color`, `full`, `last`), `firstRow`, `rowsShown`, `totalRows`, `moreAbove`, `moreBelow`, `footer`, exactly as `ui_review()` pages them
  - `pulse`: `title`, `bpmText`, `beatsText`, `elapsedText`, `status`, `progress`, `heartBig`, `ringColor`
  - `qr`: `text` (the upper-cased UR), `title`, `footer`, `version`, `ecc`, `scale` (as `ui_qr()` would draw it)
  - `message`: `title`, `color`, `lines` (9 rows max, as `ui_message()`)
- `review` (all lines, ok, refusal, allSeen), `menu`, `pulse` (`finger`, `passed`, `bpm`, `beats`, `progress`, ...,
  and `sensor`: `fault`, `sampling`, FIFO level `fifo`, `ovf`, `lastRead`, `lastLost`, `reads`), `qr`, `message`, `scan`
- `k1`, `k1Short`, `p1`, `vault` (the vault derived from K1: MetaMask SimpleFactory CREATE2, salt 0, of the
  HybridDeleGator proxy owned by K1, `docs/PROTOCOL.md` 2.1; the companion deploys and funds exactly this account),
  `paired`, `context` (pinned contracts, counters, `notBefore`, and the layout v3 fields `pulseToken`, `perTxAutoCap`,
  `periodAutoCap`, `period`, `newPayeeNeedsHuman`, `unpanickedMandates`), `store` (`saves`, `contextHex`)
- `battery`, `buzz` (ok / err / beat counters: the buzzer), `serial` (the device's serial log lines)
- `emulator: true`, `emulatorId`, `firmwareId`, `testMode`, `hardware`, `selftest` (`passed`, `report`)

Colours are the firmware's `UI_*` values (`colorHex`). The companion draws with its own fonts; the row breaks,
page positions and footers already come from the device's layout rules.

## Parity

Identical to the device, because it is the device's code:

- **Screens and keys**: `fsm.h` `Fsm::step` gets one `FsmIn` per loop pass, with the key event and the debounced key
  state read together and `pulse_update().passed` polled in the same pass. The key timer is `io.cpp`'s (5 ms tick,
  30 ms debounce, press < 1 s, hold 2 s, hold 5 s, 8-event queue, 1 s event age, `io_flush` swallow on every screen
  change, before the new screen is drawn and again after its frame push), so "a press belongs to the screen it began
  on", HomeHold → PANIC, the menu and the 120 s timeouts behave as on the device.
- **Timing of a screen change**: every frame the device draws is a 320 x 240 RGB565 sprite pushed over SPI at 40 MHz
  (`ui.cpp` `flush()`, at least 30.72 ms) while the 5 ms key timer keeps running. The emulator keeps the firmware
  loop busy for 31 ms after every frame it draws and runs the post-draw key drain of a screen change when that push
  is done. So a press the key timer saw before the change pass (even one still inside the 30 ms debounce when the new
  screen is decided) is stable by then and swallowed: a SIGN press that began on PULSE, even 5 ms before ARMED
  appears, never signs; a hold that began on SCAN just before a request opened its review, or before the 120 s
  timeout drew HOME, never cancels the review or panics. A press that begins after the change pass (while the new
  frame is still being pushed) acts on the new screen.
- **Camera handoff**: `qrscan.cpp` `deliver()`: one payload slot, and the payload delivered last is not handed to the
  firmware again within 1000 ms (so no second error beep and no second `Fsm::touch()` for a code held in front of the
  camera); `qrscan_start()` restarts that filter.
- **Requests**: `UrDecoder` (single + multipart), `req_type_from_ur`, `parse_*_req`, `review_*`, the refusal
  messages, footers and titles of `flows.cpp`.
- **Signing**: `respond_*` (policy re-check, digest from the reviewed struct, signature, response CBOR), keys
  derived with `crypto.cpp` (K1 BIP-32 `m/44'/60'/0'/0/0`, P1 SLIP-10 `m/7951'/0'`), signed, verified (K1 also
  recovered) and wiped per signature as in `keys.cpp`; the `Save` rules of `deliver()` (Required / BestEffort /
  Restrict) against the emulated NVS.
- **Pulse gate**: the real `PulseDetector`, fed like `pulse.cpp` does (32-sample FIFO with rollover and OVF counter,
  the `fifo_read()` quirk that a full FIFO without overflow reads as 0 samples, +10 ms sample clock advanced over lost
  samples and re-synced after a stall, started when the review has been shown, stopped when PULSE / ARMED is left);
  the evidence of the signature is read from it. No samples for 250 ms (`setPulseFault('stall' | 'unplug')`) means
  not passed, so ARMED falls back to PULSE; after a stall the timestamp gap restarts the measurement.
- **Self-test** before anything else; a failure is terminal (`Screen::Fail`, nothing is signed).
- **Boot** (`app_setup()`): the vault is derived from K1; a stored context that is not layout v3 (v1 / v2 of older
  firmware), fails its CRC or flag bytes, or pins another vault than the derived one (e.g. an `exportNvs()` context
  restored with another seed) is dropped: **PAIRING LOST**, unpaired.

Checked by the tests: every signed response verifies with `make_request.py parse` and is byte-identical to
`make_request.py`'s `simulate()` for the same request, seed and salt / evidence (and to the `simulate` CLI itself for
the salt-free mandate and Privy responses).

Limits (what is not the hardware):

- **No camera**: `scan()` hands the decoded QR text to the device (no viewfinder, no quirc).
- **No LCD**: `state().display` is the screen as data; pixels, fonts and the pulse heart are the companion's.
- **No NVS**: the context blob (`context_serialize`, CRC and version checked on load) lives in memory; the companion
  persists `exportNvs()`. The seed is exported too, which a real device never does: **an emulated device is a demo,
  never put real funds behind it.**
- **Synthetic PPG**: a model of a thumb, not a thumb. The detector is real, so the gate behaves like the device's for
  what it is fed (spoof shapes are rejected, a lifted thumb disarms), but no sensor physics, ambient light or motion.
- **Entropy**: seed = `sha256(entropy)` from `crypto.getRandomValues()` (the device hashes TRNG, sensor, camera and
  timing noise); the TRNG is an HMAC-DRBG seeded from that entropy and reseeded on every key press.
- **Self-test**: the device's published vectors plus the independent Python reference vectors of
  `test/host/crypto_vectors.h` in place of the device's mbedTLS cross-check.
- **Timing**: one firmware loop pass per 5 ms of emulated time (the device loops every few ms), except for 31 ms after
  each frame drawn (the SPI push; the real draw also composes the sprite first, so it takes somewhat longer). Other
  work of a pass (parsing, signing, NVS writes) takes no emulated time. The LED-drive liveness challenge
  (`RIPAR_LED_CHALLENGE`, off in the device build) is not emulated; the buzzer and battery are counters.
- **Test mode** (`create({test: true})`): seed = `sha256("ripar demo seed")` (the `make_request.py` demo device),
  fixed TRNG and PPG seeds, `injectTrng()` allowed. Never use test mode keys for anything real.

## Tests

```bash
cd firmware
node emu/test/run_tests.mjs              # needs python (stdlib) on PATH or RIPAR_PYTHON; ~12 s (runs the audits too)
node emu/test/audit_key_window.mjs       # parity audits (also run by run_tests.mjs): the key window around a screen
node emu/test/audit_scan_repeat.mjs      #   change, the camera repeat filter, sensor stall / unplug / FIFO quirk,
node emu/test/audit_pulse_faults.mjs     #   a stalled loop and the key event age
bash emu/test/run_wasm_host_tests.sh     # test_fsm + test_pulse + test_vault compiled with Emscripten, run under Node
```

`run_tests.mjs` builds every request with `make_request.py build` (the Ripar contracts compiled into firmware v1.2,
the demo K1's derived vault `0xc36F625D426eBa8f1e0129276B284a939CD3A57D`), drives one deterministic device through pair
(multipart, no key 8) → pairing QR → device menu → mandate → co-sign (ERC-20 transfer + native) → deny from a co-sign
review → companion deny request → Privy → revoke → PANIC → reopen, plus the refusals (unpaired co-sign; a pairing with a
wrong key 8 vault, registry, DelegationManager, PulseCosignEnforcer or relay; a mandate / co-sign for another vault;
wrong chain, MANDATE WITHOUT PULSE CO-SIGN, UNKNOWN CALLDATA, stale epoch, expiry too far, PANIC FIRST re-pairing to
another chain (also after a revoke, and after a restart that lost an unsaved panic), wrong agent, unpaired PANIC), the
co-sign "becomes an AUTO payee" line against the v1.2 predicate (transfer of the mandate token, native send under native
terms with a lifetime cap, and none for approve, transferFrom, another token, a 0 amount, the zero payee, an unknown
mandate, a mandate without `newPayeeNeedsHuman`, a refused co-sign), the "may become an AUTO payee" line for an unknown or
revoked mandate, the review lines of v1.2 (derived vault, firmware table, agent id, AUTO period, FORGETS mandate ... killed
once the PANIC is relayed, the red PANIC line on a chain move after a panic), a second device with a minimal pairing that is refused PANIC FIRST until
it panics and then pairs to Monad (143), key semantics (a hold that began on another screen never panics, a hold carried
into a co-sign review never denies, a SIGN press that began on PULSE never signs whether it began 300, 20 or 5 ms before
ARMED was drawn, while a press that begins as ARMED is drawn signs, release between 1 and 2 s does nothing, 120 s
timeouts), the camera repeat filter, the pulse gate (square / sine spoofs, lifted thumb, and spoofs switched with the
thumb kept on: square 66 → sine 72 at 5 s on three PPG seeds, which the v1.1 detector armed about 6.5 s after the
switch, flat → sine, sine 60 → 72, sine → square), NVS failures, persistence / PAIRING LOST (corrupt, v2 layout,
version 2, a bad flag byte, another device's context), a failed self-test, missing hardware, and a non-test device
(its own derived vault, checked against `make_request.py`). Then `oracle.py verify` checks every response with
`make_request.py`, and the three `audit_*.mjs` parity audits run (each check there states the device outcome derived
from `flows.cpp` / `io.cpp` / `qrscan.cpp` / `pulse.cpp`; a `GAP` line is the emulator deviating from it).
