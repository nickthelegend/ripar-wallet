// Ripar device emulator: the Ripar Wallet firmware's portable modules + a port of its device driver (flows.cpp),
// compiled to WebAssembly (./ripar-emu-core.mjs + .wasm, built by emu/build.sh). ES module for browsers and Node 18+.
//
//   import { RiparEmulator } from './ripar-emu.mjs';
//   const emu = await RiparEmulator.create();                 // a new emulated device (keys from crypto.getRandomValues)
//   emu.key('press');                                         // HOME -> SCAN
//   emu.scan('UR:RIPAR-PAIR-REQ/...');                        // one UR (or one multipart part) per call
//   emu.key('press') ...                                      // page through the review; last page -> PULSE
//   emu.finger({ on: true, bpm: 72 });                        // synthetic thumb on the MAX30102
//   emu.tickUntil(s => s.screen === 'armed', { maxMs: 15000 });
//   emu.key('press');                                         // SIGN -> state().qr.text is the response UR
//
// Time only advances through tick() (and the key()/hold() helpers, which tick while the key is held, and scan(), which
// runs up to the firmware loop pass that reads the QR). A real-time UI calls tick(elapsedMs) from its animation loop
// and keyDown()/keyUp() from pointer / keyboard events. Every method except create() is synchronous.
//
// Timing model: every 5 ms the key timer ticks and the pulse sensor samples; the firmware loop runs one pass unless it
// is still pushing the last frame to the LCD (31 ms after every frame drawn, as the 320x240 SPI push takes on the
// device). A press belongs to the screen on which it began: one the key timer saw before a screen change is swallowed
// by the key drain that follows the new screen's frame push; one that begins after the change acts on the new screen.
import createRiparEmuCore from './ripar-emu-core.mjs';

let corePromise = null;

function loadCore(moduleArg) {
  if (!corePromise) corePromise = createRiparEmuCore(moduleArg || {});
  return corePromise;
}

function toHex(v, what) {
  if (v == null) return undefined;
  if (typeof v === 'string') {
    const s = v.startsWith('0x') || v.startsWith('0X') ? v.slice(2) : v;
    if (!/^([0-9a-fA-F]{2})*$/.test(s)) throw new TypeError(`${what}: not a hex string`);
    return s.toLowerCase();
  }
  const b = v instanceof Uint8Array ? v : ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
    : v instanceof ArrayBuffer ? new Uint8Array(v) : null;
  if (!b) throw new TypeError(`${what}: expected Uint8Array or hex string`);
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

/**
 * Key timings used by key(): a press is released well under 1 s; holds end past the 2 s / 5 s events. settleMs covers
 * the 30 ms debounce of the release plus the longest wait for the firmware loop (a 31 ms frame push in progress).
 */
export const KEY_TIMING = Object.freeze({ pressMs: 120, settleMs: 60, hold2Ms: 2300, hold5Ms: 5300 });

export class RiparEmulator {
  #api;
  #h;
  #test;
  #saves = 0;
  #destroyed = false;
  /** Called with exportNvs() after every successful context write (pairing, mandate, panic, ...). */
  onContextSaved = null;

  constructor(api, h, test) {
    this.#api = api;
    this.#h = h;
    this.#test = test;
  }

  /**
   * Powers on a new emulated device (self-test, first-run keys, context load, HOME).
   * opts.entropy: >= 32 bytes (Uint8Array | hex); default 64 bytes from crypto.getRandomValues().
   * opts.seed / opts.context: restore a device from exportNvs(). opts.test: deterministic test mode
   * (true, or {seed?, trngSeed?, ppgSeed?, selftestFault?}); the seed is then DEMO_SEED unless given.
   * opts.hardware: {camera?, pulseSensor?} (default both present; the device also boots without them).
   * opts.moduleArg: extra Emscripten module options (e.g. locateFile) for the first load.
   */
  static async create(opts = {}) {
    const m = await loadCore(opts.moduleArg);
    const api = {
      create: m.cwrap('emu_new', 'number', ['string']),
      del: m.cwrap('emu_delete', null, ['number']),
      lastError: m.cwrap('emu_last_error', 'string', []),
      state: m.cwrap('emu_state', 'string', ['number']),
      key: m.cwrap('emu_key', 'number', ['number', 'number']),
      tick: m.cwrap('emu_tick', 'number', ['number', 'number']),
      scan: m.cwrap('emu_scan', 'string', ['number', 'string']),
      finger: m.cwrap('emu_finger', 'string', ['number', 'string']),
      control: m.cwrap('emu_control', 'string', ['number', 'string']),
      context: m.cwrap('emu_context', 'string', ['number']),
      nvs: m.cwrap('emu_nvs', 'string', ['number']),
    };
    const test = opts.test ? (opts.test === true ? {} : { ...opts.test }) : null;
    const o = {};
    const entropy = opts.entropy ?? (test ? undefined : randomBytes(64));
    if (entropy != null) o.entropy = toHex(entropy, 'entropy');
    if (opts.seed != null) o.seed = toHex(opts.seed, 'seed');
    if (opts.context != null) o.context = toHex(opts.context, 'context');
    if (opts.clockMs != null) o.clockMs = opts.clockMs;
    if (opts.battery != null) o.battery = opts.battery;
    if (opts.hardware) o.hardware = { ...opts.hardware };
    if (test) {
      o.test = {};
      if (test.seed != null) o.test.seed = toHex(test.seed, 'test.seed');
      if (test.trngSeed != null) o.test.trngSeed = toHex(test.trngSeed, 'test.trngSeed');
      if (test.ppgSeed != null) o.test.ppgSeed = test.ppgSeed;
      if (test.selftestFault) o.test.selftestFault = true;
    }
    const h = api.create(JSON.stringify(o));
    if (!h) throw new Error('RiparEmulator: ' + api.lastError());
    const emu = new RiparEmulator(api, h, !!test);
    emu.#saves = emu.state().store.saves;
    return emu;
  }

  #check() {
    if (this.#destroyed) throw new Error('RiparEmulator: destroyed');
  }

  #json(text) {
    const v = JSON.parse(text);
    if (v && typeof v === 'object' && typeof v.error === 'string') throw new Error('RiparEmulator: ' + v.error);
    return v;
  }

  #after() {
    const s = this.state();
    if (s.store.saves !== this.#saves) {
      this.#saves = s.store.saves;
      if (typeof this.onContextSaved === 'function') this.onContextSaved(this.exportNvs());
    }
    return s;
  }

  /** Everything a UI needs to draw the 320x240 screen (see ripar-emu.d.ts EmuState). */
  state() {
    this.#check();
    return this.#json(this.#api.state(this.#h));
  }

  /** The emulated millis() clock. */
  get nowMs() {
    return this.state().nowMs;
  }

  /** Advances emulated time by `ms` (5 ms steps: key timer, sensor samples, one firmware loop pass each). */
  tick(ms) {
    this.#check();
    let left = Math.max(0, Math.floor(ms));
    while (left > 0) {
      const n = Math.min(left, 0x3fffffff);
      this.#api.tick(this.#h, n);
      left -= n;
    }
    return this.#after();
  }

  /** Ticks in steps of opts.stepMs (default 50) until pred(state) is true or opts.maxMs passed; returns the state. */
  tickUntil(pred, opts = {}) {
    const step = opts.stepMs ?? 50;
    const max = opts.maxMs ?? 30000;
    let s = this.state();
    for (let t = 0; t < max && !pred(s); t += step) s = this.tick(step);
    return s;
  }

  /** The SIGN (BOOT) key goes down now. The press belongs to the screen on display when it began. */
  keyDown() {
    this.#check();
    if (!this.#test) this.#api.control(this.#h, JSON.stringify({ addEntropy: toHex(randomBytes(32)) }));
    this.#api.key(this.#h, 1);
    return this.#after();
  }

  /** The SIGN key is released now (events are produced by the next 5 ms key-timer ticks). */
  keyUp() {
    this.#check();
    this.#api.key(this.#h, 0);
    return this.#after();
  }

  /** Holds the key for `ms` of emulated time, releases it and lets the release settle. */
  hold(ms) {
    this.keyDown();
    this.tick(ms);
    this.keyUp();
    return this.tick(KEY_TIMING.settleMs);
  }

  /** 'press' (< 1 s), 'hold2' (2.3 s: the 2 s event, released before 5 s) or 'hold5' (5.3 s). */
  key(kind = 'press') {
    switch (kind) {
      case 'press':
        return this.hold(KEY_TIMING.pressMs);
      case 'hold2':
        return this.hold(KEY_TIMING.hold2Ms);
      case 'hold5':
        return this.hold(KEY_TIMING.hold5Ms);
      default:
        throw new TypeError(`RiparEmulator.key: unknown kind ${kind}`);
    }
  }

  /**
   * The camera decodes one QR: a single-part UR or one part of a multipart UR (case-insensitive). Only read on the
   * SCAN screen. As on the device (qrscan.cpp), the payload that was delivered last is not delivered again within
   * 1000 ms (result 'repeat'), so a companion may call this for every decoded camera frame. A delivered QR is read by
   * the next firmware loop pass (time advances up to it, normally 5..35 ms). Returns {result: 'accepted'|'complete'|
   * 'error'|'ignored'|'repeat'|'empty'|'pending'|'camera-off', progress, received, seqLen, hint, screen}
   * ('pending': the loop is stalled by stallApp(); the QR waits in the handoff slot).
   */
  scan(qrText) {
    this.#check();
    const r = this.#json(this.#api.scan(this.#h, String(qrText)));
    this.#after();
    return r;
  }

  /** The synthetic thumb on the pulse sensor: {on, bpm, amplitude, noise, hrv, shape: 'ppg'|'sine'|'square'|'flat'}. */
  finger(p = {}) {
    this.#check();
    return this.#json(this.#api.finger(this.#h, JSON.stringify(p)));
  }

  /** The pinned device context: {hex (RAM), stored (NVS blob hex | null), paired, chainId, ...}. */
  exportContext() {
    this.#check();
    return this.#json(this.#api.context(this.#h));
  }

  /** The emulated NVS {emulator: true, seed, context}: pass it to create({seed, context}) to restore this device. */
  exportNvs() {
    this.#check();
    return this.#json(this.#api.nvs(this.#h));
  }

  /** Adds entropy to the emulated TRNG (non-test mode also does this on every keyDown()). */
  addEntropy(bytes) {
    this.#check();
    this.#json(this.#api.control(this.#h, JSON.stringify({ addEntropy: toHex(bytes, 'entropy') })));
  }

  /** Test mode: the next TRNG bytes (e.g. the 16-byte salt of the next co-sign / deny) are exactly these. */
  injectTrng(bytes) {
    this.#check();
    this.#json(this.#api.control(this.#h, JSON.stringify({ injectTrng: toHex(bytes, 'bytes') })));
  }

  /** Fault injection: every NVS context write fails (shows the respond.h Save rules). */
  setNvsFail(fail) {
    this.#check();
    this.#json(this.#api.control(this.#h, JSON.stringify({ nvsFail: !!fail })));
    return this.#after();
  }

  /**
   * Fault injection on the MAX30102 after power-on: 'stall' = the I2C bus fails (no samples are read while the sensor
   * keeps filling its FIFO; clearing it gives the overflow / re-sync path), 'unplug' = the sensor loses power (after
   * 'none' it samples nothing until the next measurement starts), 'none' = working. After 250 ms without samples the
   * firmware reports no finger / not passed, so ARMED falls back to PULSE.
   */
  setPulseFault(kind) {
    this.#check();
    this.#json(this.#api.control(this.#h, JSON.stringify({ pulseFault: String(kind) })));
    return this.#after();
  }

  /**
   * Fault injection: the firmware loop blocks for `ms` of emulated time from now (e.g. a slow flash write), while the
   * key timer, the camera handoff and the pulse sensor keep running. Does not advance time itself (use tick()).
   */
  stallApp(ms) {
    this.#check();
    this.#json(this.#api.control(this.#h, JSON.stringify({ appStallMs: Math.max(0, Math.floor(ms)) })));
    return this.#after();
  }

  /** The (fake) battery percentage on HOME (-1 = unknown). */
  setBattery(pct) {
    this.#check();
    this.#json(this.#api.control(this.#h, JSON.stringify({ battery: pct })));
    return this.#after();
  }

  /** Frees the emulated device (keys and buffers wiped). */
  destroy() {
    if (this.#destroyed) return;
    this.#api.del(this.#h);
    this.#destroyed = true;
  }
}

export default RiparEmulator;
