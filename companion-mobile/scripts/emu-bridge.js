// Runs inside the emulator WebView, after the firmware emulator (RiparEmulator) is defined. A port of the web
// companion's EmulatorHost + EmulatorTransport (companion/src/device/emulator.ts): the real-time tick loop, the camera
// handoff (the presented UR parts are looped into emu.scan() while the device is on SCAN, a frame every frameMs, the
// same frame again after 1 s like a camera held in front of a QR), the LCD QR read-back, key and thumb input.
// Messages: app -> page via window.riparReceive(json); page -> app via ReactNativeWebView.postMessage(json).
/* global RiparEmulator, WASM_B64 */
(function () {
  const post = (m) => {
    try {
      window.ReactNativeWebView.postMessage(JSON.stringify(m));
    } catch (e) {
      /* not in a WebView */
    }
  };
  let emu = null;
  let mode = 'random';
  let timer = null;
  let lastT = 0;
  let finger = { on: false };
  let parts = null;
  let frameMs = 300;
  let frameIdx = 0;
  let frameAt = 0;
  let fedFrame = null;
  let fedAt = -Infinity;
  let lastRead = null;
  let lastPostAt = 0;
  let lastSig = '';
  let downAt = 0;
  let upTimer = null;

  function wasmBytes() {
    const bin = atob(WASM_B64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  const moduleArg = {
    instantiateWasm(imports, receive) {
      WebAssembly.instantiate(wasmBytes(), imports).then(
        (r) => receive(r.instance),
        (e) => post({ t: 'error', message: 'wasm: ' + String(e) }),
      );
      return {};
    },
  };

  function snapshot(s) {
    return {
      screen: s.screen,
      job: s.job,
      paired: s.paired,
      k1: s.k1,
      vault: s.vault,
      display: s.display,
      qr: s.qr ? { text: s.qr.text, signed: s.qr.signed, title: s.qr.title } : null,
      scan: s.scan,
      pulse: {
        finger: s.pulse.finger,
        passed: s.pulse.passed,
        bpm: s.pulse.bpm,
        beats: s.pulse.beats,
        minBeats: s.pulse.minBeats,
        progress: s.pulse.progress,
      },
      review: s.review ? { ok: s.review.ok, refusal: s.review.refusal, allSeen: s.review.allSeen, title: s.review.title } : null,
      message: s.message ? { title: s.message.title, body: s.message.body, color: s.message.color } : null,
      thumb: finger.on,
      nowMs: s.nowMs,
    };
  }

  /** camera + LCD handoff for the current emulated instant (EmulatorTransport.pump) */
  function pump() {
    let s = emu.state();
    const t = performance.now();
    if (parts && parts.length > 1 && t - frameAt >= frameMs) {
      frameIdx = (frameIdx + 1) % parts.length;
      frameAt = t;
    }
    const frame = parts ? parts[frameIdx % parts.length] : null;
    if (s.screen === 'scan' && frame) {
      if (frame !== fedFrame || s.nowMs - fedAt >= 1000) {
        emu.scan(frame);
        fedFrame = frame;
        fedAt = s.nowMs;
        s = emu.state();
      }
    } else if (s.screen !== 'scan') {
      fedFrame = null;
    }
    const qr = (s.screen === 'qr' || s.screen === 'pairQr') && s.qr ? s.qr.text : null;
    if (qr && qr !== lastRead) {
      lastRead = qr;
      post({ t: 'read', text: qr });
    } else if (!qr && s.screen === 'home') {
      lastRead = null;
    }
    return s;
  }

  function publish(s, force) {
    // lift the synthetic thumb once a round is over, so the next review does not arm by itself
    if (finger.on && s.screen !== 'pulse' && s.screen !== 'armed' && s.screen !== 'review') {
      finger = emu.finger({ on: false });
    }
    const sig = s.screen + ':' + (s.display && s.display.seq) + ':' + finger.on;
    const t = performance.now();
    if (!force && sig === lastSig && t - lastPostAt < 250) return;
    lastSig = sig;
    lastPostAt = t;
    post({ t: 'state', s: snapshot(s) });
  }

  function start() {
    if (timer) return;
    lastT = performance.now();
    timer = setInterval(() => {
      const t = performance.now();
      const dt = Math.min(250, Math.max(0, t - lastT));
      lastT = t;
      if (dt > 0 && emu) {
        emu.tick(dt);
        publish(pump(), false);
      }
    }, 20);
  }

  function saveNvs(img) {
    post({ t: 'nvs', nvs: { seed: img.seed, context: img.context }, mode });
  }

  async function boot(m) {
    try {
      if (timer) clearInterval(timer);
      timer = null;
      if (emu) emu.destroy();
      emu = null;
      const saved = m.fresh ? null : m.nvs;
      if (saved && saved.seed) {
        mode = saved.mode === 'demo-seed' ? 'demo-seed' : 'random';
        const ctx = saved.context ? { context: saved.context } : {};
        emu =
          mode === 'demo-seed'
            ? await RiparEmulator.create({ moduleArg, test: { seed: saved.seed }, ...ctx })
            : await RiparEmulator.create({ moduleArg, seed: saved.seed, ...ctx });
      } else {
        mode = m.fresh || 'random';
        emu = await RiparEmulator.create(mode === 'demo-seed' ? { moduleArg, test: true } : { moduleArg });
      }
      finger = emu.finger({ on: false });
      emu.onContextSaved = saveNvs;
      saveNvs(emu.exportNvs());
      post({ t: 'booted', mode });
      start();
      publish(pump(), true);
    } catch (e) {
      post({ t: 'error', message: String((e && e.message) || e) });
    }
  }

  window.riparReceive = function (json) {
    let m;
    try {
      m = JSON.parse(json);
    } catch (e) {
      return;
    }
    if (m.t === 'boot') return void boot(m);
    if (!emu) return;
    if (m.t === 'present') {
      parts = m.parts && m.parts.length ? m.parts : null;
      frameMs = m.frameMs || 300;
      frameIdx = 0;
      frameAt = performance.now();
      fedFrame = null;
      lastRead = null;
      publish(pump(), true);
    } else if (m.t === 'keyDown') {
      if (upTimer) {
        clearTimeout(upTimer);
        upTimer = null;
        emu.keyUp();
      }
      downAt = performance.now();
      emu.keyDown();
      publish(pump(), true);
    } else if (m.t === 'keyUp') {
      // the firmware debounces for 30 ms: a synthetic tap is held down at least 120 ms
      const held = performance.now() - downAt;
      const up = () => {
        upTimer = null;
        emu.keyUp();
        publish(pump(), true);
      };
      if (held >= 120) up();
      else upTimer = setTimeout(up, 120 - held);
    } else if (m.t === 'finger') {
      finger = emu.finger({ on: !!m.on, bpm: 72 });
      publish(pump(), true);
    }
  };

  post({ t: 'ready' });
})();
