// The EMULATOR transport: the Ripar firmware compiled to WASM (firmware/emu/dist), driven exactly like the hardware
// minus the camera. present(frame) is what the emulated camera sees: while the device is on its SCAN screen, every
// new frame is handed to emu.scan() (the firmware's own repeat filter drops a payload repeated within 1 s). What the
// emulated LCD shows as a QR (state().qr.text) is reported through onRead().
//
// The emulated device is a demo: its NVS (seed + context) is persisted in localStorage by EmulatorHost, labelled
// EMULATOR - DEMO KEYS everywhere. Never put real funds behind it.
import type * as Emu from 'ripar-emu';
import { type DeviceTransport, ReadBus } from './transport';

export type EmuModule = typeof Emu;
export type RiparEmulator = Emu.RiparEmulator;
export type EmuState = Emu.EmuState;
export type EmuDisplay = Emu.Display;

export const EMULATOR_LABEL = 'EMULATOR - DEMO KEYS';

export class EmulatorTransport implements DeviceTransport {
  readonly kind = 'emulator' as const;
  readonly label = EMULATOR_LABEL;
  private bus = new ReadBus();
  private frame: string | null = null;
  private fedFrame: string | null = null;
  private fedAt = -Infinity;
  private lastRead: string | null = null;
  /** last scan() result (progress for the UI) */
  lastScan: Emu.ScanResult | null = null;

  constructor(readonly emu: RiparEmulator) {}

  present(frame: string | null): void {
    this.frame = frame;
    this.pump();
  }

  onRead(listener: (text: string) => void): () => void {
    return this.bus.on(listener);
  }

  resetReads(): void {
    this.lastRead = null;
  }

  /** advance emulated time and move frames / responses */
  tick(ms: number): EmuState {
    this.emu.tick(ms);
    return this.pump();
  }

  /**
   * The camera + LCD handoff for the current emulated instant: feed the presented frame while on SCAN (a new frame
   * at once, the same frame again after 1 s like a camera held in front of it), report a QR on the LCD.
   */
  pump(): EmuState {
    let s = this.emu.state();
    if (s.screen === 'scan' && this.frame) {
      const now = s.nowMs;
      if (this.frame !== this.fedFrame || now - this.fedAt >= 1000) {
        this.lastScan = this.emu.scan(this.frame);
        this.fedFrame = this.frame;
        this.fedAt = now;
        s = this.emu.state();
      }
    } else if (s.screen !== 'scan') {
      this.fedFrame = null;
    }
    const qr = (s.screen === 'qr' || s.screen === 'pairQr') && s.qr ? s.qr.text : null;
    if (qr && qr !== this.lastRead) {
      this.lastRead = qr;
      this.bus.emit(qr);
    } else if (!qr && s.screen === 'home') {
      // a QR left on screen is gone: the same text shown again later is a new read
      this.lastRead = null;
    }
    return s;
  }

  dispose(): void {
    this.bus.clear();
  }
}

// ------------------------------------------------------------------------------------------------ host (browser)
export interface EmulatorNvsRecord {
  /** always true: this is an emulated demo device, never a real key */
  emulator: true;
  warning: 'EMULATOR - DEMO KEYS - never put real funds behind this device';
  mode: 'demo-seed' | 'random';
  seed: string | null;
  context: string | null;
  savedAt: number;
}

export interface NvsStore {
  load(): EmulatorNvsRecord | null;
  save(r: EmulatorNvsRecord): void;
  clear(): void;
}

export interface BootOptions {
  /** power on a fresh device: 'demo-seed' = the public make_request demo seed (test mode), 'random' = new keys */
  fresh?: 'demo-seed' | 'random';
  moduleArg?: Record<string, unknown>;
}

type Listener = (s: EmuState) => void;

/**
 * Owns the one in-page emulated device: boot / restore from the persisted NVS, the real-time tick loop, key and
 * finger input, and state snapshots for the LCD view. The transport is what exchanges talk to.
 */
export class EmulatorHost {
  readonly transport: EmulatorTransport;
  private listeners = new Set<Listener>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastT = 0;
  private state: EmuState;
  private finger: Emu.FingerParams;

  private constructor(
    readonly emu: RiparEmulator,
    readonly mode: 'demo-seed' | 'random',
    private readonly nvs: NvsStore,
  ) {
    this.transport = new EmulatorTransport(emu);
    this.state = emu.state();
    this.finger = emu.finger({ on: false });
    emu.onContextSaved = (img) => this.persist(img);
    this.persist(emu.exportNvs());
  }

  static async boot(mod: EmuModule, nvs: NvsStore, opts: BootOptions = {}): Promise<EmulatorHost> {
    const saved = opts.fresh ? null : nvs.load();
    let emu: RiparEmulator;
    let mode: 'demo-seed' | 'random';
    const base = opts.moduleArg ? { moduleArg: opts.moduleArg } : {};
    if (saved && saved.emulator === true && saved.seed) {
      mode = saved.mode === 'demo-seed' ? 'demo-seed' : 'random';
      const ctx = saved.context ? { context: saved.context } : {};
      emu =
        mode === 'demo-seed'
          ? await mod.RiparEmulator.create({ ...base, test: { seed: saved.seed }, ...ctx })
          : await mod.RiparEmulator.create({ ...base, seed: saved.seed, ...ctx });
    } else {
      mode = opts.fresh ?? 'random';
      emu = await mod.RiparEmulator.create(mode === 'demo-seed' ? { ...base, test: true } : base);
    }
    return new EmulatorHost(emu, mode, nvs);
  }

  private persist(img: Emu.NvsImage): void {
    this.nvs.save({
      emulator: true,
      warning: 'EMULATOR - DEMO KEYS - never put real funds behind this device',
      mode: this.mode,
      seed: img.seed,
      context: img.context,
      savedAt: Date.now(),
    });
  }

  get snapshot(): EmuState {
    return this.state;
  }

  get fingerParams(): Emu.FingerParams {
    return this.finger;
  }

  subscribe(l: Listener): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }

  private publish(s: EmuState): void {
    // the synthetic thumb is lifted once a round is over (the pulse screens were left for the answer QR, a message
    // or Home), so the next review does not arm by itself as soon as its last page is passed
    const was = this.state.screen;
    if (this.finger.on && (was === 'pulse' || was === 'armed') && s.screen !== 'pulse' && s.screen !== 'armed') {
      this.finger = this.emu.finger({ ...this.finger, on: false });
    }
    this.state = s;
    for (const l of [...this.listeners]) l(s);
  }

  /** real-time loop: tick by the wall-clock delta (capped), pump the transport, publish */
  start(): void {
    if (this.timer) return;
    this.lastT = performance.now();
    this.timer = setInterval(() => {
      const t = performance.now();
      const dt = Math.min(250, Math.max(0, t - this.lastT));
      this.lastT = t;
      if (dt > 0) this.publish(this.transport.tick(dt));
    }, 16);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private downAt = 0;
  private upTimer: ReturnType<typeof setTimeout> | null = null;

  keyDown(): void {
    if (this.upTimer) {
      clearTimeout(this.upTimer);
      this.upTimer = null;
      this.emu.keyUp();
    }
    this.downAt = performance.now();
    this.emu.keyDown();
    this.publish(this.transport.pump());
  }

  /**
   * A physical key stays down for tens of milliseconds even on the quickest tap, and the firmware debounces for 30 ms:
   * a release that comes sooner (a synthetic click) is held back until the key has been down MIN_PRESS_MS.
   */
  keyUp(): void {
    const held = performance.now() - this.downAt;
    const up = () => {
      this.upTimer = null;
      this.emu.keyUp();
      this.publish(this.transport.pump());
    };
    if (held >= EmulatorHost.MIN_PRESS_MS) up();
    else this.upTimer = setTimeout(up, EmulatorHost.MIN_PRESS_MS - held);
  }

  static readonly MIN_PRESS_MS = 120;

  setFinger(p: Partial<Emu.FingerParams>): Emu.FingerParams {
    this.finger = this.emu.finger({ ...this.finger, ...p });
    this.publish(this.transport.pump());
    return this.finger;
  }

  destroy(): void {
    this.stop();
    this.listeners.clear();
    this.transport.dispose();
    this.emu.onContextSaved = null;
    this.emu.destroy();
  }
}
