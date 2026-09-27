// All device I/O goes through one interface. The device (or its EMULATOR) is only ever reached by QR: the companion
// shows request frames (the device's camera looks at them) and reads the device's single-part response QR.
//
//   HardwareQrTransport: frames are drawn on this screen as an animated QR; responses come from this computer's
//                        camera (qr-scanner).
//   EmulatorTransport:   the in-page WASM firmware "scans" the very frames the QR would show, and its response QR
//                        text is read back from its LCD state: the same path as hardware, minus the camera.
//
// DeviceExchange runs one request/response round over any transport: loop the parts, collect what the device shows,
// accept the first QR of an expected type that passes the caller's filter (e.g. the request's req-id).
import { UrDecoder, urRead } from '@ripar/protocol';

export type TransportKind = 'hardware' | 'emulator';

export interface DeviceTransport {
  readonly kind: TransportKind;
  /** what the UI must show next to anything this transport produced ('EMULATOR - DEMO KEYS' for the emulator) */
  readonly label: string;
  /** the QR frame the companion shows right now (what the device's camera sees); null = no QR shown */
  present(frame: string | null): void;
  /** QR texts read from the device's screen */
  onRead(listener: (text: string) => void): () => void;
  /** forget what was already read, so a QR still on the device's screen is reported again (new exchange) */
  resetReads(): void;
  dispose(): void;
}

/** listener bookkeeping shared by the transports */
export class ReadBus {
  private listeners = new Set<(t: string) => void>();
  on(l: (t: string) => void): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }
  emit(text: string): void {
    for (const l of [...this.listeners]) l(text);
  }
  clear(): void {
    this.listeners.clear();
  }
}

/** the physical device: this screen shows the frames, this computer's camera reads the answer */
export class HardwareQrTransport implements DeviceTransport {
  readonly kind = 'hardware' as const;
  readonly label = 'Ripar device (camera)';
  private bus = new ReadBus();
  private last: { text: string; at: number } | null = null;
  frame: string | null = null;

  present(frame: string | null): void {
    this.frame = frame;
  }

  onRead(listener: (text: string) => void): () => void {
    return this.bus.on(listener);
  }

  /** the camera decoded a QR (called for every decoded video frame; repeats within 1 s are dropped) */
  cameraRead(text: string, now = Date.now()): void {
    const t = text.trim();
    if (!t) return;
    if (this.last && this.last.text === t && now - this.last.at < 1000) return;
    this.last = { text: t, at: now };
    this.bus.emit(t);
  }

  resetReads(): void {
    this.last = null;
  }

  dispose(): void {
    this.bus.clear();
  }
}

// ------------------------------------------------------------------------------------------------ exchange
export interface Scheduler {
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(h: unknown): void;
}

export const realScheduler: Scheduler = {
  setInterval: (fn, ms) => globalThis.setInterval(fn, ms),
  clearInterval: (h) => globalThis.clearInterval(h as ReturnType<typeof setInterval>),
};

export interface ExchangeOptions {
  /** request frames to loop (upper-case UR parts); [] for device-initiated messages (panic, pairing QR, ...) */
  parts: string[];
  /** response UR types to accept, e.g. ['ripar-cosign', 'ripar-deny'] */
  expect: string[];
  /** ms per frame (default 300) */
  frameMs?: number;
  /** extra filter on a response of an expected type (e.g. req-id echo); a rejected QR is reported as ignored */
  accept?: (ur: string) => boolean;
}

export type ExchangeEvent =
  | { kind: 'frame'; index: number; total: number; frame: string }
  | { kind: 'ignored'; text: string; reason: string }
  | { kind: 'response'; ur: string; type: string };

export class ExchangeCancelled extends Error {
  override name = 'ExchangeCancelled';
}

/**
 * One request/response round. start() begins looping the frames through transport.present() and resolves with the
 * first response QR (single-part UR text) whose type is expected and which passes `accept`.
 */
export class DeviceExchange {
  private timer: unknown = null;
  private index = 0;
  private off: (() => void) | null = null;
  private listeners = new Set<(e: ExchangeEvent) => void>();
  private settle: { resolve: (ur: string) => void; reject: (e: Error) => void } | null = null;
  done = false;

  constructor(
    readonly transport: DeviceTransport,
    readonly opts: ExchangeOptions,
    private readonly scheduler: Scheduler = realScheduler,
  ) {}

  on(l: (e: ExchangeEvent) => void): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }

  private emit(e: ExchangeEvent): void {
    for (const l of [...this.listeners]) l(e);
  }

  get frameIndex(): number {
    return this.index;
  }

  start(): Promise<string> {
    if (this.settle) throw new Error('exchange already started');
    const p = new Promise<string>((resolve, reject) => (this.settle = { resolve, reject }));
    this.transport.resetReads();
    this.off = this.transport.onRead((t) => this.read(t));
    const { parts } = this.opts;
    if (parts.length) {
      this.show(0);
      if (parts.length > 1) this.timer = this.scheduler.setInterval(() => this.show(this.index + 1), this.opts.frameMs ?? 300);
    } else {
      this.transport.present(null);
    }
    return p;
  }

  private show(i: number): void {
    const parts = this.opts.parts;
    this.index = i % parts.length;
    const frame = parts[this.index]!;
    this.transport.present(frame);
    this.emit({ kind: 'frame', index: this.index, total: parts.length, frame });
  }

  /** a QR read from the device (also usable for a pasted response) */
  read(text: string): void {
    if (this.done) return;
    let type: string;
    let ur = text.trim();
    try {
      const dec = new UrDecoder();
      const r = dec.receive(ur);
      if (r !== 'complete' || !dec.result) {
        this.emit({ kind: 'ignored', text: ur, reason: 'not a complete single-part UR' });
        return;
      }
      type = dec.result.type;
      urRead(ur); // CRC + bytewords check
    } catch (e) {
      this.emit({ kind: 'ignored', text: ur, reason: (e as Error).message });
      return;
    }
    if (!this.opts.expect.includes(type)) {
      this.emit({ kind: 'ignored', text: ur, reason: `unexpected ${type}` });
      return;
    }
    if (this.opts.accept && !this.opts.accept(ur)) {
      this.emit({ kind: 'ignored', text: ur, reason: `${type} does not answer this request` });
      return;
    }
    ur = ur.toUpperCase();
    this.finish();
    this.emit({ kind: 'response', ur, type });
    this.settle?.resolve(ur);
  }

  cancel(): void {
    if (this.done) return;
    this.finish();
    this.settle?.reject(new ExchangeCancelled('cancelled'));
  }

  private finish(): void {
    this.done = true;
    if (this.timer !== null) this.scheduler.clearInterval(this.timer);
    this.timer = null;
    this.off?.();
    this.off = null;
    this.transport.present(null);
  }
}
