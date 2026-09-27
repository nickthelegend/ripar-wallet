// The air-gapped default. send() puts the request's UR parts on show (the AnimatedQr component loops them at
// `frameMs`, ~300 ms per frame, and the device's camera reads them); the device's answer QR is read with this phone's
// camera and handed to cameraRead(). Nothing here touches a radio. Pure: no React Native imports.
import { DEFAULT_FRAGMENT_LEN } from '@ripar/protocol';
import { type DeviceLink, type DeviceRequest, type Unsubscribe, ResponseBus, ValueSubject, requestParts } from './link';

export interface QrFrames {
  parts: string[];
  frameMs: number;
  /** changes with every send(), so the player restarts at part 1 */
  seq: number;
}

export class QrLink implements DeviceLink {
  readonly kind = 'qr' as const;
  /** the request on show (null = nothing to show: the phone only reads) */
  readonly frames = new ValueSubject<QrFrames | null>(null);
  private bus = new ResponseBus();
  private last: { text: string; at: number } | null = null;
  private seq = 0;

  constructor(
    private frameMs = 300,
    private fragLen = DEFAULT_FRAGMENT_LEN,
  ) {}

  configure(opts: { frameMs?: number; fragLen?: number }): void {
    if (opts.frameMs) this.frameMs = Math.min(2000, Math.max(80, opts.frameMs));
    if (opts.fragLen) this.fragLen = Math.min(200, Math.max(20, opts.fragLen));
  }

  async send(req: DeviceRequest): Promise<void> {
    this.last = null;
    this.frames.set({ parts: requestParts(req, this.fragLen), frameMs: this.frameMs, seq: ++this.seq });
  }

  /** stop showing the request (answer received, or the round was cancelled) */
  stopPresenting(): void {
    if (this.frames.get()) this.frames.set(null);
  }

  onResponse(cb: (urText: string) => void): Unsubscribe {
    return this.bus.on(cb);
  }

  /** the camera decoded a QR (called for every decoded frame; the same text within 1 s is reported once) */
  cameraRead(text: string, now = Date.now()): void {
    const t = text.trim();
    if (!t) return;
    if (this.last && this.last.text === t && now - this.last.at < 1000) return;
    this.last = { text: t, at: now };
    this.bus.emit(t);
  }

  /** forget the last read, so a QR still on the device's screen is reported again (a new round) */
  resetReads(): void {
    this.last = null;
  }

  close(): void {
    this.stopPresenting();
    this.bus.clear();
  }
}
