// The demo link: the Ripar firmware emulator (firmware/emu, the device's own C++ compiled to WASM) running inside a
// hidden WebView (EmulatorHost.tsx, page built by scripts/build-emu-html.mjs). send() hands the UR parts to the page,
// which loops them into the emulated camera while the device is on SCAN, exactly like the QR on this screen would be
// seen; whatever the emulated LCD shows as a QR comes back through onResponse. Keys and the synthetic thumb are driven
// from the app. Its keys are DEMO KEYS: never put real funds behind it. No React Native imports here.
import { DEFAULT_FRAGMENT_LEN } from '@ripar/protocol';
import { type DeviceLink, type DeviceRequest, type DeviceStatus, type Unsubscribe, ResponseBus, ValueSubject, requestParts } from './link';

/** the part of the emulator's state the page posts (see scripts/emu-bridge.js) */
export interface EmuSnapshot {
  screen: string;
  job: string;
  paired: boolean;
  k1: string;
  vault: string;
  display: EmuDisplay;
  qr: { text: string; signed: boolean; title: string } | null;
  scan: { active: boolean; progress: number; received: number; seqLen: number; hint: string };
  pulse: { finger: boolean; passed: boolean; bpm: number; beats: number; minBeats: number; progress: number };
  review: { ok: boolean; refusal: string; allSeen: boolean; title: string } | null;
  message: { title: string; body: string; color: string } | null;
  thumb: boolean;
  nowMs: number;
}

export type EmuTone = 'normal' | 'good' | 'warn' | 'bad' | 'dim' | 'accent';

export type EmuDisplay =
  | { kind: 'boot'; seq: number; title: string; lines: string[] }
  | { kind: 'home'; seq: number; k1Short: string; battery: number; paired: boolean; badge: string; badgeColorHex: string; hints: string[] }
  | { kind: 'message'; seq: number; title: string; colorHex: string; lines: string[] }
  | { kind: 'scan'; seq: number; hint: string; progress: number; progressText: string }
  | {
      kind: 'review';
      seq: number;
      title: string;
      rows: { label: string; value: string; tone: EmuTone; colorHex: string; full: boolean; last: boolean }[];
      moreAbove: boolean;
      moreBelow: boolean;
      footer: string;
    }
  | {
      kind: 'pulse';
      seq: number;
      title: string;
      bpmText: string;
      beatsText: string;
      elapsedText: string;
      status: string;
      statusColorHex: string;
      progress: number;
      passed: boolean;
      finger: boolean;
      heartBig: boolean;
      ringColorHex: string;
    }
  | { kind: 'qr'; seq: number; title: string; footer: string; text: string };

export type EmuToPage =
  | { t: 'boot'; nvs: { seed: string; context: string | null; mode: 'demo-seed' | 'random' } | null; fresh?: 'demo-seed' | 'random' }
  | { t: 'present'; parts: string[] | null; frameMs: number }
  | { t: 'keyDown' }
  | { t: 'keyUp' }
  | { t: 'finger'; on: boolean };

export type EmuFromPage =
  | { t: 'ready' }
  | { t: 'booted'; mode: 'demo-seed' | 'random' }
  | { t: 'state'; s: EmuSnapshot }
  | { t: 'read'; text: string }
  | { t: 'nvs'; nvs: { seed: string | null; context: string | null }; mode: 'demo-seed' | 'random' }
  | { t: 'error'; message: string };

const SCREEN_MAP: Record<string, DeviceStatus['screen']> = {
  home: 'HOME',
  homeHold: 'HOME',
  scan: 'SCAN',
  review: 'REVIEW',
  pulse: 'PULSE',
  armed: 'ARMED',
  qr: 'QR',
  pairQr: 'QR',
  message: 'MESSAGE',
  fail: 'MESSAGE',
  menu: 'MENU',
};

/** the emulator's state as a DeviceStatus (the same shape Bluetooth STATUS has) */
export function statusOfSnapshot(s: EmuSnapshot, now = Date.now()): DeviceStatus {
  return {
    v: 1,
    screen: SCREEN_MAP[s.screen] ?? s.screen.toUpperCase(),
    paired: s.paired,
    k1: s.k1 || null,
    scan: s.screen === 'scan' ? { got: s.scan.received, of: s.scan.seqLen } : null,
    radio: 'off',
    fw: 'ripar-emulator v1',
    note: null,
    at: now,
  };
}

export class EmulatorLink implements DeviceLink {
  readonly kind = 'emulator' as const;
  readonly status = new ValueSubject<DeviceStatus | null>(null);
  readonly snapshot = new ValueSubject<EmuSnapshot | null>(null);
  private bus = new ResponseBus();

  constructor(
    readonly post: (m: EmuToPage) => void,
    private frameMs = 300,
    private fragLen = DEFAULT_FRAGMENT_LEN,
  ) {}

  configure(opts: { frameMs?: number; fragLen?: number }): void {
    if (opts.frameMs) this.frameMs = opts.frameMs;
    if (opts.fragLen) this.fragLen = opts.fragLen;
  }

  /** a message from the page */
  receive(m: EmuFromPage): void {
    if (m.t === 'state') {
      this.snapshot.set(m.s);
      this.status.set(statusOfSnapshot(m.s));
    } else if (m.t === 'read') {
      this.bus.emit(m.text);
    }
  }

  async send(req: DeviceRequest): Promise<void> {
    this.post({ t: 'present', parts: requestParts(req, this.fragLen), frameMs: this.frameMs });
  }

  stopPresenting(): void {
    this.post({ t: 'present', parts: null, frameMs: this.frameMs });
  }

  onResponse(cb: (urText: string) => void): Unsubscribe {
    return this.bus.on(cb);
  }

  keyDown(): void {
    this.post({ t: 'keyDown' });
  }

  keyUp(): void {
    this.post({ t: 'keyUp' });
  }

  setThumb(on: boolean): void {
    this.post({ t: 'finger', on });
  }

  close(): void {
    this.stopPresenting();
    this.bus.clear();
  }
}
