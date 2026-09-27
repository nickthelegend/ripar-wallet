// The Bluetooth fallback. Same UR parts as the QR path, carried as lines over the Ripar GATT service (ble-framing.ts),
// with the device's live STATUS. It turns the device's radio on (the device shows RADIO ON while BLE LINK runs), so the
// app offers it only as "use if the camera cannot read".
//
// The device accepts RX lines only while it is on SCAN (the user pressed SIGN on its Home screen; otherwise it ignores
// them and says so in STATUS.note). send() therefore waits for STATUS screen = SCAN (phase 'waiting-scan', which the UI
// turns into "press SIGN on the device"), then keeps cycling the parts, as the QR animation does, until STATUS leaves
// SCAN (docs/BLE_LINK.md §4.3: the device queues at most 32 lines, a dropped part only costs time: fountain codes).
//
// BleLink is written against the small BleTransport interface below; ble-plx.ts adapts react-native-ble-plx to it and
// the unit tests use a fake. No React Native imports here.
import { DEFAULT_FRAGMENT_LEN } from '@ripar/protocol';
import { LineAssembler, parseDeviceStatus, rxChunks, withKnownIp } from './ble-framing';
import { type WifiCredentials, encodeProvisioning } from './wifi-prov';
import {
  type DeviceLink,
  type DeviceRequest,
  type DeviceStatus,
  type Unsubscribe,
  DeviceCancelledError,
  DeviceLinkError,
  DeviceTimeoutError,
  ResponseBus,
  ValueSubject,
  requestParts,
} from './link';
import { utf8Decode } from '../lib/utf8';

/** what BleLink needs from a connected Ripar peripheral */
export interface BleTransport {
  /** the negotiated ATT MTU (23 when none was negotiated) */
  readonly mtu: number;
  /** one write to RX (<= MTU-3 bytes) */
  write(chunk: Uint8Array): Promise<void>;
  /** TX notifications */
  onData(cb: (chunk: Uint8Array) => void): Unsubscribe;
  /** STATUS notifications (a whole JSON value per notification when it fits; else read it) */
  onStatus(cb: (value: Uint8Array) => void): Unsubscribe;
  /** a read of STATUS (a long read returns the whole value) */
  readStatus(): Promise<Uint8Array>;
  onDisconnect(cb: (why: string) => void): Unsubscribe;
  /** re-enable TX / STATUS notifications that failed before the link was authenticated (bonding) */
  ensureSubscribed?(): void;
  /**
   * one write of the whole PROV value (Wi-Fi provisioning, TEMPORARY for testing, wifi-prov.ts): the firmware takes one
   * write as one value, so it is never split; beyond MTU-3 the BLE stack sends it as a long write (prepare + execute)
   */
  writeProvisioning?(value: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

export type BlePhase =
  | { kind: 'idle' }
  | { kind: 'waiting-scan'; since: number }
  | { kind: 'sending'; part: number; of: number; round: number }
  | { kind: 'sent'; at: number }
  | { kind: 'disconnected'; why: string };

export interface BleLinkOptions {
  fragLen?: number;
  /** how long send() waits for the user to put the device on SCAN (default 3 min) */
  scanWaitMs?: number;
  /** after a full round of parts, how long to watch STATUS before cycling them again (default 400 ms) */
  settleMs?: number;
  /** pause between two parts, so the device's 32-line queue is not flooded (default 25 ms) */
  partPauseMs?: number;
  /** stop cycling after this long on SCAN without the device completing (default 2 min) */
  cycleTimeoutMs?: number;
  /** clock + timers (tests inject fakes) */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class BleLink implements DeviceLink {
  readonly kind = 'ble' as const;
  readonly status = new ValueSubject<DeviceStatus | null>(null);
  readonly phase = new ValueSubject<BlePhase>({ kind: 'idle' });
  private bus = new ResponseBus();
  private lines: LineAssembler;
  private subs: Unsubscribe[] = [];
  private closed = false;
  private sendSeq = 0;
  private readonly opts: Required<Omit<BleLinkOptions, 'now' | 'sleep'>> & { now: () => number; sleep: (ms: number) => Promise<void> };

  constructor(
    private readonly transport: BleTransport,
    opts: BleLinkOptions = {},
  ) {
    this.opts = {
      fragLen: opts.fragLen ?? DEFAULT_FRAGMENT_LEN,
      scanWaitMs: opts.scanWaitMs ?? 180_000,
      settleMs: opts.settleMs ?? 400,
      partPauseMs: opts.partPauseMs ?? 25,
      cycleTimeoutMs: opts.cycleTimeoutMs ?? 120_000,
      now: opts.now ?? (() => Date.now()),
      sleep: opts.sleep ?? realSleep,
    };
    this.lines = new LineAssembler();
    this.subs.push(
      transport.onData((chunk) => {
        for (const line of this.lines.push(chunk)) {
          const t = line.trim();
          if (/^ur:/i.test(t)) this.bus.emit(t);
        }
      }),
      transport.onStatus((value) => this.takeStatus(value, true)),
      transport.onDisconnect((why) => {
        this.phase.set({ kind: 'disconnected', why });
        this.status.set(null);
      }),
    );
  }

  /** reads STATUS once (call after connecting; notifications keep it current afterwards) */
  async refreshStatus(): Promise<DeviceStatus | null> {
    const v = await this.transport.readStatus();
    // the read worked, so the link is authenticated now: notifications that failed before bonding can be enabled
    this.transport.ensureSubscribed?.();
    return this.takeStatus(v, false);
  }

  private takeStatus(value: Uint8Array, notified: boolean): DeviceStatus | null {
    let text: string;
    try {
      text = utf8Decode(value, true);
    } catch {
      return null;
    }
    const parsed = parseDeviceStatus(text, this.opts.now());
    const s = parsed ? withKnownIp(this.status.get(), parsed) : null;
    if (s) this.status.set(s);
    // a notification cut at the MTU is not valid JSON: read the whole value instead
    else if (notified) void this.transport.readStatus().then((v) => this.takeStatus(v, false), () => {});
    return s;
  }

  onResponse(cb: (urText: string) => void): Unsubscribe {
    return this.bus.on(cb);
  }

  /** resolves once the device is on SCAN (the user pressed SIGN on Home); rejects after scanWaitMs */
  private waitForScan(seq: number): Promise<void> {
    if (this.status.get()?.screen === 'SCAN') return Promise.resolve();
    this.phase.set({ kind: 'waiting-scan', since: this.opts.now() });
    return new Promise<void>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const off = this.status.subscribe((s) => {
        if (seq !== this.sendSeq || this.closed) {
          cleanup();
          reject(new DeviceCancelledError('superseded'));
        } else if (s?.screen === 'SCAN') {
          cleanup();
          resolve();
        }
      });
      const cleanup = () => {
        off();
        if (timer) clearTimeout(timer);
      };
      timer = setTimeout(() => {
        cleanup();
        reject(new DeviceTimeoutError('the device did not start scanning: press SIGN once on its Home screen'));
      }, this.opts.scanWaitMs);
    });
  }

  async send(req: DeviceRequest): Promise<void> {
    if (this.closed) throw new DeviceLinkError('the Bluetooth link is closed');
    const seq = ++this.sendSeq;
    const parts = requestParts(req, this.opts.fragLen);
    await this.waitForScan(seq);
    const leftScan = () => {
      const st = this.status.get();
      return !st || st.screen !== 'SCAN' || (!!st.scan && st.scan.of > 0 && st.scan.got >= st.scan.of);
    };
    const until = this.opts.now() + this.opts.cycleTimeoutMs;
    for (let round = 1; ; round++) {
      const chunks = rxChunks(parts, this.transport.mtu);
      for (let i = 0; i < chunks.length; i++) {
        if (seq !== this.sendSeq || this.closed) throw new DeviceCancelledError('superseded');
        // the device left SCAN (review opened, or the user cancelled) or has every part: stop writing
        if (leftScan()) {
          this.phase.set({ kind: 'sent', at: this.opts.now() });
          return;
        }
        this.phase.set({ kind: 'sending', part: i + 1, of: chunks.length, round });
        for (const c of chunks[i]!) await this.transport.write(c);
        if (this.opts.partPauseMs > 0 && chunks.length > 1) await this.opts.sleep(this.opts.partPauseMs);
      }
      // watch STATUS a moment: a complete set moves the device to REVIEW
      const deadline = this.opts.now() + this.opts.settleMs;
      while (this.opts.now() < deadline && !leftScan()) await this.opts.sleep(50);
      if (leftScan()) break;
      if (this.opts.now() >= until) {
        this.phase.set({ kind: 'sent', at: this.opts.now() });
        throw new DeviceTimeoutError('the device kept scanning without completing the request: check STATUS note, or use QR');
      }
    }
    this.phase.set({ kind: 'sent', at: this.opts.now() });
  }

  /**
   * TEMPORARY, for testing the Wi-Fi link: writes the Wi-Fi credentials to PROV as one JSON value (wifi-prov.ts). The
   * device (on HOME) then opens JOIN WI-FI <ssid>? and stores the network only after SIGN; a refusal comes back as the
   * STATUS note. Throws before writing anything when the credentials break a rule. The password is never logged or kept.
   */
  async provisionWifi(c: WifiCredentials): Promise<{ bytes: number }> {
    if (this.closed) throw new DeviceLinkError('the Bluetooth link is closed');
    const write = this.transport.writeProvisioning?.bind(this.transport);
    if (!write) throw new DeviceLinkError('this Bluetooth connection cannot send Wi-Fi settings');
    const value = encodeProvisioning(c);
    await write(value);
    return { bytes: value.length };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.sendSeq++;
    for (const u of this.subs) u();
    this.subs = [];
    this.bus.clear();
    this.phase.set({ kind: 'idle' });
    void this.transport.close().catch(() => {});
  }
}
