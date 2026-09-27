// The Wi-Fi link: TEMPORARY, for testing only. The same UR parts as the QR and Bluetooth paths, carried over plain HTTP
// on the local network. It needs the device's Wi-Fi ON (device menu), so while it runs the Ripar is NOT air-gapped: QR
// stays the default and the recommended link.
//
// Device side (firmware contract, docs/WIFI_LINK.md; firmware/src/wifi_proto.cpp):
//   address   the IP on the device's Home screen / in STATUS "ip" (mDNS ripar-xxxx.local may not resolve on Android)
//   GET  /status   the STATUS JSON (as over BLE, plus "wifi":"off|connecting|on" and "ip")
//   POST /rx       text/plain, one or more UR lines each ending LF; taken only while the device is on SCAN (200 + STATUS),
//                  else 409 + STATUS whose note says why
//   GET  /tx       the UR text of the QR on the device's screen; 204 when it shows none
//   every request carries X-Ripar-Code: <the 8-digit code on the device's Home screen>; 401 on a wrong code, 429 +
//   Retry-After while the device locks the link after repeated wrong codes. One connection at a time: the requests
//   are serialised here.
//
// As with Bluetooth, the device takes request lines only on SCAN (the user pressed SIGN on its Home screen): send()
// waits for STATUS SCAN (phase 'waiting-scan', which the UI turns into "press SIGN on the device"), POSTs the parts in
// small batches and repeats them until STATUS leaves SCAN (a dropped part only costs time: fountain codes). STATUS and
// TX are polled every ~700 ms. An answer is handed to onResponse when the device shows a QR or /tx changes; the caller
// filters and verifies it exactly as it does a camera read.
//
// Written against a fetch-like function (the app passes the global fetch; Android allows cleartext HTTP to the LAN IP,
// see plugins/with-ripar-android.js). No React Native imports here: unit-tested in test/wifi.test.ts against a local
// HTTP server whose far end is the emulated firmware.
import { DEFAULT_FRAGMENT_LEN } from '@ripar/protocol';
import { isIpv4, parseDeviceStatus, withKnownIp } from './ble-framing';
import type { BlePhase } from './ble-link';
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

/** the same phases as the Bluetooth link, so the round UI treats both alike */
export type WifiPhase = BlePhase;

export type WifiErrorKind = 'bad-address' | 'bad-code' | 'unauthorized' | 'locked' | 'unreachable' | 'not-scanning' | 'not-ripar' | 'http' | 'closed';

export class WifiLinkError extends DeviceLinkError {
  override name = 'WifiLinkError';
  constructor(
    readonly kind: WifiErrorKind,
    message: string,
    readonly httpStatus?: number,
    /** the device's own note (409) */
    readonly note?: string,
    /** 429: how long the device keeps the link locked (Retry-After) */
    readonly retryAfterMs?: number,
  ) {
    super(message);
  }
}

/** the link's health as the poller sees it */
export type WifiConn =
  | { state: 'connecting' }
  | { state: 'online'; at: number }
  /** polls have been failing: the device is off the network, Wi-Fi was turned off, or the phone left the network */
  | { state: 'offline'; message: string; since: number }
  /** the device refused the code (a new code after every restart of the Ripar): polling stopped */
  | { state: 'unauthorized'; message: string }
  /** the device locked the link after repeated wrong codes (from any client): polling pauses until `until` */
  | { state: 'locked'; message: string; until: number }
  | { state: 'closed' };

/** the part of fetch the link uses (the global fetch satisfies it; tests may pass their own) */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<{ status: number; text(): Promise<string>; headers?: { get(name: string): string | null } }>;

export interface WifiLinkOptions {
  /** the device's address: an IPv4 (optionally :port) or a host name such as ripar-3f9a.local */
  host: string;
  /** the 8-digit link code on the device's Home screen while Wi-Fi is on (spaces / dashes are ignored) */
  code: string;
  fetch?: FetchLike;
  fragLen?: number;
  /** STATUS / TX poll period (default 700 ms) */
  pollMs?: number;
  /** per-request timeout (default 4 s) */
  requestTimeoutMs?: number;
  /** extra attempts after a network error or timeout (default 2; the poller itself does not retry) */
  retries?: number;
  retryDelayMs?: number;
  /** how long send() waits for the user to put the device on SCAN (default 3 min) */
  scanWaitMs?: number;
  /** stop repeating the parts after this long on SCAN without the device completing (default 2 min) */
  cycleTimeoutMs?: number;
  /** after a full round of parts, how long to watch STATUS before repeating them (default 800 ms) */
  settleMs?: number;
  /** at most this many lines / bytes per POST /rx (defaults 4 / 1024) */
  batchLines?: number;
  batchBytes?: number;
  /** consecutive failed polls before the link reports 'offline' (default 3) */
  offlineAfter?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** the device answers with these screens once it has the whole request: the send is done */
const PAST_SCAN = new Set(['REVIEW', 'PULSE', 'ARMED', 'QR', 'MESSAGE']);

// ------------------------------------------------------------------------------------------------ addresses, code
/**
 * The base URL for what the user typed: "192.168.1.23", "192.168.1.23:8080", "ripar-3f9a.local", "http://..." (a path
 * is dropped). Plain http only (the device serves no TLS). Throws WifiLinkError('bad-address') with the reason.
 */
export function wifiBaseUrl(input: string): string {
  let t = input.trim();
  if (!t) throw new WifiLinkError('bad-address', 'Enter the IP address the Ripar shows (e.g. 192.168.1.23).');
  if (/^https:\/\//i.test(t)) throw new WifiLinkError('bad-address', 'The Ripar serves plain http on the local network: drop https://.');
  t = t.replace(/^http:\/\//i, '');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) throw new WifiLinkError('bad-address', 'Only an IP address or a .local name, over http.');
  t = t.replace(/[/?#].*$/, '');
  const m = /^([A-Za-z0-9.-]+)(?::(\d{1,5}))?$/.exec(t);
  if (!m) throw new WifiLinkError('bad-address', `"${input.trim().slice(0, 40)}" is not an address: type the IP the Ripar shows, e.g. 192.168.1.23.`);
  const host = m[1]!.toLowerCase();
  const port = m[2] ? Number(m[2]) : 80;
  if (port < 1 || port > 65535) throw new WifiLinkError('bad-address', `Port ${port} is out of range.`);
  if (/^[\d.]+$/.test(host)) {
    if (!isIpv4(host)) throw new WifiLinkError('bad-address', `${host} is not an IPv4 address (four numbers 0-255, e.g. 192.168.1.23).`);
  } else if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(host)) {
    throw new WifiLinkError('bad-address', `${host} is not a valid host name.`);
  }
  return `http://${host}${port === 80 ? '' : `:${port}`}`;
}

/** true for an IPv4 address on a private / link-local / loopback range (where a Ripar on your Wi-Fi can be) */
export function isLanIpv4(ip: string): boolean {
  if (!isIpv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number) as [number, number];
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

/** the 8 digits of a code as typed ("1234 5678", "1234-5678"), or null when it is not 8 digits */
export function normalizeWifiCode(input: string): string | null {
  const d = input.replace(/[\s-]/g, '');
  return /^\d{8}$/.test(d) ? d : null;
}

/** the device's note from a 409 body (JSON {"note"} / {"error"}, or short plain text), printable ASCII only */
export function noteOf(body: string): string | null {
  const t = body.trim();
  if (!t) return null;
  let v: unknown = t;
  try {
    const o = JSON.parse(t) as unknown;
    if (o && typeof o === 'object' && !Array.isArray(o)) {
      const r = o as Record<string, unknown>;
      v = r.note ?? r.error ?? r.message ?? null;
    }
  } catch {
    /* plain text */
  }
  if (typeof v !== 'string') return null;
  const s = v.replace(/[^\x20-\x7e]+/g, ' ').trim();
  return s ? s.slice(0, 180) : null;
}

/** groups lines into POST bodies of at most `maxLines` lines and (except a single longer line) `maxBytes` bytes */
export function rxBatches(parts: readonly string[], maxLines = 4, maxBytes = 1024): string[][] {
  const out: string[][] = [];
  let cur: string[] = [];
  let bytes = 0;
  for (const p of parts) {
    const n = p.length + 1;
    if (cur.length && (cur.length >= maxLines || bytes + n > maxBytes)) {
      out.push(cur);
      cur = [];
      bytes = 0;
    }
    cur.push(p);
    bytes += n;
  }
  if (cur.length) out.push(cur);
  return out;
}

// ------------------------------------------------------------------------------------------------ the link
export class WifiLink implements DeviceLink {
  readonly kind = 'wifi' as const;
  readonly status = new ValueSubject<DeviceStatus | null>(null);
  readonly phase = new ValueSubject<WifiPhase>({ kind: 'idle' });
  readonly conn = new ValueSubject<WifiConn>({ state: 'connecting' });
  /** the base URL requests go to (http://a.b.c.d[:port]) */
  readonly baseUrl: string;
  private readonly code: string;
  private readonly fetchFn: FetchLike;
  private bus = new ResponseBus();
  private closed = false;
  private polling = false;
  private sendSeq = 0;
  private failures = 0;
  private inflight = new Set<AbortController>();
  private queue: Promise<unknown> = Promise.resolve();
  /** the /tx text seen by the last poll (undefined: never polled) */
  private lastTx: string | null | undefined = undefined;
  /** an answer was handed out while the device shows its current QR screen */
  private qrEmitted = false;
  private readonly opts: Required<Omit<WifiLinkOptions, 'host' | 'code' | 'fetch'>>;

  constructor(opts: WifiLinkOptions) {
    this.baseUrl = wifiBaseUrl(opts.host);
    const code = normalizeWifiCode(opts.code);
    if (!code) throw new WifiLinkError('bad-code', "The code is the 8 digits on the Ripar's Home screen while Wi-Fi is on (CODE 1234 5678).");
    this.code = code;
    const f = opts.fetch ?? (globalThis as { fetch?: FetchLike }).fetch;
    if (!f) throw new WifiLinkError('unreachable', 'no fetch in this environment');
    this.fetchFn = f;
    this.opts = {
      fragLen: opts.fragLen ?? DEFAULT_FRAGMENT_LEN,
      pollMs: opts.pollMs ?? 700,
      requestTimeoutMs: opts.requestTimeoutMs ?? 4000,
      retries: opts.retries ?? 2,
      retryDelayMs: opts.retryDelayMs ?? 300,
      scanWaitMs: opts.scanWaitMs ?? 180_000,
      cycleTimeoutMs: opts.cycleTimeoutMs ?? 120_000,
      settleMs: opts.settleMs ?? 800,
      batchLines: Math.max(1, opts.batchLines ?? 4),
      batchBytes: Math.max(64, opts.batchBytes ?? 1024),
      offlineAfter: Math.max(1, opts.offlineAfter ?? 3),
      now: opts.now ?? (() => Date.now()),
      sleep: opts.sleep ?? realSleep,
    };
  }

  /** "a.b.c.d" / "a.b.c.d:8080" / "ripar-3f9a.local", for messages */
  get host(): string {
    return this.baseUrl.replace(/^http:\/\//, '');
  }

  // -------------------------------------------------------------------------------------------- HTTP
  /** runs one exchange after the previous one finished: the device serves one connection at a time */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  /**
   * One request with a timeout (requests are serialised). Network errors and timeouts are retried `retries` times;
   * HTTP answers never are. 401 -> 'unauthorized', 429 -> 'locked' (the device's lock-out after wrong codes).
   */
  private async request(method: 'GET' | 'POST', path: string, body?: string, retries = this.opts.retries): Promise<{ status: number; text: string }> {
    const headers: Record<string, string> = { 'X-Ripar-Code': this.code, Accept: 'application/json, text/plain' };
    if (body !== undefined) headers['Content-Type'] = 'text/plain';
    for (let attempt = 0; ; attempt++) {
      if (this.closed) throw new WifiLinkError('closed', 'the Wi-Fi link is closed');
      let timedOut = false;
      try {
        const r = await this.serial(async () => {
          if (this.closed) throw new WifiLinkError('closed', 'the Wi-Fi link is closed');
          const ctl = new AbortController();
          this.inflight.add(ctl);
          const timer = setTimeout(() => {
            timedOut = true;
            ctl.abort();
          }, this.opts.requestTimeoutMs);
          try {
            const res = await this.fetchFn(`${this.baseUrl}${path}`, { method, headers, ...(body !== undefined ? { body } : {}), signal: ctl.signal });
            const text = res.status === 204 ? '' : await res.text();
            return { status: res.status, text, retryAfter: res.headers?.get('retry-after') ?? null };
          } finally {
            clearTimeout(timer);
            this.inflight.delete(ctl);
          }
        });
        if (r.status === 401 || r.status === 403) {
          throw new WifiLinkError(
            'unauthorized',
            "The Ripar refused the code. Type the 8-digit code on the Ripar's Home screen (CODE 1234 5678; it changes when the Ripar restarts).",
            r.status,
          );
        }
        if (r.status === 429) {
          const n = Number(r.retryAfter);
          const secs = Number.isFinite(n) && n > 0 ? Math.min(300, Math.ceil(n)) : 5;
          throw new WifiLinkError(
            'locked',
            `Locked: too many wrong codes. The Ripar refuses every request for ${secs} s; wait, check the code on its Home screen, then try again.`,
            429,
            undefined,
            secs * 1000,
          );
        }
        return { status: r.status, text: r.text };
      } catch (e) {
        if (e instanceof WifiLinkError) throw e;
        if (this.closed) throw new WifiLinkError('closed', 'the Wi-Fi link is closed');
        if (attempt >= retries) {
          throw new WifiLinkError(
            'unreachable',
            `${timedOut ? `No answer from ${this.host} within ${Math.round(this.opts.requestTimeoutMs / 1000)} s` : `Cannot reach ${this.host}`}. ` +
              'Is the phone on the same Wi-Fi as the Ripar, and does the Ripar show WIFI ON? Use the IP address on its Home screen (a .local name may not resolve on Android).',
          );
        }
      }
      await this.opts.sleep(this.opts.retryDelayMs * (attempt + 1));
    }
  }

  /** a STATUS JSON body (GET /status, and the answers to POST /rx): published when it parses */
  private takeStatus(text: string): DeviceStatus | null {
    const parsed = parseDeviceStatus(text, this.opts.now());
    if (!parsed) return null;
    const s = withKnownIp(this.status.get(), parsed);
    if (s.screen !== 'QR') this.qrEmitted = false;
    this.status.set(s);
    return s;
  }

  /** GET /status: parses and publishes the device status */
  async refreshStatus(retries = this.opts.retries): Promise<DeviceStatus> {
    const r = await this.request('GET', '/status', undefined, retries);
    const s = r.status === 200 ? this.takeStatus(r.text) : null;
    if (!s) {
      const foreign = r.status === 200 || r.status === 404;
      throw new WifiLinkError(
        foreign ? 'not-ripar' : 'http',
        foreign ? `${this.host} answered, but not as a Ripar (no STATUS): check the address.` : `GET /status answered HTTP ${r.status}`,
        r.status,
      );
    }
    return s;
  }

  /** GET /tx: hands a new answer (or the one on a freshly shown QR screen) to onResponse */
  private async pollTx(): Promise<void> {
    const r = await this.request('GET', '/tx', undefined, 0);
    if (r.status !== 200 && r.status !== 204) return;
    const lines = r.status === 204 ? [] : r.text.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^ur:/i.test(l));
    const text = lines.length ? lines.join('\n') : null;
    const first = this.lastTx === undefined;
    const changed = !first && text !== this.lastTx;
    this.lastTx = text;
    if (!text) return;
    const onQr = this.status.get()?.screen === 'QR';
    // an answer that appeared since the last poll, or the one the device shows right now (the same text can be a new
    // round's answer: the keys-only pairing QR); an old answer the device no longer shows is not handed out at start
    if (changed || (onQr && !this.qrEmitted)) {
      if (onQr) this.qrEmitted = true;
      for (const l of lines) this.bus.emit(l);
    }
  }

  /** one poll: STATUS, then TX; tracks the link's health */
  private async pollOnce(): Promise<void> {
    try {
      await this.refreshStatus(0);
      await this.pollTx();
      this.failures = 0;
      if (this.conn.get().state !== 'online') this.conn.set({ state: 'online', at: this.opts.now() });
    } catch (e) {
      if (this.closed) return;
      if (e instanceof WifiLinkError && e.kind === 'unauthorized') {
        this.polling = false;
        this.status.set(null);
        this.conn.set({ state: 'unauthorized', message: e.message });
        return;
      }
      if (e instanceof WifiLinkError && e.kind === 'locked') {
        // someone sent wrong codes: every request gets 429 until the lock ends; ask again only then
        this.conn.set({ state: 'locked', message: e.message, until: this.opts.now() + (e.retryAfterMs ?? 5000) });
        return;
      }
      this.failures++;
      if (this.failures >= this.opts.offlineAfter && this.conn.get().state !== 'offline') {
        // a stale status would give wrong advice (e.g. "scanning"): drop it while the device is unreachable
        this.status.set(null);
        this.conn.set({ state: 'offline', message: (e as Error).message, since: this.opts.now() });
      }
    }
  }

  private async pollLoop(): Promise<void> {
    while (this.polling && !this.closed) {
      await this.pollOnce();
      if (!this.polling || this.closed) break;
      const c = this.conn.get();
      await this.opts.sleep(c.state === 'locked' ? Math.max(this.opts.pollMs, c.until - this.opts.now()) : this.opts.pollMs);
    }
  }

  /**
   * Checks the address and the code (GET /status, with retries) and starts polling. Rejects with WifiLinkError:
   * 'unauthorized' (wrong code), 'locked' (429 after repeated wrong codes), 'unreachable', 'not-ripar'.
   */
  async open(): Promise<DeviceStatus> {
    if (this.closed) throw new WifiLinkError('closed', 'the Wi-Fi link is closed');
    this.conn.set({ state: 'connecting' });
    let s: DeviceStatus;
    try {
      s = await this.refreshStatus();
    } catch (e) {
      if (e instanceof WifiLinkError && e.kind === 'unauthorized') this.conn.set({ state: 'unauthorized', message: e.message });
      else if (e instanceof WifiLinkError && e.kind === 'locked') this.conn.set({ state: 'locked', message: e.message, until: this.opts.now() + (e.retryAfterMs ?? 5000) });
      else if (!this.closed) this.conn.set({ state: 'offline', message: (e as Error).message, since: this.opts.now() });
      throw e;
    }
    this.conn.set({ state: 'online', at: this.opts.now() });
    if (!this.polling) {
      this.polling = true;
      void this.pollLoop();
    }
    return s;
  }

  onResponse(cb: (urText: string) => void): Unsubscribe {
    return this.bus.on(cb);
  }

  /** forget what was handed out, so an answer still on the device's screen is handed out again (a new round) */
  resetReads(): void {
    this.qrEmitted = false;
  }

  /**
   * POST /rx with UR lines. Rejects with WifiLinkError 'not-scanning' (409: the device is not on SCAN; `note` carries
   * its reason), 'unauthorized', 'unreachable' or 'http'.
   */
  async postLines(lines: readonly string[]): Promise<void> {
    const clean = lines.map((l) => l.trim()).filter(Boolean);
    if (!clean.length) return;
    for (const l of clean) if (/[\r\n]/.test(l)) throw new WifiLinkError('http', 'a request line must not contain CR / LF');
    const r = await this.request('POST', '/rx', `${clean.join('\n')}\n`);
    // the device answers 200 and 409 with its STATUS (409: with the note saying why it did not take the lines)
    if (r.status === 200 || r.status === 409) this.takeStatus(r.text);
    if (r.status === 409) {
      const note = noteOf(r.text) ?? undefined;
      throw new WifiLinkError(
        'not-scanning',
        `The Ripar is not scanning, so it did not take the request${note ? ` (it says: ${note})` : ''}. Press SIGN once on its Home screen.`,
        409,
        note,
      );
    }
    if (r.status === 413) throw new WifiLinkError('http', 'The Ripar refused the request as too large (HTTP 413).', 413);
    if (r.status < 200 || r.status >= 300) throw new WifiLinkError('http', `POST /rx answered HTTP ${r.status}${noteOf(r.text) ? `: ${noteOf(r.text)}` : ''}`, r.status);
  }

  /** resolves once STATUS says SCAN; rejects when `deadline` passes, the send is superseded or the link closes */
  private async waitForScan(seq: number, deadline: number, why: string | null): Promise<void> {
    if (this.status.get()?.screen === 'SCAN') return;
    this.phase.set({ kind: 'waiting-scan', since: this.opts.now() });
    for (;;) {
      if (seq !== this.sendSeq || this.closed) throw new DeviceCancelledError('superseded');
      const c = this.conn.get();
      if (c.state === 'unauthorized') throw new WifiLinkError('unauthorized', c.message);
      if (c.state === 'offline') throw new WifiLinkError('unreachable', c.message);
      if (this.status.get()?.screen === 'SCAN') return;
      if (this.opts.now() >= deadline) {
        throw new WifiLinkError(
          'not-scanning',
          `The Ripar did not start scanning${why ? ` (it said: ${why})` : ''}: press SIGN once on its Home screen, then try again.`,
          undefined,
          why ?? undefined,
        );
      }
      // the poller keeps STATUS current; if it is not running (open() not called), ask directly
      if (!this.polling) await this.refreshStatus(0).catch(() => {});
      await this.opts.sleep(Math.min(200, this.opts.pollMs));
    }
  }

  async send(req: DeviceRequest): Promise<void> {
    if (this.closed) throw new WifiLinkError('closed', 'the Wi-Fi link is closed');
    const seq = ++this.sendSeq;
    const parts = requestParts(req, this.opts.fragLen);
    const batches = rxBatches(parts, this.opts.batchLines, this.opts.batchBytes);
    const done = () => {
      const s = this.status.get();
      return !!s && (PAST_SCAN.has(s.screen) || (s.screen === 'SCAN' && !!s.scan && s.scan.of > 0 && s.scan.got >= s.scan.of));
    };
    let cycleUntil = 0;
    let delivered = false;
    let refusals = 0;
    let why: string | null = null;
    for (let round = 1; ; round++) {
      // (again) not scanning: the user has to press SIGN on Home; a fresh wait each time the device leaves SCAN
      if (this.status.get()?.screen !== 'SCAN') await this.waitForScan(seq, this.opts.now() + this.opts.scanWaitMs, why);
      if (!cycleUntil) cycleUntil = this.opts.now() + this.opts.cycleTimeoutMs;
      let sent = 0;
      let refused = false;
      for (const batch of batches) {
        if (seq !== this.sendSeq || this.closed) throw new DeviceCancelledError('superseded');
        if (delivered && done()) {
          this.phase.set({ kind: 'sent', at: this.opts.now() });
          return;
        }
        this.phase.set({ kind: 'sending', part: Math.min(parts.length, sent + batch.length), of: parts.length, round });
        try {
          await this.postLines(batch);
        } catch (e) {
          if (!(e instanceof WifiLinkError) || e.kind !== 'not-scanning') throw e;
          // the device left SCAN between two polls: finished (review open) or cancelled / timed out (back Home)
          why = e.note ?? null;
          await this.refreshStatus().catch(() => {});
          if (delivered && done()) {
            this.phase.set({ kind: 'sent', at: this.opts.now() });
            return;
          }
          // STATUS says SCAN but the device keeps refusing lines: do not loop on it
          if (++refusals >= 5) throw e;
          refused = true;
          break;
        }
        delivered = true;
        refusals = 0;
        sent += batch.length;
      }
      if (refused) {
        await this.opts.sleep(Math.min(500, this.opts.pollMs));
        continue;
      }
      // watch STATUS a moment: a complete set moves the device to REVIEW
      const settle = this.opts.now() + this.opts.settleMs;
      for (;;) {
        await this.refreshStatus(0).catch(() => {});
        if (done() || this.opts.now() >= settle) break;
        if (seq !== this.sendSeq || this.closed) throw new DeviceCancelledError('superseded');
        await this.opts.sleep(150);
      }
      if (done()) break;
      if (this.opts.now() >= cycleUntil) {
        this.phase.set({ kind: 'sent', at: this.opts.now() });
        throw new DeviceTimeoutError('The Ripar kept scanning without completing the request: check the note on its screen, or use QR.');
      }
    }
    this.phase.set({ kind: 'sent', at: this.opts.now() });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.polling = false;
    this.sendSeq++;
    for (const c of [...this.inflight]) c.abort();
    this.inflight.clear();
    this.bus.clear();
    this.phase.set({ kind: 'idle' });
    this.status.set(null);
    this.conn.set({ state: 'closed' });
  }
}
