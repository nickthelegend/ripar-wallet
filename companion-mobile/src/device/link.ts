// The one interface every screen talks to the Ripar device through, whatever carries the bytes:
//
//   QrLink        (default, air-gapped) the request is shown as an animated BC-UR QR that the device's camera reads;
//                 the device's single-part answer QR is read with this phone's camera.
//   BleLink       (fallback) the same UR parts as UTF-8 lines over Bluetooth LE, answers come back as notifications.
//                 Turns the device's radio on: only when the camera cannot read.
//   EmulatorLink  (demo) the firmware emulator (WASM) running in a WebView, fed the same parts.
//
// The link is a dumb courier. Everything it returns is checked by the caller's verifier (@ripar/protocol parseResponse
// with the request, the pinned context and the device keys) before the app acts on it. Pure module: no React Native
// imports, unit-tested in test/link.test.ts.
import { type BuiltRequest, DEFAULT_FRAGMENT_LEN, UrDecoder, urParts, urRead, urSingle } from '@ripar/protocol';

export type Unsubscribe = () => void;

/** a value that changes over time (device status, frames on show, BLE phase) */
export interface Observable<T> {
  get(): T;
  subscribe(cb: (v: T) => void): Unsubscribe;
}

/** the minimal Observable implementation used by the links */
export class ValueSubject<T> implements Observable<T> {
  private listeners = new Set<(v: T) => void>();
  constructor(private value: T) {}
  get(): T {
    return this.value;
  }
  set(v: T): void {
    this.value = v;
    for (const l of [...this.listeners]) l(v);
  }
  subscribe(cb: (v: T) => void): Unsubscribe {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }
  clear(): void {
    this.listeners.clear();
  }
}

/** fan-out of response texts to listeners (shared by the links) */
export class ResponseBus {
  private listeners = new Set<(ur: string) => void>();
  on(cb: (ur: string) => void): Unsubscribe {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }
  emit(text: string): void {
    for (const l of [...this.listeners]) l(text);
  }
  clear(): void {
    this.listeners.clear();
  }
}

/** the screens the device reports over BLE STATUS (firmware BLE LINK) */
export type DeviceScreen = 'HOME' | 'SCAN' | 'REVIEW' | 'PULSE' | 'ARMED' | 'QR' | 'MESSAGE' | 'MENU' | 'BLE_PAIR';

/** BLE STATUS characteristic (docs/BLE_LINK.md §4.5): JSON {"v":1,"screen","paired","k1","scan":{"got","of"},"radio","fw","note"?} */
export interface DeviceStatus {
  v: 1;
  /** a known DeviceScreen, or whatever newer firmware reports (shown as is) */
  screen: DeviceScreen | string;
  paired: boolean;
  /** the device's K1 as it reports it (short or full), null when absent */
  k1: string | null;
  /** multipart progress while scanning */
  scan: { got: number; of: number } | null;
  radio: string;
  fw: string | null;
  /** optional short note from the device: why the last line was not used (e.g. "ignored: not on SCAN ...") */
  note: string | null;
  /** when this status was received (ms) */
  at: number;
}

export type LinkKind = 'qr' | 'ble' | 'emulator';

/** a request as the links take it: the CBOR payload and its UR type, or ready-made (upper-case) UR parts */
export type DeviceRequest = { urType: string; cbor: Uint8Array } | readonly string[];

export interface DeviceLink {
  readonly kind: LinkKind;
  /** start presenting / transmitting the request (resolves once it is on its way; the answer comes via onResponse) */
  send(req: DeviceRequest): Promise<void>;
  /** every UR text the device shows / sends (unfiltered: awaitDeviceResponse filters) */
  onResponse(cb: (urText: string) => void): Unsubscribe;
  /** live device status, where the link has one (BLE STATUS, the emulator's state) */
  readonly status?: Observable<DeviceStatus | null>;
  close(): void;
}

// ------------------------------------------------------------------------------------------------ errors
export class DeviceLinkError extends Error {
  override name = 'DeviceLinkError';
}
export class DeviceTimeoutError extends DeviceLinkError {
  override name = 'DeviceTimeoutError';
}
export class DeviceCancelledError extends DeviceLinkError {
  override name = 'DeviceCancelledError';
}

// ------------------------------------------------------------------------------------------------ helpers
export function isBuiltRequest(x: unknown): x is BuiltRequest {
  return !!x && typeof x === 'object' && Array.isArray((x as BuiltRequest).parts) && typeof (x as BuiltRequest).type === 'string';
}

/**
 * The upper-case UR parts of a request: the pure multipart fragments of `fragLen` bytes (the protocol suggests 60-80),
 * identical to @ripar/protocol buildRequest(...).parts for the same CBOR (a request that fits one fragment is one
 * "1-1" part, as the protocol cuts it; only a CBOR under 10 bytes, too short for the fountain, is a single part).
 */
export function requestParts(req: DeviceRequest | BuiltRequest, fragLen = DEFAULT_FRAGMENT_LEN): string[] {
  if (isBuiltRequest(req)) return [...req.parts];
  if (Array.isArray(req)) {
    const parts = (req as readonly string[]).map((p) => p.trim().toUpperCase()).filter(Boolean);
    if (!parts.length) throw new DeviceLinkError('no request parts');
    for (const p of parts) if (!/^UR:[A-Z0-9-]+\//.test(p)) throw new DeviceLinkError(`not a UR part: ${p.slice(0, 24)}`);
    return parts;
  }
  const r = req as { urType: string; cbor: Uint8Array };
  if (!/^[a-z0-9-]+$/.test(r.urType)) throw new DeviceLinkError(`bad UR type ${r.urType}`);
  // below the fountain's minimum fragment length (10 bytes) there is nothing to cut: one single-part UR
  if (r.cbor.length < 10) return [urSingle(r.urType, r.cbor).toUpperCase()];
  return urParts(r.urType, r.cbor, fragLen);
}

/** sends a request (a BuiltRequest from @ripar/protocol, a {urType, cbor} or ready parts) over the link */
export async function sendToDevice(link: DeviceLink, request: DeviceRequest | BuiltRequest, opts: { fragLen?: number } = {}): Promise<void> {
  await link.send(requestParts(request, opts.fragLen));
}

export type Classified = { ok: true; type: string; ur: string } | { ok: false; reason: string };

/**
 * Is this text a complete, CRC-valid single-part UR of one of the expected types? The device always answers with one
 * single-part QR (docs/PROTOCOL.md §1); anything else (a multipart frame of our own request seen by the camera, a QR of
 * another type, garbage) is reported as ignored with the reason.
 */
export function classifyResponse(text: string, expect: readonly string[]): Classified {
  const t = text.trim();
  if (!t) return { ok: false, reason: 'empty' };
  let type: string;
  try {
    const dec = new UrDecoder();
    if (dec.receive(t) !== 'complete' || !dec.result) return { ok: false, reason: 'not a complete single-part UR' };
    type = dec.result.type;
    urRead(t); // bytewords + CRC-32
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
  if (expect.length && !expect.includes(type)) return { ok: false, reason: `unexpected ${type}` };
  return { ok: true, type, ur: t.toUpperCase() };
}

export interface AwaitOptions {
  timeoutMs?: number;
  /** extra filter on a response of an expected type (e.g. the request's req-id echo); a rejected one is ignored */
  accept?: (ur: string) => boolean;
  signal?: AbortSignal;
  /** told about every text that was not the answer (for the UI's "ignored: ..." line) */
  onIgnored?: (text: string, reason: string) => void;
}

/**
 * Resolves with the first response (upper-case single-part UR) of an expected type that passes `accept`. Rejects with
 * DeviceTimeoutError after `timeoutMs` (default: no timeout) or DeviceCancelledError when `signal` aborts.
 */
export function awaitDeviceResponse(link: DeviceLink, expectedType: string | readonly string[], opts: AwaitOptions = {}): Promise<string> {
  const expect = typeof expectedType === 'string' ? [expectedType] : expectedType;
  return new Promise<string>((resolve, reject) => {
    let done = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const finish = (fn: () => void) => {
      if (done) return;
      done = true;
      off();
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      fn();
    };
    const onAbort = () => finish(() => reject(new DeviceCancelledError('cancelled')));
    const off = link.onResponse((text) => {
      if (done) return;
      const c = classifyResponse(text, expect);
      if (!c.ok) return opts.onIgnored?.(text, c.reason);
      let accepted = true;
      try {
        accepted = opts.accept ? opts.accept(c.ur) : true;
      } catch {
        accepted = false;
      }
      if (!accepted) return opts.onIgnored?.(text, `${c.type} does not answer this request`);
      finish(() => resolve(c.ur));
    });
    if (opts.signal?.aborted) return onAbort();
    opts.signal?.addEventListener('abort', onAbort);
    if (opts.timeoutMs && opts.timeoutMs > 0) {
      timer = setTimeout(() => finish(() => reject(new DeviceTimeoutError(`no answer from the device within ${Math.round(opts.timeoutMs! / 1000)} s`))), opts.timeoutMs);
    }
  });
}

/** what an answer must be and how it is checked: expected UR types, a cheap filter (req-id echo) and the verification */
export interface Verifier<T> {
  expect: readonly string[];
  accept?: (ur: string) => boolean;
  /** full verification (signatures, pinned context); throws when the answer must not be used */
  verify: (ur: string) => T;
}

export function verifierOf<T>(expect: readonly string[], verify: (ur: string) => T, accept?: (ur: string) => boolean): Verifier<T> {
  return { expect, verify, ...(accept ? { accept } : {}) };
}

/**
 * One round: listen first (a Bluetooth answer can arrive before send() returns), send the request (null = a message
 * the device starts by itself: keys-only pairing QR, PANIC, revoke, reopen), wait for the first acceptable answer and
 * verify it. A verification failure rejects: the device answered, but with something that must not be used.
 */
export async function requestAndVerify<T>(
  link: DeviceLink,
  request: DeviceRequest | BuiltRequest | null,
  verifier: Verifier<T>,
  opts: Omit<AwaitOptions, 'accept'> & { fragLen?: number } = {},
): Promise<{ ur: string; result: T }> {
  // an inner abort (a failed send) must end the waiter too, without touching the caller's signal
  const inner = new AbortController();
  const onOuter = () => inner.abort();
  if (opts.signal?.aborted) inner.abort();
  else opts.signal?.addEventListener('abort', onOuter);
  try {
    const answer = awaitDeviceResponse(link, verifier.expect, {
      ...opts,
      signal: inner.signal,
      ...(verifier.accept ? { accept: verifier.accept } : {}),
    });
    if (request) {
      try {
        await sendToDevice(link, request, opts.fragLen !== undefined ? { fragLen: opts.fragLen } : {});
      } catch (e) {
        answer.catch(() => {});
        inner.abort();
        throw e;
      }
    }
    const ur = await answer;
    return { ur, result: verifier.verify(ur) };
  } finally {
    opts.signal?.removeEventListener('abort', onOuter);
  }
}
