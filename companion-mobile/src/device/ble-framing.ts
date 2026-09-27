// Bluetooth LE framing of the Ripar link, per docs/BLE_LINK.md (v1, the firmware's contract):
//
//   service  52495041-5200-4c49-4e4b-000000000001   ("RIPAR" "LINK"), advertised name "RIPAR-XXXX" (random per enable)
//   RX       ...0002  write     phone -> device: each UR part as a UTF-8 line ending LF, writes of at most MTU-3 bytes
//                               (the device reassembles lines, drops a trailing CR, ignores empty lines, drops > 4096 B)
//   TX       ...0003  notify    device -> phone: the QR's UR text + LF, in notifications of at most MTU-3 bytes
//   STATUS   ...0004  read+notify  JSON <= 180 B {"v":1,"screen","paired","k1","scan":{"got","of"},"radio","fw","note"?};
//                               a notification that does not fit MTU-3 is truncated: then READ the characteristic
//
// Pure functions and classes (no BLE library here): unit-tested in test/link.test.ts.
import { utf8Decode, utf8Encode } from '../lib/utf8';
import type { DeviceStatus } from './link';

export const RIPAR_BLE = {
  service: '52495041-5200-4c49-4e4b-000000000001',
  rx: '52495041-5200-4c49-4e4b-000000000002',
  tx: '52495041-5200-4c49-4e4b-000000000003',
  status: '52495041-5200-4c49-4e4b-000000000004',
  namePrefix: 'RIPAR-',
  /** the ATT MTU the app asks for (Android caps at 517; the device's stack decides) */
  requestMtu: 247,
} as const;

/** ATT payload of a write / notification: MTU minus the 3-byte ATT header (the default MTU 23 gives 20 bytes) */
export function attPayload(mtu: number): number {
  const m = Number.isFinite(mtu) && mtu >= 23 ? Math.floor(mtu) : 23;
  return Math.min(m, 517) - 3;
}

/** one UR part as the RX line: UTF-8 bytes of the text followed by '\n' (a part never contains a newline) */
export function encodeLine(text: string): Uint8Array {
  if (/[\r\n]/.test(text)) throw new RangeError('a BLE line must not contain CR / LF');
  return utf8Encode(`${text}\n`);
}

/** splits bytes into chunks of at most `size` bytes (in order; the last one may be shorter) */
export function chunkBytes(bytes: Uint8Array, size: number): Uint8Array[] {
  if (!Number.isInteger(size) || size < 1) throw new RangeError('chunk size must be >= 1');
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += size) out.push(bytes.subarray(i, Math.min(bytes.length, i + size)));
  return out;
}

/** the RX writes for a list of UR parts at a negotiated MTU: one list of chunks per part */
export function rxChunks(parts: readonly string[], mtu: number): Uint8Array[][] {
  const size = attPayload(mtu);
  return parts.map((p) => chunkBytes(encodeLine(p), size));
}

/**
 * Reassembles '\n'-terminated lines from notification chunks (a line may span notifications, one notification may
 * carry the end of one line and the start of the next). CR before LF is dropped, empty lines are skipped, a line that
 * is not valid UTF-8 is dropped (reported via onBad), and a runaway line without LF is discarded past `maxLine` bytes.
 */
export class LineAssembler {
  private buf: number[] = [];
  private overflow = false;

  constructor(
    private readonly maxLine = 16 * 1024,
    private readonly onBad?: (why: string) => void,
  ) {}

  push(chunk: Uint8Array): string[] {
    const lines: string[] = [];
    for (const b of chunk) {
      if (b === 0x0a) {
        if (this.overflow) {
          this.onBad?.(`line longer than ${this.maxLine} bytes dropped`);
        } else {
          let bytes = Uint8Array.from(this.buf);
          if (bytes.length && bytes[bytes.length - 1] === 0x0d) bytes = bytes.subarray(0, bytes.length - 1);
          if (bytes.length) {
            try {
              lines.push(utf8Decode(bytes, true));
            } catch {
              this.onBad?.('line is not valid UTF-8');
            }
          }
        }
        this.buf = [];
        this.overflow = false;
        continue;
      }
      if (this.overflow) continue;
      if (this.buf.length >= this.maxLine) {
        this.overflow = true;
        this.buf = [];
        continue;
      }
      this.buf.push(b);
    }
    return lines;
  }

  /** bytes of an unfinished line waiting for its LF */
  get pending(): number {
    return this.buf.length;
  }

  reset(): void {
    this.buf = [];
    this.overflow = false;
  }
}

const SCREENS = new Set(['HOME', 'SCAN', 'REVIEW', 'PULSE', 'ARMED', 'QR', 'MESSAGE', 'MENU', 'BLE_PAIR']);

/**
 * Parses the STATUS JSON. Strict on types, ignores unknown keys (BLE_LINK.md: clients must). Returns null
 * for anything that is not a v1 status object. An unknown screen name is kept (upper-cased) so the UI can show it.
 */
export function parseDeviceStatus(text: string, now = Date.now()): DeviceStatus | null {
  let o: unknown;
  try {
    o = JSON.parse(text);
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
  const r = o as Record<string, unknown>;
  if (r.v !== 1) return null;
  if (typeof r.screen !== 'string' || !/^[A-Za-z_]{1,24}$/.test(r.screen)) return null;
  const screen = r.screen.toUpperCase();
  let scan: DeviceStatus['scan'] = null;
  if (r.scan && typeof r.scan === 'object' && !Array.isArray(r.scan)) {
    const s = r.scan as Record<string, unknown>;
    const got = Number(s.got);
    const of = Number(s.of);
    if (Number.isInteger(got) && Number.isInteger(of) && got >= 0 && of >= 0 && of <= 10_000) scan = { got: Math.min(got, of || got), of };
  }
  const str = (v: unknown, max: number) => (typeof v === 'string' && v.length <= max && /^[\x20-\x7e]*$/.test(v) ? v : null);
  return {
    v: 1,
    screen: SCREENS.has(screen) ? (screen as DeviceStatus['screen']) : screen,
    paired: r.paired === true,
    k1: str(r.k1, 64),
    scan,
    radio: str(r.radio, 16) ?? 'on',
    fw: str(r.fw, 64),
    note: str(r.note, 180),
    at: now,
  };
}

// ------------------------------------------------------------------------------------------------ base64
// react-native-ble-plx reads and writes characteristic values as base64 strings.
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_INV: Record<string, number> = Object.fromEntries([...B64].map((c, i) => [c, i]));

export function toBase64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 3) {
    const x = (b[i]! << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    s += B64[(x >> 18) & 63]! + B64[(x >> 12) & 63]! + (i + 1 < b.length ? B64[(x >> 6) & 63]! : '=') + (i + 2 < b.length ? B64[x & 63]! : '=');
  }
  return s;
}

export function fromBase64(s: string): Uint8Array {
  const t = s.replace(/[\s=]+/g, '');
  if (!/^[A-Za-z0-9+/]*$/.test(t) || t.length % 4 === 1) throw new RangeError('not base64');
  const out: number[] = [];
  for (let i = 0; i < t.length; i += 4) {
    const c = [t[i], t[i + 1], t[i + 2], t[i + 3]].map((ch) => (ch === undefined ? -1 : B64_INV[ch]!));
    const x = (c[0]! << 18) | (c[1]! << 12) | ((c[2]! < 0 ? 0 : c[2]!) << 6) | (c[3]! < 0 ? 0 : c[3]!);
    out.push((x >> 16) & 255);
    if (c[2]! >= 0) out.push((x >> 8) & 255);
    if (c[3]! >= 0) out.push(x & 255);
  }
  return Uint8Array.from(out);
}
