// Byte / integer helpers mirroring make_request.py's value helpers (h, unhex, to_int, to_bytes, to_addr, u256_min).
import { ProtoError } from './errors.js';

/** 0x-prefixed hex string (compatible with viem's `Hex`). */
export type Hex = `0x${string}`;
/** 0x-prefixed 20-byte address (EIP-55 or lower case). */
export type Address = `0x${string}`;
/** Bytes given as a Uint8Array or a hex string (the 0x prefix is optional, like make_request's unhex). */
export type BytesLike = Uint8Array | string;
/**
 * An integer like make_request's to_int: a bigint, a safe-integer number, a string ("0x.." hex or decimal) or
 * big-endian bytes. Booleans and unsafe / fractional numbers are refused.
 */
export type IntLike = bigint | number | string | Uint8Array;

export const MAX256 = (1n << 256n) - 1n;
export const MAX64 = (1n << 64n) - 1n;

const HEX_RE = /^[0-9a-fA-F]*$/;

/** hex string (optional 0x, surrounding whitespace ignored) -> bytes; odd length / bad digits -> ProtoError */
export function unhex(s: string): Uint8Array {
  let t = s.trim();
  if (t.startsWith('0x') || t.startsWith('0X')) t = t.slice(2);
  if (t.length % 2 !== 0 || !HEX_RE.test(t)) throw new ProtoError(`not a hex string: ${JSON.stringify(s.slice(0, 40))}`);
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** bytes -> lower-case hex without 0x (make_request's h()) */
export function h(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

/** bytes -> 0x-prefixed lower-case hex */
export function toHex(b: Uint8Array): Hex {
  return `0x${h(b)}`;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function isZero(b: Uint8Array): boolean {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
}

/** big-endian bytes -> bigint */
export function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

/** bigint -> big-endian bytes of exactly n bytes (throws when it does not fit) */
export function bigIntToBytes(x: bigint, n: number): Uint8Array {
  if (x < 0n) throw new ProtoError('negative integer');
  const out = new Uint8Array(n);
  let v = x;
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new ProtoError(`integer does not fit ${n} bytes`);
  return out;
}

/** byte length of the minimal big-endian form (0 for 0) */
export function bitLengthBytes(x: bigint): number {
  let n = 0;
  let v = x;
  while (v > 0n) {
    n++;
    v >>= 8n;
  }
  return n;
}

/** 32-byte big-endian word (ABI uint256) */
export function word(x: bigint): Uint8Array {
  return bigIntToBytes(x, 32);
}

/** 32-byte ABI word of a 20-byte address */
export function addrWord(a: Uint8Array): Uint8Array {
  if (a.length !== 20) throw new ProtoError('address must be 20 bytes');
  const out = new Uint8Array(32);
  out.set(a, 12);
  return out;
}

/** make_request to_int */
export function toInt(v: unknown): bigint {
  if (typeof v === 'boolean') throw new ProtoError('expected an integer, got a boolean');
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) {
      throw new ProtoError(`expected an integer: ${v} (pass integers above 2^53 as a bigint or a string)`);
    }
    return BigInt(v);
  }
  if (typeof v === 'string') {
    const t = v.trim();
    if (t.startsWith('0x') || t.startsWith('0X')) {
      const d = t.slice(2);
      if (!/^[0-9a-fA-F]+$/.test(d)) throw new ProtoError(`expected an integer: ${JSON.stringify(v)}`);
      return BigInt('0x' + d);
    }
    if (!/^[+-]?[0-9]+$/.test(t)) throw new ProtoError(`expected an integer: ${JSON.stringify(v)}`);
    return BigInt(t);
  }
  if (v instanceof Uint8Array) return bytesToBigInt(v);
  throw new ProtoError(`expected an integer: ${String(v)}`);
}

/** make_request to_bytes: Uint8Array or hex string; n = exact length */
export function toBytes(v: unknown, n?: number | null, what = 'bytes'): Uint8Array {
  let b: Uint8Array;
  if (v instanceof Uint8Array) b = Uint8Array.from(v);
  else if (typeof v === 'string') {
    try {
      b = unhex(v);
    } catch {
      throw new ProtoError(`${what}: expected hex, got ${JSON.stringify(v.slice(0, 40))}`);
    }
  } else throw new ProtoError(`${what}: expected hex, got ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`);
  if (n !== undefined && n !== null && b.length !== n) {
    throw new ProtoError(`${what}: expected ${n} bytes, got ${b.length}`);
  }
  return b;
}

/** make_request to_addr: exactly 20 bytes */
export function toAddr(v: unknown, what = 'address'): Uint8Array {
  return toBytes(v, 20, what);
}

/** make_request u256_min: minimal big-endian, at least one byte (0 -> 0x00) */
export function u256Min(x: IntLike): Uint8Array {
  const v = toInt(x);
  if (v < 0n || v > MAX256) throw new ProtoError('u256 out of range');
  return bigIntToBytes(v, Math.max(1, bitLengthBytes(v)));
}

/** Python truthiness of a JSON-ish value (for flags such as newPayeeNeedsHuman / uuidTag) */
export function pyTruthy(v: unknown): boolean {
  if (v === undefined || v === null || v === false || v === 0 || v === 0n || v === '') return false;
  if (Array.isArray(v)) return v.length > 0;
  if (v instanceof Uint8Array) return v.length > 0;
  if (v instanceof Map) return v.size > 0;
  if (typeof v === 'object') return Object.keys(v as object).length > 0;
  return true;
}

export const utf8 = {
  encode: (s: string): Uint8Array => new TextEncoder().encode(s),
  /** strict decoding (invalid UTF-8 -> throws TypeError); a BOM is kept */
  decodeStrict: (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b),
};

/** random bytes from the platform CSPRNG (Web Crypto; Node 19+ and every browser) */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (!c || typeof c.getRandomValues !== 'function') throw new ProtoError('no crypto.getRandomValues available');
  c.getRandomValues(out);
  return out;
}
