// Minimal CBOR, byte-compatible with firmware/tools/ref_ur.py cbor() (encoder) and make_request.py cbor_decode()
// (strict decoder): shortest heads, definite lengths, maps in insertion order, tags, true / false / null.
import { bytesToBigInt, h } from './bytes.js';
import { ProtoError } from './errors.js';

/** CBOR tag (e.g. 37 = UUID around a req-id). */
export class Tag {
  constructor(
    readonly tag: number | bigint,
    readonly value: CborValue,
  ) {}
}

export type CborKey = bigint | number | string | Uint8Array | boolean | null;
/**
 * Values the encoder accepts. The decoder returns: bigint for every integer, Uint8Array, string, arrays, Map (in
 * wire order), Tag, boolean and null.
 */
export type CborValue =
  | bigint
  | number
  | string
  | Uint8Array
  | boolean
  | null
  | Tag
  | CborValue[]
  | Map<CborKey, CborValue>;
export type CborMap = Map<CborKey, CborValue>;

const M64 = (1n << 64n) - 1n;

function head(major: number, v: bigint): number[] {
  if (v < 0n || v > M64) throw new ProtoError('CBOR argument out of range');
  const mt = major << 5;
  if (v < 24n) return [mt | Number(v)];
  if (v <= 0xffn) return [mt | 24, Number(v)];
  if (v <= 0xffffn) return [mt | 25, Number(v >> 8n), Number(v & 0xffn)];
  if (v <= 0xffffffffn) {
    const out = [mt | 26];
    for (let i = 3; i >= 0; i--) out.push(Number((v >> BigInt(8 * i)) & 0xffn));
    return out;
  }
  const out = [mt | 27];
  for (let i = 7; i >= 0; i--) out.push(Number((v >> BigInt(8 * i)) & 0xffn));
  return out;
}

function encInto(out: number[], v: CborValue): void {
  if (v === null) {
    out.push(0xf6);
  } else if (v === true) {
    out.push(0xf5);
  } else if (v === false) {
    out.push(0xf4);
  } else if (typeof v === 'number' || typeof v === 'bigint') {
    if (typeof v === 'number' && !Number.isSafeInteger(v)) throw new ProtoError(`CBOR: not an integer: ${v}`);
    const b = BigInt(v);
    if (b >= 0n) out.push(...head(0, b));
    else out.push(...head(1, -1n - b));
  } else if (v instanceof Uint8Array) {
    out.push(...head(2, BigInt(v.length)));
    for (let i = 0; i < v.length; i++) out.push(v[i]!);
  } else if (typeof v === 'string') {
    const b = new TextEncoder().encode(v);
    out.push(...head(3, BigInt(b.length)));
    for (let i = 0; i < b.length; i++) out.push(b[i]!);
  } else if (Array.isArray(v)) {
    out.push(...head(4, BigInt(v.length)));
    for (const x of v) encInto(out, x);
  } else if (v instanceof Map) {
    out.push(...head(5, BigInt(v.size)));
    for (const [k, x] of v) {
      encInto(out, k as CborValue);
      encInto(out, x);
    }
  } else if (v instanceof Tag) {
    out.push(...head(6, BigInt(v.tag)));
    encInto(out, v.value);
  } else {
    throw new ProtoError(`CBOR: cannot encode ${Object.prototype.toString.call(v)}`);
  }
}

/** Canonical CBOR of a value (ref_ur.py cbor()). Maps are encoded in their insertion order. */
export function cborEncode(v: CborValue): Uint8Array {
  const out: number[] = [];
  encInto(out, v);
  return Uint8Array.from(out);
}

function keyId(k: CborValue): string {
  // Python dict semantics: 1 == True, 0 == False
  if (k === true) return 'i:1';
  if (k === false) return 'i:0';
  if (k === null) return 'null';
  if (typeof k === 'bigint') return 'i:' + k.toString();
  if (typeof k === 'string') return 's:' + k;
  if (k instanceof Uint8Array) return 'b:' + h(k);
  return 'x';
}

/**
 * Strict decode of exactly one item (make_request.py cbor_decode): definite lengths only, depth <= 16, no floats /
 * other simple values, map keys scalar and untagged, no duplicate map keys, valid UTF-8 text, no trailing bytes.
 */
export function cborDecode(data: Uint8Array): CborValue {
  let pos = 0;
  const take = (n: number): Uint8Array => {
    if (pos + n > data.length) throw new ProtoError('CBOR truncated');
    const b = data.subarray(pos, pos + n);
    pos += n;
    return b;
  };
  const td = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const item = (depth: number): CborValue => {
    if (depth > 16) throw new ProtoError('CBOR nesting too deep');
    const ib = take(1)[0]!;
    const major = ib >> 5;
    const ai = ib & 31;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      throw new ProtoError('CBOR simple/float value not supported');
    }
    let arg: bigint;
    if (ai < 24) arg = BigInt(ai);
    else if (ai >= 24 && ai <= 27) arg = bytesToBigInt(take(1 << (ai - 24)));
    else throw new ProtoError('CBOR indefinite / reserved length');
    const len = (): number => {
      if (arg > BigInt(data.length)) throw new ProtoError('CBOR truncated');
      return Number(arg);
    };
    switch (major) {
      case 0:
        return arg;
      case 1:
        return -1n - arg;
      case 2:
        return Uint8Array.from(take(len()));
      case 3: {
        const b = take(len());
        try {
          return td.decode(b);
        } catch {
          throw new ProtoError('CBOR text is not UTF-8');
        }
      }
      case 4: {
        const n = len();
        const a: CborValue[] = [];
        for (let i = 0; i < n; i++) a.push(item(depth + 1));
        return a;
      }
      case 5: {
        const n = len();
        const m: CborMap = new Map();
        const seen = new Set<string>();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          if (Array.isArray(k) || k instanceof Map) throw new ProtoError('CBOR map key must be a scalar');
          if (k instanceof Tag) throw new ProtoError('CBOR tagged map key not supported');
          const id = keyId(k);
          if (seen.has(id)) throw new ProtoError('CBOR duplicate map key');
          seen.add(id);
          m.set(k as CborKey, item(depth + 1));
        }
        return m;
      }
      default: {
        // major 6: tag
        const tag = arg <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(arg) : arg;
        return new Tag(tag, item(depth + 1));
      }
    }
  };
  const v = item(0);
  if (pos !== data.length) throw new ProtoError('CBOR trailing bytes');
  return v;
}

/** Map lookup by an unsigned integer key (decoded maps use bigint keys, built maps may use numbers). */
export function mget(m: CborMap, k: number): CborValue | undefined {
  if (m.has(BigInt(k))) return m.get(BigInt(k));
  return m.get(k);
}

export function mhas(m: CborMap, k: number): boolean {
  return m.has(BigInt(k)) || m.has(k);
}

/** integer keys of a map as numbers (non-integer keys are returned as NaN) */
export function mkeys(m: CborMap): number[] {
  return [...m.keys()].map((k) => (typeof k === 'bigint' || typeof k === 'number' ? Number(k) : NaN));
}

/** deep structural equality of CBOR values (bigint and number compare by value) */
export function cborEqual(a: CborValue, b: CborValue): boolean {
  if ((typeof a === 'bigint' || typeof a === 'number') && (typeof b === 'bigint' || typeof b === 'number')) {
    return BigInt(a) === BigInt(b);
  }
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    return a.length === b.length && a.every((x, i) => x === b[i]);
  }
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => cborEqual(x, b[i]!));
  if (a instanceof Map && b instanceof Map) {
    if (a.size !== b.size) return false;
    const ea = [...a.entries()];
    const eb = [...b.entries()];
    return ea.every(([k, v], i) => cborEqual(k as CborValue, eb[i]![0] as CborValue) && cborEqual(v, eb[i]![1]));
  }
  if (a instanceof Tag && b instanceof Tag) return BigInt(a.tag) === BigInt(b.tag) && cborEqual(a.value, b.value);
  return a === b;
}
