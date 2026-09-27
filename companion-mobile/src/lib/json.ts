// Ported from companion/src/lib/json.ts.
// JSON helpers for data that crosses a trust boundary (agent service, localStorage). bigint travels as a decimal
// string, Uint8Array as 0x-hex; parsing never evals and never trusts a shape it did not check.
import { type Hex, toHex } from '@ripar/protocol';

/** JSON.stringify with bigint -> decimal string and Uint8Array -> 0x-hex */
export function stringifyJson(v: unknown, space?: number): string {
  return JSON.stringify(
    v,
    (_k, x: unknown) => {
      if (typeof x === 'bigint') return x.toString();
      if (x instanceof Uint8Array) return toHex(x);
      return x;
    },
    space,
  );
}

export type JsonRecord = Record<string, unknown>;

export function isRecord(v: unknown): v is JsonRecord {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export class ShapeError extends Error {
  override name = 'ShapeError';
}

/** 0x-hex string (even length), optionally of exactly `bytes` bytes */
export function hexField(o: JsonRecord, k: string, bytes?: number): Hex {
  const v = o[k];
  if (typeof v !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(v)) throw new ShapeError(`${k}: expected 0x-hex`);
  if (bytes !== undefined && v.length !== 2 + 2 * bytes) throw new ShapeError(`${k}: expected ${bytes} bytes`);
  return v as Hex;
}

/** a non-negative integer given as a JSON number (safe) or a decimal / 0x string */
export function uintField(o: JsonRecord, k: string, optional = false): bigint | undefined {
  const v = o[k];
  if (v === undefined || v === null) {
    if (optional) return undefined;
    throw new ShapeError(`${k}: missing`);
  }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v < 0) throw new ShapeError(`${k}: not a safe non-negative integer`);
    return BigInt(v);
  }
  if (typeof v === 'string' && (/^[0-9]{1,78}$/.test(v) || /^0x[0-9a-fA-F]{1,64}$/.test(v))) return BigInt(v);
  throw new ShapeError(`${k}: not an unsigned integer`);
}

/**
 * Display-only text from an untrusted source (an invoice memo, a vendor name): a string cut to `max` characters, or
 * undefined. Never a reason to reject the record it is in: an injected memo is exactly what the user must see.
 */
export function clipField(o: JsonRecord, k: string, max: number): string | undefined {
  const v = o[k];
  if (typeof v !== 'string') return undefined;
  return v.length > max ? `${v.slice(0, max - 1)}…` : v;
}

export function strField(o: JsonRecord, k: string, optional = false, max = 2000): string | undefined {
  const v = o[k];
  if (v === undefined || v === null) {
    if (optional) return undefined;
    throw new ShapeError(`${k}: missing`);
  }
  if (typeof v !== 'string') throw new ShapeError(`${k}: expected a string`);
  if (v.length > max) throw new ShapeError(`${k}: longer than ${max} characters`);
  return v;
}
