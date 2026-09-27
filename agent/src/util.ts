// Small shared helpers: JSON with bigint / bytes, ids, a promise mutex, unit formatting.
import { randomBytes } from 'node:crypto';
import { formatUnits, getAddress, isAddress, parseUnits, type Address, type Hex } from 'viem';

/** unix seconds of the local clock (the chain's block time is authoritative for expiries: RiparChain.now()) */
export const nowSec = (): number => Math.floor(Date.now() / 1000);

/** JSON.stringify replacer: bigint -> decimal string, Uint8Array -> 0x-hex */
export function jsonReplacer(_key: string, v: unknown): unknown {
  if (typeof v === 'bigint') return v.toString();
  if (v instanceof Uint8Array) return '0x' + Buffer.from(v).toString('hex');
  return v;
}

export function toJson(v: unknown, space?: number): string {
  return JSON.stringify(v, jsonReplacer, space);
}

/** a deep copy that is plain JSON (bigints as strings) */
export function jsonSafe<T = unknown>(v: unknown): T {
  return JSON.parse(toJson(v)) as T;
}

export function randomId(prefix: string, bytes = 8): string {
  return `${prefix}_${randomBytes(bytes).toString('hex')}`;
}

/** serializes async critical sections (payments, co-sign submissions) so nothing is paid twice concurrently */
export class Mutex {
  private tail: Promise<unknown> = Promise.resolve();

  run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn, fn);
    this.tail = next.catch(() => undefined);
    return next;
  }
}

export function isHexBytes(s: unknown, bytes?: number): s is Hex {
  if (typeof s !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(s)) return false;
  return bytes === undefined || s.length === 2 + 2 * bytes;
}

/** EIP-55 address or throws (a mixed-case address must have a valid checksum) */
export function checksum(a: unknown, what = 'address'): Address {
  if (typeof a !== 'string' || !isAddress(a, { strict: true })) throw new TypeError(`${what}: not a valid address`);
  return getAddress(a);
}

export function sameAddress(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

export const ZERO_ADDRESS: Address = '0x0000000000000000000000000000000000000000';

/** "12.5" -> base units; refuses anything that is not a plain non-negative decimal */
export function parseAmount(s: unknown, decimals: number): bigint {
  if (typeof s !== 'string' || !/^\d{1,30}(\.\d{1,36})?$/.test(s)) throw new TypeError(`amount "${String(s)}" is not a decimal`);
  const frac = s.split('.')[1] ?? '';
  if (frac.length > decimals) throw new TypeError(`amount "${s}" has more than ${decimals} decimals`);
  return parseUnits(s, decimals);
}

export function fmtAmount(v: bigint, decimals: number): string {
  return formatUnits(v, decimals);
}

export function shortAddr(a: string): string {
  return a.length > 12 ? `${a.slice(0, 6)}...${a.slice(-4)}` : a;
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return (e as { shortMessage?: string }).shortMessage ?? e.message;
  return String(e);
}

export const SAFE_SYMBOL = /^[\x20-\x7e]{1,16}$/;

/**
 * An on-chain token symbol as shown to people: printable ASCII of 1..16 characters, otherwise '?'. symbol() is
 * attacker-controlled (control characters, bidi overrides, an emoji split in half by a slice).
 */
export function displaySymbol(s: unknown): string {
  return typeof s === 'string' && SAFE_SYMBOL.test(s) ? s : '?';
}
