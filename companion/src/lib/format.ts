// Text formatting shared by every screen. Addresses are always shown in full (EIP-55, like the device), grouped in
// 4-character blocks for reading; amounts use the device's own format (formatUnitsDevice) so the companion and the
// LCD agree character for character.
import { formatUnitsDevice, toChecksumAddress } from '@ripar/protocol';

/** EIP-55 form of any 20-byte address (hex or bytes) */
export function checksum(a: string | Uint8Array): `0x${string}` {
  return toChecksumAddress(a);
}

/** ["0x", "7534", "5483", ...]: display groups of a hex string (0x kept as its own group) */
export function hexGroups(hex: string, size = 4): string[] {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out: string[] = hex.startsWith('0x') ? ['0x'] : [];
  for (let i = 0; i < body.length; i += size) out.push(body.slice(i, i + size));
  return out;
}

/** 0x1234…abcd (for tight places only: never where the user decides) */
export function shortHex(hex: string, head = 6, tail = 4): string {
  if (hex.length <= head + tail + 3) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

/** the device's UTC text: "2026-09-27 09:06:40 UTC" (firmware review.cpp utc_text) */
export function utcText(unixSeconds: bigint | number): string {
  const t = typeof unixSeconds === 'bigint' ? Number(unixSeconds) : unixSeconds;
  const d = new Date(t * 1000);
  if (Number.isNaN(d.getTime())) return `${unixSeconds} (unix s)`;
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getUTCFullYear(), 4)}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(
    d.getUTCMinutes(),
  )}:${p(d.getUTCSeconds())} UTC`;
}

/** the device's duration text: "86400 s = 1 d" (firmware review.cpp duration_text) */
export function durationText(seconds: bigint): string {
  const n = seconds;
  let o = `${n} s`;
  if (n < 60n) return o;
  o += ' =';
  const d = n / 86400n;
  const h = (n % 86400n) / 3600n;
  const mi = (n % 3600n) / 60n;
  const s = n % 60n;
  if (d) o += ` ${d} d`;
  if (h) o += ` ${h} h`;
  if (mi) o += ` ${mi} min`;
  if (s) o += ` ${s} s`;
  return o;
}

/** amount with the device's format, e.g. "25 AUSD", or "25000000 base units" for an unlisted token */
export function amountText(amount: bigint, decimals: number | null, symbol: string | null): string {
  if (decimals === null || symbol === null) return `${amount} base units`;
  return `${formatUnitsDevice(amount, decimals, decimals)} ${symbol}`;
}

/** relative time for activity rows: "12 s ago", "3 min ago", "2 h ago", else the UTC date */
export function ago(unixSeconds: number, now = Date.now() / 1000): string {
  const d = Math.max(0, Math.round(now - unixSeconds));
  if (d < 60) return `${d} s ago`;
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return utcText(unixSeconds).slice(0, 16) + ' UTC';
}

/** parse "12.5" with `decimals` into base units; throws on anything else */
export function parseUnits(text: string, decimals: number): bigint {
  const t = text.trim().replace(/[,_\s]/g, '');
  if (!/^\d+(\.\d+)?$/.test(t)) throw new Error('not a positive decimal number');
  const [i, f = ''] = t.split('.') as [string, string?];
  if (f.length > decimals) throw new Error(`at most ${decimals} decimal places`);
  return BigInt(i) * 10n ** BigInt(decimals) + BigInt((f + '0'.repeat(decimals)).slice(0, decimals) || '0');
}

export function errorText(e: unknown): string {
  if (e instanceof Error) {
    const short = (e as { shortMessage?: string }).shortMessage;
    return short || e.message;
  }
  return String(e);
}
