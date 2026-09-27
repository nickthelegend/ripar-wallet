// The firmware v1.2 token table (firmware/src/tokens.cpp, security review B3: AUSD and MockUSD on 10143, MON), the
// AI-claims rule (MINOR 1) and the token check of a co-sign request (make_request.py TOKENS / NATIVE / token_check /
// ai_matches).
import { type Address, type BytesLike, type IntLike, bytesEqual, h, isZero, toAddr, toInt } from './bytes.js';
import { decodeErc20 } from './erc20.js';
import { ProtoError } from './errors.js';

export interface TokenInfo {
  decimals: number;
  symbol: string;
  name: string;
}

/** Agora USD on Monad testnet (listed in the firmware token table) */
export const AUSD_10143: Address = '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC';

/** MockUSD (contracts/src/MockUSD.sol, CREATE2) on Monad testnet: in the firmware v1.2 token table */
export const MUSD_10143: Address = '0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a';

/** ERC-20 tokens listed in the firmware table, keyed `${chainId}:${lowercase address without 0x}` */
export const FIRMWARE_TOKENS: Readonly<Record<string, TokenInfo>> = {
  [`10143:${AUSD_10143.slice(2).toLowerCase()}`]: { decimals: 6, symbol: 'AUSD', name: 'Agora USD' },
  [`10143:${MUSD_10143.slice(2).toLowerCase()}`]: { decimals: 6, symbol: 'mUSD', name: 'MockUSD (Ripar demo)' },
};

/** native coins of the supported chains */
export const NATIVE_COINS: Readonly<Record<string, TokenInfo>> = {
  '10143': { decimals: 18, symbol: 'MON', name: 'Monad testnet' },
  '143': { decimals: 18, symbol: 'MON', name: 'Monad' },
};

/** chains in the firmware chain table */
export const SUPPORTED_CHAINS: readonly bigint[] = [10143n, 143n];

export function firmwareToken(chainId: IntLike, token: BytesLike): TokenInfo | undefined {
  return FIRMWARE_TOKENS[`${toInt(chainId)}:${h(toAddr(token, 'token'))}`];
}

export function nativeCoin(chainId: IntLike): TokenInfo | undefined {
  return NATIVE_COINS[String(toInt(chainId))];
}

/** the co-sign fields the token / AI rules look at */
export interface CosignTokenView {
  chainId: bigint;
  target: Uint8Array;
  value: bigint;
  calldata: Uint8Array;
  decimals?: bigint | undefined;
  symbol?: string | undefined;
  hasDecimals: boolean;
  hasSymbol: boolean;
  claims?: { to: Uint8Array; token: Uint8Array; amount: bigint } | undefined;
}

export interface TokenCheck {
  /** the asset is the native coin of a supported chain or a listed token */
  listed: boolean;
  /** table decimals, -1 when unlisted */
  decimals: number;
  /** table symbol, or the companion's key-16 symbol for an unlisted asset ("" if none) */
  symbol: string;
}

/**
 * make_request token_check: the asset of a co-sign amount (native coin for empty calldata, else the call target).
 * Throws ProtoError when a LISTED asset carries key 15 / 16 values that differ from the table (the device refuses).
 */
export function tokenCheck(q: CosignTokenView): TokenCheck {
  const kind = decodeErc20(q.calldata).kind;
  const ent = kind === 'none' ? nativeCoin(q.chainId) : firmwareToken(q.chainId, q.target);
  if (!ent) return { listed: false, decimals: -1, symbol: q.hasSymbol ? (q.symbol ?? '') : '' };
  if (q.hasDecimals && q.decimals !== BigInt(ent.decimals)) {
    throw new ProtoError(`key 15 (decimals) = ${q.decimals} disagrees with the firmware token table (${ent.symbol} has ${ent.decimals})`);
  }
  if (q.hasSymbol && q.symbol !== ent.symbol) {
    throw new ProtoError(`key 16 (symbol) "${q.symbol}" disagrees with the firmware token table (${ent.symbol})`);
  }
  return { listed: true, decimals: ent.decimals, symbol: ent.symbol };
}

/**
 * make_request ai_matches (security review MINOR 1): only a plain native send or an ERC-20 transfer can match the AI
 * claims, and only when recipient, token (zero = native) and amount all equal the decode.
 */
export function aiMatches(q: CosignTokenView): boolean {
  const cl = q.claims;
  if (!cl) return false;
  const c = decodeErc20(q.calldata);
  if (c.kind === 'none') return bytesEqual(cl.to, q.target) && isZero(cl.token) && cl.amount === q.value;
  if (c.kind === 'transfer') {
    return q.value === 0n && bytesEqual(cl.to, c.to) && bytesEqual(cl.token, q.target) && cl.amount === c.amount;
  }
  return false;
}

/** base units -> decimal string (no grouping; trailing fraction zeros trimmed) */
export function formatUnits(amount: bigint, decimals: number): string {
  if (decimals <= 0) return amount.toString();
  const neg = amount < 0n;
  const a = neg ? -amount : amount;
  const base = 10n ** BigInt(decimals);
  const ip = a / base;
  const fp = (a % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + ip.toString() + (fp ? '.' + fp : '');
}

/**
 * The device's amount text (firmware abi.cpp format_units, reference ref_eip712.format_units): thousands separators,
 * at most `maxFrac` fraction digits, trailing zeros trimmed, "..." when non-zero digits were cut.
 * e.g. (1234500000, 6) -> "1,234.5"; (1, 18) -> "0.000000...".
 */
export function formatUnitsDevice(amount: bigint, decimals: number, maxFrac = 6): string {
  if (amount < 0n) throw new ProtoError('formatUnitsDevice: negative amount');
  const d = Math.max(0, decimals);
  const mf = Math.max(0, maxFrac);
  const base = 10n ** BigInt(d);
  const ip = amount / base;
  const frac = d ? (amount % base).toString().padStart(d, '0') : '';
  const keep = frac.slice(0, mf);
  const dropped = frac.slice(mf);
  const s = ip.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  if (/[1-9]/.test(dropped)) return s + (keep ? '.' + keep : '') + '...';
  const k = keep.replace(/0+$/, '');
  return s + (k ? '.' + k : '');
}
