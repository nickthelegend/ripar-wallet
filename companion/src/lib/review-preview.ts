// "What your device will show": the review lines of a request, mirrored line for line from the firmware
// (firmware/src/review.cpp review_mandate / review_cosign, tokens.cpp, enforcers.cpp). The device renders its own
// review from the bytes it scanned; this preview is the companion's prediction, tested against the WASM emulator.
// It assumes the device accepts the request (no REFUSED line) and that its context is the one the companion pinned.
import {
  type CosignRequest,
  type MandateRequest,
  aiMatches,
  bytesEqual,
  bytesToBigInt,
  decodeErc20,
  decodePulseTerms,
  enforcerKind,
  firmwareToken,
  formatUnitsDevice,
  isZero,
  nativeCoin,
  toAddr,
  toChecksumAddress,
  toHex,
  unhex,
} from '@ripar/protocol';
import { durationText, utcText } from './format';

export type Tone = 'normal' | 'good' | 'warn' | 'bad' | 'dim';

export interface PreviewLine {
  label: string;
  value: string;
  tone: Tone;
}

export interface ReviewPreview {
  title: string;
  lines: PreviewLine[];
}

const KIND_TEXT: Record<string, string> = {
  pulse: 'Pulse co-sign + spend caps',
  erc20TransferAmount: 'ERC-20 total spend cap',
  nativeTokenTransferAmount: 'MON total spend cap',
  valueLte: 'Max MON value per call',
  limitedCalls: 'Limited number of calls',
  erc20PeriodTransfer: 'ERC-20 cap per period',
  timestamp: 'Valid time window',
  allowedTargets: 'Only listed contracts',
  redeemer: 'Only listed redeemers',
};

const MAX256 = (1n << 256n) - 1n;

/** the device's view of an asset: a listed token / native coin, or UNKNOWN (tokens.cpp TokenView) */
interface TokenView {
  listed: boolean;
  native: boolean;
  token: string;
  decimals: number;
  symbol: string;
  name: string;
}

function tokenView(chainId: bigint, native: boolean, token: Uint8Array | null, claimSymbol?: string): TokenView {
  const ent = native ? nativeCoin(chainId) : token && !isZero(token) ? firmwareToken(chainId, token) : undefined;
  const addr = token ? toChecksumAddress(token) : '';
  if (ent) return { listed: true, native, token: addr, decimals: ent.decimals, symbol: ent.symbol, name: ent.name };
  return { listed: false, native, token: addr, decimals: -1, symbol: claimSymbol ?? '', name: '' };
}

function amountText(tv: TokenView, a: bigint): string {
  let s = tv.listed && tv.decimals >= 0 ? `${formatUnitsDevice(a, tv.decimals, tv.decimals)} ${tv.symbol}` : `${a} base units`;
  if (a === MAX256) s += ' (UNLIMITED)';
  return s;
}

function chainText(chainId: bigint): string {
  if (chainId === 10143n) return 'Monad testnet (10143)';
  if (chainId === 143n) return 'Monad (143)';
  return `UNKNOWN CHAIN ${chainId}`;
}

/** firmware ascii_text: printable ASCII kept, one '?' per other character */
export function asciiText(s: string): string {
  let o = '';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    o += c >= 0x20 && c < 0x7f ? ch : '?';
  }
  return o;
}

function timeText(t: bigint): string {
  return t < 1n << 64n ? utcText(t) : `${t} (unix s)`;
}

class Out {
  lines: PreviewLine[] = [];
  add(label: string, value: string, tone: Tone = 'normal'): void {
    this.lines.push({ label, value, tone });
  }
  token(tv: TokenView): void {
    if (tv.listed) this.add('Token', `${tv.symbol} - ${tv.name}`, 'good');
    else this.add('Token', 'UNKNOWN TOKEN - decimals unverified', 'bad');
    this.add('Token addr', tv.token);
    if (!tv.listed && tv.symbol) this.add('Symbol', `${asciiText(tv.symbol)} (companion)`, 'warn');
  }
}

export interface PreviewContext {
  /** the device's P1 key px‖py */
  p1Key: string;
  /** the pinned vault / sentinel */
  vault: string;
  sentinel: string;
  /** the device's panic floor (the mandate's epoch must equal it) */
  minEpoch: bigint;
  /** the last mandate the device signed (co-sign: known / UNKNOWN MANDATE) */
  lastDelegationHash?: string | null;
}

const eqAddr = (a: Uint8Array, b: string) => bytesEqual(a, toAddr(b));

export function previewMandate(r: MandateRequest, ctx: PreviewContext): ReviewPreview {
  const o = new Out();
  if (r.label) o.add('Label', `${asciiText(r.label)} (companion)`, 'dim');
  o.add('Agent id', r.agentId !== null ? String(r.agentId) : 'none');
  o.add('Delegate', toChecksumAddress(r.delegate));
  const vaultPinned = !isZero(toAddr(ctx.vault)) && eqAddr(r.delegator, ctx.vault);
  o.add('Vault', toChecksumAddress(r.delegator), vaultPinned ? 'good' : 'normal');
  o.add('Chain', chainText(r.chainId));
  o.add('Manager', toChecksumAddress(r.manager));
  const n = r.caveats.length;
  r.caveats.forEach((c, i) => {
    const kind = decodeKind(c.enforcer, c.terms);
    o.add(`Rule ${i + 1}/${n}`, kind ? KIND_TEXT[kind]! : 'REFUSED', kind ? 'normal' : 'bad');
    if (kind === 'pulse') {
      const t = decodePulseTerms(c.terms);
      const mine = t.p1Key.toLowerCase() === ctx.p1Key.toLowerCase();
      if (mine) o.add('Device key', 'THIS DEVICE', 'good');
      else o.add('Device key', `OTHER KEY ${t.px}${t.py.slice(2)}`, 'bad');
      const tokenZero = /^0x0{40}$/i.test(t.token);
      const tv = tokenView(r.chainId, tokenZero, tokenZero ? null : unhex(t.token));
      if (tokenZero) o.add('Metered', `${tv.listed ? tv.symbol : 'native coin'} only (native)`);
      else o.token(tv);
      o.add('Auto per tx', amountText(tv, t.perTxAutoCap));
      o.add('Auto per period', amountText(tv, t.periodAutoCap));
      o.add('Period', durationText(t.period));
      const e = t.epoch;
      o.add(
        'Epoch',
        `${e}` + (e < ctx.minEpoch ? ' (STALE)' : e > ctx.minEpoch ? ` (ABOVE THE PANIC FLOOR ${ctx.minEpoch})` : ' (= panic floor)'),
        e === ctx.minEpoch ? 'normal' : 'bad',
      );
      o.add('New payees', t.newPayeeNeedsHuman ? 'need a pulse co-sign' : 'AUTO path allowed', t.newPayeeNeedsHuman ? 'good' : 'warn');
      const pinnedSentinel = toChecksumAddress(ctx.sentinel);
      if (/^0x0{40}$/i.test(t.sentinel)) {
        o.add('Sentinel', 'none - no kill-switch lane', /^0x0{40}$/i.test(pinnedSentinel) ? 'warn' : 'bad');
      } else {
        const same = t.sentinel === pinnedSentinel;
        o.add('Sentinel', t.sentinel + (same ? '' : ' (NOT PINNED)'), same ? 'good' : 'bad');
      }
    } else if (kind === 'erc20TransferAmount') {
      const tv = tokenView(r.chainId, false, c.terms.subarray(0, 20));
      o.token(tv);
      o.add('Total cap', amountText(tv, bytesToBigInt(c.terms.subarray(20))));
    } else if (kind === 'nativeTokenTransferAmount') {
      o.add('Total cap', amountText(tokenView(r.chainId, true, null), bytesToBigInt(c.terms)));
    } else if (kind === 'valueLte') {
      o.add('Max per call', amountText(tokenView(r.chainId, true, null), bytesToBigInt(c.terms)));
    } else if (kind === 'limitedCalls') {
      o.add('Max calls', bytesToBigInt(c.terms).toString());
    } else if (kind === 'erc20PeriodTransfer') {
      const tv = tokenView(r.chainId, false, c.terms.subarray(0, 20));
      o.token(tv);
      o.add('Per period', amountText(tv, bytesToBigInt(c.terms.subarray(20, 52))));
      o.add('Period', durationText(bytesToBigInt(c.terms.subarray(52, 84))));
      o.add('Starts', timeText(bytesToBigInt(c.terms.subarray(84, 116))));
    } else if (kind === 'timestamp') {
      const after = bytesToBigInt(c.terms.subarray(0, 16));
      const before = bytesToBigInt(c.terms.subarray(16, 32));
      o.add('Valid after', after === 0n ? 'no start limit' : timeText(after));
      o.add('Valid before', before === 0n ? 'no end' : timeText(before), before === 0n ? 'warn' : 'normal');
    } else if (kind === 'allowedTargets' || kind === 'redeemer') {
      const m = c.terms.length / 20;
      for (let j = 0; j < m; j++) {
        o.add(`${kind === 'allowedTargets' ? 'Contract' : 'Redeemer'} ${j + 1}/${m}`, toChecksumAddress(c.terms.subarray(20 * j, 20 * j + 20)));
      }
    }
    o.add('Enforcer', toChecksumAddress(c.enforcer), 'dim');
  });
  o.add('Salt', r.salt.toString(), 'dim');
  o.add('Authority', 'ROOT (new mandate, not a re-delegation)', 'dim');
  return { title: 'SIGN MANDATE', lines: o.lines };
}

/** the device's decoder for a caveat (review.cpp decode_caveat), by enforcer; null = refused */
function decodeKind(enforcer: Uint8Array, terms: Uint8Array): string | null {
  if (terms.length === 288) {
    try {
      decodePulseTerms(terms);
      if (!enforcerKind(enforcer)) return 'pulse';
    } catch {
      /* not pulse terms */
    }
  }
  const k = enforcerKind(enforcer);
  if (!k) return null;
  const len = terms.length;
  const ok =
    (k === 'erc20TransferAmount' && len === 52) ||
    ((k === 'nativeTokenTransferAmount' || k === 'valueLte' || k === 'limitedCalls') && len === 32) ||
    (k === 'erc20PeriodTransfer' && len === 116) ||
    (k === 'timestamp' && len === 32) ||
    ((k === 'allowedTargets' || k === 'redeemer') && len > 0 && len % 20 === 0 && len <= 320);
  return ok ? k : null;
}

export function previewCosign(r: CosignRequest, ctx: PreviewContext): ReviewPreview {
  const o = new Out();
  const call = decodeErc20(r.calldata);
  const native = call.kind === 'none';
  const tv = tokenView(r.chainId, native, native ? null : r.target, r.hasSymbol ? r.symbol : undefined);
  const tok = tv.listed ? tv.symbol : 'UNKNOWN TOKEN';
  switch (call.kind) {
    case 'none':
      o.add('Action', `Send ${tv.listed ? tv.symbol : 'native coin'} (native)`);
      o.add('Amount', amountText(tv, r.value));
      o.add('To', toChecksumAddress(r.target));
      if (!tv.listed) o.add('Asset', 'native coin of an UNKNOWN CHAIN - decimals unverified', 'bad');
      break;
    case 'transfer':
      o.add('Action', `Send ${tok} (ERC-20 transfer)`);
      o.add('Amount', amountText(tv, call.amount));
      o.add('To', toChecksumAddress(call.to));
      o.token(tv);
      break;
    case 'transferFrom': {
      const fromVault = bytesEqual(call.from, r.delegator);
      o.add('Action', `Pull ${tok} (ERC-20 transferFrom)`, fromVault ? 'normal' : 'warn');
      o.add('Amount', amountText(tv, call.amount));
      o.add('From', toChecksumAddress(call.from) + (fromVault ? ' (vault)' : ' (NOT the vault)'), fromVault ? 'normal' : 'warn');
      o.add('To', toChecksumAddress(call.to));
      o.token(tv);
      break;
    }
    case 'approve':
      o.add('Action', `APPROVE ${tok} spending (ERC-20 approve)`, 'warn');
      o.add('Allowance', amountText(tv, call.amount), 'warn');
      o.add('Spender', toChecksumAddress(call.to));
      o.token(tv);
      break;
    default: {
      const n = r.calldata.length;
      o.add('Action', `UNKNOWN CALL ${toHex(r.calldata.subarray(0, Math.min(4, n)))} (${n} bytes)`, 'bad');
      o.add('Contract', toChecksumAddress(r.target));
    }
  }
  if (!tv.listed && r.hasDecimals) o.add('Decimals', `${r.decimals} (companion, unverified)`, 'warn');
  if (call.kind !== 'none' && r.value !== 0n) o.add('Native value', `${amountText(tokenView(r.chainId, true, null), r.value)} ALSO SENT`, 'bad');
  o.add('Chain', chainText(r.chainId));
  const vaultPinned = !isZero(toAddr(ctx.vault)) && eqAddr(r.delegator, ctx.vault);
  o.add('Vault', toChecksumAddress(r.delegator), vaultPinned ? 'good' : 'normal');
  o.add('Redeemer', toChecksumAddress(r.redeemer));
  const dh = toHex(r.delegationHash);
  const known = !!ctx.lastDelegationHash && ctx.lastDelegationHash.toLowerCase() === dh.toLowerCase();
  o.add('Mandate', dh, known ? 'good' : 'warn');
  if (!known) o.add('', 'UNKNOWN MANDATE - not the last mandate this device signed', 'warn');
  o.add('Expires', utcText(r.expiry));
  o.add('Nonce', r.nonce.toString());
  if (r.budgetLeft !== null) o.add('Budget left', `${amountText(tv, r.budgetLeft)} (companion)`, 'dim');
  if (r.ai !== null) o.add('AI says', `${asciiText(r.ai)} (companion)`, 'dim');
  if (r.claims) {
    const kindText = call.kind === 'none' ? 'native send' : call.kind === 'transfer' ? 'ERC-20 transfer' : null;
    if (!kindText) o.add('AI claims', 'NOT CHECKED - only a transfer can match', 'warn');
    else if (aiMatches(r)) o.add('AI claims', `MATCH - recipient, token and amount (${kindText})`, 'good');
    else o.add('AI claims', "MISMATCH - the agent's claim differs from this request", 'bad');
  }
  if (r.risk) {
    o.add(
      'Risk',
      `${asciiText(r.risk.src)}: ${asciiText(r.risk.category)} / ${asciiText(r.risk.label)}, ${r.risk.ageDays} days old (companion)`,
      'warn',
    );
  }
  o.add('Enforcer', toChecksumAddress(r.enforcer), 'dim');
  return { title: 'CO-SIGN PAYMENT', lines: o.lines };
}
