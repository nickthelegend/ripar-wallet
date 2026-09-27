// Caveat terms: the Ripar PulseCosignEnforcer Terms and the MetaMask delegation-framework v1.3.0 enforcers the device
// decodes (getTermsInfo layouts), make_request.py terms_pulse / caveat_terms / caveat_from_spec / caveat_dump.
import {
  type Address,
  type BytesLike,
  type IntLike,
  addrWord,
  bytesEqual,
  bytesToBigInt,
  concatBytes,
  h,
  isZero,
  pyTruthy,
  toAddr,
  toBytes,
  toInt,
  unhex,
  word,
} from './bytes.js';
import { ProtoError } from './errors.js';
import { toChecksumAddress } from './hash.js';

/** MetaMask delegation-framework v1.3.0 enforcer addresses (the same on 10143 and 143; firmware src/enforcers.cpp) */
export const MM_ENFORCERS = {
  AllowedTargetsEnforcer: '0x7F20f61b1f09b08D970938F6fa563634d65c4EeB',
  AllowedMethodsEnforcer: '0x2c21fD0Cb9DC8445CB3fb0DC5E7Bb0Aca01842B5',
  AllowedCalldataEnforcer: '0xc2b0d624c1c4319760C96503BA27C347F3260f55',
  ERC20PeriodTransferEnforcer: '0x474e3Ae7E169e940607cC624Da8A15Eb120139aB',
  ERC20TransferAmountEnforcer: '0xf100b0819427117EcF76Ed94B358B1A5b5C6D2Fc',
  LimitedCallsEnforcer: '0x04658B29F6b82ed55274221a06Fc97D318E25416',
  NativeTokenTransferAmountEnforcer: '0xF71af580b9c3078fbc2BBF16FbB8EEd82b330320',
  NonceEnforcer: '0xDE4f2FAC4B3D87A1d9953Ca5FC09FCa7F366254f',
  RedeemerEnforcer: '0xE144b0b2618071B4E56f746313528a669c7E65c5',
  TimestampEnforcer: '0x1046bb45C8d673d4ea75321280DB34899413c069',
  ValueLteEnforcer: '0x92Bf12322527cAA612fd31a0e810472BBB106A8F',
} as const satisfies Record<string, Address>;

/** typed caveat kinds (make_request KIND_ENF) -> the MetaMask enforcer that decodes them */
export const KIND_ENFORCER = {
  erc20TransferAmount: 'ERC20TransferAmountEnforcer',
  nativeTokenTransferAmount: 'NativeTokenTransferAmountEnforcer',
  valueLte: 'ValueLteEnforcer',
  limitedCalls: 'LimitedCallsEnforcer',
  erc20PeriodTransfer: 'ERC20PeriodTransferEnforcer',
  timestamp: 'TimestampEnforcer',
  allowedTargets: 'AllowedTargetsEnforcer',
  redeemer: 'RedeemerEnforcer',
} as const satisfies Record<string, keyof typeof MM_ENFORCERS>;
export type MetaMaskCaveatKind = keyof typeof KIND_ENFORCER;
export type CaveatKind = 'pulse' | MetaMaskCaveatKind;

/** the typed caveat kind a MetaMask enforcer address stands for (make_request ENF_KIND), or undefined */
export function enforcerKind(enforcer: BytesLike): MetaMaskCaveatKind | undefined {
  const e = toAddr(enforcer, 'enforcer');
  for (const [kind, name] of Object.entries(KIND_ENFORCER) as [MetaMaskCaveatKind, keyof typeof MM_ENFORCERS][]) {
    if (bytesEqual(unhex(MM_ENFORCERS[name]), e)) return kind;
  }
  return undefined;
}

const Z20 = new Uint8Array(20);

function wUint(x: IntLike, bits: number): Uint8Array {
  const v = toInt(x);
  if (v < 0n || v >= 1n << BigInt(bits)) throw new ProtoError(`value does not fit uint${bits}`);
  return word(v);
}

function wAddr(a: unknown): Uint8Array {
  return addrWord(toAddr(a));
}

/** IPulseCosignEnforcer.PulseTerms */
export interface PulseTerms {
  /** device P1 key x (32 bytes) */
  px: BytesLike;
  py: BytesLike;
  /** metered asset: zero = native coin only */
  token: BytesLike;
  perTxAutoCap: IntLike;
  periodAutoCap: IntLike;
  /** seconds; 0 = lifetime cap */
  period: IntLike;
  /** must equal the device's panic floor (minEpoch) exactly */
  epoch: IntLike;
  newPayeeNeedsHuman: boolean;
  /** RiparSentinel gating the AUTO path; zero = none */
  sentinel: BytesLike;
}

/**
 * PulseCosignEnforcer terms = abi.encode(bytes32 px, bytes32 py, address token, uint128 perTxAutoCap,
 * uint128 periodAutoCap, uint32 period, uint64 epoch, bool newPayeeNeedsHuman, address sentinel): 288 bytes
 */
export function encodePulseTerms(t: PulseTerms): Uint8Array {
  return concatBytes(
    toBytes(t.px, 32, 'px'),
    toBytes(t.py, 32, 'py'),
    wAddr(t.token),
    wUint(t.perTxAutoCap, 128),
    wUint(t.periodAutoCap, 128),
    wUint(t.period, 32),
    wUint(t.epoch, 64),
    wUint(pyTruthy(t.newPayeeNeedsHuman) ? 1 : 0, 8),
    wAddr(t.sentinel),
  );
}

/** decoded pulse terms (addresses EIP-55) */
export interface DecodedPulseTerms {
  px: `0x${string}`;
  py: `0x${string}`;
  p1Key: `0x${string}`;
  token: Address;
  perTxAutoCap: bigint;
  periodAutoCap: bigint;
  period: bigint;
  epoch: bigint;
  newPayeeNeedsHuman: boolean;
  sentinel: Address;
}

/**
 * Strict decode of 288-byte pulse terms with the device's canonical-word rules (caveat_dump); throws ProtoError for
 * anything the device (and the enforcer's abi.decode) would refuse.
 */
export function decodePulseTerms(terms: BytesLike): DecodedPulseTerms {
  const t = toBytes(terms, null, 'terms');
  if (t.length !== 288) throw new ProtoError('pulse terms must be 288 bytes');
  const w = Array.from({ length: 9 }, (_, i) => t.subarray(32 * i, 32 * i + 32));
  const zeroHi: [number, number][] = [
    [2, 12],
    [3, 16],
    [4, 16],
    [5, 28],
    [6, 24],
    [7, 31],
    [8, 12],
  ];
  if (zeroHi.some(([i, n]) => !isZero(w[i]!.subarray(0, n))) || w[7]![31]! > 1) {
    throw new ProtoError('pulse terms: non-canonical word');
  }
  return {
    px: `0x${h(w[0]!)}`,
    py: `0x${h(w[1]!)}`,
    p1Key: `0x${h(w[0]!)}${h(w[1]!)}`,
    token: toChecksumAddress(w[2]!.slice(12)),
    perTxAutoCap: bytesToBigInt(w[3]!),
    periodAutoCap: bytesToBigInt(w[4]!),
    period: bytesToBigInt(w[5]!),
    epoch: bytesToBigInt(w[6]!),
    newPayeeNeedsHuman: w[7]![31] === 1,
    sentinel: toChecksumAddress(w[8]!.slice(12)),
  };
}

// ---------------------------------------------------------------------------------------------- typed caveat specs
/** make_request typed caveat specs (the `kind` form); field names exactly as `make_request.py build mandate` */
export type CaveatSpecTyped =
  | {
      kind: 'pulse';
      /** the PulseCosignEnforcer pinned at pairing (required) */
      enforcer: BytesLike;
      /** px‖py (64 bytes), or px + py */
      p1Key?: BytesLike;
      px?: BytesLike;
      py?: BytesLike;
      token?: BytesLike;
      perTxAutoCap: IntLike;
      periodAutoCap: IntLike;
      period: IntLike;
      epoch?: IntLike;
      newPayeeNeedsHuman?: boolean;
      sentinel?: BytesLike;
    }
  | { kind: 'erc20TransferAmount'; enforcer?: BytesLike; token: BytesLike; amount: IntLike }
  | { kind: 'nativeTokenTransferAmount' | 'valueLte' | 'limitedCalls'; enforcer?: BytesLike; amount: IntLike }
  | { kind: 'erc20PeriodTransfer'; enforcer?: BytesLike; token: BytesLike; amount: IntLike; duration: IntLike; start: IntLike }
  | { kind: 'timestamp'; enforcer?: BytesLike; after?: IntLike; before?: IntLike }
  | { kind: 'allowedTargets' | 'redeemer'; enforcer?: BytesLike; addresses: BytesLike[] };

/** any caveat form make_request accepts: typed, {enforcer, terms} or [enforcer, termsHex] */
export type CaveatSpec = CaveatSpecTyped | { enforcer: BytesLike; terms?: BytesLike } | readonly [BytesLike, BytesLike];

type AnyRec = Record<string, unknown>;

/** make_request caveat_terms(kind, c) */
export function caveatTerms(kind: string, c: AnyRec): Uint8Array {
  const need = (k: string): unknown => {
    if (!(k in c) || c[k] === undefined) throw new ProtoError(`missing field: ${k}`);
    return c[k];
  };
  const get = (k: string, dflt: unknown): unknown => (k in c && c[k] !== undefined ? c[k] : dflt);
  switch (kind) {
    case 'pulse': {
      let px: unknown;
      let py: unknown;
      if ('p1Key' in c && c.p1Key !== undefined) {
        const xy = toBytes(c.p1Key, 64, 'p1Key');
        px = xy.subarray(0, 32);
        py = xy.subarray(32);
      } else {
        px = need('px');
        py = need('py');
      }
      return encodePulseTerms({
        px: px as BytesLike,
        py: py as BytesLike,
        token: get('token', Z20) as BytesLike,
        perTxAutoCap: need('perTxAutoCap') as IntLike,
        periodAutoCap: need('periodAutoCap') as IntLike,
        period: need('period') as IntLike,
        epoch: get('epoch', 0) as IntLike,
        newPayeeNeedsHuman: pyTruthy(get('newPayeeNeedsHuman', true)),
        sentinel: get('sentinel', Z20) as BytesLike,
      });
    }
    case 'erc20TransferAmount':
      return concatBytes(toAddr(need('token')), wUint(need('amount') as IntLike, 256));
    case 'nativeTokenTransferAmount':
    case 'valueLte':
    case 'limitedCalls':
      return wUint(need('amount') as IntLike, 256);
    case 'erc20PeriodTransfer':
      return concatBytes(
        toAddr(need('token')),
        wUint(need('amount') as IntLike, 256),
        wUint(need('duration') as IntLike, 256),
        wUint(need('start') as IntLike, 256),
      );
    case 'timestamp':
      return concatBytes(wUint(get('after', 0) as IntLike, 128).subarray(16), wUint(get('before', 0) as IntLike, 128).subarray(16));
    case 'allowedTargets':
    case 'redeemer': {
      const a = need('addresses');
      if (!Array.isArray(a)) throw new ProtoError('addresses must be an array');
      return concatBytes(...a.map((x) => toAddr(x)));
    }
    default:
      throw new ProtoError('unknown caveat kind ' + kind);
  }
}

/** one caveat as [enforcer (20 bytes), terms] */
export type CaveatPair = [Uint8Array, Uint8Array];

/** make_request caveat_from_spec */
export function caveatFromSpec(c: CaveatSpec | unknown): CaveatPair {
  if (c !== null && typeof c === 'object' && !Array.isArray(c) && !(c instanceof Uint8Array)) {
    const o = c as AnyRec;
    if ('kind' in o) {
      const k = String(o.kind);
      let enf: unknown;
      if (k === 'pulse') {
        if (!('enforcer' in o) || o.enforcer === undefined) {
          throw new ProtoError('pulse caveat: give the PulseCosignEnforcer address (enforcer)');
        }
        enf = o.enforcer;
      } else {
        const name = (KIND_ENFORCER as Record<string, keyof typeof MM_ENFORCERS>)[k];
        if (name === undefined) throw new ProtoError('unknown caveat kind ' + k);
        enf = pyTruthy(o.enforcer) ? o.enforcer : MM_ENFORCERS[name];
      }
      return [toAddr(enf, 'caveat.enforcer'), caveatTerms(k, o)];
    }
    if (!('enforcer' in o)) throw new ProtoError('missing field: enforcer');
    // c.get("terms", "") in make_request: an absent member is empty terms, an explicit null is refused
    return [toAddr(o.enforcer, 'caveat.enforcer'), toBytes(o.terms === undefined ? '' : o.terms, null, 'caveat.terms')];
  }
  if (Array.isArray(c)) {
    if (c.length < 2) throw new ProtoError('caveat: expected [enforcer, terms]');
    return [toAddr(c[0], 'caveat.enforcer'), toBytes(c[1], null, 'caveat.terms')];
  }
  throw new ProtoError('caveat: expected {kind, ...}, {enforcer, terms} or [enforcer, terms]');
}

/**
 * Independent decode of one caveat, same text as the device's review (make_request caveat_dump /
 * test_policy.cpp dump()). null = the device must refuse this caveat. (pulseChain, pulseEnforcer) = the
 * PulseCosignEnforcer pinned at pairing.
 */
export function caveatDump(
  chain: IntLike,
  enforcer: BytesLike,
  terms: BytesLike,
  pulseChain: IntLike,
  pulseEnforcer: BytesLike,
): string | null {
  const t = toBytes(terms, null, 'terms');
  const e = toAddr(enforcer, 'enforcer');
  const ch = toInt(chain);
  const d = (b: Uint8Array): string => bytesToBigInt(b).toString();
  if (isZero(e)) return null;
  if (ch === toInt(pulseChain) && bytesEqual(e, toAddr(pulseEnforcer, 'pulseEnforcer'))) {
    let p: DecodedPulseTerms;
    try {
      p = decodePulseTerms(t);
    } catch {
      return null;
    }
    return (
      `pulse px=${p.px.slice(2)} py=${p.py.slice(2)} token=${p.token.slice(2).toLowerCase()} perTx=${p.perTxAutoCap} ` +
      `periodCap=${p.periodAutoCap} period=${p.period} epoch=${p.epoch} human=${p.newPayeeNeedsHuman ? 1 : 0} ` +
      `sentinel=${p.sentinel.slice(2).toLowerCase()}`
    );
  }
  if (ch !== 10143n && ch !== 143n) return null;
  const k = enforcerKind(e);
  if (k === 'erc20TransferAmount' && t.length === 52 && !isZero(t.subarray(0, 20))) {
    return `erc20TransferAmount token=${h(t.subarray(0, 20))} amount=${d(t.subarray(20))}`;
  }
  if ((k === 'nativeTokenTransferAmount' || k === 'valueLte' || k === 'limitedCalls') && t.length === 32) {
    return `${k} amount=${d(t)}`;
  }
  if (k === 'erc20PeriodTransfer' && t.length === 116 && !isZero(t.subarray(0, 20)) && !isZero(t.subarray(52, 84))) {
    return `erc20PeriodTransfer token=${h(t.subarray(0, 20))} amount=${d(t.subarray(20, 52))} duration=${d(t.subarray(52, 84))} start=${d(t.subarray(84))}`;
  }
  if (k === 'timestamp' && t.length === 32) return `timestamp after=${d(t.subarray(0, 16))} before=${d(t.subarray(16))}`;
  if ((k === 'allowedTargets' || k === 'redeemer') && t.length > 0 && t.length % 20 === 0 && t.length / 20 <= 16) {
    const list: string[] = [];
    for (let i = 0; i < t.length; i += 20) list.push(h(t.subarray(i, i + 20)));
    return `${k} ${list.join(',')}`;
  }
  return null;
}
