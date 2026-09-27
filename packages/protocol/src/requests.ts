// Request builders and readers: a byte-for-byte port of make_request.py build_*_req / read_fields / read_request /
// guess_kind and the `build` CLI (UR single part + multipart pure parts). Same field names, same validation.
import {
  type BytesLike,
  type Hex,
  type IntLike,
  bytesToBigInt,
  pyTruthy,
  randomBytes,
  toAddr,
  toBytes,
  toHex,
  toInt,
  u256Min,
  unhex,
  utf8,
} from './bytes.js';
import { type CaveatSpec, caveatFromSpec } from './caveats.js';
import { type CborMap, type CborValue, Tag, cborDecode, cborEncode, mget, mhas } from './cbor.js';
import { FIRMWARE_PULSE_ENFORCER, FIRMWARE_REGISTRY, FIRMWARE_RELAY, firmwareAddress } from './constants.js';
import { erc20Approve, erc20Transfer, erc20TransferFrom } from './erc20.js';
import { ProtoError } from './errors.js';
import { canonicalJson } from './privy.js';
import { DEFAULT_FRAGMENT_LEN, urParts, urRead, urSingle } from './ur.js';
import { ROOT_AUTHORITY } from './eip712.js';

export type RequestKind = 'pair' | 'cosign' | 'mandate' | 'deny' | 'privy';

/** UR type of each request */
export const REQ_TYPES = {
  pair: 'ripar-pair-req',
  cosign: 'ripar-cosign-req',
  mandate: 'ripar-mandate-req',
  deny: 'ripar-deny-req',
  privy: 'ripar-privy-req',
} as const satisfies Record<RequestKind, string>;

/** UR type of the device's answer to each request */
export const RESP_TYPES = {
  pair: 'ripar-pair',
  cosign: 'ripar-cosign',
  mandate: 'eth-signature',
  deny: 'ripar-deny',
  privy: 'ripar-der-sig',
} as const satisfies Record<RequestKind, string>;

// ---------------------------------------------------------------------------------------------- field types
interface Common {
  /** 16 bytes; default: 16 random bytes */
  reqId?: BytesLike | null;
  /** wrap the req-id in CBOR tag 37 (UUID) */
  uuidTag?: boolean;
}

/**
 * Firmware v1.2 pins registry / manager / enforcer / relay on 10143 and 143 (constants FIRMWARE_*): a pair request
 * naming any other address is refused; an absent key 4 / 5 / 7 pins the firmware's. The vault is DERIVED by the device
 * from its K1 (computeVaultAddress): leave it out (the device pins its own), or give exactly that address.
 */
export interface PairFields extends Common {
  chainId: IntLike;
  /** RiparDeviceRegistry (key 3, the BindDevice domain); default: the one compiled into the firmware for the chain */
  registry?: BytesLike;
  /** DelegationManager (optional: the firmware pins its compiled-in MetaMask address when absent) */
  manager?: BytesLike | null;
  /** PulseCosignEnforcer (optional: the firmware pins its compiled-in address when absent) */
  enforcer?: BytesLike | null;
  /** RiparSentinel (not compiled in: pinned as given; without one there is no reopen) */
  sentinel?: BytesLike | null;
  /** RiparReputationRelay (optional: the firmware pins its compiled-in address when absent) */
  relay?: BytesLike | null;
  /** key 8: only the vault derived from K1 (computeVaultAddress) is accepted; best left out */
  vault?: BytesLike | null;
  /** companion clock, unix seconds (buildRequest adds the current time unless noNow) */
  now?: IntLike | null;
  /** floor for the device's panic epoch (< 2^63) */
  minEpoch?: IntLike | null;
  /** floor for the device's reopen nonce (< 2^63) */
  reopenNonce?: IntLike | null;
}

export interface CosignFields extends Common {
  chainId: IntLike;
  /** PulseCosignEnforcer (the domain verifyingContract); default: the firmware's for the chain */
  enforcer?: BytesLike;
  delegationHash: BytesLike;
  /** the vault = the vault derived from the device's K1 (computeVaultAddress), else the device refuses */
  delegator: BytesLike;
  redeemer: BytesLike;
  /** ERC-20 token or native payee */
  target: BytesLike;
  /** native value (default 0) */
  value?: IntLike;
  /** single-use per mandate (v1.2): see randomCosignNonce */
  nonce: IntLike;
  /** unix seconds, < 2^40 and at most 7 days after the device's time */
  expiry: IntLike;
  /** give at most one of calldata / transfer / approve / transferFrom */
  calldata?: BytesLike;
  transfer?: { to: BytesLike; amount: IntLike };
  approve?: { spender: BytesLike; amount: IntLike };
  transferFrom?: { from: BytesLike; to: BytesLike; amount: IntLike };
  risk?: { src?: string; category?: string; label?: string; ageDays?: IntLike };
  /** ai.text is truncated to 100 UTF-8 bytes (control characters become spaces) */
  ai?: { text?: string; claims?: { to: BytesLike; token?: BytesLike; amount: IntLike } | null };
  budgetLeft?: IntLike;
  /** token decimals claim (a listed token must match the firmware table) */
  decimals?: IntLike;
  /** token symbol claim, <= 16 bytes */
  symbol?: string;
}

export interface MandateFields extends Common {
  chainId: IntLike;
  /** DelegationManager */
  manager: BytesLike;
  /** the agent (not ANY_DELEGATE) */
  delegate: BytesLike;
  /** the vault = the vault derived from the device's K1 (computeVaultAddress), else the device refuses */
  delegator: BytesLike;
  /** default ROOT_AUTHORITY (the device refuses any other) */
  authority?: BytesLike;
  /** 1..16 caveats; exactly one pulse caveat for the device to sign */
  caveats: readonly CaveatSpec[];
  salt: IntLike;
  /** <= 64 bytes, shown as "(companion)" */
  label?: string;
  /** ERC-8004 agent id denials are filed against */
  agentId?: IntLike;
}

export interface DenyFields extends Common {
  chainId: IntLike;
  /** RiparReputationRelay; default: the firmware's for the chain */
  relay?: BytesLike;
  agentId: IntLike;
  requestHash: BytesLike;
}

export interface PrivyFields extends Common {
  /** a string = the exact bytes (UTF-8), bytes as is, an object = canonical JSON (sorted keys, no whitespace) */
  json: string | Uint8Array | Record<string, unknown>;
}

export type RequestFields = PairFields | CosignFields | MandateFields | DenyFields | PrivyFields;

// ---------------------------------------------------------------------------------------------- helpers
type Rec = Record<string, unknown>;
const has = (f: Rec, k: string): boolean => k in f && f[k] !== undefined;
const present = (f: Rec, k: string): boolean => f[k] !== undefined && f[k] !== null;

function need(f: Rec, ...keys: string[]): void {
  for (const k of keys) if (!has(f, k)) throw new ProtoError('missing field: ' + k);
}

function rid(f: Rec): Uint8Array | Tag {
  const r = present(f, 'reqId') ? toBytes(f.reqId, 16, 'reqId') : randomBytes(16);
  return pyTruthy(f.uuidTag) ? new Tag(37, r) : r;
}

const isCtl = (c: number): boolean => c < 0x20 || c === 0x7f;

/** make_request _text: string without control characters, at most `limit` UTF-8 bytes */
export function checkText(s: unknown, limit: number, what: string): string {
  if (typeof s !== 'string') throw new ProtoError(what + ': expected a string');
  for (const ch of s) if (isCtl(ch.codePointAt(0)!)) throw new ProtoError(what + ': control characters are refused by the device');
  if (utf8.encode(s).length > limit) throw new ProtoError(`${what}: longer than ${limit} UTF-8 bytes`);
  return s;
}

/** make_request ai_text_trunc: control characters -> spaces, then cut to <= limit UTF-8 bytes on a character boundary */
export function aiTextTrunc(s: string, limit = 100): string {
  const t = Array.from(s, (ch) => (isCtl(ch.codePointAt(0)!) ? ' ' : ch)).join('');
  const b = utf8.encode(t);
  if (b.length <= limit) return t;
  let end = limit;
  while (end > 0 && (b[end]! & 0xc0) === 0x80) end--;
  return new TextDecoder().decode(b.subarray(0, end));
}

const PAIR_OPT: [number, keyof PairFields][] = [
  [4, 'manager'],
  [5, 'enforcer'],
  [6, 'sentinel'],
  [7, 'relay'],
  [8, 'vault'],
];
const PAIR_FLOORS: [number, keyof PairFields][] = [
  [10, 'minEpoch'],
  [11, 'reopenNonce'],
];

// ---------------------------------------------------------------------------------------------- builders
/** make_request build_pair_req -> request CBOR map */
export function buildPairReq(fields: PairFields): CborMap {
  const f = fields as unknown as Rec;
  need(f, 'chainId');
  const chain = toInt(f.chainId);
  const reg = has(f, 'registry') ? f.registry : firmwareAddress(FIRMWARE_REGISTRY, chain);
  if (reg === undefined) {
    throw new ProtoError(`missing field: registry (no RiparDeviceRegistry is compiled in for chain ${chain})`);
  }
  // key 8 (vault) only when given: the device derives it
  const m: CborMap = new Map<number, CborValue>([
    [1, rid(f)],
    [2, chain],
    [3, toAddr(reg, 'registry')],
  ]) as CborMap;
  for (const [k, name] of PAIR_OPT) if (present(f, name)) m.set(k, toAddr(f[name], name));
  if (present(f, 'now')) m.set(9, toInt(f.now));
  for (const [k, name] of PAIR_FLOORS) {
    if (present(f, name)) {
      const v = toInt(f[name]);
      if (v < 0n || v >= 1n << 63n) throw new ProtoError(`${name}: must be 0 .. 2^63-1`);
      m.set(k, v);
    }
  }
  return m;
}

function obj(v: unknown, what: string): Rec {
  if (v === null || typeof v !== 'object' || Array.isArray(v) || v instanceof Uint8Array) {
    throw new ProtoError(`${what}: expected an object`);
  }
  return v as Rec;
}

/** make_request cosign_calldata */
export function cosignCalldata(fields: Pick<CosignFields, 'calldata' | 'transfer' | 'approve' | 'transferFrom'>): Uint8Array {
  const f = fields as unknown as Rec;
  const n = ['calldata', 'transfer', 'approve', 'transferFrom'].filter((k) => has(f, k)).length;
  if (n > 1) throw new ProtoError('give only one of calldata / transfer / approve / transferFrom');
  if (has(f, 'transfer')) {
    const t = obj(f.transfer, 'transfer');
    return erc20Transfer(toAddr(t.to, 'transfer.to'), toInt(t.amount));
  }
  if (has(f, 'approve')) {
    const t = obj(f.approve, 'approve');
    return erc20Approve(toAddr(t.spender, 'approve.spender'), toInt(t.amount));
  }
  if (has(f, 'transferFrom')) {
    const t = obj(f.transferFrom, 'transferFrom');
    return erc20TransferFrom(toAddr(t.from, 'transferFrom.from'), toAddr(t.to, 'transferFrom.to'), toInt(t.amount));
  }
  return toBytes(has(f, 'calldata') ? f.calldata : '', null, 'calldata');
}

/** make_request build_cosign_req -> request CBOR map */
export function buildCosignReq(fields: CosignFields): CborMap {
  const f = fields as unknown as Rec;
  need(f, 'chainId', 'delegationHash', 'delegator', 'redeemer', 'target', 'nonce', 'expiry');
  const chain = toInt(f.chainId);
  const enf = has(f, 'enforcer') ? f.enforcer : firmwareAddress(FIRMWARE_PULSE_ENFORCER, chain);
  if (enf === undefined) {
    throw new ProtoError(`missing field: enforcer (no PulseCosignEnforcer is compiled in for chain ${chain})`);
  }
  const m: CborMap = new Map<number, CborValue>([
    [1, rid(f)],
    [2, chain],
    [3, toAddr(enf, 'enforcer')],
    [4, toBytes(f.delegationHash, 32, 'delegationHash')],
    [5, toAddr(f.delegator, 'delegator')],
    [6, toAddr(f.redeemer, 'redeemer')],
    [7, toAddr(f.target, 'target')],
    [8, u256Min((has(f, 'value') ? f.value : 0) as IntLike)],
    [9, cosignCalldata(fields)],
    [10, u256Min(f.nonce as IntLike)],
    [11, toInt(f.expiry)],
  ]) as CborMap;
  if (has(f, 'risk')) {
    const r = f.risk as Rec;
    if (r === null || typeof r !== 'object') throw new ProtoError('risk: expected an object');
    const g = (k: string, d: unknown): unknown => (has(r, k) ? r[k] : d);
    m.set(
      12,
      new Map<number, CborValue>([
        [1, checkText(g('src', ''), 64, 'risk.src')],
        [2, checkText(g('category', ''), 64, 'risk.category')],
        [3, checkText(g('label', ''), 64, 'risk.label')],
        [4, toInt(g('ageDays', 0))],
      ]) as CborMap,
    );
  }
  if (has(f, 'ai')) {
    const a = f.ai as Rec;
    if (a === null || typeof a !== 'object') throw new ProtoError('ai: expected an object');
    const text = has(a, 'text') ? a.text : '';
    if (typeof text !== 'string') throw new ProtoError('ai.text: expected a string');
    const am: CborMap = new Map<number, CborValue>([[1, checkText(aiTextTrunc(text), 100, 'ai.text')]]) as CborMap;
    if (pyTruthy(a.claims)) {
      const c = obj(a.claims, 'ai.claims');
      need(c, 'to', 'amount');
      am.set(
        2,
        new Map<number, CborValue>([
          [1, toAddr(c.to, 'ai.claims.to')],
          [2, toAddr(has(c, 'token') ? c.token : '0x' + '00'.repeat(20), 'ai.claims.token')],
          [3, u256Min(c.amount as IntLike)],
        ]) as CborMap,
      );
    }
    m.set(13, am);
  }
  if (has(f, 'budgetLeft')) m.set(14, u256Min(f.budgetLeft as IntLike));
  if (has(f, 'decimals')) m.set(15, toInt(f.decimals));
  if (has(f, 'symbol')) m.set(16, checkText(f.symbol, 16, 'symbol'));
  return m;
}

/** make_request build_mandate_req -> request CBOR map */
export function buildMandateReq(fields: MandateFields): CborMap {
  const f = fields as unknown as Rec;
  need(f, 'chainId', 'manager', 'delegate', 'delegator', 'caveats', 'salt');
  if (!Array.isArray(f.caveats)) throw new ProtoError('caveats: expected an array');
  const cav: CborValue[] = (f.caveats as unknown[]).map((c) => caveatFromSpec(c, toInt(f.chainId)));
  const m: CborMap = new Map<number, CborValue>([
    [1, rid(f)],
    [2, toInt(f.chainId)],
    [3, toAddr(f.manager, 'manager')],
    [4, toAddr(f.delegate, 'delegate')],
    [5, toAddr(f.delegator, 'delegator')],
    [6, toBytes(has(f, 'authority') ? f.authority : ROOT_AUTHORITY, 32, 'authority')],
    [7, cav],
    [8, u256Min(f.salt as IntLike)],
  ]) as CborMap;
  if (has(f, 'label')) m.set(9, checkText(f.label, 64, 'label'));
  if (has(f, 'agentId')) m.set(10, toInt(f.agentId));
  return m;
}

/** make_request build_deny_req -> request CBOR map */
export function buildDenyReq(fields: DenyFields): CborMap {
  const f = fields as unknown as Rec;
  need(f, 'chainId', 'agentId', 'requestHash');
  const chain = toInt(f.chainId);
  const relay = has(f, 'relay') ? f.relay : firmwareAddress(FIRMWARE_RELAY, chain);
  if (relay === undefined) {
    throw new ProtoError(`missing field: relay (no RiparReputationRelay is compiled in for chain ${chain})`);
  }
  return new Map<number, CborValue>([
    [1, rid(f)],
    [2, chain],
    [3, toAddr(relay, 'relay')],
    [4, toInt(f.agentId)],
    [5, toBytes(f.requestHash, 32, 'requestHash')],
  ]) as CborMap;
}

/** make_request build_privy_req -> request CBOR map */
export function buildPrivyReq(fields: PrivyFields): CborMap {
  const f = fields as unknown as Rec;
  need(f, 'json');
  const j = f.json;
  const js = typeof j === 'string' ? utf8.encode(j) : j instanceof Uint8Array ? Uint8Array.from(j) : canonicalJson(j);
  return new Map<number, CborValue>([
    [1, rid(f)],
    [2, js],
  ]) as CborMap;
}

export const BUILDERS = {
  pair: buildPairReq,
  cosign: buildCosignReq,
  mandate: buildMandateReq,
  deny: buildDenyReq,
  privy: buildPrivyReq,
} as const;

export interface BuildOptions {
  /** max fragment bytes of the multipart parts (default 70, make_request --frag) */
  frag?: number;
  /** also append this many mixed fountain parts (make_request --extra) */
  extra?: number;
  /** pair: do not add the current time as key 9 when `now` is absent (make_request --no-now) */
  noNow?: boolean;
  /** clock for the pair `now` default (unix seconds); default Date.now() */
  nowSeconds?: () => number;
}

export interface BuiltRequest {
  kind: RequestKind;
  /** UR type, e.g. "ripar-cosign-req" */
  type: string;
  /** the 16-byte req-id (without the tag), 0x-hex */
  reqId: Hex;
  /** the request map as encoded */
  map: CborMap;
  cbor: Uint8Array;
  /** single-part UR, upper case */
  ur: string;
  /** multipart parts (pure fragments, then `extra` mixed parts), upper case */
  parts: string[];
}

/** make_request.py `build <kind> FIELDS --json`: request map -> CBOR -> single-part UR + multipart parts */
export function buildRequest(kind: 'pair', fields: PairFields, opts?: BuildOptions): BuiltRequest;
export function buildRequest(kind: 'cosign', fields: CosignFields, opts?: BuildOptions): BuiltRequest;
export function buildRequest(kind: 'mandate', fields: MandateFields, opts?: BuildOptions): BuiltRequest;
export function buildRequest(kind: 'deny', fields: DenyFields, opts?: BuildOptions): BuiltRequest;
export function buildRequest(kind: 'privy', fields: PrivyFields, opts?: BuildOptions): BuiltRequest;
export function buildRequest(kind: RequestKind, fields: RequestFields, opts?: BuildOptions): BuiltRequest;
export function buildRequest(kind: RequestKind, fields: RequestFields, opts: BuildOptions = {}): BuiltRequest {
  let f = fields;
  if (kind === 'pair' && !opts.noNow && !has(fields as unknown as Rec, 'now')) {
    const now = opts.nowSeconds ? opts.nowSeconds() : Math.floor(Date.now() / 1000);
    f = { ...(fields as PairFields), now };
  }
  const builder = BUILDERS[kind] as (x: RequestFields) => CborMap;
  if (!builder) throw new ProtoError('unknown request kind ' + String(kind));
  const map = builder(f);
  const cbor = cborEncode(map);
  const type = REQ_TYPES[kind];
  const r = mget(map, 1)!;
  const raw = r instanceof Tag ? (r.value as Uint8Array) : (r as Uint8Array);
  return {
    kind,
    type,
    reqId: toHex(raw),
    map,
    cbor,
    ur: urSingle(type, cbor),
    parts: urParts(type, cbor, opts.frag ?? DEFAULT_FRAGMENT_LEN, opts.extra ?? 0),
  };
}

// ---------------------------------------------------------------------------------------------- readers
export interface PairRequest {
  kind: 'pair';
  reqId: Uint8Array;
  chainId: bigint;
  registry: Uint8Array;
  manager: Uint8Array | null;
  enforcer: Uint8Array | null;
  sentinel: Uint8Array | null;
  relay: Uint8Array | null;
  vault: Uint8Array | null;
  now: bigint | null;
  minEpoch: bigint | null;
  reopenNonce: bigint | null;
}

export interface CosignRequest {
  kind: 'cosign';
  reqId: Uint8Array;
  chainId: bigint;
  enforcer: Uint8Array;
  delegationHash: Uint8Array;
  delegator: Uint8Array;
  redeemer: Uint8Array;
  target: Uint8Array;
  value: bigint;
  calldata: Uint8Array;
  nonce: bigint;
  expiry: bigint;
  risk: { src: string; category: string; label: string; ageDays: bigint } | null;
  ai: string | null;
  claims?: { to: Uint8Array; token: Uint8Array; amount: bigint };
  budgetLeft: bigint | null;
  /** key 15, or 18 when absent (make_request read_fields) */
  decimals: bigint;
  /** key 16, or "" when absent */
  symbol: string;
  hasDecimals: boolean;
  hasSymbol: boolean;
}

export interface MandateRequest {
  kind: 'mandate';
  reqId: Uint8Array;
  chainId: bigint;
  manager: Uint8Array;
  delegate: Uint8Array;
  delegator: Uint8Array;
  authority: Uint8Array;
  caveats: { enforcer: Uint8Array; terms: Uint8Array }[];
  salt: bigint;
  label: string | null;
  agentId: bigint | null;
}

export interface DenyRequest {
  kind: 'deny';
  reqId: Uint8Array;
  chainId: bigint;
  relay: Uint8Array;
  agentId: bigint;
  requestHash: Uint8Array;
}

export interface PrivyRequest {
  kind: 'privy';
  reqId: Uint8Array;
  json: Uint8Array;
}

export type AnyRequest = PairRequest | CosignRequest | MandateRequest | DenyRequest | PrivyRequest;

function reqIdOf(v: CborValue | undefined): Uint8Array {
  const x = v instanceof Tag && BigInt(v.tag) === 37n ? v.value : v;
  if (!(x instanceof Uint8Array) || x.length !== 16) throw new ProtoError('req-id must be bstr(16)');
  return x;
}

function req(m: CborMap, k: number): CborValue {
  if (!mhas(m, k)) throw new ProtoError(`request key ${k} is missing`);
  return mget(m, k)!;
}

function bytesAt(m: CborMap, k: number, n?: number): Uint8Array {
  const v = req(m, k);
  if (!(v instanceof Uint8Array) || (n !== undefined && v.length !== n)) {
    throw new ProtoError(`request key ${k} must be bstr${n !== undefined ? `(${n})` : ''}`);
  }
  return v;
}

function optBytes(m: CborMap, k: number, n?: number): Uint8Array | null {
  return mhas(m, k) ? bytesAt(m, k, n) : null;
}

function uintVal(v: CborValue | undefined, what: string): bigint {
  if (typeof v === 'bigint' && v >= 0n) return v;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  throw new ProtoError(`${what} must be an unsigned integer`);
}

function uintAt(m: CborMap, k: number): bigint {
  return uintVal(req(m, k), `request key ${k}`);
}

function optUint(m: CborMap, k: number): bigint | null {
  return mhas(m, k) ? uintAt(m, k) : null;
}

/** u256 field (bstr big-endian, or a plain uint as make_request's lenient to_int accepts) */
function u256At(m: CborMap, k: number): bigint {
  const v = req(m, k);
  if (v instanceof Uint8Array) {
    if (v.length > 32) throw new ProtoError(`request key ${k}: u256 longer than 32 bytes`);
    return bytesToBigInt(v);
  }
  return uintVal(v, `request key ${k}`);
}

function textOf(v: CborValue | undefined, what: string): string {
  if (typeof v !== 'string') throw new ProtoError(`${what} must be text`);
  return v;
}

function asMap(v: CborValue | undefined, what: string): CborMap {
  if (!(v instanceof Map)) throw new ProtoError(`${what} must be a map`);
  return v;
}

/**
 * make_request read_fields: request CBOR map -> normalised fields (bigint / Uint8Array). Lenient like the tool (the
 * device is the strict parser), but type-checked so a malformed request fails here instead of in a digest.
 */
export function readFields(kind: 'pair', m: CborValue): PairRequest;
export function readFields(kind: 'cosign', m: CborValue): CosignRequest;
export function readFields(kind: 'mandate', m: CborValue): MandateRequest;
export function readFields(kind: 'deny', m: CborValue): DenyRequest;
export function readFields(kind: 'privy', m: CborValue): PrivyRequest;
export function readFields(kind: RequestKind, m: CborValue): AnyRequest;
export function readFields(kind: RequestKind, mv: CborValue): AnyRequest {
  if (!(mv instanceof Map)) throw new ProtoError('request is not a map');
  const m = mv;
  const reqId = reqIdOf(mget(m, 1));
  switch (kind) {
    case 'pair':
      return {
        kind,
        reqId,
        chainId: uintAt(m, 2),
        registry: bytesAt(m, 3, 20),
        manager: optBytes(m, 4, 20),
        enforcer: optBytes(m, 5, 20),
        sentinel: optBytes(m, 6, 20),
        relay: optBytes(m, 7, 20),
        vault: optBytes(m, 8, 20),
        now: optUint(m, 9),
        minEpoch: optUint(m, 10),
        reopenNonce: optUint(m, 11),
      };
    case 'cosign': {
      const q: CosignRequest = {
        kind,
        reqId,
        chainId: uintAt(m, 2),
        enforcer: bytesAt(m, 3, 20),
        delegationHash: bytesAt(m, 4, 32),
        delegator: bytesAt(m, 5, 20),
        redeemer: bytesAt(m, 6, 20),
        target: bytesAt(m, 7, 20),
        value: u256At(m, 8),
        calldata: bytesAt(m, 9),
        nonce: u256At(m, 10),
        expiry: uintAt(m, 11),
        risk: null,
        ai: null,
        budgetLeft: mhas(m, 14) ? u256At(m, 14) : null,
        decimals: mhas(m, 15) ? uintAt(m, 15) : 18n,
        symbol: mhas(m, 16) ? textOf(mget(m, 16), 'request key 16') : '',
        hasDecimals: mhas(m, 15),
        hasSymbol: mhas(m, 16),
      };
      if (mhas(m, 12)) {
        const r = asMap(mget(m, 12), 'risk');
        q.risk = {
          src: textOf(mget(r, 1), 'risk.src'),
          category: textOf(mget(r, 2), 'risk.category'),
          label: textOf(mget(r, 3), 'risk.label'),
          ageDays: uintVal(mget(r, 4), 'risk.ageDays'),
        };
      }
      if (mhas(m, 13)) {
        const a = asMap(mget(m, 13), 'ai');
        q.ai = textOf(mget(a, 1), 'ai.text');
        if (mhas(a, 2)) {
          const c = asMap(mget(a, 2), 'ai.claims');
          const cb = (k: number, what: string): Uint8Array => {
            const v = mget(c, k);
            if (!(v instanceof Uint8Array) || v.length !== 20) throw new ProtoError(`${what} must be bstr(20)`);
            return v;
          };
          const amt = mget(c, 3);
          if (!(amt instanceof Uint8Array) || amt.length > 32) throw new ProtoError('ai.claims.amount must be a u256');
          q.claims = { to: cb(1, 'ai.claims.to'), token: cb(2, 'ai.claims.token'), amount: bytesToBigInt(amt) };
        }
      }
      return q;
    }
    case 'mandate': {
      const cv = req(m, 7);
      if (!Array.isArray(cv)) throw new ProtoError('request key 7 (caveats) must be an array');
      const caveats = cv.map((c, i) => {
        if (!Array.isArray(c) || c.length !== 2 || !(c[0] instanceof Uint8Array) || !(c[1] instanceof Uint8Array)) {
          throw new ProtoError(`caveat ${i} must be [enforcer bstr, terms bstr]`);
        }
        return { enforcer: c[0], terms: c[1] };
      });
      return {
        kind,
        reqId,
        chainId: uintAt(m, 2),
        manager: bytesAt(m, 3, 20),
        delegate: bytesAt(m, 4, 20),
        delegator: bytesAt(m, 5, 20),
        authority: bytesAt(m, 6, 32),
        caveats,
        salt: u256At(m, 8),
        label: mhas(m, 9) ? textOf(mget(m, 9), 'label') : null,
        agentId: optUint(m, 10),
      };
    }
    case 'deny':
      return {
        kind,
        reqId,
        chainId: uintAt(m, 2),
        relay: bytesAt(m, 3, 20),
        agentId: uintAt(m, 4),
        requestHash: bytesAt(m, 5, 32),
      };
    case 'privy':
      return { kind, reqId, json: bytesAt(m, 2) };
    default:
      throw new ProtoError('unknown request kind ' + String(kind));
  }
}

/** make_request guess_kind: the kind of a bare request map (CBOR hex without a UR type) */
export function guessKind(mv: CborValue): RequestKind {
  if (!(mv instanceof Map)) throw new ProtoError('request is not a map');
  if (mhas(mv, 11)) return 'cosign';
  if (Array.isArray(mget(mv, 7))) return 'mandate';
  const k5 = mget(mv, 5);
  if (k5 instanceof Uint8Array && k5.length === 32 && typeof mget(mv, 4) === 'bigint') return 'deny';
  if (mv.size === 2 && mhas(mv, 1) && mget(mv, 2) instanceof Uint8Array) return 'privy';
  return 'pair';
}

/** decodes one request CBOR into its fields */
export function decodeRequest(kind: RequestKind, cbor: Uint8Array): AnyRequest {
  return readFields(kind, cborDecode(cbor));
}

/**
 * make_request read_request: a UR (single part or multipart parts) or CBOR hex -> (kind, cbor). The kind of bare
 * CBOR is guessed (guess_kind).
 */
export function readRequest(text: string): { kind: RequestKind; cbor: Uint8Array } {
  const t = text
    .split(/\r?\n/)
    .filter((ln) => !ln.trim().startsWith('#'))
    .join('\n')
    .trim();
  if (t.toLowerCase().startsWith('ur:')) {
    const { type, cbor } = urRead(t);
    for (const [k, v] of Object.entries(REQ_TYPES) as [RequestKind, string][]) if (v === type) return { kind: k, cbor };
    throw new ProtoError('not a Ripar request UR type: ' + type);
  }
  let cb: Uint8Array;
  try {
    cb = unhex(t);
  } catch {
    throw new ProtoError('request is neither a UR nor CBOR hex');
  }
  return { kind: guessKind(cborDecode(cb)), cbor: cb };
}

/** the request type of a UR type string ('ripar-cosign-req' -> 'cosign') */
export function requestKindOfType(urType: string): RequestKind | undefined {
  for (const [k, v] of Object.entries(REQ_TYPES) as [RequestKind, string][]) if (v === urType) return k;
  return undefined;
}

