// Response parsing + verification: a port of make_request.py parse_response. Every digest is rebuilt from the
// request (never taken from the device), every P-256 signature is verified with the low-s rule, K1 is recovered.
import {
  type Address,
  type BytesLike,
  type Hex,
  type IntLike,
  bytesEqual,
  bytesToBigInt,
  concatBytes,
  toAddr,
  toBytes,
  toHex,
  toInt,
  unhex,
  word,
} from './bytes.js';
import { type CborMap, type CborValue, cborDecode, mget, mhas } from './cbor.js';
import { P256_N, SECP256K1_N, derParse, isLowS, k1RecoverAddress, p256OnCurve, p256Verify } from './crypto.js';
import {
  cosignDigest,
  cosignRequestHash,
  delegationHash as delegationStructHash,
  denyDigest,
  mandateDigest,
  pairDigest,
  panicDigest,
  presenceHash as presenceHashOf,
  reopenDigest,
  revokeDigest,
} from './eip712.js';
import { FIRMWARE_PULSE_ENFORCER, FIRMWARE_RELAY, type FirmwareTable, firmwareAddress } from './constants.js';
import { ProtoError } from './errors.js';
import { firmwareRefusal } from './firmware.js';
import { keccak256, sha256, toChecksumAddress } from './hash.js';
import { base64Encode } from './privy.js';
import {
  type AnyRequest,
  type BuiltRequest,
  type CosignRequest,
  type RequestKind,
  decodeRequest,
  readRequest,
} from './requests.js';
import { type UrContent, urRead } from './ur.js';
import { computeVaultAddress } from './vault.js';

export const RESPONSE_TYPES = [
  'ripar-pair',
  'ripar-cosign',
  'ripar-deny',
  'eth-signature',
  'ripar-der-sig',
  'ripar-revoke',
  'ripar-panic',
  'ripar-reopen',
] as const;
export type ResponseType = (typeof RESPONSE_TYPES)[number];

/** firmware id (key 6 of ripar-pair) of the WASM emulator: sha256("ripar-emulator v1")[:8] */
export const EMULATOR_FIRMWARE_ID: Hex = toHex(sha256(new TextEncoder().encode('ripar-emulator v1')).slice(0, 8));

export interface Check {
  name: string;
  ok: boolean;
}

/** evidence12 (docs/PROTOCOL.md §5), big-endian */
export interface Evidence {
  version: number;
  bpm: number;
  beats: number;
  irDC: number;
  redDC: number;
  jitterX1000: number;
  durationMs: number;
}

export function evidenceFields(ev: Uint8Array): Evidence {
  if (ev.length !== 12) throw new ProtoError('evidence12 must be 12 bytes');
  return {
    version: ev[0]!,
    bpm: ev[1]!,
    beats: ev[2]!,
    irDC: (ev[3]! << 16) | (ev[4]! << 8) | ev[5]!,
    redDC: (ev[6]! << 16) | (ev[7]! << 8) | ev[8]!,
    jitterX1000: ev[9]!,
    durationMs: 10 * ((ev[10]! << 8) | ev[11]!),
  };
}

export interface PairResponseFields {
  /** absent in the keys-only pairing QR */
  reqId?: Hex;
  k1Address: Address;
  /** the vault derived from K1 (firmware v1.2 pins exactly this one, docs/PROTOCOL.md 2.1): deploy and fund it */
  vault: Address;
  /** px‖py */
  p1Key: Hex;
  px: Hex;
  py: Hex;
  /** keccak256(abi.encode(px, py)) */
  keyId: Hex;
  firmwareId: Hex;
  /** firmwareId = the emulator's id: label it EMULATOR */
  emulator: boolean;
  p1Signature?: Hex;
  k1Signature?: Hex;
  bindDigest?: Hex;
}

export interface CosignResponseFields {
  reqId: Hex;
  rs: Hex;
  r: Hex;
  s: Hex;
  evidence12: Hex;
  evidence: Evidence;
  salt16: Hex;
  presenceHash: Hex;
  digest?: Hex;
  /** abi.encode(nonce, expiry, presenceHash, r, s): the pulse caveat's args for redeemDelegations (HUMAN path) */
  caveatArgs?: Hex;
}

export interface DenyResponseFields {
  reqId: Hex;
  rs: Hex;
  r: Hex;
  s: Hex;
  evidence12: Hex;
  evidence: Evidence;
  salt16: Hex;
  presenceHash: Hex;
  agentId: bigint;
  requestHash: Hex;
  digest?: Hex;
}

export interface MandateResponseFields {
  reqId: Hex;
  /** r‖s‖v (v = 27/28): the Delegation.signature for redeemDelegations */
  rsv: Hex;
  delegationHash?: Hex;
  digest?: Hex;
  signer?: Address;
}

export interface DerSigResponseFields {
  reqId: Hex;
  der: Hex;
  /** base64 of the DER signature: the privy-authorization-signature header value */
  derBase64: string;
  r: Hex;
  s: Hex;
}

export interface RevokeResponseFields {
  delegationHash: Hex;
  rs: Hex;
  r: Hex;
  s: Hex;
  digest?: Hex;
}

export interface PanicResponseFields {
  minEpoch: bigint;
  rs: Hex;
  r: Hex;
  s: Hex;
  digest?: Hex;
}

export interface ReopenResponseFields {
  vault: Address;
  nonce: bigint;
  rs: Hex;
  r: Hex;
  s: Hex;
  digest?: Hex;
}

export type ParsedResponse =
  | { type: 'ripar-pair'; fields: PairResponseFields }
  | { type: 'ripar-cosign'; fields: CosignResponseFields }
  | { type: 'ripar-deny'; fields: DenyResponseFields }
  | { type: 'eth-signature'; fields: MandateResponseFields }
  | { type: 'ripar-der-sig'; fields: DerSigResponseFields }
  | { type: 'ripar-revoke'; fields: RevokeResponseFields }
  | { type: 'ripar-panic'; fields: PanicResponseFields }
  | { type: 'ripar-reopen'; fields: ReopenResponseFields };

export type VerifyResult = 'VERIFIED' | 'UNVERIFIED' | 'FAIL';

export type VerifyReport = ParsedResponse & {
  /** every check made, in make_request's order and wording */
  checks: Check[];
  /** signatures that could not be checked (key / request / contract missing) */
  unverified: string[];
  /** all checks passed (make_request rep.ok()) */
  ok: boolean;
  /** FAIL = a check failed; UNVERIFIED = nothing failed but something could not be checked (or no checks); VERIFIED */
  result: VerifyResult;
};

export type RequestInput = BuiltRequest | { kind: RequestKind; cbor: Uint8Array } | string;

export interface ParseOptions {
  /** the request this response answers (needed for pair / cosign / mandate / deny / privy digests) */
  request?: RequestInput | null;
  /** the device's P1 key px‖py (64 bytes), from the pairing */
  p1Key?: BytesLike | null;
  /** the device's K1 address, from the pairing */
  k1Address?: BytesLike | null;
  /** chain of the pinned context (revoke / panic / reopen; deny without a deny request) */
  chainId?: IntLike | null;
  /** contract of the pinned context: enforcer (revoke / panic), sentinel (reopen), relay (deny) */
  contract?: BytesLike | null;
  /** a pairing response UR: p1Key / k1Address are taken from it when not given (make_request --pair) */
  pairing?: string | null;
  /**
   * The context pinned at pairing: when chainId / contract are not given, the chain and the domain contract of the
   * response type are taken from it (revoke / panic: enforcer, reopen: sentinel, deny: relay).
   */
  pinned?: PinnedContext | null;
}

/** the chain and contracts the device pinned at pairing (the pair request the companion built) */
export interface PinnedContext {
  chainId: IntLike;
  enforcer?: BytesLike | null;
  sentinel?: BytesLike | null;
  relay?: BytesLike | null;
}

/** the domain contract of a device-signed message type in a pinned context (null when the type has none there) */
export function pinnedContractFor(type: string, pinned: PinnedContext): BytesLike | null {
  if (type === 'ripar-revoke' || type === 'ripar-panic') return pinned.enforcer ?? null;
  if (type === 'ripar-reopen') return pinned.sentinel ?? null;
  if (type === 'ripar-deny') return pinned.relay ?? null;
  return null;
}

function toRequest(r: RequestInput): AnyRequest {
  if (typeof r === 'string') {
    const { kind, cbor } = readRequest(r);
    return decodeRequest(kind, cbor);
  }
  return decodeRequest(r.kind, r.cbor);
}

class Rep {
  checks: Check[] = [];
  unverified: string[] = [];
  check(name: string, ok: boolean): boolean {
    this.checks.push({ name, ok: !!ok });
    return ok;
  }
}

function p256Check(rep: Rep, name: string, xy: Uint8Array, digest: Uint8Array, rs: Uint8Array): void {
  const r = bytesToBigInt(rs.subarray(0, 32));
  const s = bytesToBigInt(rs.subarray(32, 64));
  rep.check(name + ' low-s', isLowS(s, P256_N));
  rep.check(name + ' P-256 signature', p256Verify(xy, digest, r, s));
}

function k1Recover(rep: Rep, name: string, digest: Uint8Array, rsv: Uint8Array): Uint8Array | null {
  const r = bytesToBigInt(rsv.subarray(0, 32));
  const s = bytesToBigInt(rsv.subarray(32, 64));
  const v = rsv[64]!;
  rep.check(name + ' v is 27/28', v === 27 || v === 28);
  rep.check(name + ' low-s', isLowS(s, SECP256K1_N));
  const who = v === 27 || v === 28 ? k1RecoverAddress(digest, r, s, v - 27) : null;
  rep.check(name + ' recoverable', who !== null);
  return who;
}

/** abi.encode(uint256 nonce, uint64 expiry, bytes32 presenceHash, bytes32 r, bytes32 s): 160 bytes */
export function cosignCaveatArgs(nonce: IntLike, expiry: IntLike, presenceHash: BytesLike, rs: BytesLike): Hex {
  const sig = toBytes(rs, 64, 'rs');
  return toHex(concatBytes(word(toInt(nonce)), word(toInt(expiry)), toBytes(presenceHash, 32, 'presenceHash'), sig));
}

/**
 * make_request parse_response: UR -> fields + checks. Throws ProtoError for a malformed response (not a UR, bad
 * CBOR, unexpected keys, wrong lengths); a signature / digest mismatch is a failed check (result FAIL), never a throw.
 */
export function parseResponse(ur: string | UrContent, opts: ParseOptions = {}): VerifyReport {
  const { type: utype, cbor } = typeof ur === 'string' ? urRead(ur.trim()) : ur;
  const mv = cborDecode(cbor);
  if (!(mv instanceof Map)) throw new ProtoError('response is not a map');
  const m: CborMap = mv;
  const q = opts.request ? toRequest(opts.request) : null;
  let p1xy = opts.p1Key != null ? toBytes(opts.p1Key, 64, 'p1Key') : null;
  let k1addr = opts.k1Address != null ? toAddr(opts.k1Address, 'k1Address') : null;
  if (opts.pairing) {
    const pr = parseResponse(opts.pairing);
    if (pr.type !== 'ripar-pair') throw new ProtoError('pairing: not a ripar-pair response');
    p1xy = p1xy ?? toBytes(pr.fields.p1Key, 64);
    k1addr = k1addr ?? toAddr(pr.fields.k1Address);
  }
  const pc = opts.pinned ? pinnedContractFor(utype, opts.pinned) : null;
  const chain = opts.chainId != null ? toInt(opts.chainId) : opts.pinned ? toInt(opts.pinned.chainId) : null;
  const contract = opts.contract != null ? toAddr(opts.contract, 'contract') : pc != null ? toAddr(pc, 'pinned contract') : null;
  const rep = new Rep();
  /** the contract given (or pinned), else the one compiled into the firmware for chain `ch` (make_request pinned_or) */
  const pinnedOr = (table: FirmwareTable, ch: bigint | null): Uint8Array | null => {
    if (contract !== null) return contract;
    const a = ch === null ? undefined : firmwareAddress(table, ch);
    return a === undefined ? null : unhex(a);
  };

  const needBytes = (k: number, n: number | null): Uint8Array => {
    const v = mget(m, k);
    if (!(v instanceof Uint8Array) || (n !== null && v.length !== n)) throw new ProtoError(`key ${k} must be bstr(${n ?? 'None'})`);
    return v;
  };
  const keysOnly = (...ks: number[]): void => {
    const extra = [...m.keys()].filter((k) => !((typeof k === 'bigint' || typeof k === 'number') && ks.includes(Number(k))));
    if (extra.length) {
      const repr = (k: unknown): string => (typeof k === 'string' ? JSON.stringify(k) : String(k));
      throw new ProtoError(`unexpected keys [${extra.map(repr).join(', ')}]`);
    }
  };
  const checkReqId = (): Hex => {
    const rid = needBytes(1, 16);
    if (q) rep.check('req-id echoed', bytesEqual(rid, q.reqId));
    return toHex(rid);
  };
  const uintKey = (k: number, what: string): bigint => {
    const v = mget(m, k) as CborValue;
    if (typeof v !== 'bigint' || v < 0n) throw new ProtoError(`${what} must be uint`);
    return v;
  };
  const sigHex = (rs: Uint8Array): { rs: Hex; r: Hex; s: Hex } => ({
    rs: toHex(rs),
    r: toHex(rs.subarray(0, 32)),
    s: toHex(rs.subarray(32, 64)),
  });

  let parsed: ParsedResponse;
  switch (utype) {
    case 'ripar-pair': {
      keysOnly(1, 2, 3, 4, 5, 6);
      const k1 = needBytes(2, 20);
      const xy = needBytes(3, 64);
      const fwid = needBytes(6, 8);
      const vault = computeVaultAddress(k1);
      const f: PairResponseFields = {
        k1Address: toChecksumAddress(k1),
        vault,
        p1Key: toHex(xy),
        px: toHex(xy.subarray(0, 32)),
        py: toHex(xy.subarray(32)),
        keyId: toHex(keccak256(xy)),
        firmwareId: toHex(fwid),
        emulator: toHex(fwid) === EMULATOR_FIRMWARE_ID,
      };
      if (mhas(m, 1)) f.reqId = checkReqId();
      if (q && q.kind === 'pair') {
        // firmware v1.2: the device pins the vault it derives from K1 and only the compiled-in contracts
        if (q.vault !== null) rep.check('key 8 vault is the vault derived from K1', bytesEqual(q.vault, unhex(vault)));
        rep.check("pair request names only the firmware's pinned contracts", firmwareRefusal(q, k1) === null);
      }
      if (mhas(m, 4) || mhas(m, 5)) {
        if (!q || q.kind !== 'pair') {
          rep.unverified.push('BindDevice signatures (give the pair request)');
        } else {
          const d = pairDigest(q.chainId, q.registry, k1, xy);
          f.bindDigest = toHex(d);
          const p1sig = needBytes(4, 64);
          const k1sig = needBytes(5, 65);
          f.p1Signature = toHex(p1sig);
          f.k1Signature = toHex(k1sig);
          p256Check(rep, 'BindDevice P1', xy, d, p1sig);
          const who = k1Recover(rep, 'BindDevice K1', d, k1sig);
          rep.check('BindDevice K1 recovers the K1 address', who !== null && bytesEqual(who, k1));
        }
      }
      rep.check('P1 key on curve', p256OnCurve(xy));
      parsed = { type: utype, fields: f };
      break;
    }
    case 'ripar-cosign': {
      keysOnly(1, 2, 3, 4);
      const reqId = checkReqId();
      const rs = needBytes(2, 64);
      const ev = needBytes(3, 12);
      const salt = needBytes(4, 16);
      const ph = presenceHashOf(ev, salt);
      const f: CosignResponseFields = {
        reqId,
        ...sigHex(rs),
        evidence12: toHex(ev),
        evidence: evidenceFields(ev),
        salt16: toHex(salt),
        presenceHash: toHex(ph),
      };
      if (!q || q.kind !== 'cosign') rep.unverified.push('cosign signature (give the cosign request)');
      else if (p1xy === null) rep.unverified.push('cosign signature (give the P1 key or the pairing)');
      else {
        const d = cosignDigest(q, ph);
        f.digest = toHex(d);
        p256Check(rep, 'cosign', p1xy, d, rs);
      }
      if (q && q.kind === 'cosign' && k1addr !== null) {
        rep.check('delegator is the vault derived from the paired K1', bytesEqual(q.delegator, unhex(computeVaultAddress(k1addr))));
      }
      if (q && q.kind === 'cosign') f.caveatArgs = cosignCaveatArgs(q.nonce, q.expiry, ph, rs);
      parsed = { type: utype, fields: f };
      break;
    }
    case 'ripar-deny': {
      keysOnly(1, 2, 3, 4, 5, 6);
      const reqId = checkReqId();
      const rs = needBytes(2, 64);
      const ev = needBytes(3, 12);
      const salt = needBytes(4, 16);
      const rh = needBytes(6, 32);
      const agent = uintKey(5, 'key 5 (agentId)');
      const ph = presenceHashOf(ev, salt);
      const f: DenyResponseFields = {
        reqId,
        ...sigHex(rs),
        evidence12: toHex(ev),
        evidence: evidenceFields(ev),
        salt16: toHex(salt),
        presenceHash: toHex(ph),
        agentId: agent,
        requestHash: toHex(rh),
      };
      let dq: { chainId: bigint; relay: Uint8Array } | null = null;
      if (q && q.kind === 'deny') {
        rep.check('agentId echoed', agent === q.agentId);
        rep.check('requestHash echoed', bytesEqual(rh, q.requestHash));
        dq = { chainId: q.chainId, relay: q.relay };
      } else if (q && q.kind === 'cosign') {
        rep.check('requestHash = hashStruct(HumanApproval) of the co-sign request', bytesEqual(rh, cosignRequestHash(q)));
        const dchain = chain ?? q.chainId;
        const relay = pinnedOr(FIRMWARE_RELAY, dchain);
        if (relay === null) rep.unverified.push("deny signature (give the relay as contract; chain = chainId or the request's)");
        else dq = { chainId: dchain, relay };
      } else if (chain !== null && pinnedOr(FIRMWARE_RELAY, chain) !== null) {
        dq = { chainId: chain, relay: pinnedOr(FIRMWARE_RELAY, chain)! };
      } else {
        rep.unverified.push('deny signature (give the request, or chainId and the relay as contract)');
      }
      if (dq !== null) {
        if (p1xy === null) rep.unverified.push('deny signature (give the P1 key or the pairing)');
        else {
          const d = denyDigest(dq.chainId, dq.relay, agent, rh, ph);
          f.digest = toHex(d);
          p256Check(rep, 'deny', p1xy, d, rs);
        }
      }
      parsed = { type: utype, fields: f };
      break;
    }
    case 'eth-signature': {
      keysOnly(1, 2);
      const reqId = checkReqId();
      const rsv = needBytes(2, 65);
      const f: MandateResponseFields = { reqId, rsv: toHex(rsv) };
      if (!q || q.kind !== 'mandate') rep.unverified.push('mandate signature (give the mandate request)');
      else {
        const d = mandateDigest(q.chainId, q.manager, q);
        f.delegationHash = toHex(delegationStructHash(q));
        f.digest = toHex(d);
        const who = k1Recover(rep, 'mandate K1', d, rsv);
        if (who) f.signer = toChecksumAddress(who);
        if (k1addr === null) rep.unverified.push('mandate signer identity (give the K1 address or the pairing)');
        else {
          rep.check('mandate signed by the paired K1', who !== null && bytesEqual(who, k1addr));
          rep.check(
            'mandate delegator is the vault derived from the paired K1',
            bytesEqual(q.delegator, unhex(computeVaultAddress(k1addr))),
          );
        }
      }
      parsed = { type: utype, fields: f };
      break;
    }
    case 'ripar-der-sig': {
      keysOnly(1, 2);
      const reqId = checkReqId();
      const der = needBytes(2, null);
      const { r, s } = derParse(der);
      const rb = word(r);
      const sb = word(s);
      const f: DerSigResponseFields = { reqId, der: toHex(der), derBase64: base64Encode(der), r: toHex(rb), s: toHex(sb) };
      if (!q || q.kind !== 'privy') rep.unverified.push('Privy signature (give the privy request)');
      else if (p1xy === null) rep.unverified.push('Privy signature (give the P1 key or the pairing)');
      else p256Check(rep, 'privy', p1xy, sha256(q.json), concatBytes(rb, sb));
      parsed = { type: utype, fields: f };
      break;
    }
    case 'ripar-revoke':
    case 'ripar-panic':
    case 'ripar-reopen': {
      let rs: Uint8Array;
      let dig: (c: bigint, a: Uint8Array) => Uint8Array;
      let domain = contract;
      if (utype === 'ripar-revoke') {
        keysOnly(1, 2);
        const dh = needBytes(1, 32);
        rs = needBytes(2, 64);
        parsed = { type: utype, fields: { delegationHash: toHex(dh), ...sigHex(rs) } };
        domain = pinnedOr(FIRMWARE_PULSE_ENFORCER, chain);
        dig = (c, a) => revokeDigest(c, a, dh);
      } else if (utype === 'ripar-panic') {
        keysOnly(1, 2);
        const me = uintKey(1, 'key 1');
        rs = needBytes(2, 64);
        parsed = { type: utype, fields: { minEpoch: me, ...sigHex(rs) } };
        domain = pinnedOr(FIRMWARE_PULSE_ENFORCER, chain);
        dig = (c, a) => panicDigest(c, a, me);
      } else {
        keysOnly(1, 2, 3);
        const vault = needBytes(1, 20);
        const nb = needBytes(2, null);
        rs = needBytes(3, 64);
        if (nb.length > 32) throw new ProtoError('nonce longer than 32 bytes');
        const nonce = bytesToBigInt(nb);
        parsed = { type: utype, fields: { vault: toChecksumAddress(vault), nonce, ...sigHex(rs) } };
        if (k1addr !== null) {
          rep.check('reopen vault is the vault derived from the paired K1', bytesEqual(vault, unhex(computeVaultAddress(k1addr))));
        }
        dig = (c, a) => reopenDigest(c, a, vault, nonce);
      }
      if (chain === null || domain === null) rep.unverified.push(`${utype} signature (give chainId and contract)`);
      else if (p1xy === null) rep.unverified.push(`${utype} signature (give the P1 key or the pairing)`);
      else {
        const d = dig(chain, domain);
        (parsed.fields as { digest?: Hex }).digest = toHex(d);
        p256Check(rep, utype, p1xy, d, rs);
      }
      break;
    }
    default:
      throw new ProtoError('unknown response type ' + utype);
  }
  const ok = rep.checks.every((c) => c.ok);
  const result: VerifyResult = !ok ? 'FAIL' : rep.unverified.length || !rep.checks.length ? 'UNVERIFIED' : 'VERIFIED';
  return { ...parsed, checks: rep.checks, unverified: rep.unverified, ok, result } as VerifyReport;
}

/** throws ProtoError unless the report is VERIFIED (every signature checked, every check passed) */
export function expectVerified<R extends VerifyReport>(rep: R): R {
  if (rep.result !== 'VERIFIED') {
    const failed = rep.checks.filter((c) => !c.ok).map((c) => c.name);
    throw new ProtoError(
      `${rep.type}: ${rep.result}` +
        (failed.length ? ` (failed: ${failed.join('; ')})` : '') +
        (rep.unverified.length ? ` (unverified: ${rep.unverified.join('; ')})` : ''),
    );
  }
  return rep;
}

export interface DeviceIdentity {
  k1Address: Address;
  p1Key: Hex;
  px: Hex;
  py: Hex;
  keyId: Hex;
  firmwareId: Hex;
  /** the pairing came from the WASM emulator: always label it EMULATOR */
  emulator: boolean;
  /** BindDevice signatures (for RiparDeviceRegistry.registerDevice) */
  p1Signature: Hex;
  k1Signature: Hex;
  bindDigest: Hex;
}

/**
 * Strict pairing check for a companion: the response must echo the req-id and carry BOTH BindDevice signatures,
 * all verified against the pair request. Returns the device identity to pin; throws ProtoError otherwise.
 */
export function verifyPairing(pairUr: string, request: RequestInput): DeviceIdentity {
  const rep = parseResponse(pairUr, { request });
  if (rep.type !== 'ripar-pair') throw new ProtoError(`expected ripar-pair, got ${rep.type}`);
  const f = rep.fields;
  if (!f.reqId || !f.p1Signature || !f.k1Signature || !f.bindDigest) {
    throw new ProtoError('pairing response without req-id / BindDevice signatures (keys-only QR?)');
  }
  expectVerified(rep);
  return {
    k1Address: f.k1Address,
    p1Key: f.p1Key,
    px: f.px,
    py: f.py,
    keyId: f.keyId,
    firmwareId: f.firmwareId,
    emulator: f.emulator,
    p1Signature: f.p1Signature,
    k1Signature: f.k1Signature,
    bindDigest: f.bindDigest,
  };
}

/** requestHash a device deny from this co-sign review would sign (hashStruct(HumanApproval), presence 0) */
export function denyRequestHashOf(cosign: CosignRequest): Hex {
  return toHex(cosignRequestHash(cosign));
}

