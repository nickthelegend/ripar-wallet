// Privy authorization requests (docs/PROTOCOL.md §4 ripar-privy-req): canonical JSON, a strict RFC 8259 syntax
// check and the device's allow-list, ports of make_request.py canonical_json / _json_syntax_invalid / privy_parse /
// privy_dump / p256_spki_b64. The device is the reference; this lets a companion refuse early and show the same view.
import { type BytesLike, h, toBytes, utf8 } from './bytes.js';
import { ProtoError } from './errors.js';

export const PRIVY_API = 'https://api.privy.io';
export const PRIVY_WALLETS = 'https://api.privy.io/v1/wallets/';
export const PRIVY_QUORUMS = 'https://api.privy.io/v1/key_quorums/';
const PRIVY_ID = /^[A-Za-z0-9_:.-]{1,64}$/;
/** DER SubjectPublicKeyInfo prefix of an uncompressed P-256 key, followed by 0x04 */
export const SPKI_P256_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);

// ---------------------------------------------------------------------------------------------- base64
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function base64Encode(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i]! << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    s += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]!;
    s += i + 1 < b.length ? B64[(n >> 6) & 63]! : '=';
    s += i + 2 < b.length ? B64[n & 63]! : '=';
  }
  return s;
}

/** strict standard base64 (padding required, no whitespace); null when invalid */
export function base64DecodeStrict(s: string): Uint8Array | null {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const v = [0, 1, 2, 3].map((j) => (s[i + j] === '=' ? 0 : B64.indexOf(s[i + j]!)));
    const n = (v[0]! << 18) | (v[1]! << 12) | (v[2]! << 6) | v[3]!;
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

/** base64 DER SubjectPublicKeyInfo of an uncompressed P-256 key px‖py (Privy key quorum public_keys format) */
export function p256SpkiB64(p1Key: BytesLike): string {
  const xy = toBytes(p1Key, 64, 'P-256 key');
  const der = new Uint8Array(SPKI_P256_PREFIX.length + 64);
  der.set(SPKI_P256_PREFIX);
  der.set(xy, SPKI_P256_PREFIX.length);
  return base64Encode(der);
}

// ---------------------------------------------------------------------------------------------- canonical JSON
function cmpCodePoints(a: string, b: string): number {
  const A = Array.from(a);
  const B = Array.from(b);
  for (let i = 0; i < Math.min(A.length, B.length); i++) {
    const x = A[i]!.codePointAt(0)!;
    const y = B[i]!.codePointAt(0)!;
    if (x !== y) return x - y;
  }
  return A.length - B.length;
}

function jsonString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else if (c >= 0xd800 && c <= 0xdfff) throw new ProtoError('canonical JSON: lone surrogate');
    else out += ch;
  }
  return out + '"';
}

/**
 * make_request canonical_json: json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) as UTF-8.
 * Integers only (number or bigint); floats are refused (Privy payloads carry none).
 */
export function canonicalJson(obj: unknown): Uint8Array {
  const enc = (v: unknown): string => {
    if (v === null) return 'null';
    if (v === true) return 'true';
    if (v === false) return 'false';
    if (typeof v === 'bigint') return v.toString();
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) throw new ProtoError('canonical JSON: only integers are supported');
      return String(v);
    }
    if (typeof v === 'string') return jsonString(v);
    if (Array.isArray(v)) return '[' + v.map(enc).join(',') + ']';
    if (typeof v === 'object') {
      const keys = Object.keys(v as object).sort(cmpCodePoints);
      return '{' + keys.map((k) => jsonString(k) + ':' + enc((v as Record<string, unknown>)[k])).join(',') + '}';
    }
    throw new ProtoError('canonical JSON: unsupported value');
  };
  return utf8.encode(enc(obj));
}

// ---------------------------------------------------------------------------------------------- strict JSON
/** parsed JSON that keeps member order, duplicates and the raw text of numbers */
export type JsonNode =
  | { t: 'obj'; pairs: [string, JsonNode][] }
  | { t: 'arr'; items: JsonNode[] }
  | { t: 'str'; v: string }
  | { t: 'num'; raw: string }
  | { t: 'bool'; v: boolean }
  | { t: 'null' };

class JsonSyntax extends Error {}

/**
 * Strict RFC 8259 parse with the device's extra rules (make_request _json_syntax_invalid): valid UTF-8, no BOM, no
 * "\u0000" escape, no duplicate member names (after unescaping), depth <= 16, no lone surrogates, no trailing data.
 * Returns null when the document must be refused.
 */
export function parseStrictJson(bytes: Uint8Array): JsonNode | null {
  let s: string;
  try {
    s = utf8.decodeStrict(bytes);
  } catch {
    return null;
  }
  // BOM, or the 6-character escape "\u0000" anywhere in the text (make_request _json_syntax_invalid)
  if (s.charCodeAt(0) === 0xfeff || s.includes('\\' + 'u0000')) return null;
  let i = 0;
  const ws = (): void => {
    while (i < s.length && (s[i] === ' ' || s[i] === '\t' || s[i] === '\n' || s[i] === '\r')) i++;
  };
  const fail = (): never => {
    throw new JsonSyntax();
  };
  const str = (): string => {
    if (s[i] !== '"') fail();
    i++;
    let out = '';
    for (;;) {
      if (i >= s.length) fail();
      const c = s[i]!;
      if (c === '"') {
        i++;
        break;
      }
      if (c.charCodeAt(0) < 0x20) fail();
      if (c === '\\') {
        const e = s[i + 1];
        i += 2;
        if (e === '"') out += '"';
        else if (e === '\\') out += '\\';
        else if (e === '/') out += '/';
        else if (e === 'b') out += '\b';
        else if (e === 'f') out += '\f';
        else if (e === 'n') out += '\n';
        else if (e === 'r') out += '\r';
        else if (e === 't') out += '\t';
        else if (e === 'u') {
          const hx = s.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hx)) fail();
          i += 4;
          let cu = parseInt(hx, 16);
          // a high surrogate followed by an escaped low surrogate combines (Python json); otherwise it stays lone
          if (cu >= 0xd800 && cu <= 0xdbff && s[i] === '\\' && s[i + 1] === 'u') {
            const hx2 = s.slice(i + 2, i + 6);
            if (/^[0-9a-fA-F]{4}$/.test(hx2)) {
              const lo = parseInt(hx2, 16);
              if (lo >= 0xdc00 && lo <= 0xdfff) {
                i += 6;
                out += String.fromCharCode(cu, lo);
                continue;
              }
            }
          }
          if (cu >= 0xd800 && cu <= 0xdfff) throw new JsonSyntax(); // lone surrogate: refused (after decode)
          out += String.fromCharCode(cu);
          cu = 0;
        } else fail();
        continue;
      }
      out += c;
      i++;
    }
    return out;
  };
  const num = (): string => {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?/.exec(s.slice(i));
    if (!m || m[0].length === 0) fail();
    i += m![0].length;
    return m![0];
  };
  const value = (depth: number): JsonNode => {
    ws();
    const c = s[i];
    if (c === '{') {
      if (depth + 1 > 16) fail();
      i++;
      const pairs: [string, JsonNode][] = [];
      const seen = new Set<string>();
      ws();
      if (s[i] === '}') {
        i++;
        return { t: 'obj', pairs };
      }
      for (;;) {
        ws();
        const k = str();
        ws();
        if (s[i] !== ':') fail();
        i++;
        const v = value(depth + 1);
        if (seen.has(k)) fail();
        seen.add(k);
        pairs.push([k, v]);
        ws();
        if (s[i] === ',') {
          i++;
          continue;
        }
        if (s[i] === '}') {
          i++;
          return { t: 'obj', pairs };
        }
        fail();
      }
    }
    if (c === '[') {
      if (depth + 1 > 16) fail();
      i++;
      const items: JsonNode[] = [];
      ws();
      if (s[i] === ']') {
        i++;
        return { t: 'arr', items };
      }
      for (;;) {
        items.push(value(depth + 1));
        ws();
        if (s[i] === ',') {
          i++;
          continue;
        }
        if (s[i] === ']') {
          i++;
          return { t: 'arr', items };
        }
        fail();
      }
    }
    if (c === '"') return { t: 'str', v: str() };
    if (s.startsWith('true', i)) {
      i += 4;
      return { t: 'bool', v: true };
    }
    if (s.startsWith('false', i)) {
      i += 5;
      return { t: 'bool', v: false };
    }
    if (s.startsWith('null', i)) {
      i += 4;
      return { t: 'null' };
    }
    return { t: 'num', raw: num() };
  };
  try {
    const v = value(0);
    ws();
    if (i !== s.length) return null;
    return v;
  } catch (e) {
    if (e instanceof JsonSyntax) return null;
    throw e;
  }
}

// ---------------------------------------------------------------------------------------------- allow-list
export interface PrivySigner {
  signerId: string;
  /** null when the member is absent */
  overridePolicyIds: string[] | null;
}

/** The device's view of an allow-listed Privy request (make_request privy_parse). */
export interface PrivyView {
  kind: 'wallet' | 'key_quorum';
  id: string;
  app: string;
  idem: string | null;
  method: 'PATCH';
  /** URL path, e.g. "/v1/wallets/<id>" */
  path: string;
  policyIds?: string[];
  signers?: PrivySigner[];
  /** key quorum public keys as px‖py hex (0x, 64 bytes) */
  publicKeys?: `0x${string}`[];
  threshold?: number;
  displayName?: string;
  userIds?: string[];
  keyQuorumIds?: string[];
}

function isObj(n: JsonNode | undefined): n is { t: 'obj'; pairs: [string, JsonNode][] } {
  return n !== undefined && n.t === 'obj';
}

function allowed(pairs: [string, JsonNode][], names: readonly string[], what: string): void {
  for (const [k] of pairs) if (!names.includes(k)) throw new ProtoError(`${what} member ${JSON.stringify(k)} is not allowed`);
}

function asDict(pairs: [string, JsonNode][]): Map<string, JsonNode> {
  return new Map(pairs);
}

function idList(v: JsonNode, what: string): string[] {
  if (v.t !== 'arr') throw new ProtoError(`${what} must be an array`);
  if (v.items.length > 8) throw new ProtoError(`${what} has more than 8 entries`);
  return v.items.map((e) => {
    if (e.t !== 'str' || !PRIVY_ID.test(e.v)) throw new ProtoError(`${what} entries must be ids`);
    return e.v;
  });
}

/**
 * Independent reference of the device's Privy allow-list (security review M1): returns the view the device shows, or
 * throws ProtoError for anything the device must refuse.
 */
export function privyParse(json: Uint8Array | string): PrivyView {
  const js = typeof json === 'string' ? utf8.encode(json) : json;
  if (!js.length) throw new ProtoError('JSON is not strict RFC 8259 (or has duplicate keys / too deep)');
  const doc = parseStrictJson(js);
  if (doc === null) throw new ProtoError('JSON is not strict RFC 8259 (or has duplicate keys / too deep)');
  if (!isObj(doc)) throw new ProtoError('top level is not an object');
  allowed(doc.pairs, ['version', 'method', 'url', 'body', 'headers'], 'top-level');
  const top = asDict(doc.pairs);
  const ver = top.get('version');
  if (!ver || ver.t !== 'num' || ver.raw !== '1') throw new ProtoError('version must be the number 1');
  for (const k of ['method', 'url']) {
    if (top.get(k)?.t !== 'str') throw new ProtoError(`${k} must be a string`);
  }
  const headers = top.get('headers');
  if (!isObj(headers)) throw new ProtoError('headers must be an object');
  if (!top.has('body')) throw new ProtoError('body is missing');
  const method = (top.get('method') as { v: string }).v;
  if (method !== 'PATCH') throw new ProtoError('method must be PATCH');
  const url = (top.get('url') as { v: string }).v;
  let kind: 'wallet' | 'key_quorum';
  let rid: string;
  if (url.startsWith(PRIVY_WALLETS) && url.length > PRIVY_WALLETS.length) {
    kind = 'wallet';
    rid = url.slice(PRIVY_WALLETS.length);
  } else if (url.startsWith(PRIVY_QUORUMS) && url.length > PRIVY_QUORUMS.length) {
    kind = 'key_quorum';
    rid = url.slice(PRIVY_QUORUMS.length);
  } else throw new ProtoError('url is not a Privy wallet / key quorum');
  if (!PRIVY_ID.test(rid)) throw new ProtoError('bad id in url');
  allowed(headers.pairs, ['privy-app-id', 'privy-idempotency-key'], 'header');
  const hd = asDict(headers.pairs);
  const app = hd.get('privy-app-id');
  if (!app || app.t !== 'str' || !PRIVY_ID.test(app.v)) throw new ProtoError('privy-app-id must be an id');
  const idemN = hd.get('privy-idempotency-key');
  let idem: string | null = null;
  if (idemN !== undefined) {
    if (idemN.t !== 'str' || !PRIVY_ID.test(idemN.v)) throw new ProtoError('privy-idempotency-key must be an id');
    idem = idemN.v;
  }
  const body = top.get('body');
  if (!isObj(body) || body.pairs.length === 0) throw new ProtoError('body must be a non-empty object');
  const v: PrivyView = { kind, id: rid, app: app.v, idem, method: 'PATCH', path: url.slice(PRIVY_API.length) };
  const b = asDict(body.pairs);
  if (kind === 'wallet') {
    allowed(body.pairs, ['policy_ids', 'additional_signers'], 'wallet body');
    if (b.has('policy_ids')) v.policyIds = idList(b.get('policy_ids')!, 'policy_ids');
    if (b.has('additional_signers')) {
      const sg = b.get('additional_signers')!;
      if (sg.t !== 'arr' || sg.items.length > 8) throw new ProtoError('additional_signers must be an array of <= 8');
      v.signers = sg.items.map((e) => {
        if (!isObj(e)) throw new ProtoError('signer must be an object');
        allowed(e.pairs, ['signer_id', 'override_policy_ids'], 'signer');
        const ed = asDict(e.pairs);
        const sid = ed.get('signer_id');
        if (!sid || sid.t !== 'str' || !PRIVY_ID.test(sid.v)) throw new ProtoError('signer_id must be an id');
        const ov = ed.has('override_policy_ids') ? idList(ed.get('override_policy_ids')!, 'override_policy_ids') : null;
        return { signerId: sid.v, overridePolicyIds: ov };
      });
    }
  } else {
    allowed(body.pairs, ['public_keys', 'authorization_threshold', 'display_name', 'user_ids', 'key_quorum_ids'], 'key quorum body');
    if (b.has('public_keys')) {
      const pk = b.get('public_keys')!;
      if (pk.t !== 'arr' || pk.items.length < 1 || pk.items.length > 8) throw new ProtoError('public_keys must be an array of 1..8');
      v.publicKeys = pk.items.map((e) => {
        if (e.t !== 'str') throw new ProtoError('public key must be a string');
        if (!/^[\x00-\x7f]*$/.test(e.v)) throw new ProtoError('public key is not base64');
        const der = base64DecodeStrict(e.v);
        if (der === null) throw new ProtoError('public key is not base64');
        if (base64Encode(der) !== e.v) throw new ProtoError('public key base64 is not canonical');
        if (der.length !== 91 || !SPKI_P256_PREFIX.every((x, i) => der[i] === x)) {
          throw new ProtoError('public key is not an uncompressed P-256 SPKI');
        }
        return `0x${h(der.subarray(27))}` as `0x${string}`;
      });
    }
    if (b.has('authorization_threshold')) {
      const t = b.get('authorization_threshold')!;
      if (t.t !== 'num' || !/^[1-9][0-9]?$/.test(t.raw)) throw new ProtoError('authorization_threshold must be an integer 1..99');
      v.threshold = parseInt(t.raw, 10);
    }
    if (b.has('display_name')) {
      const n = b.get('display_name')!;
      if (n.t !== 'str' || utf8.encode(n.v).length > 64 || !/^[\x20-\x7e]*$/.test(n.v)) {
        throw new ProtoError('display_name must be printable ASCII <= 64');
      }
      v.displayName = n.v;
    }
    if (b.has('user_ids')) v.userIds = idList(b.get('user_ids')!, 'user_ids');
    if (b.has('key_quorum_ids')) v.keyQuorumIds = idList(b.get('key_quorum_ids')!, 'key_quorum_ids');
  }
  return v;
}

/** canonical text of a parsed Privy request (make_request privy_dump / test_protocol.cpp privy_dump()) */
export function privyDump(v: PrivyView): string {
  const L = [`kind=${v.kind} id=${v.id} app=${v.app} idem=${v.idem !== null ? v.idem : '-'}`];
  if (v.policyIds) L.push('policy_ids=' + v.policyIds.join(','));
  if (v.signers) {
    L.push('signers=' + v.signers.map((s) => s.signerId + (s.overridePolicyIds === null ? '' : '[' + s.overridePolicyIds.join(',') + ']')).join(';'));
  }
  if (v.publicKeys) L.push('public_keys=' + v.publicKeys.map((x) => x.slice(2)).join(','));
  if (v.threshold !== undefined) L.push(`threshold=${v.threshold}`);
  if (v.displayName !== undefined) L.push('display_name=' + v.displayName);
  if (v.userIds) L.push('user_ids=' + v.userIds.join(','));
  if (v.keyQuorumIds) L.push('key_quorum_ids=' + v.keyQuorumIds.join(','));
  return L.join('\n');
}
