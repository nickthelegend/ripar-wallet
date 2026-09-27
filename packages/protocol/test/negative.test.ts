// Negative tests: tampered responses, high-s twins, wrong chain / contract domains, wrong keys, malformed data.
// Every signature failure must be a failed check (result FAIL), every malformed message a thrown ProtoError.
import { describe, expect, it } from 'vitest';
import {
  type CborMap,
  type CborValue,
  P256_N,
  ProtoError,
  SECP256K1_N,
  Tag,
  UrDecoder,
  buildRequest,
  bytewordsEncode,
  cborDecode,
  cborEncode,
  derEncode,
  derParse,
  expectVerified,
  parseResponse,
  urRead,
  urSingle,
  verifyPairing,
} from '../src/index.js';
import { DEMO_P1, simulate } from './helpers/demo-device.js';
import { VECTORS_PATH, bytesToHex, hexToBytes, readJson } from './helpers/env.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: any = readJson(VECTORS_PATH);
const A = V.addresses;
const P1 = V.demo.px + V.demo.py.slice(2);
const CHAIN = V.chainId as number;

const respMap = (ur: string): CborMap => cborDecode(urRead(ur).cbor) as CborMap;
const reUr = (type: string, m: CborMap): string => urSingle(type, cborEncode(m));
const flip = (b: Uint8Array, i: number, bit = 1): Uint8Array => {
  const c = Uint8Array.from(b);
  c[i]! ^= bit;
  return c;
};
const be32 = (x: bigint): Uint8Array => hexToBytes(x.toString(16).padStart(64, '0'));
const b2i = (b: Uint8Array): bigint => BigInt(bytesToHex(b));
/** the high-s twin of r‖s (plain-ECDSA valid, refused by the low-s rule) */
function highS(rs: Uint8Array, n: bigint): Uint8Array {
  const out = Uint8Array.from(rs);
  out.set(be32(n - b2i(rs.subarray(32, 64))), 32);
  return out;
}

const pairReq = { kind: 'pair' as const, cbor: hexToBytes(V.pair.request.cbor) };
const mandateReq = { kind: 'mandate' as const, cbor: hexToBytes(V.mandate.request.cbor) };
const cosignReq = { kind: 'cosign' as const, cbor: hexToBytes(V.cosignErc20.request.cbor) };
const denyReq = { kind: 'deny' as const, cbor: hexToBytes(V.denyRequest.request.cbor) };

/** a request map with one key replaced */
function withKey(req: { kind: 'pair' | 'mandate' | 'cosign' | 'deny'; cbor: Uint8Array }, k: number, v: CborValue) {
  const m = cborDecode(req.cbor) as CborMap;
  m.set(BigInt(k), v);
  return { kind: req.kind, cbor: cborEncode(m) };
}

describe('baseline: the untouched vector responses verify', () => {
  it('pair / mandate / cosign / deny / revoke / panic / reopen', () => {
    expect(parseResponse(V.pair.response.ur, { request: pairReq }).result).toBe('VERIFIED');
    expect(parseResponse(V.mandate.response.ur, { request: mandateReq, k1Address: V.demo.k1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.cosignErc20.response.ur, { request: cosignReq, p1Key: P1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.denyRequest.response.ur, { request: denyReq, p1Key: P1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.revoke.response.ur, { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.panic.response.ur, { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.reopen.response.ur, { chainId: CHAIN, contract: A.sentinel, p1Key: P1 }).result).toBe('VERIFIED');
  });
});

describe('tampered responses fail verification', () => {
  it('flipped signature bits (every response type)', () => {
    const cases: [string, number, Record<string, unknown>][] = [
      [V.pair.response.ur, 4, { request: pairReq }],
      [V.pair.response.ur, 5, { request: pairReq }],
      [V.mandate.response.ur, 2, { request: mandateReq, k1Address: V.demo.k1 }],
      [V.cosignErc20.response.ur, 2, { request: cosignReq, p1Key: P1 }],
      [V.denyRequest.response.ur, 2, { request: denyReq, p1Key: P1 }],
      [V.revoke.response.ur, 2, { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }],
      [V.panic.response.ur, 2, { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }],
      [V.reopen.response.ur, 3, { chainId: CHAIN, contract: A.sentinel, p1Key: P1 }],
    ];
    for (const [ur, key, opts] of cases) {
      const type = urRead(ur).type;
      for (const byte of [0, 31, 33, 63]) {
        const m = respMap(ur);
        m.set(BigInt(key), flip(m.get(BigInt(key)) as Uint8Array, byte));
        const rep = parseResponse(reUr(type, m), opts);
        expect(rep.result, `${type} key ${key} byte ${byte}`).toBe('FAIL');
        expect(() => expectVerified(rep)).toThrow(ProtoError);
      }
    }
  });
  it('changed evidence / salt breaks the presenceHash binding', () => {
    for (const k of [3, 4]) {
      const m = respMap(V.cosignErc20.response.ur);
      m.set(BigInt(k), flip(m.get(BigInt(k)) as Uint8Array, 1));
      expect(parseResponse(reUr('ripar-cosign', m), { request: cosignReq, p1Key: P1 }).result).toBe('FAIL');
      const d = respMap(V.denyRequest.response.ur);
      d.set(BigInt(k), flip(d.get(BigInt(k)) as Uint8Array, 1));
      expect(parseResponse(reUr('ripar-deny', d), { request: denyReq, p1Key: P1 }).result).toBe('FAIL');
    }
  });
  it('changed signed values (panic epoch, reopen nonce / vault, revoke hash, deny agent / request hash)', () => {
    const p = respMap(V.panic.response.ur);
    p.set(1n, 2n);
    expect(parseResponse(reUr('ripar-panic', p), { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }).result).toBe('FAIL');
    const r = respMap(V.reopen.response.ur);
    r.set(2n, Uint8Array.of(2));
    expect(parseResponse(reUr('ripar-reopen', r), { chainId: CHAIN, contract: A.sentinel, p1Key: P1 }).result).toBe('FAIL');
    const r2 = respMap(V.reopen.response.ur);
    r2.set(1n, flip(r2.get(1n) as Uint8Array, 19));
    expect(parseResponse(reUr('ripar-reopen', r2), { chainId: CHAIN, contract: A.sentinel, p1Key: P1 }).result).toBe('FAIL');
    const v = respMap(V.revoke.response.ur);
    v.set(1n, flip(v.get(1n) as Uint8Array, 0));
    expect(parseResponse(reUr('ripar-revoke', v), { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }).result).toBe('FAIL');
    const d = respMap(V.denyRequest.response.ur);
    d.set(5n, 18n);
    const rep = parseResponse(reUr('ripar-deny', d), { request: denyReq, p1Key: P1 });
    expect(rep.result).toBe('FAIL');
    expect(rep.checks.find((c) => c.name === 'agentId echoed')!.ok).toBe(false);
    const d2 = respMap(V.deny.response.ur);
    d2.set(6n, flip(d2.get(6n) as Uint8Array, 5));
    const rep2 = parseResponse(reUr('ripar-deny', d2), { request: cosignReq, contract: A.relay, p1Key: P1 });
    expect(rep2.checks.find((c) => c.name.startsWith('requestHash ='))!.ok).toBe(false);
  });
  it('a req-id that is not echoed', () => {
    const m = respMap(V.cosignErc20.response.ur);
    m.set(1n, flip(m.get(1n) as Uint8Array, 15));
    const rep = parseResponse(reUr('ripar-cosign', m), { request: cosignReq, p1Key: P1 });
    expect(rep.result).toBe('FAIL');
    expect(rep.checks[0]).toEqual({ name: 'req-id echoed', ok: false });
  });
  it('a pairing whose P1 key was replaced (off curve / another key)', () => {
    const m = respMap(V.pair.response.ur);
    m.set(3n, flip(m.get(3n) as Uint8Array, 63));
    const rep = parseResponse(reUr('ripar-pair', m), { request: pairReq });
    expect(rep.result).toBe('FAIL');
    expect(rep.checks.find((c) => c.name === 'P1 key on curve')!.ok).toBe(false);
    expect(() => verifyPairing(reUr('ripar-pair', m), pairReq)).toThrow(ProtoError);
    const k = respMap(V.pair.response.ur);
    k.set(2n, flip(k.get(2n) as Uint8Array, 0));
    const rk = parseResponse(reUr('ripar-pair', k), { request: pairReq });
    expect(rk.checks.find((c) => c.name === 'BindDevice K1 recovers the K1 address')!.ok).toBe(false);
  });
});

describe('high-s signatures are rejected', () => {
  it('P-256 (co-sign, deny, revoke, panic, reopen, BindDevice): the twin is plain-ECDSA valid, low-s fails', () => {
    const cases: [string, number, Record<string, unknown>, string][] = [
      [V.cosignErc20.response.ur, 2, { request: cosignReq, p1Key: P1 }, 'cosign'],
      [V.denyRequest.response.ur, 2, { request: denyReq, p1Key: P1 }, 'deny'],
      [V.revoke.response.ur, 2, { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }, 'ripar-revoke'],
      [V.panic.response.ur, 2, { chainId: CHAIN, contract: A.enforcer, p1Key: P1 }, 'ripar-panic'],
      [V.reopen.response.ur, 3, { chainId: CHAIN, contract: A.sentinel, p1Key: P1 }, 'ripar-reopen'],
      [V.pair.response.ur, 4, { request: pairReq }, 'BindDevice P1'],
    ];
    for (const [ur, key, opts, name] of cases) {
      const type = urRead(ur).type;
      const m = respMap(ur);
      m.set(BigInt(key), highS(m.get(BigInt(key)) as Uint8Array, P256_N));
      const rep = parseResponse(reUr(type, m), opts);
      expect(rep.result, name).toBe('FAIL');
      expect(rep.checks.find((c) => c.name === `${name} low-s`)!.ok, name).toBe(false);
      expect(rep.checks.find((c) => c.name === `${name} P-256 signature`)!.ok, name).toBe(true);
    }
  });
  it('secp256k1 (mandate, BindDevice K1): the twin with the flipped v recovers K1, low-s fails', () => {
    for (const [ur, key, opts, name] of [
      [V.mandate.response.ur, 2, { request: mandateReq, k1Address: V.demo.k1 }, 'mandate K1'],
      [V.pair.response.ur, 5, { request: pairReq }, 'BindDevice K1'],
    ] as const) {
      const type = urRead(ur).type;
      const m = respMap(ur);
      const rsv = highS(m.get(BigInt(key)) as Uint8Array, SECP256K1_N);
      rsv[64] = rsv[64] === 27 ? 28 : 27;
      m.set(BigInt(key), rsv);
      const rep = parseResponse(reUr(type, m), opts);
      expect(rep.result).toBe('FAIL');
      expect(rep.checks.find((c) => c.name === `${name} low-s`)!.ok).toBe(false);
      expect(rep.checks.find((c) => c.name === `${name} recoverable`)!.ok).toBe(true);
      if (name === 'mandate K1') {
        expect(rep.checks.find((c) => c.name === 'mandate signed by the paired K1')!.ok).toBe(true);
      }
    }
  });
  it('v other than 27 / 28 is refused', () => {
    const m = respMap(V.mandate.response.ur);
    const rsv = Uint8Array.from(m.get(2n) as Uint8Array);
    rsv[64] = rsv[64]! - 27; // 0 / 1
    m.set(2n, rsv);
    const rep = parseResponse(reUr('eth-signature', m), { request: mandateReq, k1Address: V.demo.k1 });
    expect(rep.result).toBe('FAIL');
    expect(rep.checks.find((c) => c.name === 'mandate K1 v is 27/28')!.ok).toBe(false);
  });
});

describe('wrong chain / contract domains fail', () => {
  it('co-sign: another chain, another enforcer', () => {
    expect(parseResponse(V.cosignErc20.response.ur, { request: withKey(cosignReq, 2, 143n), p1Key: P1 }).result).toBe('FAIL');
    expect(parseResponse(V.cosignErc20.response.ur, { request: withKey(cosignReq, 3, hexToBytes(A.sentinel)), p1Key: P1 }).result).toBe('FAIL');
  });
  it('mandate: another chain, another DelegationManager', () => {
    expect(parseResponse(V.mandate.response.ur, { request: withKey(mandateReq, 2, 143n), k1Address: V.demo.k1 }).result).toBe('FAIL');
    expect(parseResponse(V.mandate.response.ur, { request: withKey(mandateReq, 3, hexToBytes(A.enforcer)), k1Address: V.demo.k1 }).result).toBe('FAIL');
  });
  it('pair: another chain, another registry', () => {
    expect(parseResponse(V.pair.response.ur, { request: withKey(pairReq, 2, 143n) }).result).toBe('FAIL');
    expect(parseResponse(V.pair.response.ur, { request: withKey(pairReq, 3, hexToBytes(A.relay)) }).result).toBe('FAIL');
  });
  it('deny: another chain, another relay (request or pinned context)', () => {
    expect(parseResponse(V.denyRequest.response.ur, { request: withKey(denyReq, 2, 143n), p1Key: P1 }).result).toBe('FAIL');
    expect(parseResponse(V.denyRequest.response.ur, { request: withKey(denyReq, 3, hexToBytes(A.registry)), p1Key: P1 }).result).toBe('FAIL');
    expect(parseResponse(V.deny.response.ur, { request: cosignReq, contract: A.registry, p1Key: P1 }).result).toBe('FAIL');
    expect(parseResponse(V.deny.response.ur, { request: cosignReq, chainId: 143, contract: A.relay, p1Key: P1 }).result).toBe('FAIL');
    expect(parseResponse(V.deny.response.ur, { chainId: CHAIN, contract: A.relay, p1Key: P1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.deny.response.ur, { chainId: 143, contract: A.relay, p1Key: P1 }).result).toBe('FAIL');
  });
  it('revoke / panic / reopen: another chain, the other contract', () => {
    for (const [ur, good, bad] of [
      [V.revoke.response.ur, A.enforcer, A.sentinel],
      [V.panic.response.ur, A.enforcer, A.relay],
      [V.reopen.response.ur, A.sentinel, A.enforcer],
    ] as const) {
      expect(parseResponse(ur, { chainId: CHAIN, contract: bad, p1Key: P1 }).result).toBe('FAIL');
      expect(parseResponse(ur, { chainId: 143, contract: good, p1Key: P1 }).result).toBe('FAIL');
      expect(parseResponse(ur, { chainId: CHAIN, contract: good, p1Key: P1 }).result).toBe('VERIFIED');
    }
  });
});

describe('pinned context option', () => {
  const pinned = { chainId: CHAIN, enforcer: A.enforcer, sentinel: A.sentinel, relay: A.relay };
  it('picks the domain contract per response type', () => {
    for (const ur of [V.revoke.response.ur, V.panic.response.ur, V.reopen.response.ur]) {
      expect(parseResponse(ur, { pinned, p1Key: P1 }).result).toBe('VERIFIED');
    }
    expect(parseResponse(V.deny.response.ur, { request: cosignReq, pinned, p1Key: P1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.deny.response.ur, { pinned, p1Key: P1 }).result).toBe('VERIFIED');
  });
  it('a different pinned set fails; explicit chainId / contract win', () => {
    const other = { chainId: CHAIN, enforcer: A.sentinel, sentinel: A.enforcer, relay: A.registry };
    for (const ur of [V.revoke.response.ur, V.panic.response.ur, V.reopen.response.ur, V.deny.response.ur]) {
      expect(parseResponse(ur, { pinned: other, p1Key: P1 }).result).toBe('FAIL');
    }
    expect(parseResponse(V.revoke.response.ur, { pinned: { ...pinned, chainId: 143 }, p1Key: P1 }).result).toBe('FAIL');
    expect(parseResponse(V.revoke.response.ur, { pinned: other, contract: A.enforcer, p1Key: P1 }).result).toBe('VERIFIED');
    expect(parseResponse(V.revoke.response.ur, { pinned: { chainId: CHAIN }, p1Key: P1 }).result).toBe('UNVERIFIED');
  });
});

describe('wrong keys and missing context', () => {
  const OTHER_P1 = '0x' + '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' + '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'; // the P-256 generator
  it('a P1 key other than the device key fails', () => {
    expect(parseResponse(V.cosignErc20.response.ur, { request: cosignReq, p1Key: OTHER_P1 }).result).toBe('FAIL');
    expect(parseResponse(V.panic.response.ur, { chainId: CHAIN, contract: A.enforcer, p1Key: OTHER_P1 }).result).toBe('FAIL');
  });
  it('a mandate signed by K1 but checked against another K1 fails', () => {
    const rep = parseResponse(V.mandate.response.ur, { request: mandateReq, k1Address: A.agent });
    expect(rep.result).toBe('FAIL');
    expect(rep.checks.at(-1)).toEqual({ name: 'mandate signed by the paired K1', ok: false });
  });
  it('missing key / request / contract -> UNVERIFIED, and expectVerified throws', () => {
    const cases = [
      parseResponse(V.cosignErc20.response.ur, { request: cosignReq }),
      parseResponse(V.cosignErc20.response.ur, { p1Key: P1 }),
      parseResponse(V.mandate.response.ur, { request: mandateReq }),
      parseResponse(V.revoke.response.ur, { p1Key: P1 }),
      parseResponse(V.deny.response.ur, { request: cosignReq, p1Key: P1 }),
      parseResponse(V.pair.response.ur, {}),
    ];
    for (const rep of cases) {
      expect(rep.result).toBe('UNVERIFIED');
      expect(rep.unverified.length).toBeGreaterThan(0);
      expect(() => expectVerified(rep)).toThrow(ProtoError);
    }
  });
  it('verifyPairing refuses a response to another pair request', () => {
    const other = buildRequest('pair', { chainId: CHAIN, registry: A.registry, now: V.now, reqId: '00'.repeat(16) });
    expect(() => verifyPairing(V.pair.response.ur, other)).toThrow(ProtoError);
    // a signed pair response for the right request id but another registry domain
    const req2 = buildRequest('pair', { chainId: CHAIN, registry: A.relay, now: V.now, reqId: V.pair.reqId });
    expect(() => verifyPairing(V.pair.response.ur, req2)).toThrow(/FAIL/);
  });
});

describe('malformed responses throw ProtoError', () => {
  it('unexpected keys, wrong lengths, wrong types, not a map', () => {
    const add = respMap(V.cosignErc20.response.ur);
    add.set(5n, 1n);
    expect(() => parseResponse(reUr('ripar-cosign', add))).toThrow(/unexpected keys \[5\]/);
    const txt = respMap(V.cosignErc20.response.ur);
    txt.set('x', 1n);
    expect(() => parseResponse(reUr('ripar-cosign', txt))).toThrow(/unexpected keys/);
    const short = respMap(V.cosignErc20.response.ur);
    short.set(2n, new Uint8Array(63));
    expect(() => parseResponse(reUr('ripar-cosign', short))).toThrow(/key 2 must be bstr\(64\)/);
    const neg = respMap(V.panic.response.ur);
    neg.set(1n, -1n);
    expect(() => parseResponse(reUr('ripar-panic', neg))).toThrow(ProtoError);
    const tagged = respMap(V.cosignErc20.response.ur);
    tagged.set(1n, new Tag(37, tagged.get(1n)!)); // responses echo the req-id as a PLAIN bstr
    expect(() => parseResponse(reUr('ripar-cosign', tagged))).toThrow(/key 1 must be bstr\(16\)/);
    const nonce = respMap(V.reopen.response.ur);
    nonce.set(2n, new Uint8Array(33));
    expect(() => parseResponse(reUr('ripar-reopen', nonce))).toThrow(/nonce longer than 32 bytes/);
    expect(() => parseResponse(urSingle('ripar-cosign', cborEncode([1n, 2n])))).toThrow(/not a map/);
    expect(() => parseResponse(urSingle('ripar-unknown', cborEncode(new Map())))).toThrow(/unknown response type/);
  });
  it('bad URs', () => {
    const ur = V.cosignErc20.response.ur as string;
    const last = ur.at(-1) === 'A' ? 'B' : 'A';
    expect(() => parseResponse(ur.slice(0, -1) + last)).toThrow(ProtoError); // CRC
    expect(() => parseResponse(ur.slice(0, -2))).toThrow(ProtoError);
    expect(() => parseResponse('UR:RIPAR-COSIGN/ZZZZ')).toThrow(ProtoError);
    expect(() => parseResponse('not a ur')).toThrow(ProtoError);
    expect(() => parseResponse('')).toThrow(ProtoError);
    expect(() => urRead(`${V.cosignErc20.request.ur} UR:RIPAR-DENY/${bytewordsEncode(new Uint8Array([0xa0]))}`)).not.toThrow(); // the first single part wins (make_request)
  });
  it('strict DER', () => {
    const good = derEncode(1n, 2n);
    expect(derParse(good)).toEqual({ r: 1n, s: 2n });
    expect(() => derParse(Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02))).toThrow(/negative/);
    expect(() => derParse(Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02))).toThrow(/non-minimal/);
    expect(() => derParse(Uint8Array.of(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00))).toThrow(ProtoError);
    expect(() => derParse(Uint8Array.of(0x30, 0x06, 0x02, 0x00, 0x02, 0x01, 0x02, 0x00))).toThrow(ProtoError);
    // a Privy DER signature with trailing bytes is malformed
    const req = buildRequest('privy', { json: { version: 1, method: 'PATCH', url: 'https://api.privy.io/v1/wallets/w1', body: { policy_ids: ['p1'] }, headers: { 'privy-app-id': 'app1' } } });
    const m = cborDecode(simulate('privy', req.cbor)) as CborMap;
    expect(parseResponse(urSingle('ripar-der-sig', cborEncode(m)), { request: req, p1Key: DEMO_P1 }).result).toBe('VERIFIED');
    const der = m.get(2n) as Uint8Array;
    const bad = new Uint8Array(der.length + 1);
    bad.set(der);
    m.set(2n, bad);
    expect(() => parseResponse(urSingle('ripar-der-sig', cborEncode(m)), { request: req, p1Key: DEMO_P1 })).toThrow(ProtoError);
  });
});

describe('strict CBOR and UR decoding', () => {
  const bad: [string, string][] = [
    ['indefinite array', '9f01ff'],
    ['indefinite bytes', '5f4101ff'],
    ['float', 'f93c00'],
    ['undefined', 'f7'],
    ['reserved length', '1c'],
    ['truncated', '4201'],
    ['trailing', '0101'],
    ['duplicate key (int)', 'a201010102'],
    ['array key', 'a18001'],
    ['tagged key', 'a1d8250101'],
    ['bad utf-8 text', '61ff'],
    ['huge length', '5bffffffffffffffff'],
  ];
  for (const [name, hex] of bad) {
    it(`refuses ${name}`, () => {
      expect(() => cborDecode(hexToBytes(hex))).toThrow(ProtoError);
    });
  }
  it('refuses nesting deeper than 16', () => {
    expect(() => cborDecode(hexToBytes('81'.repeat(17) + '00'))).toThrow(/too deep/);
    expect(cborDecode(hexToBytes('81'.repeat(16) + '00'))).toBeDefined();
  });
  it('UrDecoder refuses parts of another message / type', () => {
    const a = buildRequest('deny', { chainId: CHAIN, relay: A.relay, agentId: 1, requestHash: '0x' + '11'.repeat(32) }, { frag: 20 });
    const b = buildRequest('deny', { chainId: CHAIN, relay: A.relay, agentId: 2, requestHash: '0x' + '22'.repeat(32) }, { frag: 20 });
    const d = new UrDecoder();
    d.receive(a.parts[0]!);
    expect(() => d.receive(b.parts[1]!)).toThrow(ProtoError);
    const e = new UrDecoder();
    e.receive(a.parts[0]!);
    expect(() => e.receive(a.parts[1]!.replace('RIPAR-DENY-REQ', 'RIPAR-PAIR-REQ'))).toThrow(ProtoError);
    // a part whose sequence component lies
    const f = new UrDecoder();
    expect(() => f.receive(a.parts[1]!.replace(/\/2-/, '/3-'))).toThrow(ProtoError);
  });
});
