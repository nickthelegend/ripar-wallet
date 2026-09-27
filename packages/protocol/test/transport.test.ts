// BC-UR transport against the official bc-ur test vectors (as carried by firmware/tools/ref_ur.py OFFICIAL) and the
// ref_ur fountain stream: bytewords, CRC-32, xoshiro256**, the random sampler, shuffle, degrees, fragment choice,
// the UR encoder parts, the optimal fountain decoder (mixed parts only), UrDecoder / urRead, and CBOR canonical form.
import { describe, expect, it } from 'vitest';
import {
  FountainDecoder,
  FountainEncoder,
  RandomSampler,
  Tag,
  UrDecoder,
  Xoshiro256,
  buildRequest,
  bytewordsDecode,
  bytewordsEncode,
  cborDecode,
  cborEncode,
  chooseDegree,
  chooseFragments,
  crc32,
  decodePartCbor,
  findNominalFragmentLength,
  isMultipartUr,
  partitionMessage,
  shuffled,
  u256Min,
  urPart,
  urParts,
  urRead,
  urSingle,
  aiTextTrunc,
  checkText,
} from '../src/index.js';
import { bytesToHex, hexToBytes, oracle } from './helpers/env.js';

interface Official {
  bytewords_1_in: string;
  bytewords_1_std: string;
  bytewords_1_uri: string;
  bytewords_1_min: string;
  bytewords_2_in: string;
  bytewords_2_min: string;
  spec_in: string;
  spec_min: string;
  spec_crc: number;
  rng_1: number[];
  shuffle: number[][];
  degrees: number[];
  choose_fragments: number[][];
  single_part_ur: string;
  ur_encoder_parts: string[];
  seed_ur: string;
  seed_part1: string;
  part1_cbor: string;
  sampler: number[];
  msg1024: string;
  wolf256cbor: string;
  wolf50cbor: string;
  stream: { msg: string; seqLen: number; fragLen: number; crc: number; mixed: string[]; mixedIdx: number[][]; pure: string[] };
}

const O = oracle<Official>('official');

describe('official bc-ur vectors', () => {
  it('bytewords (standard / uri / minimal) and decode', () => {
    const in1 = hexToBytes(O.bytewords_1_in);
    expect(bytewordsEncode(in1, 'standard')).toBe(O.bytewords_1_std);
    expect(bytewordsEncode(in1, 'uri')).toBe(O.bytewords_1_uri);
    expect(bytewordsEncode(in1)).toBe(O.bytewords_1_min);
    expect(bytesToHex(bytewordsDecode(O.bytewords_1_min))).toBe(O.bytewords_1_in);
    expect(bytesToHex(bytewordsDecode(O.bytewords_1_std, 'standard'))).toBe(O.bytewords_1_in);
    expect(bytewordsEncode(hexToBytes(O.bytewords_2_in))).toBe(O.bytewords_2_min);
    expect(bytesToHex(bytewordsDecode(O.bytewords_2_min.toUpperCase()))).toBe(O.bytewords_2_in);
    expect(() => bytewordsDecode(O.bytewords_1_min.slice(0, -2) + 'ae')).toThrow();
  });
  it('CRC-32 and the spec example', () => {
    expect(crc32(hexToBytes(O.spec_in))).toBe(O.spec_crc);
    expect(bytewordsEncode(hexToBytes(O.spec_in))).toBe(O.spec_min);
  });
  it('xoshiro256** / sampler / shuffle / degrees / fragment choice', () => {
    const rng = Xoshiro256.fromString('Wolf');
    expect(Array.from({ length: 100 }, () => Number(rng.next() % 100n))).toEqual(O.rng_1);
    const r2 = Xoshiro256.fromString('Wolf');
    const sampler = new RandomSampler([1, 2, 4, 8]);
    expect(Array.from({ length: 500 }, () => sampler.next(() => r2.nextDouble()))).toEqual(O.sampler);
    const r3 = Xoshiro256.fromString('Wolf');
    expect(Array.from({ length: 10 }, () => shuffled([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], r3))).toEqual(O.shuffle);
    const msg = hexToBytes(O.msg1024);
    expect(bytesToHex(Xoshiro256.fromString('Wolf').nextData(1024))).toBe(O.msg1024);
    const fl = findNominalFragmentLength(msg.length, 10, 100);
    const n = partitionMessage(msg, fl).length;
    expect(Array.from({ length: 200 }, (_, k) => chooseDegree(n, Xoshiro256.fromString(`Wolf-${k + 1}`)))).toEqual(O.degrees);
    expect(Array.from({ length: 30 }, (_, s) => chooseFragments(s + 1, n, crc32(msg)))).toEqual(O.choose_fragments);
    expect(findNominalFragmentLength(12345, 1005, 1955)).toBe(1764);
    expect(findNominalFragmentLength(12345, 1005, 30000)).toBe(12345);
  });
  it('single-part UR and the 20 encoder parts (upper-cased for QR)', () => {
    expect(urSingle('bytes', hexToBytes(O.wolf50cbor))).toBe(O.single_part_ur.toUpperCase());
    const enc = new FountainEncoder(hexToBytes(O.wolf256cbor), 30);
    const parts = Array.from({ length: 20 }, (_, i) => urPart('bytes', enc, i + 1));
    expect(parts).toEqual(O.ur_encoder_parts.map((p) => p.toUpperCase()));
    expect(bytesToHex(new FountainEncoder(Xoshiro256.fromString('Wolf').nextData(256), 30).partCbor(1))).toBe('0x' + O.part1_cbor);
    const seedMsg = bytewordsDecode(O.seed_ur.split('/').at(-1)!);
    expect(urPart('seed', new FountainEncoder(seedMsg, 18), 1)).toBe(O.seed_part1.toUpperCase());
    expect(urParts('bytes', hexToBytes(O.wolf256cbor), 30, 11)).toEqual(parts);
  });
  it('the fountain decoder completes from MIXED parts only, exactly where an optimal decoder can', () => {
    const d = new UrDecoder();
    const S = O.stream;
    S.mixed.forEach((p, i) => {
      const part = decodePartCbor(bytewordsDecode(p.split('/').at(-1)!));
      expect(chooseFragments(part.seqNum, S.seqLen, S.crc)).toEqual(S.mixedIdx[i]);
      const r = d.receive(p);
      if (i === S.mixed.length - 1) expect(r).toBe('complete');
      else expect(['accepted', 'duplicate']).toContain(r);
    });
    expect(bytesToHex(d.result!.cbor)).toBe(S.msg);
    expect(d.result!.type).toBe('ripar-cosign-req');
    expect(d.progress).toBe(1);
  });
  it('pure parts in any order with duplicates; urRead of the pure loop', () => {
    const S = O.stream;
    const order = [7, 3, 3, 11, 1, 9, 7, 2, 10, 5, 4, 8, 6].filter((i) => i <= S.seqLen);
    const d = new UrDecoder();
    let last = '';
    for (const i of order) last = d.receive(S.pure[i - 1]!);
    expect(last === 'complete' || d.isComplete).toBe(true);
    expect(bytesToHex(d.result!.cbor)).toBe(S.msg);
    expect(bytesToHex(urRead(S.pure.join('\n')).cbor)).toBe(S.msg);
    expect(() => urRead(S.pure.slice(1).join(' '))).toThrow(/missing pure parts \[1\]/);
    expect(isMultipartUr(S.pure[0]!)).toBe(true);
  });
});

describe('fountain decoder vs encoder (random messages)', () => {
  it('any 1.x * seqLen mixed parts solve every message', () => {
    for (const [len, frag] of [
      [10, 70],
      [69, 70],
      [70, 70],
      [71, 70],
      [300, 70],
      [1000, 60],
      [2500, 80],
    ] as const) {
      const msg = Xoshiro256.fromString(`msg-${len}`).nextData(len);
      const enc = new FountainEncoder(msg, frag);
      const dec = new FountainDecoder();
      let s = enc.seqLen + 1;
      while (!dec.isComplete) {
        dec.receive(enc.part(s++));
        expect(s).toBeLessThan(enc.seqLen * 4 + 40);
      }
      expect(bytesToHex(dec.message!)).toBe(bytesToHex(msg));
    }
  });
});

describe('decoder limits (hostile multipart parts)', () => {
  const hostile = (seqNum: number, seqLen: number, messageLen: number, frag: Uint8Array): string =>
    `ur:ripar-cosign/${seqNum}-${seqLen}/${bytewordsEncode(cborEncode([seqNum, seqLen, messageLen, 0, frag]))}`;
  it('a part claiming seqLen 2^32-1 is refused at once by urRead, UrDecoder and FountainDecoder', () => {
    const t0 = Date.now();
    const ur = hostile(1, 0xffffffff, 60, new Uint8Array(1));
    expect(() => urRead(ur)).toThrow(/seqLen 4294967295 outside 1\.\.128/);
    expect(() => new UrDecoder().receive(ur)).toThrow(/seqLen/);
    expect(() => new FountainDecoder().receive({ seqNum: 1, seqLen: 1_000_000, messageLen: 1_000_000, checksum: 0, data: new Uint8Array(1) })).toThrow(
      /seqLen/,
    );
    expect(Date.now() - t0).toBeLessThan(1000);
  });
  it('a mixed part with a huge seqLen does not hang the camera decoder', () => {
    const t0 = Date.now();
    expect(() => new UrDecoder().receive(hostile(2_000_001, 1_000_000, 1_000_000, new Uint8Array(1)))).toThrow(/seqLen/);
    expect(Date.now() - t0).toBeLessThan(1000);
  });
  it('messageLen above 8192 and inconsistent lengths are refused', () => {
    expect(() => urRead(hostile(1, 100, 9000, new Uint8Array(90)))).toThrow(/messageLen 9000/);
    expect(() => urRead(hostile(1, 5, 100, new Uint8Array(10)))).toThrow(/inconsistent/);
    expect(() => urRead(hostile(0, 1, 10, new Uint8Array(10)))).toThrow(/seqNum/);
  });
  it('missing-part errors stay short', () => {
    const parts = urParts('ripar-cosign', Xoshiro256.fromString('big').nextData(8000), 70);
    expect(parts.length).toBeLessThanOrEqual(128);
    let msg = '';
    try {
      urRead(parts[0]!);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/in all\)/);
    expect(msg.length).toBeLessThan(200);
    expect(urRead(parts.join(' ')).cbor.length).toBe(8000);
  });
});

describe('canonical CBOR (ref_ur.cbor)', () => {
  it('shortest heads, negative ints, tags, simple values, insertion-order maps', () => {
    const cases: [unknown, string][] = [
      [0n, '00'], [23, '17'], [24, '1818'], [255, '18ff'], [256, '190100'], [65535, '19ffff'], [65536, '1a00010000'],
      [0xffffffffn, '1affffffff'], [0x100000000n, '1b0000000100000000'], [(1n << 64n) - 1n, '1bffffffffffffffff'],
      [-1, '20'], [-24n, '37'], [-25, '3818'], [-(1n << 64n), '3bffffffffffffffff'],
      [new Uint8Array(0), '40'], [Uint8Array.of(1, 2), '420102'], ['', '60'], ['é', '62c3a9'],
      [[], '80'], [[1, [2]], '820181' + '02'], [new Map(), 'a0'], [true, 'f5'], [false, 'f4'], [null, 'f6'],
      [new Tag(37, new Uint8Array(16)), 'd82550' + '00'.repeat(16)],
      [new Map<number, unknown>([[2, 1], [1, 2]]), 'a202010102'],
    ];
    for (const [v, hex] of cases) {
      expect(bytesToHex(cborEncode(v as never)), String(v)).toBe('0x' + hex);
      expect(bytesToHex(cborEncode(cborDecode(hexToBytes(hex))))).toBe('0x' + hex);
    }
    expect(() => cborEncode((1n << 64n) as never)).toThrow();
    expect(() => cborEncode(1.5 as never)).toThrow();
  });
  it('u256 minimal encoding and text rules of the builders', () => {
    expect(bytesToHex(u256Min(0))).toBe('0x00');
    expect(bytesToHex(u256Min(256))).toBe('0x0100');
    expect(bytesToHex(u256Min((1n << 256n) - 1n))).toBe('0x' + 'ff'.repeat(32));
    expect(() => u256Min(1n << 256n)).toThrow();
    expect(() => u256Min(-1)).toThrow();
    expect(aiTextTrunc('€'.repeat(40))).toBe('€'.repeat(33));
    expect(new TextEncoder().encode(aiTextTrunc('€'.repeat(40))).length).toBe(99);
    expect(aiTextTrunc('a\nb\u007f')).toBe('a b ');
    expect(() => checkText('x\ny', 100, 't')).toThrow(/control characters/);
    expect(() => checkText('é'.repeat(33), 64, 't')).toThrow(/longer than 64/);
  });
  it('req-id: random by default, tag 37 on request', () => {
    const f = { chainId: 10143, relay: '0x' + '11'.repeat(20), agentId: 1, requestHash: '0x' + '22'.repeat(32) };
    const a = buildRequest('deny', f);
    const b = buildRequest('deny', f);
    expect(a.reqId).not.toBe(b.reqId);
    const t = buildRequest('deny', { ...f, uuidTag: true, reqId: '0x' + '33'.repeat(16) });
    expect(bytesToHex(t.cbor).startsWith('0xa501d82550' + '33'.repeat(16))).toBe(true);
    expect(t.reqId).toBe('0x' + '33'.repeat(16));
  });
});
