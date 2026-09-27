// BC-UR fountain codes (BCR-2024-001), a port of firmware/tools/ref_ur.py (itself a port of the bc-ur C++ reference:
// xoshiro256.cpp, random-sampler.cpp, fountain-utils.cpp, fountain-encoder.cpp), plus an optimal GF(2) decoder.
import { be32, crc32 } from './bytewords.js';
import { cborEncode } from './cbor.js';
import { ProtoError } from './errors.js';
import { sha256 } from './hash.js';

/**
 * Decoder limits, the same as the firmware's (firmware/src/ur.cpp kMaxSeqLen / kMaxMessageLen): every Ripar message
 * fits in them, and they keep a hostile part (seqLen up to 2^32-1 in its CBOR) from costing unbounded time or memory
 * (fragment choice and the GF(2) rows are O(seqLen) per part, the reference shuffle O(seqLen^2)).
 */
export const UR_MAX_SEQ_LEN = 128;
export const UR_MAX_MESSAGE_LEN = 8192;

/** refuses part metadata outside the decoder limits or inconsistent with the fragment length (ProtoError) */
export function checkPartLimits(p: { seqLen: number; messageLen: number; data: Uint8Array }): void {
  if (!Number.isInteger(p.seqLen) || p.seqLen < 1 || p.seqLen > UR_MAX_SEQ_LEN) {
    throw new ProtoError(`UR part: seqLen ${p.seqLen} outside 1..${UR_MAX_SEQ_LEN}`);
  }
  if (!Number.isInteger(p.messageLen) || p.messageLen < 1 || p.messageLen > UR_MAX_MESSAGE_LEN) {
    throw new ProtoError(`UR part: messageLen ${p.messageLen} outside 1..${UR_MAX_MESSAGE_LEN}`);
  }
  if (p.data.length === 0 || Math.ceil(p.messageLen / p.data.length) !== p.seqLen) {
    throw new ProtoError('UR part: seqLen, messageLen and fragment length are inconsistent');
  }
}

const M64 = (1n << 64n) - 1n;
const TWO64 = 18446744073709551616.0;

const rotl = (x: bigint, k: bigint): bigint => ((x << k) | (x >> (64n - k))) & M64;

/** xoshiro256** seeded with SHA-256(seed), exactly as bc-ur xoshiro256.cpp */
export class Xoshiro256 {
  private s: [bigint, bigint, bigint, bigint];

  constructor(seed: Uint8Array) {
    const d = sha256(seed);
    const w = (i: number): bigint => {
      let v = 0n;
      for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(d[8 * i + j]!);
      return v;
    };
    this.s = [w(0), w(1), w(2), w(3)];
  }

  static fromString(s: string): Xoshiro256 {
    return new Xoshiro256(new TextEncoder().encode(s));
  }

  static fromCrc32(c: number): Xoshiro256 {
    return new Xoshiro256(be32(c));
  }

  next(): bigint {
    const s = this.s;
    const result = (rotl((s[1] * 5n) & M64, 7n) * 9n) & M64;
    const t = (s[1] << 17n) & M64;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45n);
    return result;
  }

  /** (double)next() / 2^64: the bigint -> double conversion rounds to nearest-even, as C++ and Python do */
  nextDouble(): number {
    return Number(this.next()) / TWO64;
  }

  nextInt(low: number, high: number): number {
    return Math.floor(this.nextDouble() * (high - low + 1)) + low;
  }

  nextByte(): number {
    return this.nextInt(0, 255);
  }

  nextData(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = this.nextByte();
    return out;
  }
}

/** bc-ur random-sampler.cpp (Vose alias method, reversed index order, LIFO work lists) */
export class RandomSampler {
  readonly probs: number[];
  readonly aliases: number[];

  constructor(probs: number[]) {
    let total = 0;
    for (const p of probs) {
      if (!(p >= 0)) throw new ProtoError('sampler: negative probability');
      total += p; // plain left-to-right sum, as std::accumulate
    }
    if (!(total > 0)) throw new ProtoError('sampler: zero total');
    const n = probs.length;
    const P = probs.map((d) => (d * n) / total);
    const S: number[] = [];
    const L: number[] = [];
    for (let i = n - 1; i >= 0; i--) (P[i]! < 1 ? S : L).push(i);
    const probs_ = new Array<number>(n).fill(0);
    const aliases = new Array<number>(n).fill(0);
    while (S.length && L.length) {
      const a = S.pop()!;
      const g = L.pop()!;
      probs_[a] = P[a]!;
      aliases[a] = g;
      P[g] = P[g]! + P[a]! - 1;
      (P[g]! < 1 ? S : L).push(g);
    }
    while (L.length) probs_[L.pop()!] = 1.0;
    while (S.length) probs_[S.pop()!] = 1.0;
    this.probs = probs_;
    this.aliases = aliases;
  }

  next(rngDouble: () => number): number {
    const r1 = rngDouble();
    const r2 = rngDouble();
    const n = this.probs.length;
    const i = Math.floor(n * r1);
    return r2 < this.probs[i]! ? i : this.aliases[i]!;
  }
}

export function chooseDegree(seqLen: number, rng: Xoshiro256): number {
  const probs: number[] = [];
  for (let i = 1; i <= seqLen; i++) probs.push(1.0 / i);
  return new RandomSampler(probs).next(() => rng.nextDouble()) + 1;
}

export function shuffled<T>(items: readonly T[], rng: Xoshiro256): T[] {
  const remaining = [...items];
  const result: T[] = [];
  while (remaining.length) {
    const idx = rng.nextInt(0, remaining.length - 1);
    result.push(remaining.splice(idx, 1)[0]!);
  }
  return result;
}

/** 0-based fragment indexes (sorted) mixed into part seqNum (1-based) */
export function chooseFragments(seqNum: number, seqLen: number, checksum: number): number[] {
  if (seqNum <= seqLen) return [seqNum - 1];
  const seed = new Uint8Array(8);
  seed.set(be32(seqNum >>> 0), 0);
  seed.set(be32(checksum >>> 0), 4);
  const rng = new Xoshiro256(seed);
  const degree = chooseDegree(seqLen, rng);
  const idx = Array.from({ length: seqLen }, (_, i) => i);
  return shuffled(idx, rng)
    .slice(0, degree)
    .sort((a, b) => a - b);
}

export function findNominalFragmentLength(messageLen: number, minFragmentLen: number, maxFragmentLen: number): number {
  if (!(messageLen > 0 && minFragmentLen > 0 && maxFragmentLen >= minFragmentLen)) {
    throw new ProtoError('fountain: bad message / fragment length');
  }
  const maxCount = Math.floor(messageLen / minFragmentLen);
  let fragLen: number | null = null;
  for (let count = 1; count <= maxCount; count++) {
    fragLen = Math.ceil(messageLen / count);
    if (fragLen <= maxFragmentLen) break;
  }
  if (fragLen === null) throw new ProtoError('fountain: message shorter than the minimum fragment length');
  return fragLen;
}

export function partitionMessage(message: Uint8Array, fragLen: number): Uint8Array[] {
  const frags: Uint8Array[] = [];
  for (let i = 0; i < message.length; i += fragLen) {
    const f = new Uint8Array(fragLen);
    f.set(message.subarray(i, i + fragLen));
    frags.push(f);
  }
  return frags;
}

function xorInto(a: Uint8Array, b: Uint8Array): void {
  for (let i = 0; i < a.length; i++) a[i]! ^= b[i]!;
}

export interface FountainPart {
  seqNum: number;
  seqLen: number;
  messageLen: number;
  checksum: number;
  data: Uint8Array;
}

/** bc-ur fountain-encoder.cpp: parts 1..seqLen are the pure fragments, higher parts mix several */
export class FountainEncoder {
  readonly message: Uint8Array;
  readonly messageLen: number;
  readonly checksum: number;
  readonly fragLen: number;
  readonly frags: Uint8Array[];
  readonly seqLen: number;

  constructor(message: Uint8Array, maxFragmentLen: number, minFragmentLen = 10) {
    this.message = Uint8Array.from(message);
    this.messageLen = message.length;
    this.checksum = crc32(message);
    this.fragLen = findNominalFragmentLength(this.messageLen, minFragmentLen, maxFragmentLen);
    this.frags = partitionMessage(this.message, this.fragLen);
    this.seqLen = this.frags.length;
  }

  indexes(seqNum: number): number[] {
    return chooseFragments(seqNum, this.seqLen, this.checksum);
  }

  part(seqNum: number): FountainPart {
    const data = new Uint8Array(this.fragLen);
    for (const i of this.indexes(seqNum)) xorInto(data, this.frags[i]!);
    return { seqNum, seqLen: this.seqLen, messageLen: this.messageLen, checksum: this.checksum, data };
  }

  /** CBOR [seqNum, seqLen, messageLen, checksum, data] */
  partCbor(seqNum: number): Uint8Array {
    const p = this.part(seqNum);
    return cborEncode([p.seqNum, p.seqLen, p.messageLen, p.checksum, p.data]);
  }
}

/**
 * Optimal fountain decoder: every part (pure or mixed) is a row of a GF(2) system over the fragments; the message is
 * complete as soon as the rows reach full rank (the earliest point any decoder can finish; ref_ur.gf2_complete_at).
 */
export class FountainDecoder {
  seqLen = 0;
  messageLen = 0;
  checksum = 0;
  fragLen = 0;
  private rows = new Map<number, { mask: bigint; data: Uint8Array }>(); // pivot (lowest index) -> row
  private seen = new Set<number>();
  private result: Uint8Array | null = null;

  get rank(): number {
    return this.rows.size;
  }

  get isComplete(): boolean {
    return this.result !== null;
  }

  get message(): Uint8Array | null {
    return this.result;
  }

  /** number of distinct part sequence numbers accepted so far */
  get partsReceived(): number {
    return this.seen.size;
  }

  /** feeds one part; returns true when it added information. Inconsistent parts -> ProtoError */
  receive(p: FountainPart): boolean {
    if (this.result) return false;
    if (!Number.isInteger(p.seqNum) || p.seqNum < 1) throw new ProtoError('fountain: bad seqNum');
    if (!Number.isInteger(p.seqLen) || p.seqLen < 1) throw new ProtoError('fountain: bad seqLen');
    checkPartLimits(p);
    if (this.seqLen === 0) {
      if (p.data.length === 0 || p.messageLen < 1 || p.messageLen > p.seqLen * p.data.length) {
        throw new ProtoError('fountain: bad message length');
      }
      if (p.messageLen <= (p.seqLen - 1) * p.data.length) throw new ProtoError('fountain: bad message length');
      this.seqLen = p.seqLen;
      this.messageLen = p.messageLen;
      this.checksum = p.checksum >>> 0;
      this.fragLen = p.data.length;
    } else if (
      p.seqLen !== this.seqLen ||
      p.messageLen !== this.messageLen ||
      p.checksum >>> 0 !== this.checksum ||
      p.data.length !== this.fragLen
    ) {
      throw new ProtoError('fountain: part belongs to another message');
    }
    if (this.seen.has(p.seqNum)) return false;
    this.seen.add(p.seqNum);
    let mask = 0n;
    for (const i of chooseFragments(p.seqNum, this.seqLen, this.checksum)) mask ^= 1n << BigInt(i);
    const data = Uint8Array.from(p.data);
    while (mask !== 0n) {
      const low = mask & -mask;
      const pivot = low.toString(2).length - 1;
      const row = this.rows.get(pivot);
      if (!row) {
        this.rows.set(pivot, { mask, data });
        if (this.rows.size === this.seqLen) this.solve();
        return true;
      }
      mask ^= row.mask;
      xorInto(data, row.data);
    }
    return false;
  }

  private solve(): void {
    const pivots = [...this.rows.keys()].sort((a, b) => b - a);
    for (const p of pivots) {
      const row = this.rows.get(p)!;
      for (let q = p + 1; q < this.seqLen; q++) {
        if ((row.mask >> BigInt(q)) & 1n) {
          const r = this.rows.get(q)!;
          row.mask ^= r.mask;
          xorInto(row.data, r.data);
        }
      }
    }
    const msg = new Uint8Array(this.seqLen * this.fragLen);
    for (let i = 0; i < this.seqLen; i++) msg.set(this.rows.get(i)!.data, i * this.fragLen);
    const out = msg.slice(0, this.messageLen);
    if (crc32(out) !== this.checksum) throw new ProtoError('multipart message CRC mismatch');
    this.result = out;
  }
}
