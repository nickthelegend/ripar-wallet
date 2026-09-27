// UR strings (BCR-2020-005): single-part and multipart, upper-cased for QR alphanumeric mode (make_request.py
// ur_single / ur_parts / ur_read), and an incremental multipart decoder for pure and mixed fountain parts.
import { bytewordsDecode, bytewordsEncode, crc32 as crc32Of } from './bytewords.js';
import { type CborValue, cborDecode } from './cbor.js';
import { ProtoError } from './errors.js';
import { FountainDecoder, FountainEncoder, type FountainPart, checkPartLimits } from './fountain.js';

/** default maximum fragment size of make_request build (bytes of CBOR per multipart part) */
export const DEFAULT_FRAGMENT_LEN = 70;

/** "UR:<TYPE>/<MINIMAL BYTEWORDS>" (upper case) */
export function urSingle(urType: string, cbor: Uint8Array): string {
  return `ur:${urType}/${bytewordsEncode(cbor)}`.toUpperCase();
}

/** one multipart part "UR:<TYPE>/<SEQ>-<LEN>/<BYTEWORDS OF THE PART CBOR>" (upper case) */
export function urPart(urType: string, enc: FountainEncoder, seqNum: number): string {
  return `ur:${urType}/${seqNum}-${enc.seqLen}/${bytewordsEncode(enc.partCbor(seqNum))}`.toUpperCase();
}

/**
 * The multipart QR loop of make_request build: the pure parts 1..seqLen (fragments of at most `frag` bytes), then
 * `extra` mixed fountain parts. Loop them at about 300 ms per frame.
 */
export function urParts(urType: string, cbor: Uint8Array, frag = DEFAULT_FRAGMENT_LEN, extra = 0): string[] {
  const enc = new FountainEncoder(cbor, frag);
  const out: string[] = [];
  for (let s = 1; s <= enc.seqLen + extra; s++) out.push(urPart(urType, enc, s));
  return out;
}

/** decodes the CBOR of one multipart part: [seqNum, seqLen, messageLen, checksum, fragment] */
export function decodePartCbor(b: Uint8Array): FountainPart {
  const v = cborDecode(b);
  if (!Array.isArray(v) || v.length !== 5) throw new ProtoError('UR part is not a 5-item array');
  const [seq, slen, mlen, crc, frag] = v as CborValue[];
  const u32 = (x: CborValue | undefined, what: string): number => {
    if (typeof x !== 'bigint' || x < 0n || x > 0xffffffffn) throw new ProtoError(`UR part: bad ${what}`);
    return Number(x);
  };
  if (!(frag instanceof Uint8Array)) throw new ProtoError('UR part: fragment must be a byte string');
  const part = {
    seqNum: u32(seq, 'seqNum'),
    seqLen: u32(slen, 'seqLen'),
    messageLen: u32(mlen, 'messageLen'),
    checksum: u32(crc, 'checksum'),
    data: frag,
  };
  if (part.seqNum < 1) throw new ProtoError('UR part: bad seqNum');
  // bounded before anything loops over seqLen (a 60-character part may claim seqLen 2^32-1)
  checkPartLimits(part);
  return part;
}

export interface UrContent {
  /** UR type, lower case (e.g. "ripar-cosign") */
  type: string;
  /** the CBOR payload */
  cbor: Uint8Array;
}

/**
 * make_request ur_read: one single-part UR, or several multipart parts (whitespace / newline separated; lines that
 * start with '#' are comments). When a single-part UR is present it wins (build output lists it first). Pure parts
 * are reassembled; mixed parts are ignored here (use UrDecoder for fountain solving).
 */
export function urRead(text: string): UrContent {
  const lines = text.split(/\r?\n|\r/).filter((ln) => ln.trim() && !ln.trim().startsWith('#'));
  let parts = lines.join(' ').split(/\s+/).filter((p) => p.length > 0);
  if (!parts.length) throw new ProtoError('no UR given');
  const singles = parts.filter((p) => p.toLowerCase().startsWith('ur:') && (p.match(/\//g) || []).length === 1);
  if (singles.length) parts = singles.slice(0, 1);
  const frags = new Map<number, Uint8Array>();
  let meta: [number, number, number] | null = null;
  let utype: string | null = null;
  for (const p of parts) {
    const s = p.trim().toLowerCase();
    if (!s.startsWith('ur:')) throw new ProtoError(`not a UR: ${JSON.stringify(p.slice(0, 40))}`);
    const path = s.slice(3).split('/');
    if (utype !== null && path[0] !== utype) throw new ProtoError('mixed UR types');
    utype = path[0]!;
    if (path.length === 2) {
      if (parts.length !== 1) throw new ProtoError('single-part UR mixed with other parts');
      return { type: utype, cbor: bytewordsDecode(path[1]!) };
    }
    if (path.length !== 3) throw new ProtoError('bad UR path');
    const part = decodePartCbor(bytewordsDecode(path[2]!));
    const m: [number, number, number] = [part.seqLen, part.messageLen, part.checksum];
    if (meta === null) meta = m;
    else if (meta[0] !== m[0] || meta[1] !== m[1] || meta[2] !== m[2]) {
      throw new ProtoError('parts belong to different messages');
    }
    if (part.seqNum <= part.seqLen) frags.set(part.seqNum, part.data);
  }
  const [slen, mlen, crc] = meta!;
  const missing: number[] = [];
  for (let i = 1; i <= slen; i++) if (!frags.has(i)) missing.push(i);
  if (missing.length) {
    const list = missing.slice(0, 16).join(', ') + (missing.length > 16 ? `, ... (${missing.length} in all)` : '');
    throw new ProtoError(`missing pure parts [${list}] (mixed-part solving: use UrDecoder)`);
  }
  let total = 0;
  for (let i = 1; i <= slen; i++) total += frags.get(i)!.length;
  const joined = new Uint8Array(total);
  let o = 0;
  for (let i = 1; i <= slen; i++) {
    joined.set(frags.get(i)!, o);
    o += frags.get(i)!.length;
  }
  const msg = joined.slice(0, mlen);
  if (crc32Of(msg) !== crc) throw new ProtoError('multipart message CRC mismatch');
  return { type: utype!, cbor: msg };
}


export type UrReceiveResult = 'accepted' | 'duplicate' | 'complete' | 'ignored';

/**
 * Incremental UR decoder (what a companion's camera loop feeds): single-part URs complete at once; multipart parts
 * (pure or mixed, any order, duplicates ignored) complete when the fragments are solvable. Parts of another type or
 * message -> ProtoError (call reset() to start over).
 */
export class UrDecoder {
  private dec: FountainDecoder | null = null;
  private done: UrContent | null = null;
  type: string | null = null;

  get isComplete(): boolean {
    return this.done !== null;
  }

  get result(): UrContent | null {
    return this.done;
  }

  /** 0..1: rank / seqLen for multipart, 1 once complete */
  get progress(): number {
    if (this.done) return 1;
    if (!this.dec || this.dec.seqLen === 0) return 0;
    return this.dec.rank / this.dec.seqLen;
  }

  get seqLen(): number {
    return this.dec?.seqLen ?? 0;
  }

  get partsReceived(): number {
    return this.dec?.partsReceived ?? 0;
  }

  reset(): void {
    this.dec = null;
    this.done = null;
    this.type = null;
  }

  receive(text: string): UrReceiveResult {
    if (this.done) return 'ignored';
    const s = text.trim().toLowerCase();
    if (!s.startsWith('ur:')) throw new ProtoError(`not a UR: ${JSON.stringify(text.slice(0, 40))}`);
    const path = s.slice(3).split('/');
    const utype = path[0]!;
    if (!/^[a-z0-9-]+$/.test(utype)) throw new ProtoError('bad UR type');
    if (this.type !== null && utype !== this.type) throw new ProtoError('UR of another type');
    if (path.length === 2) {
      if (this.dec) throw new ProtoError('single-part UR while a multipart message is in progress');
      this.type = utype;
      this.done = { type: utype, cbor: bytewordsDecode(path[1]!) };
      return 'complete';
    }
    if (path.length !== 3) throw new ProtoError('bad UR path');
    const sq = /^([1-9][0-9]*)-([1-9][0-9]*)$/.exec(path[1]!);
    if (!sq) throw new ProtoError('bad UR sequence component');
    const part = decodePartCbor(bytewordsDecode(path[2]!));
    if (BigInt(sq[1]!) !== BigInt(part.seqNum) || BigInt(sq[2]!) !== BigInt(part.seqLen)) {
      throw new ProtoError('UR sequence component disagrees with the part');
    }
    this.type = utype;
    if (!this.dec) this.dec = new FountainDecoder();
    const added = this.dec.receive(part);
    if (this.dec.isComplete) {
      this.done = { type: utype, cbor: this.dec.message! };
      return 'complete';
    }
    return added ? 'accepted' : 'duplicate';
  }
}

/** true when the text looks like a multipart part ("ur:type/n-m/...") */
export function isMultipartUr(text: string): boolean {
  return /^ur:[a-z0-9-]+\/[0-9]+-[0-9]+\//i.test(text.trim());
}
