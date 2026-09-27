// Signature checks of the device's P1 (P-256) and K1 (secp256k1) signatures, with the conventions of
// firmware/tools/ref_crypto.py: plain ECDSA verify / recover plus a SEPARATE low-s rule (OpenZeppelin P256.verify and
// ECDSA.recover reject high-s).
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { type BytesLike, bigIntToBytes, bytesToBigInt, concatBytes, toBytes } from './bytes.js';
import { ProtoError } from './errors.js';
import { keccak256 } from './hash.js';

export const P256_N = p256.CURVE.n;
export const SECP256K1_N = secp256k1.CURVE.n;

/** s <= n/2 */
export function isLowS(s: bigint, n: bigint): boolean {
  return s <= n / 2n;
}

/** true when (x, y) = p1Key (64 bytes) is a point on P-256 */
export function p256OnCurve(p1Key: BytesLike): boolean {
  const xy = toBytes(p1Key, 64, 'p1Key');
  try {
    const P = p256.Point.fromAffine({ x: bytesToBigInt(xy.subarray(0, 32)), y: bytesToBigInt(xy.subarray(32)) });
    P.assertValidity();
    return true;
  } catch {
    return false;
  }
}

/** plain ECDSA-P256 verification of r, s over a 32-byte digest (no hashing, no low-s rule) */
export function p256Verify(p1Key: BytesLike, digest: Uint8Array, r: bigint, s: bigint): boolean {
  try {
    const xy = toBytes(p1Key, 64, 'p1Key');
    if (!(r >= 1n && r < P256_N && s >= 1n && s < P256_N)) return false;
    const pub = concatBytes(Uint8Array.of(4), xy);
    const sig = concatBytes(bigIntToBytes(r, 32), bigIntToBytes(s, 32));
    return p256.verify(sig, digest, pub, { lowS: false, prehash: false, format: 'compact' });
  } catch {
    return false;
  }
}

/** secp256k1 public-key recovery (recid 0 / 1) -> the Ethereum address (20 bytes), or null */
export function k1RecoverAddress(digest: Uint8Array, r: bigint, s: bigint, recid: number): Uint8Array | null {
  if (recid !== 0 && recid !== 1) return null;
  try {
    const Q = new secp256k1.Signature(r, s, recid).recoverPublicKey(digest);
    const raw = Q.toBytes(false);
    return keccak256(raw.subarray(1)).slice(12);
  } catch {
    return null;
  }
}

/** r‖s (64 bytes) -> bigints */
export function splitRS(rs: Uint8Array): { r: bigint; s: bigint } {
  if (rs.length < 64) throw new ProtoError('signature shorter than 64 bytes');
  return { r: bytesToBigInt(rs.subarray(0, 32)), s: bytesToBigInt(rs.subarray(32, 64)) };
}

/** make_request der_parse: strict DER SEQUENCE{INTEGER r, INTEGER s} (minimal, positive, <= 33 bytes each) */
export function derParse(der: Uint8Array): { r: bigint; s: bigint } {
  const integer = (b: Uint8Array, i: number): [bigint, number] => {
    if (i + 2 > b.length || b[i] !== 0x02) throw new ProtoError('DER: INTEGER expected');
    const n = b[i + 1]!;
    const v = b.subarray(i + 2, i + 2 + n);
    if (n === 0 || v.length !== n || n > 33) throw new ProtoError('DER: bad INTEGER length');
    if (v[0]! & 0x80) throw new ProtoError('DER: negative INTEGER');
    if (n > 1 && v[0] === 0 && !(v[1]! & 0x80)) throw new ProtoError('DER: non-minimal INTEGER');
    return [bytesToBigInt(v), i + 2 + n];
  };
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) throw new ProtoError('DER: bad SEQUENCE');
  const [r, i] = integer(der, 2);
  const [s, j] = integer(der, i);
  if (j !== der.length) throw new ProtoError('DER: trailing bytes');
  return { r, s };
}

/** DER SEQUENCE{INTEGER r, INTEGER s} (ref_crypto.der) */
export function derEncode(r: bigint, s: bigint): Uint8Array {
  const enc = (v: bigint): Uint8Array => {
    let len = 0;
    for (let x = v; x > 0n; x >>= 8n) len++;
    let b = bigIntToBytes(v, Math.max(1, len));
    if (b[0]! & 0x80) b = concatBytes(Uint8Array.of(0), b);
    return concatBytes(Uint8Array.of(0x02, b.length), b);
  };
  const body = concatBytes(enc(r), enc(s));
  return concatBytes(Uint8Array.of(0x30, body.length), body);
}
