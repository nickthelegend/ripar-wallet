import { sha256 as nobleSha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { type Address, type BytesLike, h, toBytes, utf8 } from './bytes.js';
import { ProtoError } from './errors.js';

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

/** EIP-55 mixed-case checksum form of a 20-byte address (hex with or without 0x, or bytes). */
export function toChecksumAddress(addr: BytesLike): Address {
  const b = toBytes(addr, 20, 'address');
  const lower = h(b);
  const hash = h(keccak256(utf8.encode(lower)));
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    const c = lower[i]!;
    out += parseInt(hash[i]!, 16) >= 8 ? c.toUpperCase() : c;
  }
  return out as Address;
}

/**
 * true when `s` is a 0x address whose letters are either all one case or a correct EIP-55 checksum
 * (the rule viem / ethers apply to user-typed addresses).
 */
export function isValidAddress(s: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) return false;
  const body = s.slice(2);
  if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
  try {
    return toChecksumAddress(s) === s;
  } catch {
    return false;
  }
}

/** parses a user-typed address strictly (bad EIP-55 checksum -> ProtoError) and returns its bytes */
export function parseAddress(s: string, what = 'address'): Uint8Array {
  if (!isValidAddress(s)) throw new ProtoError(`${what}: not a valid address (or bad EIP-55 checksum): ${s}`);
  return toBytes(s, 20, what);
}

/** Ethereum address of an uncompressed secp256k1 public key given as x‖y (64 bytes) */
export function ethAddressOfXY(xy: Uint8Array): Uint8Array {
  if (xy.length !== 64) throw new ProtoError('public key must be x||y (64 bytes)');
  return keccak256(xy).slice(12);
}

/** keyId of a device P1 key as the contracts compute it: keccak256(abi.encode(bytes32 px, bytes32 py)) */
export function keyIdOf(p1Key: BytesLike): Uint8Array {
  return keccak256(toBytes(p1Key, 64, 'p1Key'));
}
