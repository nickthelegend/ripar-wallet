// Co-sign nonces (ripar-cosign-req key 10). v1.2: the PulseCosignEnforcer accepts each nonce at most once per
// (DelegationManager, mandate) (nonceUsed view), so a companion must never reuse one: signing the same request twice
// with a fresh presence salt must not be able to pay twice. Random 64-bit nonces keep the QR small and make a
// collision negligible; the tracker also refuses repeats it has seen.
import { type IntLike, bytesToBigInt, randomBytes, toInt } from './bytes.js';
import { ProtoError } from './errors.js';

/** a uniformly random non-zero nonce of `bytes` bytes (default 8 = 64 bits; 1..32) from the platform CSPRNG */
export function randomCosignNonce(bytes = 8): bigint {
  if (!Number.isInteger(bytes) || bytes < 1 || bytes > 32) throw new ProtoError('nonce size must be 1..32 bytes');
  for (;;) {
    const n = bytesToBigInt(randomBytes(bytes));
    if (n !== 0n) return n;
  }
}

/**
 * Remembers the nonces handed out / seen per mandate and never returns one twice. Seed it with the nonces already
 * used on-chain (or check candidates with the enforcer's nonceUsed view via `isUsedOnChain`).
 */
export class CosignNonceTracker {
  private readonly used = new Map<string, Set<bigint>>();

  constructor(private readonly bytes = 8) {}

  private set(delegationHash: string): Set<bigint> {
    const k = delegationHash.toLowerCase();
    let s = this.used.get(k);
    if (!s) {
      s = new Set();
      this.used.set(k, s);
    }
    return s;
  }

  /** marks a nonce as used for this mandate (e.g. one read from a HumanCosigned event) */
  markUsed(delegationHash: string, nonce: IntLike): void {
    this.set(delegationHash).add(toInt(nonce));
  }

  has(delegationHash: string, nonce: IntLike): boolean {
    return this.set(delegationHash).has(toInt(nonce));
  }

  /** a fresh random nonce for this mandate, remembered as used */
  next(delegationHash: string): bigint {
    const s = this.set(delegationHash);
    for (;;) {
      const n = randomCosignNonce(this.bytes);
      if (!s.has(n)) {
        s.add(n);
        return n;
      }
    }
  }

  /** like next(), but also skips nonces the chain reports as used (enforcer.nonceUsed(manager, dh, n)) */
  async nextUnused(delegationHash: string, isUsedOnChain: (nonce: bigint) => Promise<boolean>): Promise<bigint> {
    for (;;) {
      const n = this.next(delegationHash);
      if (!(await isUsedOnChain(n))) return n;
    }
  }
}
