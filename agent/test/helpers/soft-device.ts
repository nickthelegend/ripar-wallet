// TEST-ONLY software stand-in for a Ripar device with RANDOM keys generated per test (never real keys): it signs
// mandates with K1 (secp256k1) and co-signs / denies with P1 (P-256), low-s, exactly the digests the device signs.
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  DELEGATION_MANAGER,
  ROOT_AUTHORITY,
  cborEncode,
  computeVaultAddress,
  cosignDigest,
  denyDigest,
  encodePulseTerms,
  mandateDigest,
  presenceHash,
  toChecksumAddress,
  toHex,
  urSingle,
  type CborValue,
  type Delegation,
} from '@ripar/protocol';
import type { Address, Hex } from 'viem';
import { privateKeyToAddress } from 'viem/accounts';
import type { CosignRequestJson, Escalation } from '../../src/types.js';

const be32 = (x: bigint): Uint8Array => Uint8Array.from(Buffer.from(x.toString(16).padStart(64, '0'), 'hex'));
const hexb = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));

export interface SoftDevice {
  k1: Address;
  vault: Address;
  p1Key: Hex;
  px: Hex;
  py: Hex;
  signK1(digest: Uint8Array): Uint8Array;
  signP1(digest: Uint8Array): Uint8Array;
}

export function newSoftDevice(): SoftDevice {
  const k1Priv = secp256k1.utils.randomPrivateKey();
  const p1Priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(p1Priv, false);
  const k1 = privateKeyToAddress(toHex(k1Priv));
  return {
    k1,
    vault: computeVaultAddress(k1),
    p1Key: toHex(pub.subarray(1)),
    px: toHex(pub.subarray(1, 33)),
    py: toHex(pub.subarray(33)),
    signK1(digest) {
      const s = secp256k1.sign(digest, k1Priv, { lowS: true, prehash: false });
      const out = new Uint8Array(65);
      out.set(be32(s.r), 0);
      out.set(be32(s.s), 32);
      out[64] = 27 + (s.recovery ?? 0);
      return out;
    },
    signP1(digest) {
      const s = p256.sign(digest, p1Priv, { lowS: true, prehash: false });
      const out = new Uint8Array(64);
      out.set(be32(s.r), 0);
      out.set(be32(s.s), 32);
      return out;
    },
  };
}

export interface PulseOpts {
  enforcer: Address;
  token: Address;
  perTxAutoCap: bigint;
  periodAutoCap: bigint;
  period: number;
  epoch?: number;
  newPayeeNeedsHuman?: boolean;
  sentinel: Address;
}

/** a signed root mandate from the device's vault to `agent` with one pulse caveat (+ extra caveats) */
export function signMandate(
  dev: SoftDevice,
  o: { chainId: number; agent: Address; pulse: PulseOpts; extra?: { enforcer: Address; terms: Hex }[]; salt?: bigint; delegator?: Address },
): Delegation {
  const terms = toHex(
    encodePulseTerms({
      px: dev.px,
      py: dev.py,
      token: o.pulse.token,
      perTxAutoCap: o.pulse.perTxAutoCap,
      periodAutoCap: o.pulse.periodAutoCap,
      period: o.pulse.period,
      epoch: o.pulse.epoch ?? 0,
      newPayeeNeedsHuman: o.pulse.newPayeeNeedsHuman ?? true,
      sentinel: o.pulse.sentinel,
    }),
  );
  const d: Delegation = {
    delegate: toChecksumAddress(o.agent),
    delegator: o.delegator ?? dev.vault,
    authority: toHex(ROOT_AUTHORITY),
    caveats: [{ enforcer: o.pulse.enforcer, terms, args: '0x' }, ...(o.extra ?? []).map((c) => ({ ...c, args: '0x' as Hex }))],
    salt: o.salt ?? 1n,
    signature: '0x',
  };
  d.signature = toHex(dev.signK1(mandateDigest(o.chainId, DELEGATION_MANAGER, d)));
  return d;
}

export function delegationJson(d: Delegation): Record<string, unknown> {
  return { ...d, caveats: d.caveats.map((c) => ({ ...c })), salt: d.salt.toString() };
}

export const DEMO_EVIDENCE = Uint8Array.from([1, 72, 9, 0x01, 0xd4, 0xc0, 0x01, 0x5f, 0x90, 42, 0x03, 0x20]);

/** the device's co-sign of an escalation: {evidence12, salt16, r, s, rs} and the ripar-cosign UR */
export function cosignEscalation(dev: SoftDevice, c: CosignRequestJson, reqId: Hex, salt?: Uint8Array) {
  const salt16 = salt ?? p256.utils.randomPrivateKey().subarray(0, 16);
  const ph = presenceHash(DEMO_EVIDENCE, salt16);
  const digest = cosignDigest(
    {
      chainId: c.chainId,
      enforcer: c.enforcer,
      delegationHash: c.delegationHash,
      delegator: c.delegator,
      redeemer: c.redeemer,
      target: c.target,
      value: BigInt(c.value),
      calldata: c.calldata,
      nonce: BigInt(c.nonce),
      expiry: c.expiry,
    },
    ph,
  );
  const rs = dev.signP1(digest);
  const map = new Map<number, CborValue>([
    [1, hexb(reqId)],
    [2, rs],
    [3, DEMO_EVIDENCE],
    [4, salt16],
  ]);
  return {
    evidence12: toHex(DEMO_EVIDENCE),
    salt16: toHex(salt16),
    r: toHex(rs.subarray(0, 32)),
    s: toHex(rs.subarray(32)),
    rs: toHex(rs),
    ur: urSingle('ripar-cosign', cborEncode(map)),
    digest: toHex(digest),
  };
}

/** a device deny from the co-sign review of an escalation (evidence all zero, as the device does) */
export function denyEscalation(dev: SoftDevice, e: Escalation, relay: Address, agentId: bigint): string {
  const ev = new Uint8Array(12);
  const salt16 = p256.utils.randomPrivateKey().subarray(0, 16);
  const ph = presenceHash(ev, salt16);
  const rs = dev.signP1(denyDigest(e.cosign.chainId, relay, agentId, e.requestHash, ph));
  const map = new Map<number, CborValue>([
    [1, hexb(e.request.reqId)],
    [2, rs],
    [3, ev],
    [4, salt16],
    [5, agentId],
    [6, hexb(e.requestHash)],
  ]);
  return urSingle('ripar-deny', cborEncode(map));
}
