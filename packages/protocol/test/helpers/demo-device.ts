// A TEST-ONLY software stand-in for the device: make_request.py's demo device (DEMO_SEED = sha256("ripar demo seed"),
// a PUBLIC seed whose keys are listed in contracts/test/vectors/device_vectors.json). It signs exactly like
// make_request simulate() (RFC 6979 + low-s), so its responses are byte-identical to the Python ones. Never ship it.
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  type CborValue,
  type RequestKind,
  ROOT_AUTHORITY,
  bytesEqual,
  cborEncode,
  cosignDigest,
  cosignRequestHash,
  decodeRequest,
  denyDigest,
  derEncode,
  mandateDigest,
  pairDigest,
  panicDigest,
  presenceHash,
  privyParse,
  reopenDigest,
  revokeDigest,
  sha256,
  tokenCheck,
  u256Min,
} from '../../src/index.js';
import { hexToBytes } from './env.js';

export const DEMO_K1_PRIV = '834f049d9693a923ccf9de63189a7564f954dfdc1666145bdd375dd7d9d0e655';
export const DEMO_P1_PRIV = 'e00be7b300b675b89142035e110bc529936715a1ffa43355fb89c7af1f402423';
export const DEMO_K1 = '0x753454832754c071704be47915d4DeC6339624Eb';
export const DEMO_P1 =
  '0x5cbcd94e72c801fc1b1167ef6f648a5b998d41819020703610637bca5d182765b8f1fb687dc1ceb07f52f98cf80292b23d7583879c75689c4cf35393b67bd954';
/** the canonical vault of the demo K1 (contracts/.work/vault-derivation.md) */
export const DEMO_VAULT = '0xc36F625D426eBa8f1e0129276B284a939CD3A57D';

const be32 = (x: bigint): Uint8Array => hexToBytes(x.toString(16).padStart(64, '0'));

export function signP1(digest: Uint8Array): Uint8Array {
  const s = p256.sign(digest, DEMO_P1_PRIV, { lowS: true, prehash: false });
  const out = new Uint8Array(64);
  out.set(be32(s.r), 0);
  out.set(be32(s.s), 32);
  return out;
}

export function signK1(digest: Uint8Array): Uint8Array {
  const s = secp256k1.sign(digest, DEMO_K1_PRIV, { lowS: true, prehash: false });
  const out = new Uint8Array(65);
  out.set(be32(s.r), 0);
  out.set(be32(s.s), 32);
  out[64] = 27 + (s.recovery ?? 0);
  return out;
}

/** make_request demo_evidence(bpm): version 1, bpm, 9 beats, IR 120000, red 90000, jitter 42, 8000 ms */
export function demoEvidence(bpm = 72): Uint8Array {
  return Uint8Array.from([1, bpm, 9, 0x01, 0xd4, 0xc0, 0x01, 0x5f, 0x90, 42, 0x03, 0x20]);
}

const m = (entries: [number, CborValue][]): Map<number, CborValue> => new Map(entries);

/** make_request simulate(): the response CBOR the demo device builds for a request */
export function simulate(
  kind: RequestKind,
  cbor: Uint8Array,
  opt: { ev12?: Uint8Array; salt16?: Uint8Array; fwid?: Uint8Array } = {},
): Uint8Array {
  const ev = opt.ev12 ?? demoEvidence();
  const salt = opt.salt16 ?? new Uint8Array(16);
  const q = decodeRequest(kind, cbor);
  const k1 = hexToBytes(DEMO_K1);
  const p1 = hexToBytes(DEMO_P1);
  switch (q.kind) {
    case 'pair': {
      const fwid = opt.fwid ?? sha256(new TextEncoder().encode('ripar demo firmware')).slice(0, 8);
      const d = pairDigest(q.chainId, q.registry, k1, p1);
      return cborEncode(m([[1, q.reqId], [2, k1], [3, p1], [4, signP1(d)], [5, signK1(d)], [6, fwid]]));
    }
    case 'cosign': {
      tokenCheck(q);
      const rs = signP1(cosignDigest(q, presenceHash(ev, salt)));
      return cborEncode(m([[1, q.reqId], [2, rs], [3, ev], [4, salt]]));
    }
    case 'mandate': {
      if (!bytesEqual(q.authority, ROOT_AUTHORITY)) throw new Error('device refuses non-ROOT authority');
      return cborEncode(m([[1, q.reqId], [2, signK1(mandateDigest(q.chainId, q.manager, q))]]));
    }
    case 'deny': {
      const rs = signP1(denyDigest(q.chainId, q.relay, q.agentId, q.requestHash, presenceHash(ev, salt)));
      return cborEncode(m([[1, q.reqId], [2, rs], [3, ev], [4, salt], [5, q.agentId], [6, q.requestHash]]));
    }
    case 'privy': {
      privyParse(q.json);
      const s = p256.sign(sha256(q.json), DEMO_P1_PRIV, { lowS: true, prehash: false });
      return cborEncode(m([[1, q.reqId], [2, derEncode(s.r, s.s)]]));
    }
  }
}

/** make_request simulate_deny_from_cosign */
export function simulateDenyFromCosign(
  cosignCbor: Uint8Array,
  chainId: bigint,
  relay: Uint8Array,
  agentId: bigint,
  salt16: Uint8Array,
  ev12: Uint8Array = new Uint8Array(12),
): Uint8Array {
  const q = decodeRequest('cosign', cosignCbor);
  if (q.kind !== 'cosign') throw new Error('not a cosign');
  const rh = cosignRequestHash(q);
  const rs = signP1(denyDigest(chainId, relay, agentId, rh, presenceHash(ev12, salt16)));
  return cborEncode(m([[1, q.reqId], [2, rs], [3, ev12], [4, salt16], [5, agentId], [6, rh]]));
}

export function revokeResponse(chainId: bigint, enforcer: Uint8Array, dh: Uint8Array): Uint8Array {
  return cborEncode(m([[1, dh], [2, signP1(revokeDigest(chainId, enforcer, dh))]]));
}

export function panicResponse(chainId: bigint, enforcer: Uint8Array, minEpoch: bigint): Uint8Array {
  return cborEncode(m([[1, minEpoch], [2, signP1(panicDigest(chainId, enforcer, minEpoch))]]));
}

export function reopenResponse(chainId: bigint, sentinel: Uint8Array, vault: Uint8Array, nonce: bigint): Uint8Array {
  return cborEncode(m([[1, vault], [2, u256Min(nonce)], [3, signP1(reopenDigest(chainId, sentinel, vault, nonce))]]));
}
