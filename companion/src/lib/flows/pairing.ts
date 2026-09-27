// Pairing, in two rounds (docs/PROTOCOL.md §4 ripar-pair-req):
//   1. keys only: the device's HOME -> hold 2 s -> release shows a ripar-pair QR with K1, P1 and the firmware id
//      (nothing signed, nothing pinned). The companion learns K1 and derives the canonical vault from it.
//   2. the full pairing request pins chain, registry, DelegationManager, enforcer, sentinel, relay and that vault;
//      the device signs BindDevice(K1, P1) with both keys, which the companion verifies and relays to the registry.
import {
  type BuiltRequest,
  type RiparDeployment,
  ProtoError,
  buildRequest,
  computeVaultAddress,
  decodeRequest,
  pairFieldsFromDeployment,
  parseResponse,
  toChecksumAddress,
  verifyPairing,
} from '@ripar/protocol';
import type { KeysOnly, PairedDevice, PinnedContext } from '../store';

const ZERO = '0x0000000000000000000000000000000000000000';

/** reads a keys-only pairing QR (no req-id, no signatures) */
export function readKeysOnly(ur: string, now = Date.now()): KeysOnly {
  const rep = parseResponse(ur);
  if (rep.type !== 'ripar-pair') throw new ProtoError(`expected the device's pairing QR, got ${rep.type}`);
  const f = rep.fields;
  if (f.reqId || f.p1Signature) throw new ProtoError('this is a signed pairing answer, not the keys-only pairing QR');
  return { k1Address: f.k1Address, p1Key: f.p1Key, keyId: f.keyId, firmwareId: f.firmwareId, emulator: f.emulator, readAt: now };
}

/** accept() filter of the keys-only round: a ripar-pair without a req-id */
export function isKeysOnlyPair(ur: string): boolean {
  try {
    const rep = parseResponse(ur);
    return rep.type === 'ripar-pair' && !rep.fields.reqId;
  } catch {
    return false;
  }
}

export interface PairPlan {
  request: BuiltRequest;
  vault: `0x${string}`;
  pinned: PinnedContext;
}

/**
 * The full pairing request for a device whose K1 is known: the deployment's contracts plus the canonical vault of
 * K1. `floors` raise the device's panic epoch / reopen nonce after a lost context (only sent when > 0).
 */
export function planPairing(
  dep: RiparDeployment,
  k1Address: string,
  opts: { now: number; minEpoch?: bigint | null; reopenNonce?: bigint | null; fragLen?: number },
): PairPlan {
  const vault = computeVaultAddress(k1Address);
  const fields = pairFieldsFromDeployment(dep, {
    vault,
    now: opts.now,
    ...(opts.minEpoch && opts.minEpoch > 0n ? { minEpoch: opts.minEpoch } : {}),
    ...(opts.reopenNonce && opts.reopenNonce > 0n ? { reopenNonce: opts.reopenNonce } : {}),
  });
  const request = buildRequest('pair', fields, { frag: opts.fragLen ?? 70 });
  return { request, vault, pinned: pinnedOf(request) };
}

/** the context a pair request pins (the device pins the firmware DelegationManager when key 4 is absent) */
export function pinnedOf(request: BuiltRequest | { kind: 'pair'; cbor: Uint8Array }): PinnedContext {
  const q = decodeRequest('pair', request.cbor);
  if (q.kind !== 'pair') throw new ProtoError('not a pair request');
  const a = (b: Uint8Array | null) => (b ? toChecksumAddress(b) : (ZERO as `0x${string}`));
  return {
    chainId: Number(q.chainId),
    registry: a(q.registry),
    manager: q.manager ? a(q.manager) : toChecksumAddress('0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3'),
    enforcer: a(q.enforcer),
    sentinel: a(q.sentinel),
    relay: a(q.relay),
    vault: a(q.vault),
  };
}

/** accept() filter of the full round: a ripar-pair echoing this request's req-id */
export function answersRequest(ur: string, request: BuiltRequest): boolean {
  try {
    const rep = parseResponse(ur);
    return 'reqId' in rep.fields && typeof rep.fields.reqId === 'string' && rep.fields.reqId.toLowerCase() === request.reqId.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Verifies the signed pairing (both BindDevice signatures, req-id) and that it is the device whose keys-only QR was
 * read, whose canonical vault the request pinned. Returns the record to store.
 */
export function acceptPairing(pairUr: string, plan: PairPlan, keysOnly: KeysOnly | null, now = Date.now()): PairedDevice {
  const id = verifyPairing(pairUr, plan.request);
  if (keysOnly && id.k1Address !== keysOnly.k1Address) {
    throw new ProtoError(`a different device answered: K1 ${id.k1Address}, expected ${keysOnly.k1Address}`);
  }
  if (keysOnly && id.p1Key.toLowerCase() !== keysOnly.p1Key.toLowerCase()) {
    throw new ProtoError('the P1 key differs from the keys-only pairing QR');
  }
  const vault = computeVaultAddress(id.k1Address);
  if (vault !== plan.vault) throw new ProtoError(`the pinned vault ${plan.vault} is not the canonical vault ${vault} of this K1`);
  return {
    k1Address: id.k1Address,
    p1Key: id.p1Key,
    px: id.px,
    py: id.py,
    keyId: id.keyId,
    firmwareId: id.firmwareId,
    emulator: id.emulator,
    p1Signature: id.p1Signature,
    k1Signature: id.k1Signature,
    bindDigest: id.bindDigest,
    pinned: plan.pinned,
    pairedAt: now,
    requestUr: plan.request.ur,
  };
}
