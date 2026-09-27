// EIP-712 digests of every Ripar message (docs/PROTOCOL.md §3), hand-written from the exact type strings, plus
// viem-compatible typed-data descriptions (tests prove viem's hashTypedData gives the same digests).
import {
  type BytesLike,
  type Hex,
  type IntLike,
  MAX256,
  MAX64,
  addrWord,
  concatBytes,
  toAddr,
  toBytes,
  toHex,
  toInt,
  utf8,
  word,
} from './bytes.js';
import { ProtoError } from './errors.js';
import { keccak256, sha256, toChecksumAddress } from './hash.js';

export const DOMAIN_TYPE = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)';

/** The struct type strings exactly as hashed (docs/PROTOCOL.md §3, contracts/SPEC.md). */
export const TYPE_STRINGS = {
  Delegation:
    'Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)' +
    'Caveat(address enforcer,bytes terms)',
  Caveat: 'Caveat(address enforcer,bytes terms)',
  HumanApproval:
    'HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,' +
    'bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)',
  Revoke: 'Revoke(bytes32 delegationHash)',
  Panic: 'Panic(uint64 minEpoch)',
  Reopen: 'Reopen(address vault,uint256 nonce)',
  Deny: 'Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)',
  BindDevice: 'BindDevice(address owner,bytes32 px,bytes32 py)',
} as const;
export type StructName = keyof typeof TYPE_STRINGS;

export function typeHash(name: StructName): Uint8Array {
  return keccak256(utf8.encode(TYPE_STRINGS[name]));
}

/** Domain names (version is always "1"); the verifyingContract is the contract pinned at pairing. */
export const DOMAIN_NAMES = {
  delegationManager: 'DelegationManager',
  enforcer: 'RiparPulseCosign',
  registry: 'RiparDeviceRegistry',
  sentinel: 'RiparSentinel',
  relay: 'RiparReputationRelay',
} as const;
export type DomainName = (typeof DOMAIN_NAMES)[keyof typeof DOMAIN_NAMES];

/** make_request DOMAIN_OF: the domain of each message kind */
export const DOMAIN_OF = {
  pair: 'RiparDeviceRegistry',
  cosign: 'RiparPulseCosign',
  mandate: 'DelegationManager',
  deny: 'RiparReputationRelay',
  revoke: 'RiparPulseCosign',
  panic: 'RiparPulseCosign',
  reopen: 'RiparSentinel',
} as const satisfies Record<string, DomainName>;

/** ROOT_AUTHORITY = 32 bytes of 0xff (the device refuses any other authority) */
export const ROOT_AUTHORITY = new Uint8Array(32).fill(0xff);

function uintWord(v: IntLike, bits: number, what: string): Uint8Array {
  const x = toInt(v);
  const max = bits === 256 ? MAX256 : bits === 64 ? MAX64 : (1n << BigInt(bits)) - 1n;
  if (x < 0n || x > max) throw new ProtoError(`${what}: out of range for uint${bits}`);
  return word(x);
}

function b32(v: BytesLike, what: string): Uint8Array {
  return toBytes(v, 32, what);
}

/** hashStruct(EIP712Domain{name, "1", chainId, verifyingContract}) */
export function domainSeparator(name: string, chainId: IntLike, verifyingContract: BytesLike): Uint8Array {
  return keccak256(
    concatBytes(
      keccak256(utf8.encode(DOMAIN_TYPE)),
      keccak256(utf8.encode(name)),
      keccak256(utf8.encode('1')),
      uintWord(chainId, 256, 'chainId'),
      addrWord(toAddr(verifyingContract, 'verifyingContract')),
    ),
  );
}

/** keccak256(0x19 0x01 ‖ domainSeparator ‖ structHash) */
export function digestFrom(domainSep: Uint8Array, structHash: Uint8Array): Uint8Array {
  return keccak256(concatBytes(Uint8Array.of(0x19, 0x01), domainSep, structHash));
}

// ---------------------------------------------------------------------------------------------- structs
export interface CaveatLike {
  enforcer: BytesLike;
  terms: BytesLike;
}

/** EncoderLib._getCaveatPacketHash = hashStruct(Caveat) */
export function caveatHash(enforcer: BytesLike, terms: BytesLike): Uint8Array {
  return keccak256(
    concatBytes(typeHash('Caveat'), addrWord(toAddr(enforcer, 'caveat.enforcer')), keccak256(toBytes(terms, null, 'caveat.terms'))),
  );
}

export interface DelegationFields {
  delegate: BytesLike;
  delegator: BytesLike;
  authority: BytesLike;
  caveats: readonly CaveatLike[];
  salt: IntLike;
}

/**
 * hashStruct(Delegation) = MetaMask EncoderLib._getDelegationHash: the delegation hash the enforcer sees, what
 * `ripar-revoke` revokes and what a co-sign names (key 4).
 */
export function delegationHash(d: DelegationFields): Uint8Array {
  const arr = keccak256(concatBytes(...d.caveats.map((c) => caveatHash(c.enforcer, c.terms))));
  return keccak256(
    concatBytes(
      typeHash('Delegation'),
      addrWord(toAddr(d.delegate, 'delegate')),
      addrWord(toAddr(d.delegator, 'delegator')),
      b32(d.authority, 'authority'),
      arr,
      uintWord(d.salt, 256, 'salt'),
    ),
  );
}

export interface HumanApprovalFields {
  delegationHash: BytesLike;
  delegator: BytesLike;
  redeemer: BytesLike;
  target: BytesLike;
  value: IntLike;
  /** keccak256(calldata) */
  callDataHash: BytesLike;
  nonce: IntLike;
  expiry: IntLike;
  presenceHash: BytesLike;
}

export function humanApprovalHash(f: HumanApprovalFields): Uint8Array {
  return keccak256(
    concatBytes(
      typeHash('HumanApproval'),
      b32(f.delegationHash, 'delegationHash'),
      addrWord(toAddr(f.delegator, 'delegator')),
      addrWord(toAddr(f.redeemer, 'redeemer')),
      addrWord(toAddr(f.target, 'target')),
      uintWord(f.value, 256, 'value'),
      b32(f.callDataHash, 'callDataHash'),
      uintWord(f.nonce, 256, 'nonce'),
      uintWord(f.expiry, 64, 'expiry'),
      b32(f.presenceHash, 'presenceHash'),
    ),
  );
}

export function revokeHash(dh: BytesLike): Uint8Array {
  return keccak256(concatBytes(typeHash('Revoke'), b32(dh, 'delegationHash')));
}

export function panicHash(minEpoch: IntLike): Uint8Array {
  return keccak256(concatBytes(typeHash('Panic'), uintWord(minEpoch, 64, 'minEpoch')));
}

export function reopenHash(vault: BytesLike, nonce: IntLike): Uint8Array {
  return keccak256(concatBytes(typeHash('Reopen'), addrWord(toAddr(vault, 'vault')), uintWord(nonce, 256, 'nonce')));
}

export function denyHash(agentId: IntLike, requestHash: BytesLike, presenceHash: BytesLike): Uint8Array {
  return keccak256(
    concatBytes(typeHash('Deny'), uintWord(agentId, 256, 'agentId'), b32(requestHash, 'requestHash'), b32(presenceHash, 'presenceHash')),
  );
}

export function bindDeviceHash(owner: BytesLike, p1Key: BytesLike): Uint8Array {
  const xy = toBytes(p1Key, 64, 'p1Key');
  return keccak256(concatBytes(typeHash('BindDevice'), addrWord(toAddr(owner, 'owner')), xy.subarray(0, 32), xy.subarray(32)));
}

// ---------------------------------------------------------------------------------------------- digests
/** presenceHash = sha256(evidence12 ‖ salt16) (SHA-256, not keccak) */
export function presenceHash(evidence12: BytesLike, salt16: BytesLike): Uint8Array {
  return sha256(concatBytes(toBytes(evidence12, 12, 'evidence12'), toBytes(salt16, 16, 'salt16')));
}

/** BindDevice(owner = K1, px, py) in the RiparDeviceRegistry domain (make_request pair_digest) */
export function pairDigest(chainId: IntLike, registry: BytesLike, k1Address: BytesLike, p1Key: BytesLike): Uint8Array {
  return digestFrom(domainSeparator(DOMAIN_OF.pair, chainId, registry), bindDeviceHash(k1Address, p1Key));
}

/** the parts of a co-sign request the HumanApproval hash covers */
export interface CosignDigestInput {
  chainId: IntLike;
  enforcer: BytesLike;
  delegationHash: BytesLike;
  delegator: BytesLike;
  redeemer: BytesLike;
  target: BytesLike;
  value: IntLike;
  calldata: BytesLike;
  nonce: IntLike;
  expiry: IntLike;
}

function approvalFields(q: CosignDigestInput, presence: BytesLike): HumanApprovalFields {
  return {
    delegationHash: q.delegationHash,
    delegator: q.delegator,
    redeemer: q.redeemer,
    target: q.target,
    value: q.value,
    callDataHash: keccak256(toBytes(q.calldata, null, 'calldata')),
    nonce: q.nonce,
    expiry: q.expiry,
    presenceHash: presence,
  };
}

/** HumanApproval digest in the RiparPulseCosign domain (make_request cosign_digest); what P1 signs */
export function cosignDigest(q: CosignDigestInput, presence: BytesLike): Uint8Array {
  return digestFrom(domainSeparator(DOMAIN_OF.cosign, q.chainId, q.enforcer), humanApprovalHash(approvalFields(q, presence)));
}

/** requestHash of a deny from a co-sign review: hashStruct(HumanApproval) with presenceHash = 0 */
export function cosignRequestHash(q: CosignDigestInput): Uint8Array {
  return humanApprovalHash(approvalFields(q, new Uint8Array(32)));
}

/** Delegation digest in the DelegationManager domain (make_request mandate_digest); what K1 signs */
export function mandateDigest(chainId: IntLike, manager: BytesLike, d: DelegationFields): Uint8Array {
  return digestFrom(domainSeparator(DOMAIN_OF.mandate, chainId, manager), delegationHash(d));
}

/** Deny digest in the RiparReputationRelay domain (make_request deny_digest) */
export function denyDigest(chainId: IntLike, relay: BytesLike, agentId: IntLike, requestHash: BytesLike, presence: BytesLike): Uint8Array {
  return digestFrom(domainSeparator(DOMAIN_OF.deny, chainId, relay), denyHash(agentId, requestHash, presence));
}

export function revokeDigest(chainId: IntLike, enforcer: BytesLike, dh: BytesLike): Uint8Array {
  return digestFrom(domainSeparator(DOMAIN_OF.revoke, chainId, enforcer), revokeHash(dh));
}

export function panicDigest(chainId: IntLike, enforcer: BytesLike, minEpoch: IntLike): Uint8Array {
  return digestFrom(domainSeparator(DOMAIN_OF.panic, chainId, enforcer), panicHash(minEpoch));
}

export function reopenDigest(chainId: IntLike, sentinel: BytesLike, vault: BytesLike, nonce: IntLike): Uint8Array {
  return digestFrom(domainSeparator(DOMAIN_OF.reopen, chainId, sentinel), reopenHash(vault, nonce));
}

// ---------------------------------------------------------------------------------------------- viem typed data
/** EIP-712 types in viem's format (for hashTypedData / signTypedData / wallet display) */
export const EIP712_TYPES = {
  Delegation: [
    { name: 'delegate', type: 'address' },
    { name: 'delegator', type: 'address' },
    { name: 'authority', type: 'bytes32' },
    { name: 'caveats', type: 'Caveat[]' },
    { name: 'salt', type: 'uint256' },
  ],
  Caveat: [
    { name: 'enforcer', type: 'address' },
    { name: 'terms', type: 'bytes' },
  ],
  HumanApproval: [
    { name: 'delegationHash', type: 'bytes32' },
    { name: 'delegator', type: 'address' },
    { name: 'redeemer', type: 'address' },
    { name: 'target', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'callDataHash', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'expiry', type: 'uint64' },
    { name: 'presenceHash', type: 'bytes32' },
  ],
  Revoke: [{ name: 'delegationHash', type: 'bytes32' }],
  Panic: [{ name: 'minEpoch', type: 'uint64' }],
  Reopen: [
    { name: 'vault', type: 'address' },
    { name: 'nonce', type: 'uint256' },
  ],
  Deny: [
    { name: 'agentId', type: 'uint256' },
    { name: 'requestHash', type: 'bytes32' },
    { name: 'presenceHash', type: 'bytes32' },
  ],
  BindDevice: [
    { name: 'owner', type: 'address' },
    { name: 'px', type: 'bytes32' },
    { name: 'py', type: 'bytes32' },
  ],
} as const;

export interface TypedDataDomain {
  name: string;
  version: '1';
  chainId: bigint;
  verifyingContract: Hex;
}

/** viem TypedDataDefinition-compatible object: pass it to hashTypedData / signTypedData */
export interface RiparTypedData {
  domain: TypedDataDomain;
  types: Record<string, readonly { name: string; type: string }[]>;
  primaryType: StructName;
  message: Record<string, unknown>;
}

export function typedDataDomain(name: DomainName, chainId: IntLike, contract: BytesLike): TypedDataDomain {
  return { name, version: '1', chainId: toInt(chainId), verifyingContract: toChecksumAddress(toAddr(contract, 'verifyingContract')) };
}

function td(primaryType: StructName, domain: TypedDataDomain, message: Record<string, unknown>): RiparTypedData {
  const types: Record<string, readonly { name: string; type: string }[]> = { [primaryType]: EIP712_TYPES[primaryType] };
  if (primaryType === 'Delegation') types.Caveat = EIP712_TYPES.Caveat;
  return { domain, types, primaryType, message };
}

const hx = (b: BytesLike, n: number | null, what: string): Hex => toHex(toBytes(b, n, what));
const ad = (b: BytesLike, what: string): Hex => toChecksumAddress(toAddr(b, what));

export function typedDataDelegation(chainId: IntLike, manager: BytesLike, d: DelegationFields): RiparTypedData {
  return td('Delegation', typedDataDomain('DelegationManager', chainId, manager), {
    delegate: ad(d.delegate, 'delegate'),
    delegator: ad(d.delegator, 'delegator'),
    authority: hx(d.authority, 32, 'authority'),
    caveats: d.caveats.map((c) => ({ enforcer: ad(c.enforcer, 'caveat.enforcer'), terms: hx(c.terms, null, 'caveat.terms') })),
    salt: toInt(d.salt),
  });
}

export function typedDataHumanApproval(q: CosignDigestInput, presence: BytesLike): RiparTypedData {
  return td('HumanApproval', typedDataDomain('RiparPulseCosign', q.chainId, q.enforcer), {
    delegationHash: hx(q.delegationHash, 32, 'delegationHash'),
    delegator: ad(q.delegator, 'delegator'),
    redeemer: ad(q.redeemer, 'redeemer'),
    target: ad(q.target, 'target'),
    value: toInt(q.value),
    callDataHash: toHex(keccak256(toBytes(q.calldata, null, 'calldata'))),
    nonce: toInt(q.nonce),
    expiry: toInt(q.expiry),
    presenceHash: hx(presence, 32, 'presenceHash'),
  });
}

export function typedDataRevoke(chainId: IntLike, enforcer: BytesLike, dh: BytesLike): RiparTypedData {
  return td('Revoke', typedDataDomain('RiparPulseCosign', chainId, enforcer), { delegationHash: hx(dh, 32, 'delegationHash') });
}

export function typedDataPanic(chainId: IntLike, enforcer: BytesLike, minEpoch: IntLike): RiparTypedData {
  return td('Panic', typedDataDomain('RiparPulseCosign', chainId, enforcer), { minEpoch: toInt(minEpoch) });
}

export function typedDataReopen(chainId: IntLike, sentinel: BytesLike, vault: BytesLike, nonce: IntLike): RiparTypedData {
  return td('Reopen', typedDataDomain('RiparSentinel', chainId, sentinel), { vault: ad(vault, 'vault'), nonce: toInt(nonce) });
}

export function typedDataDeny(chainId: IntLike, relay: BytesLike, agentId: IntLike, requestHash: BytesLike, presence: BytesLike): RiparTypedData {
  return td('Deny', typedDataDomain('RiparReputationRelay', chainId, relay), {
    agentId: toInt(agentId),
    requestHash: hx(requestHash, 32, 'requestHash'),
    presenceHash: hx(presence, 32, 'presenceHash'),
  });
}

export function typedDataBindDevice(chainId: IntLike, registry: BytesLike, owner: BytesLike, p1Key: BytesLike): RiparTypedData {
  const xy = toBytes(p1Key, 64, 'p1Key');
  return td('BindDevice', typedDataDomain('RiparDeviceRegistry', chainId, registry), {
    owner: ad(owner, 'owner'),
    px: toHex(xy.subarray(0, 32)),
    py: toHex(xy.subarray(32)),
  });
}
