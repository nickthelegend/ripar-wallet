// MetaMask delegation-framework v1.3.0 structs for redemption: the signed Delegation the device's mandate produces,
// the permission context (abi.encode(Delegation[]), leaf first), single-call execution data and the
// DelegationManager.redeemDelegations calldata.
import { encodeAbiParameters, encodeFunctionData, encodePacked, decodeAbiParameters } from 'viem';
import { type Address, type BytesLike, type Hex, type IntLike, bytesEqual, toAddr, toBytes, toHex, toInt } from './bytes.js';
import { delegationHash } from './eip712.js';
import { ProtoError } from './errors.js';
import { toChecksumAddress } from './hash.js';
import type { MandateRequest } from './requests.js';

/** framework Caveat {enforcer, terms, args} */
export interface Caveat {
  enforcer: Address;
  terms: Hex;
  /** redemption-time args (the pulse caveat: 0x for AUTO, cosignCaveatArgs(...) for HUMAN) */
  args: Hex;
}

/** framework Delegation {delegate, delegator, authority, caveats, salt, signature} */
export interface Delegation {
  delegate: Address;
  delegator: Address;
  authority: Hex;
  caveats: Caveat[];
  salt: bigint;
  /** 65-byte r‖s‖v by K1 (the HybridDeleGator's EOA owner) */
  signature: Hex;
}

export const CAVEAT_ABI = {
  type: 'tuple',
  components: [
    { name: 'enforcer', type: 'address' },
    { name: 'terms', type: 'bytes' },
    { name: 'args', type: 'bytes' },
  ],
} as const;

export const DELEGATION_ABI = {
  type: 'tuple',
  components: [
    { name: 'delegate', type: 'address' },
    { name: 'delegator', type: 'address' },
    { name: 'authority', type: 'bytes32' },
    { name: 'caveats', type: 'tuple[]', components: CAVEAT_ABI.components },
    { name: 'salt', type: 'uint256' },
    { name: 'signature', type: 'bytes' },
  ],
} as const;

/** DelegationManager.redeemDelegations(bytes[] permissionContexts, bytes32[] modes, bytes[] executionCallDatas) */
export const REDEEM_DELEGATIONS_ABI = [
  {
    type: 'function',
    name: 'redeemDelegations',
    stateMutability: 'nonpayable',
    inputs: [
      { name: '_permissionContexts', type: 'bytes[]' },
      { name: '_modes', type: 'bytes32[]' },
      { name: '_executionCallDatas', type: 'bytes[]' },
    ],
    outputs: [],
  },
] as const;

/** ERC-7579 ModeCode of a single call with the default exec type (CALLTYPE_SINGLE 0x00, EXECTYPE_DEFAULT 0x00) */
export const SINGLE_DEFAULT_MODE: Hex = `0x${'00'.repeat(32)}`;

/**
 * The signed Delegation of a mandate: the request's fields (as the device signed them) + the eth-signature (r‖s‖v).
 * Caveat args start empty; set the pulse caveat's args per redemption (withCaveatArgs).
 */
export function signedDelegation(mandate: MandateRequest, signature: BytesLike): Delegation {
  const sig = toBytes(signature, 65, 'signature');
  return {
    delegate: toChecksumAddress(mandate.delegate),
    delegator: toChecksumAddress(mandate.delegator),
    authority: toHex(mandate.authority),
    caveats: mandate.caveats.map((c) => ({ enforcer: toChecksumAddress(c.enforcer), terms: toHex(c.terms), args: '0x' })),
    salt: mandate.salt,
    signature: toHex(sig),
  };
}

/** hashStruct(Delegation) of a framework Delegation (args and signature are not part of it) */
export function hashDelegation(d: Pick<Delegation, 'delegate' | 'delegator' | 'authority' | 'caveats' | 'salt'>): Hex {
  return toHex(delegationHash(d));
}

/**
 * A copy of the delegation with the args of every caveat whose enforcer is `enforcer` replaced (e.g. the
 * PulseCosignEnforcer: '0x' = AUTO path, 160-byte co-sign args = HUMAN path). Throws when no caveat matches.
 */
export function withCaveatArgs(d: Delegation, enforcer: BytesLike, args: BytesLike): Delegation {
  const e = toAddr(enforcer, 'enforcer');
  let hit = 0;
  const caveats = d.caveats.map((c) => {
    if (!bytesEqual(toAddr(c.enforcer), e)) return { ...c };
    hit++;
    return { ...c, args: toHex(toBytes(args, null, 'args')) };
  });
  if (!hit) throw new ProtoError('no caveat uses that enforcer');
  return { ...d, caveats };
}

/** abi.encode(Delegation[]): the permission context of redeemDelegations (leaf delegation first, root last) */
export function encodePermissionContext(delegations: readonly Delegation[]): Hex {
  return encodeAbiParameters(
    [{ type: 'tuple[]', components: DELEGATION_ABI.components }],
    [
      delegations.map((d) => ({
        delegate: d.delegate,
        delegator: d.delegator,
        authority: d.authority,
        caveats: d.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: c.args })),
        salt: d.salt,
        signature: d.signature,
      })),
    ],
  );
}

/** inverse of encodePermissionContext */
export function decodePermissionContext(ctx: Hex): Delegation[] {
  const [arr] = decodeAbiParameters([{ type: 'tuple[]', components: DELEGATION_ABI.components }], ctx);
  return arr.map((d) => ({
    delegate: d.delegate,
    delegator: d.delegator,
    authority: d.authority,
    caveats: d.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms, args: c.args })),
    salt: d.salt,
    signature: d.signature,
  }));
}

/** ERC-7579 ExecutionLib.encodeSingle: abi.encodePacked(target, value, callData) */
export function encodeSingleExecution(target: BytesLike, value: IntLike, callData: BytesLike): Hex {
  return encodePacked(
    ['address', 'uint256', 'bytes'],
    [toChecksumAddress(toAddr(target, 'target')), toInt(value), toHex(toBytes(callData, null, 'callData'))],
  );
}

export interface Redemption {
  /** leaf first */
  delegations: readonly Delegation[];
  target: BytesLike;
  value: IntLike;
  callData: BytesLike;
}

/** calldata of DelegationManager.redeemDelegations for single-call redemptions (default mode) */
export function encodeRedeemDelegations(redemptions: readonly Redemption[]): Hex {
  return encodeFunctionData({
    abi: REDEEM_DELEGATIONS_ABI,
    functionName: 'redeemDelegations',
    args: [
      redemptions.map((r) => encodePermissionContext(r.delegations)),
      redemptions.map(() => SINGLE_DEFAULT_MODE),
      redemptions.map((r) => encodeSingleExecution(r.target, r.value, r.callData)),
    ],
  });
}
