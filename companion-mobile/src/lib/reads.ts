// Ported from companion/src/lib/reads.ts.
// On-chain reads (no wallet). Each returns plain data for a screen; a failed read is reported, never guessed.
import { type Address, type Hex, type PublicClient, getAddress } from 'viem';
import {
  type AutoBudget,
  type RiparDeployment,
  DELEGATION_MANAGER,
  DELEGATION_MANAGER_ABI,
  ERC173_OWNER_ABI,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_DEVICE_REGISTRY_ABI,
  RIPAR_SENTINEL_ABI,
} from '@ripar/protocol';
import { MOCK_USD_ABI } from './chain';

const ZERO = '0x0000000000000000000000000000000000000000';
const ZERO32 = `0x${'00'.repeat(32)}` as Hex;

async function settle<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch {
    return null;
  }
}

export interface CodeCheck {
  name: string;
  address: Address;
  bytes: number | null;
}

/** getCode size of each contract the companion relies on (0 = nothing deployed at that address on this RPC) */
export async function checkContracts(pc: PublicClient, dep: RiparDeployment): Promise<CodeCheck[]> {
  const list: [string, Address][] = [
    ['RiparDeviceRegistry', dep.registry],
    ['PulseCosignEnforcer', dep.enforcer],
    ['RiparSentinel', dep.sentinel],
    ['RiparReputationRelay', dep.relay],
    ['DelegationManager', dep.delegationManager],
  ];
  if (!/^0x0{40}$/i.test(dep.mockUsd)) list.push(['MockUSD', dep.mockUsd]);
  return Promise.all(
    list.map(async ([name, address]) => {
      const code = await settle(pc.getCode({ address }));
      return { name, address, bytes: code === null ? null : code ? (code.length - 2) / 2 : 0 };
    }),
  );
}

export interface DeviceStatus {
  /** registry.keyOf(keyId).owner; null = not registered (or unreadable, see `readable`) */
  registeredOwner: Address | null;
  readable: boolean;
  retired: boolean | null;
  minEpoch: bigint | null;
}

export async function readDeviceStatus(pc: PublicClient, dep: RiparDeployment, keyId: Hex): Promise<DeviceStatus> {
  const [keyOf, retired, minEpoch] = await Promise.all([
    settle(pc.readContract({ address: dep.registry, abi: RIPAR_DEVICE_REGISTRY_ABI, functionName: 'keyOf', args: [keyId] })),
    settle(pc.readContract({ address: dep.registry, abi: RIPAR_DEVICE_REGISTRY_ABI, functionName: 'isRetired', args: [keyId] })),
    settle(pc.readContract({ address: dep.enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'minEpoch', args: [keyId] })),
  ]);
  const owner = keyOf ? (keyOf[2] as Address) : null;
  return {
    registeredOwner: owner && owner.toLowerCase() !== ZERO ? getAddress(owner) : null,
    readable: keyOf !== null,
    retired: retired ?? null,
    minEpoch: minEpoch ?? null,
  };
}

/** the enforcer's minEpoch for a device key (the mandate epoch must equal the device's panic floor) */
export async function readMinEpoch(pc: PublicClient, enforcer: Address, keyId: Hex): Promise<bigint> {
  return pc.readContract({ address: enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'minEpoch', args: [keyId] });
}

export interface TokenInfoRead {
  address: Address;
  symbol: string | null;
  decimals: number | null;
  balance: bigint | null;
}

export interface VaultStatus {
  deployed: boolean | null;
  codeBytes: number | null;
  owner: Address | null;
  native: bigint | null;
  tokens: TokenInfoRead[];
  laneOpen: boolean | null;
  lastReopenNonce: bigint | null;
}

export async function readToken(pc: PublicClient, token: Address, holder: Address): Promise<TokenInfoRead> {
  const [symbol, decimals, balance] = await Promise.all([
    settle(pc.readContract({ address: token, abi: MOCK_USD_ABI, functionName: 'symbol' })),
    settle(pc.readContract({ address: token, abi: MOCK_USD_ABI, functionName: 'decimals' })),
    settle(pc.readContract({ address: token, abi: MOCK_USD_ABI, functionName: 'balanceOf', args: [holder] })),
  ]);
  return { address: token, symbol, decimals: decimals === null ? null : Number(decimals), balance };
}

export async function readVaultStatus(
  pc: PublicClient,
  dep: RiparDeployment | null,
  vault: Address,
  tokens: Address[],
): Promise<VaultStatus> {
  const [code, native, lane, nonce] = await Promise.all([
    settle(pc.getCode({ address: vault })),
    settle(pc.getBalance({ address: vault })),
    dep ? settle(pc.readContract({ address: dep.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'laneOpen', args: [vault] })) : null,
    dep
      ? settle(pc.readContract({ address: dep.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'lastReopenNonce', args: [vault] }))
      : null,
  ]);
  const codeBytes = code === null ? null : code ? (code.length - 2) / 2 : 0;
  const deployed = codeBytes === null ? null : codeBytes > 0;
  const owner = deployed ? await settle(pc.readContract({ address: vault, abi: ERC173_OWNER_ABI, functionName: 'owner' })) : null;
  const toks = await Promise.all(tokens.filter((t) => !/^0x0{40}$/i.test(t)).map((t) => readToken(pc, t, vault)));
  return { deployed, codeBytes, owner: owner ? getAddress(owner) : null, native, tokens: toks, laneOpen: lane, lastReopenNonce: nonce };
}

export interface MandateStatus {
  revoked: boolean | null;
  disabled: boolean | null;
  minEpoch: bigint | null;
  budget: AutoBudget | null;
}

export async function readMandateStatus(
  pc: PublicClient,
  enforcer: Address,
  keyId: Hex,
  delegationHash: Hex,
  pulseTerms: Hex,
): Promise<MandateStatus> {
  const [revoked, disabled, minEpoch, budget] = await Promise.all([
    settle(pc.readContract({ address: enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'isRevoked', args: [keyId, delegationHash] })),
    settle(
      pc.readContract({
        address: DELEGATION_MANAGER,
        abi: DELEGATION_MANAGER_ABI,
        functionName: 'disabledDelegations',
        args: [delegationHash],
      }),
    ),
    settle(pc.readContract({ address: enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'minEpoch', args: [keyId] })),
    settle(
      pc.readContract({
        address: enforcer,
        abi: PULSE_COSIGN_ENFORCER_ABI,
        functionName: 'autoBudget',
        args: [DELEGATION_MANAGER, delegationHash, pulseTerms],
      }),
    ),
  ]);
  return {
    revoked,
    disabled,
    minEpoch,
    budget: budget ? { spent: budget[0], remaining: budget[1], periodStart: BigInt(budget[2]), periodEnd: BigInt(budget[3]) } : null,
  };
}

/** enforcer.nonceUsed(DM, delegationHash, nonce) (v1.2: a co-sign nonce is single-use per mandate) */
export async function nonceUsed(pc: PublicClient, enforcer: Address, delegationHash: Hex, nonce: bigint): Promise<boolean> {
  return pc.readContract({
    address: enforcer,
    abi: PULSE_COSIGN_ENFORCER_ABI,
    functionName: 'nonceUsed',
    args: [DELEGATION_MANAGER, delegationHash, nonce],
  });
}

export { ZERO, ZERO32 };
