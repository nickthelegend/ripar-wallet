// THE module for chain writes (ported from companion/src/lib/chain.ts). Every transaction the app sends is built here,
// with an explicit gas limit (Monad charges for the gas LIMIT, and a failing P-256 check falls back to ~250k gas of
// Solidity), simulated first so a revert is explained before the courier pays, then signed by the phone's hot key and
// awaited.
//
// The builders are pure (tested); sendWrite() is the only function that talks to a wallet.
import {
  type Abi,
  type Address,
  type Hex,
  type PublicClient,
  BaseError,
  decodeErrorResult,
  encodeFunctionData,
  parseAbi,
} from 'viem';
import {
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_DEVICE_REGISTRY_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
  SIMPLE_FACTORY_DEPLOY_ABI,
  toChecksumAddress,
} from '@ripar/protocol';
import type { Courier } from './clients';

/** explicit gas limits per write (see README "Chain writes") */
export const GAS_LIMITS = {
  /** P-256 + ECDSA checks + key binding (P-256 falls back to Solidity where 0x0100 is absent) */
  registerDevice: 500_000n,
  /** SimpleFactory CREATE2 of the ERC1967Proxy + HybridDeleGator.initialize(K1) */
  deployVault: 600_000n,
  /** MockUSD.faucet (mint) */
  faucet: 120_000n,
  /** PulseCosignEnforcer.revoke: P-256 + one flag */
  revoke: 400_000n,
  /** PulseCosignEnforcer.panic: P-256 + minEpoch */
  panic: 400_000n,
  /** RiparSentinel.reopen: owner() + registry lookups + P-256 + lane state */
  reopen: 450_000n,
  /** RiparReputationRelay.attestDenial: P-256 + registry + ERC-8004 giveFeedback */
  attestDenial: 800_000n,
  /** DelegationManager.redeemDelegations of a personal-mandate payment (HUMAN path: P-256 + one transfer); the
   * payment flow replaces it with eth_estimateGas + 25 % when the RPC can estimate */
  redeem: 700_000n,
} as const;

export type WriteKind = keyof typeof GAS_LIMITS;

export const MOCK_USD_ABI = parseAbi([
  'function faucet(address to, uint256 amount)',
  'function balanceOf(address) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
]);

/** MockUSD.faucet mints at most 1,000 mUSD per call (contracts/SPEC.md) */
export const FAUCET_MAX = 1_000_000_000n;

/** every error a Ripar write can revert with, for decoding */
export const WRITE_ERRORS_ABI: Abi = [
  ...PULSE_COSIGN_ENFORCER_ABI,
  ...RIPAR_DEVICE_REGISTRY_ABI,
  ...RIPAR_SENTINEL_ABI,
  ...RIPAR_REPUTATION_RELAY_ABI,
].filter((x) => x.type === 'error');

export interface WriteRequest {
  kind: WriteKind;
  to: Address;
  data: Hex;
  value: bigint;
  gas: bigint;
  /** what the user is approving, in words */
  summary: string;
}

function req(kind: WriteKind, to: string, data: Hex, summary: string): WriteRequest {
  return { kind, to: toChecksumAddress(to), data, value: 0n, gas: GAS_LIMITS[kind], summary };
}

const splitRs = (rs: Hex): [Hex, Hex] => {
  if (!/^0x[0-9a-fA-F]{128}$/.test(rs)) throw new Error('r‖s must be 64 bytes');
  return [`0x${rs.slice(2, 66)}`, `0x${rs.slice(66, 130)}`];
};

// --------------------------------------------------------------------------------------------------- builders
export function registerDeviceWrite(
  registry: string,
  d: { k1Address: Hex; px: Hex; py: Hex; p1Signature: Hex; k1Signature: Hex },
): WriteRequest {
  const [pr, ps] = splitRs(d.p1Signature);
  return req(
    'registerDevice',
    registry,
    encodeFunctionData({
      abi: RIPAR_DEVICE_REGISTRY_ABI,
      functionName: 'registerDevice',
      args: [toChecksumAddress(d.k1Address), d.px, d.py, pr, ps, d.k1Signature],
    }),
    'Bind the device key (P1) to its owner K1 in the RiparDeviceRegistry',
  );
}

export function deployVaultWrite(factory: string, factoryData: Hex, vault: string): WriteRequest {
  const sel = encodeFunctionData({ abi: SIMPLE_FACTORY_DEPLOY_ABI, functionName: 'deploy', args: ['0x', `0x${'00'.repeat(32)}`] }).slice(0, 10);
  if (!factoryData.startsWith(sel)) throw new Error('factoryData is not SimpleFactory.deploy(bytes,bytes32)');
  return req('deployVault', factory, factoryData, `Deploy the vault ${toChecksumAddress(vault)} through SimpleFactory`);
}

export function faucetWrite(mockUsd: string, to: string, amount: bigint): WriteRequest {
  if (amount <= 0n || amount > FAUCET_MAX) throw new Error('the faucet mints 0 < amount <= 1,000 mUSD');
  return req(
    'faucet',
    mockUsd,
    encodeFunctionData({ abi: MOCK_USD_ABI, functionName: 'faucet', args: [toChecksumAddress(to), amount] }),
    `Mint test MockUSD to ${toChecksumAddress(to)}`,
  );
}

export function revokeWrite(enforcer: string, px: Hex, py: Hex, delegationHash: Hex, rs: Hex): WriteRequest {
  const [r, s] = splitRs(rs);
  return req(
    'revoke',
    enforcer,
    encodeFunctionData({ abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'revoke', args: [px, py, delegationHash, r, s] }),
    `Revoke mandate ${delegationHash}`,
  );
}

export function panicWrite(enforcer: string, px: Hex, py: Hex, minEpoch: bigint, rs: Hex): WriteRequest {
  const [r, s] = splitRs(rs);
  return req(
    'panic',
    enforcer,
    encodeFunctionData({ abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'panic', args: [px, py, minEpoch, r, s] }),
    `PANIC: raise the device's min epoch to ${minEpoch} (kills every older mandate)`,
  );
}

export function reopenWrite(sentinel: string, vault: string, nonce: bigint, rs: Hex): WriteRequest {
  const [r, s] = splitRs(rs);
  return req(
    'reopen',
    sentinel,
    encodeFunctionData({ abi: RIPAR_SENTINEL_ABI, functionName: 'reopen', args: [toChecksumAddress(vault), nonce, r, s] }),
    `Reopen the agent lane of ${toChecksumAddress(vault)} (nonce ${nonce})`,
  );
}

export function attestDenialWrite(
  relay: string,
  a: { agentId: bigint; requestHash: Hex; presenceHash: Hex; px: Hex; py: Hex; rs: Hex },
): WriteRequest {
  const [r, s] = splitRs(a.rs);
  return req(
    'attestDenial',
    relay,
    encodeFunctionData({
      abi: RIPAR_REPUTATION_RELAY_ABI,
      functionName: 'attestDenial',
      args: [a.agentId, a.requestHash, a.presenceHash, a.px, a.py, r, s],
    }),
    `File the device's denial against agent ${a.agentId} (ERC-8004 feedback)`,
  );
}

// --------------------------------------------------------------------------------------------------- sending
export class ChainWriteError extends Error {
  override name = 'ChainWriteError';
  constructor(
    message: string,
    readonly stage: 'simulate' | 'send' | 'receipt',
    readonly txHash?: Hex,
  ) {
    super(message);
  }
}

/** the custom error name (and args) of a revert, else viem's short message */
export function revertReason(e: unknown): string {
  if (e instanceof BaseError) {
    let data: Hex | undefined;
    e.walk((x) => {
      const d = (x as { data?: unknown }).data;
      if (typeof d === 'string' && d.startsWith('0x') && d.length >= 10) data = d as Hex;
      return false;
    });
    if (data) {
      try {
        const dec = decodeErrorResult({ abi: WRITE_ERRORS_ABI, data });
        return `${dec.errorName}()`;
      } catch {
        /* not one of ours */
      }
    }
    return e.shortMessage || e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

export type WriteStage = 'simulating' | 'signing' | 'pending' | 'confirmed';

export interface WriteResult {
  hash: Hex;
  blockNumber: bigint;
  gasUsed: bigint;
}

/**
 * Simulates the write (eth_call from the courier with the same gas limit), sends it through the courier with the
 * explicit gas limit, and waits for the receipt. Throws ChainWriteError with the decoded revert reason.
 */
export async function sendWrite(
  pc: PublicClient,
  courier: Courier,
  w: WriteRequest,
  onStage?: (s: WriteStage, hash?: Hex) => void,
): Promise<WriteResult> {
  onStage?.('simulating');
  try {
    await pc.call({ account: courier.account, to: w.to, data: w.data, value: w.value, gas: w.gas });
  } catch (e) {
    throw new ChainWriteError(`Would revert: ${revertReason(e)}`, 'simulate');
  }
  onStage?.('signing');
  let hash: Hex;
  try {
    // the wallet client carries the hot key as a local account: viem signs here and sends eth_sendRawTransaction
    hash = await courier.wallet.sendTransaction({
      account: courier.wallet.account ?? courier.account,
      chain: courier.chain,
      to: w.to,
      data: w.data,
      value: w.value,
      gas: w.gas,
    });
  } catch (e) {
    throw new ChainWriteError(revertReason(e), 'send');
  }
  onStage?.('pending', hash);
  const receipt = await pc.waitForTransactionReceipt({ hash, timeout: 120_000 });
  if (receipt.status !== 'success') throw new ChainWriteError('The transaction reverted on chain', 'receipt', hash);
  onStage?.('confirmed', hash);
  return { hash, blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed };
}
