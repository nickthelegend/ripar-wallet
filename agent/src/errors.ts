// Revert decoding: the custom errors of the Ripar contracts (PulseCosignEnforcer, RiparSentinel, RiparReputationRelay,
// RiparDeviceRegistry), the MetaMask DelegationManager / DeleGator, OpenZeppelin ERC-20 / Pausable / ECDSA, plus
// Error(string) and Panic(uint256). The enforcer's hook runs inside DelegationManager.redeemDelegations without a
// try/catch, so its revert data reaches the caller unchanged.
import {
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_DEVICE_REGISTRY_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
} from '@ripar/protocol';
import { decodeErrorResult, parseAbi, type Abi, type Hash, type Hex } from 'viem';

type AbiError = Extract<Abi[number], { type: 'error' }>;

const EXTRA_ERRORS = parseAbi([
  // MetaMask delegation-framework v1.3.0 IDelegationManager
  'error CannotUseADisabledDelegation()',
  'error InvalidAuthority()',
  'error InvalidDelegate()',
  'error InvalidDelegator()',
  'error InvalidEOASignature()',
  'error InvalidERC1271Signature()',
  'error EmptySignature()',
  'error AlreadyDisabled()',
  'error AlreadyEnabled()',
  'error BatchDataLengthMismatch()',
  // DeleGatorCore / ERC-7579 ExecutionHelper
  'error NotSelf()',
  'error NotEntryPoint()',
  'error NotEntryPointOrSelf()',
  'error NotDelegationManager()',
  'error UnsupportedCallType(bytes1 callType)',
  'error UnsupportedExecType(bytes1 execType)',
  'error ExecutionFailed()',
  'error SimpleFactoryEmptyContract(address deployed)',
  // OpenZeppelin
  'error EnforcedPause()',
  'error ExpectedPause()',
  'error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed)',
  'error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed)',
  'error ERC20InvalidReceiver(address receiver)',
  'error ERC20InvalidSender(address sender)',
  'error ECDSAInvalidSignature()',
  'error ECDSAInvalidSignatureLength(uint256 length)',
  'error ECDSAInvalidSignatureS(bytes32 s)',
  // MockUSD
  'error FaucetCapExceeded(uint256 amount, uint256 max)',
]);

function errorsOf(...abis: Abi[]): AbiError[] {
  const seen = new Set<string>();
  const out: AbiError[] = [];
  for (const abi of abis) {
    for (const item of abi) {
      if (item.type !== 'error') continue;
      const sig = `${item.name}(${item.inputs.map((i) => i.type).join(',')})`;
      if (seen.has(sig)) continue;
      seen.add(sig);
      out.push(item);
    }
  }
  return out;
}

/** every custom error the agent can meet on a redemption / attestation */
export const RIPAR_ERRORS_ABI: AbiError[] = errorsOf(
  PULSE_COSIGN_ENFORCER_ABI as Abi,
  RIPAR_SENTINEL_ABI as Abi,
  RIPAR_REPUTATION_RELAY_ABI as Abi,
  RIPAR_DEVICE_REGISTRY_ABI as Abi,
  EXTRA_ERRORS as Abi,
);

export interface DecodedRevert {
  /** error name (custom error), "Error" (require string), "Panic", "EmptyRevert" or "UnknownError" */
  name: string;
  args: readonly unknown[];
  /** raw revert data, when the node returned it */
  data: Hex | null;
  message: string;
}

/** errors after which the AUTO path is closed but a device co-sign (HUMAN path) can still pay */
export const ESCALATE_ERRORS: ReadonlySet<string> = new Set(['HumanRequired', 'LaneClosed']);
/** errors that mean the mandate itself is dead (revoked, panicked, disabled or invalid) */
export const DEAD_MANDATE_ERRORS: ReadonlySet<string> = new Set([
  'DelegationRevoked',
  'StaleEpoch',
  'CannotUseADisabledDelegation',
  'InvalidEOASignature',
  'InvalidERC1271Signature',
  'InvalidDelegate',
  'InvalidDelegator',
  'InvalidAuthority',
  'InvalidTerms',
]);

const EXPLAIN: Record<string, string> = {
  HumanRequired: 'the AUTO path does not cover this call (not meterable, over a cap, or a new payee): the device must co-sign',
  LaneClosed: 'the sentinel closed the vault\'s autonomous lane: only device co-signs pay until the device reopens it',
  CosignReplayed: 'this co-signature (or its nonce) was already used for this mandate',
  CosignExpired: 'the co-signature expired before it was redeemed',
  BadCosign: 'the P-256 co-signature does not verify for this exact call',
  DelegationRevoked: 'the device revoked this mandate',
  StaleEpoch: 'the device PANICKED: every mandate of this epoch is dead',
  InvalidArgs: 'malformed pulse caveat args',
  InvalidTerms: 'malformed pulse terms',
  CannotUseADisabledDelegation: 'the vault disabled this delegation',
  InvalidEOASignature: 'the delegation signature is invalid',
  InvalidERC1271Signature: 'the vault rejected the delegation signature (owner changed?)',
  InvalidDelegate: 'this agent is not the delegate of the mandate',
  EnforcedPause: 'the DelegationManager is paused',
  ERC20InsufficientBalance: 'the vault does not hold enough of the token',
  NotRedeemer: 'only the redeemer of an approval may attest it',
  NotConsumed: 'the approval digest was not consumed through the canonical DelegationManager',
  NotAgentRedeemer: 'the redeemer is not authorized for this ERC-8004 agentId',
  AlreadyAttested: 'this approval was already attested',
  UnknownDevice: 'the co-signing device key is not registered to the vault owner',
  AgentIsShielded: 'the agent made the relay its operator (shield): approvals are no longer credited',
};

export function explainRevert(name: string): string {
  return EXPLAIN[name] ?? name;
}

function isHexData(v: unknown): v is Hex {
  return typeof v === 'string' && /^0x([0-9a-fA-F]{2})*$/.test(v);
}

/** the raw revert data somewhere in a viem / JSON-RPC error chain (null when there is none) */
export function revertDataOf(err: unknown): Hex | null {
  let e: unknown = err;
  for (let depth = 0; depth < 12 && e && typeof e === 'object'; depth++) {
    const o = e as Record<string, unknown>;
    if (isHexData(o.raw)) return o.raw;
    if (isHexData(o.data)) return o.data;
    if (o.data && typeof o.data === 'object') {
      const d = o.data as Record<string, unknown>;
      if (isHexData(d.data)) return d.data;
    }
    if (o.error && typeof o.error === 'object') {
      const d = o.error as Record<string, unknown>;
      if (isHexData(d.data)) return d.data;
    }
    e = o.cause;
  }
  return null;
}

function looksLikeRevert(err: unknown): boolean {
  let e: unknown = err;
  for (let depth = 0; depth < 12 && e && typeof e === 'object'; depth++) {
    const o = e as Record<string, unknown>;
    const name = typeof o.name === 'string' ? o.name : '';
    const msg = `${typeof o.message === 'string' ? o.message : ''} ${typeof o.details === 'string' ? o.details : ''}`;
    if (/Revert/i.test(name) || /execution reverted|reverted/i.test(msg)) return true;
    if (o.code === 3) return true;
    e = o.cause;
  }
  return false;
}

/** decodes raw revert data */
export function decodeRevertData(data: Hex): DecodedRevert {
  if (data === '0x') return { name: 'EmptyRevert', args: [], data, message: 'reverted without data' };
  try {
    const r = decodeErrorResult({ abi: RIPAR_ERRORS_ABI, data });
    const args = (r.args ?? []) as readonly unknown[];
    if (r.errorName === 'Error') return { name: 'Error', args, data, message: String(args[0] ?? '') };
    if (r.errorName === 'Panic') return { name: 'Panic', args, data, message: `panic 0x${BigInt(args[0] as bigint).toString(16)}` };
    return { name: r.errorName, args, data, message: explainRevert(r.errorName) };
  } catch {
    return { name: 'UnknownError', args: [], data, message: `unknown revert ${data.slice(0, 10)}` };
  }
}

/** a revert found in an error chain, decoded; null when the error is not a revert (network, nonce, ...) */
export function decodeRevert(err: unknown): DecodedRevert | null {
  const data = revertDataOf(err);
  if (data !== null) return decodeRevertData(data);
  if (looksLikeRevert(err)) return { name: 'EmptyRevert', args: [], data: null, message: 'reverted (no revert data returned)' };
  return null;
}

/** a transaction the chain refused: at gas estimation (nothing was sent) or in the mined receipt */
export class ChainRevertError extends Error {
  override name = 'ChainRevertError';

  constructor(
    readonly revert: DecodedRevert,
    readonly phase: 'estimate' | 'receipt',
    readonly txHash?: Hash,
  ) {
    super(`${revert.name}: ${revert.message}`);
  }

  get escalate(): boolean {
    return ESCALATE_ERRORS.has(this.revert.name);
  }

  get mandateDead(): boolean {
    return DEAD_MANDATE_ERRORS.has(this.revert.name);
  }
}

/** an error with an HTTP status for the API */
export class ApiError extends Error {
  override name = 'ApiError';

  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}
