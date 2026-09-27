// Chain layer (viem): the reads the planner needs (vault balances, AUTO budget, sentinel lane, known payees, nonces,
// mandate liveness) and the agent's two writes: DelegationManager.redeemDelegations (AUTO: empty pulse args, HUMAN:
// the device's 160-byte co-sign args) and RiparReputationRelay.attestApproval. Every transaction carries an explicit
// gas limit = eth_estimateGas + a margin (Monad bills the gas LIMIT, not the gas used), and a revert at estimation
// time is decoded and thrown before anything is sent. Transactions are signed locally with an explicit nonce before
// they are broadcast, so their hash is known even when the broadcast itself errors: such a transaction is tracked as
// pending (never re-sent with a new nonce) until its receipt or the account nonce settles it.
import {
  DELEGATION_MANAGER_ABI,
  ERC173_OWNER_ABI,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
  encodeRedeemDelegations,
  withCaveatArgs,
  type AutoBudget,
  type Delegation,
} from '@ripar/protocol';
import {
  createPublicClient,
  encodeFunctionData,
  erc20Abi,
  http,
  keccak256,
  type Address,
  type Chain,
  type Hash,
  type Hex,
  type PublicClient,
  type Transport,
} from 'viem';
import { ChainRevertError, decodeRevert } from './errors.js';
import type { Signer, TxFees } from './signer.js';
import { displaySymbol } from './util.js';

export interface Execution {
  target: Address;
  value: bigint;
  callData: Hex;
}

export interface TxOutcome {
  hash: Hash;
  gasLimit: bigint;
  gasUsed: bigint;
  blockNumber: bigint;
}

export interface TxStatus {
  /** pending = the node has no receipt for it; unknown = the receipt could not be read (RPC error) */
  status: 'success' | 'reverted' | 'pending' | 'unknown';
  gasUsed?: bigint;
  blockNumber?: bigint;
}

/**
 * A transaction was signed and broadcast but its outcome is unknown: the broadcast call errored (the node may still
 * have accepted it) or its receipt could not be read. It must not be sent again with a new nonce: txStatus() and the
 * account nonce settle it, and `raw` (the signed transaction, keccak256(raw) = hash) can be re-broadcast unchanged.
 */
export class TxPendingError extends Error {
  override name = 'TxPendingError';

  constructor(
    readonly hash: Hash,
    readonly gasLimit: bigint,
    readonly reason: string,
    readonly nonce?: number,
    readonly raw?: Hex,
  ) {
    super(`transaction ${hash} was sent but not confirmed yet (${reason})`);
  }
}

/** a transaction signed locally, about to be broadcast: the caller persists it first (write-ahead) */
export interface SignedTx {
  hash: Hash;
  gasLimit: bigint;
  nonce: number;
  raw: Hex;
}

export interface MandateLiveness {
  revoked: boolean;
  disabled: boolean;
  minEpoch: bigint;
}

/** what the agent needs from the chain (ViemChain in production, a fake in unit tests) */
export interface RiparChain {
  readonly chainId: number;
  /** the agent's address (signer): the delegate and redeemer */
  readonly agent: Address;
  readonly manager: Address;
  readonly enforcer: Address;
  getChainId(): Promise<number>;
  /** latest block timestamp (unix s) */
  now(): Promise<bigint>;
  nativeBalance(a: Address): Promise<bigint>;
  tokenBalance(token: Address, a: Address): Promise<bigint>;
  tokenInfo(token: Address): Promise<{ decimals: number; symbol: string }>;
  hasCode(a: Address): Promise<boolean>;
  /** enforcer.autoBudget(DelegationManager, delegationHash, terms) */
  autoBudget(delegationHash: Hex, terms: Hex): Promise<AutoBudget>;
  /** enforcer.periodSpent(DelegationManager, delegationHash) */
  periodSpent(delegationHash: Hex): Promise<{ spent: bigint; start: bigint }>;
  /** sentinel.laneOpen(vault) */
  laneOpen(sentinel: Address, vault: Address): Promise<boolean>;
  isKnownPayee(delegationHash: Hex, payee: Address): Promise<boolean>;
  nonceUsed(delegationHash: Hex, nonce: bigint): Promise<boolean>;
  mandateLiveness(delegationHash: Hex, keyId: Hex): Promise<MandateLiveness>;
  /** the vault's ERC-173 owner (K1), null when the vault has no code yet */
  vaultOwner(vault: Address): Promise<Address | null>;
  /**
   * DelegationManager.redeemDelegations for one single-call execution. `args` = the pulse caveat args: '0x' (AUTO,
   * the default) or the device's 160-byte co-sign args (HUMAN). Throws ChainRevertError (decoded) when the chain
   * refuses it, TxPendingError when it was sent but its receipt could not be read. `onSigned` runs after the local
   * signature and BEFORE the broadcast, so the caller can persist the transaction first: a crash between the two
   * can then never lead to paying again with a new nonce.
   */
  redeem(delegation: Delegation, execution: Execution, args?: Hex, onSigned?: (tx: SignedTx) => void): Promise<TxOutcome>;
  /** RiparReputationRelay.attestApproval(agentId, approvalDigest), msg.sender = the redeemer */
  attestApproval(relay: Address, agentId: bigint, approvalDigest: Hex): Promise<TxOutcome>;
  /** the receipt status of a transaction sent earlier ('pending' = no receipt yet, 'unknown' = could not read) */
  txStatus(hash: Hash): Promise<TxStatus>;
  /** the agent account's nonce at the LATEST block (= how many transactions of this account were mined) */
  accountNonce(): Promise<number>;
  /** broadcasts an already signed transaction again (same bytes, same hash); "already known" is not an error */
  rebroadcast(raw: Hex): Promise<void>;
}

/** node answers meaning "this exact transaction is already in the pool" (geth, reth, anvil, ...) */
export const ALREADY_KNOWN = /already known|known transaction|already imported|alreadyknown|already exists|already in (the )?(mem)?pool/i;

export interface ViemChainOptions {
  chain: Chain;
  transport?: Transport;
  signer: Signer;
  manager: Address;
  enforcer: Address;
  gasMarginPercent?: number;
  /** receipt wait timeout, ms (default 120 s) */
  receiptTimeoutMs?: number;
}

export class ViemChain implements RiparChain {
  readonly chainId: number;
  readonly manager: Address;
  readonly enforcer: Address;
  readonly client: PublicClient;
  private readonly signer: Signer;
  private readonly margin: bigint;
  private readonly receiptTimeoutMs: number;

  constructor(o: ViemChainOptions) {
    this.chainId = o.chain.id;
    this.client = createPublicClient({ chain: o.chain, transport: o.transport ?? http(o.chain.rpcUrls.default.http[0]) }) as PublicClient;
    this.signer = o.signer;
    this.manager = o.manager;
    this.enforcer = o.enforcer;
    this.margin = BigInt(o.gasMarginPercent ?? 20);
    this.receiptTimeoutMs = o.receiptTimeoutMs ?? 120_000;
  }

  get agent(): Address {
    return this.signer.address;
  }

  async getChainId(): Promise<number> {
    return this.client.getChainId();
  }

  async now(): Promise<bigint> {
    const b = await this.client.getBlock({ blockTag: 'latest' });
    return b.timestamp;
  }

  nativeBalance(a: Address): Promise<bigint> {
    return this.client.getBalance({ address: a });
  }

  tokenBalance(token: Address, a: Address): Promise<bigint> {
    return this.client.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [a] });
  }

  private readonly tokenCache = new Map<string, { decimals: number; symbol: string }>();

  async tokenInfo(token: Address): Promise<{ decimals: number; symbol: string }> {
    const k = token.toLowerCase();
    const hit = this.tokenCache.get(k);
    if (hit) return hit;
    const [decimals, symbol] = await Promise.all([
      this.client.readContract({ address: token, abi: erc20Abi, functionName: 'decimals' }),
      this.client.readContract({ address: token, abi: erc20Abi, functionName: 'symbol' }).catch(() => '?'),
    ]);
    // symbol() is attacker-controlled: printable ASCII of at most 16 characters, otherwise '?'
    const info = { decimals: Number(decimals), symbol: displaySymbol(symbol) };
    this.tokenCache.set(k, info);
    return info;
  }

  async hasCode(a: Address): Promise<boolean> {
    const code = await this.client.getCode({ address: a });
    return !!code && code !== '0x';
  }

  async autoBudget(delegationHash: Hex, terms: Hex): Promise<AutoBudget> {
    const [spent, remaining, periodStart, periodEnd] = await this.client.readContract({
      address: this.enforcer,
      abi: PULSE_COSIGN_ENFORCER_ABI,
      functionName: 'autoBudget',
      args: [this.manager, delegationHash, terms],
    });
    return { spent, remaining, periodStart: BigInt(periodStart), periodEnd: BigInt(periodEnd) };
  }

  async periodSpent(delegationHash: Hex): Promise<{ spent: bigint; start: bigint }> {
    const [spent, start] = await this.client.readContract({
      address: this.enforcer,
      abi: PULSE_COSIGN_ENFORCER_ABI,
      functionName: 'periodSpent',
      args: [this.manager, delegationHash],
    });
    return { spent, start: BigInt(start) };
  }

  laneOpen(sentinel: Address, vault: Address): Promise<boolean> {
    return this.client.readContract({ address: sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'laneOpen', args: [vault] });
  }

  isKnownPayee(delegationHash: Hex, payee: Address): Promise<boolean> {
    return this.client.readContract({
      address: this.enforcer,
      abi: PULSE_COSIGN_ENFORCER_ABI,
      functionName: 'isKnownPayee',
      args: [this.manager, delegationHash, payee],
    });
  }

  nonceUsed(delegationHash: Hex, nonce: bigint): Promise<boolean> {
    return this.client.readContract({
      address: this.enforcer,
      abi: PULSE_COSIGN_ENFORCER_ABI,
      functionName: 'nonceUsed',
      args: [this.manager, delegationHash, nonce],
    });
  }

  async mandateLiveness(delegationHash: Hex, keyId: Hex): Promise<MandateLiveness> {
    const [revoked, minEpoch, disabled] = await Promise.all([
      this.client.readContract({ address: this.enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'isRevoked', args: [keyId, delegationHash] }),
      this.client.readContract({ address: this.enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'minEpoch', args: [keyId] }),
      this.client.readContract({ address: this.manager, abi: DELEGATION_MANAGER_ABI, functionName: 'disabledDelegations', args: [delegationHash] }),
    ]);
    return { revoked, disabled, minEpoch: BigInt(minEpoch) };
  }

  async vaultOwner(vault: Address): Promise<Address | null> {
    if (!(await this.hasCode(vault))) return null;
    return this.client.readContract({ address: vault, abi: ERC173_OWNER_ABI, functionName: 'owner' });
  }

  async redeem(delegation: Delegation, execution: Execution, args: Hex = '0x', onSigned?: (tx: SignedTx) => void): Promise<TxOutcome> {
    const d = withCaveatArgs(delegation, this.enforcer, args);
    const data = encodeRedeemDelegations([{ delegations: [d], target: execution.target, value: execution.value, callData: execution.callData }]);
    return this.send(this.manager, data, 0n, onSigned);
  }

  async attestApproval(relay: Address, agentId: bigint, approvalDigest: Hex): Promise<TxOutcome> {
    const data = encodeFunctionData({ abi: RIPAR_REPUTATION_RELAY_ABI, functionName: 'attestApproval', args: [agentId, approvalDigest] });
    return this.send(relay, data);
  }

  /** EIP-1559 fees when the chain has a base fee, the legacy gas price otherwise */
  private async fees(): Promise<TxFees> {
    try {
      const f = await this.client.estimateFeesPerGas();
      if (typeof f.maxFeePerGas === 'bigint' && typeof f.maxPriorityFeePerGas === 'bigint') {
        return { maxFeePerGas: f.maxFeePerGas, maxPriorityFeePerGas: f.maxPriorityFeePerGas };
      }
    } catch {
      /* no base fee (pre-London chain) or no eth_maxPriorityFeePerGas: legacy pricing */
    }
    return { gasPrice: await this.client.getGasPrice() };
  }

  /**
   * estimate (a revert is decoded and thrown, nothing is sent) -> gas limit = estimate + margin -> pending nonce and
   * fees -> sign locally -> hash = keccak256(signed bytes) -> broadcast -> receipt. Anything that fails after signing
   * throws TxPendingError with the hash, nonce and signed bytes: the node may have accepted the transaction even when
   * the broadcast call errored (timeout, "already known", a retried request answered "nonce too low"), so the caller
   * must never pay again with a new nonce before settlePending() has resolved this one.
   */
  async send(to: Address, data: Hex, value = 0n, onSigned?: (tx: SignedTx) => void): Promise<TxOutcome> {
    const account = this.signer.address;
    let estimate: bigint;
    try {
      estimate = await this.client.estimateGas({ account, to, data, value });
    } catch (e) {
      const r = decodeRevert(e);
      if (r) throw new ChainRevertError(r, 'estimate');
      throw e;
    }
    const gasLimit = estimate + (estimate * this.margin) / 100n;
    const [nonce, fees] = await Promise.all([this.client.getTransactionCount({ address: account, blockTag: 'pending' }), this.fees()]);
    const raw = await this.signer.signTransaction({ to, data, value, gas: gasLimit, nonce, chainId: this.chainId, ...fees });
    const hash = keccak256(raw);
    // write-ahead: the caller records the signed transaction before it can reach any node
    onSigned?.({ hash, gasLimit, nonce, raw });
    try {
      await this.client.sendRawTransaction({ serializedTransaction: raw });
    } catch (e) {
      throw new TxPendingError(hash, gasLimit, `broadcast: ${firstLine(e)}`, nonce, raw);
    }
    let rcpt;
    try {
      rcpt = await this.client.waitForTransactionReceipt({ hash, timeout: this.receiptTimeoutMs });
    } catch (e) {
      // sent, outcome unknown: the caller must not send it again before txStatus() settles it
      throw new TxPendingError(hash, gasLimit, firstLine(e), nonce, raw);
    }
    if (rcpt.status !== 'success') {
      // replay it against the parent block to learn why (best effort)
      let reason = null;
      try {
        await this.client.call({ account, to, data, value, gas: gasLimit, blockNumber: rcpt.blockNumber - 1n });
      } catch (e) {
        reason = decodeRevert(e);
      }
      throw new ChainRevertError(
        reason ?? { name: 'Reverted', args: [], data: null, message: `reverted in block ${rcpt.blockNumber} (gas used ${rcpt.gasUsed} of ${gasLimit})` },
        'receipt',
        hash,
      );
    }
    return { hash, gasLimit, gasUsed: rcpt.gasUsed, blockNumber: rcpt.blockNumber };
  }

  async txStatus(hash: Hash): Promise<TxStatus> {
    try {
      const r = await this.client.getTransactionReceipt({ hash });
      return { status: r.status === 'success' ? 'success' : 'reverted', gasUsed: r.gasUsed, blockNumber: r.blockNumber };
    } catch (e) {
      // only "no receipt" means pending: an RPC failure proves nothing and must never make a mined tx look dropped
      return { status: (e as Error | null)?.name === 'TransactionReceiptNotFoundError' ? 'pending' : 'unknown' };
    }
  }

  accountNonce(): Promise<number> {
    return this.client.getTransactionCount({ address: this.signer.address, blockTag: 'latest' });
  }

  async rebroadcast(raw: Hex): Promise<void> {
    try {
      await this.client.sendRawTransaction({ serializedTransaction: raw });
    } catch (e) {
      if (ALREADY_KNOWN.test(errorText(e))) return;
      throw e;
    }
  }
}

/** every message / details string along an error's cause chain (viem wraps the node's answer) */
function errorText(err: unknown): string {
  const out: string[] = [];
  let e: unknown = err;
  for (let depth = 0; depth < 8 && e && typeof e === 'object'; depth++) {
    const o = e as { message?: unknown; details?: unknown; cause?: unknown };
    if (typeof o.message === 'string') out.push(o.message);
    if (typeof o.details === 'string') out.push(o.details);
    e = o.cause;
  }
  return out.length ? out.join(' | ') : String(err);
}

function firstLine(e: unknown): string {
  const m = e instanceof Error ? ((e as { shortMessage?: string }).shortMessage ?? e.message) : String(e);
  return m.split('\n')[0]!.slice(0, 300);
}
