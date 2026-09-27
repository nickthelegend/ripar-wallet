// The agent's transaction signer: the delegate / redeemer of the mandate. It signs only the agent's OWN transactions
// (redeemDelegations, attestApproval, ERC-8004 register); it never sees or holds the user's device keys.
//
// - LocalKeySigner: a local development key (AGENT_PRIVATE_KEY). Kept in a private field, never logged or serialized.
// - PrivySigner: production target. The agent's wallet is a Privy server wallet whose policy / key quorum the user's
//   Ripar device authorizes (ripar-privy-req, docs/PROTOCOL.md). Not implemented yet: it throws "not configured".
import { createWalletClient, defineChain, http, type Address, type Chain, type Hash, type Hex, type Transport } from 'viem';
import { privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import type { SignerConfig } from './config.js';

export interface TxRequest {
  to: Address;
  data: Hex;
  value?: bigint;
  /** explicit gas limit (estimate + margin: Monad bills the limit) */
  gas: bigint;
}

export interface Signer {
  readonly kind: 'local' | 'privy';
  /** the agent's address (the mandate's delegate) */
  readonly address: Address;
  sendTransaction(tx: TxRequest): Promise<Hash>;
}

export function chainFor(chainId: number, rpcUrl: string): Chain {
  const known: Record<number, string> = { 10143: 'Monad Testnet', 143: 'Monad', 31337: 'Anvil' };
  return defineChain({
    id: chainId,
    name: known[chainId] ?? `chain ${chainId}`,
    nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

export class LocalKeySigner implements Signer {
  readonly kind = 'local' as const;
  readonly address: Address;
  readonly #account: PrivateKeyAccount;
  readonly #chain: Chain;
  readonly #transport: Transport;

  constructor(privateKey: Hex, chain: Chain, transport: Transport = http(chain.rpcUrls.default.http[0])) {
    this.#account = privateKeyToAccount(privateKey);
    this.address = this.#account.address;
    this.#chain = chain;
    this.#transport = transport;
  }

  async sendTransaction(tx: TxRequest): Promise<Hash> {
    const wallet = createWalletClient({ account: this.#account, chain: this.#chain, transport: this.#transport });
    return wallet.sendTransaction({ to: tx.to, data: tx.data, value: tx.value ?? 0n, gas: tx.gas, account: this.#account, chain: this.#chain });
  }

  toJSON(): Record<string, string> {
    return { kind: this.kind, address: this.address };
  }
}

export class SignerNotConfiguredError extends Error {
  override name = 'SignerNotConfiguredError';
}

/**
 * Production signer placeholder: the agent's key lives in a Privy server wallet (the agent never holds it), and the
 * wallet's policy is set by a Privy key quorum that includes the user's Ripar device (ripar-privy-req, signed by P1).
 * Sending would go through Privy's wallet RPC (eth_sendTransaction) with an authorization signature.
 */
export class PrivySigner implements Signer {
  readonly kind = 'privy' as const;

  constructor(private readonly opts: { appId?: string; walletId?: string; address?: string } = {}) {}

  get address(): Address {
    if (!this.opts.address) throw new SignerNotConfiguredError('PrivySigner: not configured (set PRIVY_WALLET_ADDRESS)');
    return this.opts.address as Address;
  }

  async sendTransaction(_tx: TxRequest): Promise<Hash> {
    throw new SignerNotConfiguredError('PrivySigner: not configured (Privy server wallets are the production signer; use AGENT_SIGNER=local for development)');
  }

  toJSON(): Record<string, string> {
    return { kind: this.kind, address: this.opts.address ?? '(not configured)' };
  }
}

export function createSigner(cfg: SignerConfig, chain: Chain, transport?: Transport): Signer {
  if (cfg.kind === 'local') return new LocalKeySigner(cfg.privateKey, chain, transport);
  return new PrivySigner(cfg);
}
