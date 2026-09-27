// viem clients. Reads go to the user's RPC URL. Writes go through the courier: this phone's hot key (lib/hotkey.ts),
// which signs locally and only pays gas: it owns nothing, and the app never sees a device key.
import {
  type Address,
  type Chain,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { hotKey } from './hotkey';
import { NETWORKS, viemChain } from './networks';
import type { Settings } from './store';

export interface Courier {
  wallet: WalletClient;
  account: Address;
  chain: Chain;
  kind: 'hotkey';
}

const pcCache = new Map<string, PublicClient>();

export function chainOf(s: Settings): Chain {
  return viemChain(s.chainId, s.rpcUrl, NETWORKS[s.network]?.explorer ?? null);
}

export function publicClientFor(s: Settings): PublicClient {
  const k = `${s.chainId}|${s.rpcUrl}`;
  let pc = pcCache.get(k);
  if (!pc) {
    pc = createPublicClient({ chain: chainOf(s), transport: http(s.rpcUrl, { retryCount: 1, timeout: 20_000 }) }) as PublicClient;
    pcCache.set(k, pc);
  }
  return pc;
}

export class CourierError extends Error {
  override name = 'CourierError';
}

/** the hot-key courier for the configured chain */
export async function connectCourier(s: Settings): Promise<Courier> {
  const chain = chainOf(s);
  const account = privateKeyToAccount(await hotKey());
  const wallet = createWalletClient({ account, chain, transport: http(s.rpcUrl, { retryCount: 1, timeout: 30_000 }) });
  return { wallet, account: account.address, chain, kind: 'hotkey' };
}
