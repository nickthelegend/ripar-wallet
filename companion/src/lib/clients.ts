// viem clients. Reads go to the user's RPC URL. Writes go through the courier: an injected EIP-1193 wallet, or (only
// on a local anvil RPC) one of anvil's unlocked dev accounts, which anvil itself signs for. The courier only pays gas:
// it owns nothing, and the companion never sees a private key.
import {
  type Address,
  type Chain,
  type EIP1193Provider,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  custom,
  http,
  numberToHex,
} from 'viem';
import { NETWORKS, isLocalRpc, viemChain } from './networks';
import type { Settings } from './store';

export interface Courier {
  wallet: WalletClient;
  account: Address;
  chain: Chain;
  kind: Settings['courier'];
}

const pcCache = new Map<string, PublicClient>();

export function chainOf(s: Settings): Chain {
  return viemChain(s.chainId, s.rpcUrl, NETWORKS[s.network]?.explorer ?? null);
}

export function publicClientFor(s: Settings): PublicClient {
  const k = `${s.chainId}|${s.rpcUrl}`;
  let pc = pcCache.get(k);
  if (!pc) {
    pc = createPublicClient({ chain: chainOf(s), transport: http(s.rpcUrl, { retryCount: 1, timeout: 20_000 }) });
    pcCache.set(k, pc);
  }
  return pc;
}

declare global {
  interface Window {
    ethereum?: EIP1193Provider;
  }
}

export function injectedProvider(): EIP1193Provider | null {
  return typeof window !== 'undefined' && window.ethereum ? window.ethereum : null;
}

export class CourierError extends Error {
  override name = 'CourierError';
}

/**
 * Connects the courier wallet for the configured chain. Injected: asks for accounts and switches (or adds) the
 * chain. Anvil: only on a 127.0.0.1 / localhost RPC, using an account anvil has unlocked (eth_sendTransaction).
 */
export async function connectCourier(s: Settings): Promise<Courier> {
  const chain = chainOf(s);
  if (s.courier === 'anvil') {
    if (!isLocalRpc(s.rpcUrl)) throw new CourierError('The anvil courier only works with a local RPC (127.0.0.1).');
    const wallet = createWalletClient({ account: s.anvilAccount, chain, transport: http(s.rpcUrl) });
    return { wallet, account: s.anvilAccount, chain, kind: 'anvil' };
  }
  const provider = injectedProvider();
  if (!provider) throw new CourierError('No injected wallet found. Install one, or use a local anvil fork.');
  const accounts = (await provider.request({ method: 'eth_requestAccounts' })) as Address[];
  const account = accounts[0];
  if (!account) throw new CourierError('The wallet returned no account.');
  const current = Number(await provider.request({ method: 'eth_chainId' }));
  if (current !== s.chainId) {
    try {
      await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: numberToHex(s.chainId) }] });
    } catch (e) {
      const code = (e as { code?: number }).code;
      if (code !== 4902) throw new CourierError(`Switch the wallet to chain ${s.chainId} (${(e as Error).message}).`);
      await provider.request({
        method: 'wallet_addEthereumChain',
        params: [
          {
            chainId: numberToHex(s.chainId),
            chainName: chain.name,
            nativeCurrency: chain.nativeCurrency,
            rpcUrls: [s.rpcUrl],
            ...(chain.blockExplorers ? { blockExplorerUrls: [chain.blockExplorers.default.url] } : {}),
          },
        ],
      });
    }
  }
  const wallet = createWalletClient({ account, chain, transport: custom(provider) });
  return { wallet, account, chain, kind: 'injected' };
}
