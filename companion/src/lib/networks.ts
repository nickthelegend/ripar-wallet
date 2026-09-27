// Network presets. The device only knows Monad testnet (10143) and Monad (143); a local anvil fork of Monad testnet
// keeps chain id 10143, so the same pairing works against the fork. The RPC URL is always the user's setting.
import { type Chain, defineChain } from 'viem';

export type NetworkId = 'monad-testnet' | 'anvil-fork';

export interface NetworkPreset {
  id: NetworkId;
  label: string;
  chainId: number;
  rpcUrl: string;
  explorer: string | null;
  note: string;
}

export const NETWORKS: Record<NetworkId, NetworkPreset> = {
  'monad-testnet': {
    id: 'monad-testnet',
    label: 'Monad testnet',
    chainId: 10143,
    rpcUrl: 'https://testnet-rpc.monad.xyz',
    explorer: 'https://testnet.monadexplorer.com',
    note: 'Public testnet. The courier wallet pays gas in testnet MON.',
  },
  'anvil-fork': {
    id: 'anvil-fork',
    label: 'Local anvil fork',
    chainId: 10143,
    rpcUrl: 'http://127.0.0.1:8545',
    explorer: null,
    note: 'anvil --fork-url https://testnet-rpc.monad.xyz keeps chain id 10143, so the device pairs with it.',
  },
};

/** anvil's first unlocked dev account (a public, well-known test account: anvil signs for it, no key here) */
export const ANVIL_DEV_ACCOUNT = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' as const;

export function isLocalRpc(url: string): boolean {
  try {
    const u = new URL(url);
    return ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}

export function viemChain(chainId: number, rpcUrl: string, explorer: string | null): Chain {
  return defineChain({
    id: chainId,
    name: chainId === 143 ? 'Monad' : chainId === 10143 ? 'Monad testnet' : `Chain ${chainId}`,
    nativeCurrency: { name: 'Monad', symbol: 'MON', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
    ...(explorer ? { blockExplorers: { default: { name: 'Explorer', url: explorer } } } : {}),
    testnet: chainId !== 143,
  });
}

export function explorerAddressUrl(explorer: string | null, address: string): string | null {
  return explorer ? `${explorer.replace(/\/$/, '')}/address/${address}` : null;
}

export function explorerTxUrl(explorer: string | null, hash: string): string | null {
  return explorer ? `${explorer.replace(/\/$/, '')}/tx/${hash}` : null;
}
