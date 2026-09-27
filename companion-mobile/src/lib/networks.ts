// Network presets. The device only knows Monad testnet (10143) and Monad (143); a local anvil fork of Monad testnet
// keeps chain id 10143, so the same pairing works against the fork. The RPC URL is always the user's setting.
// On a phone, "local" means a dev stack on a computer: http://<its LAN IP>:8545, or http://127.0.0.1:8545 after
// `adb reverse tcp:8545 tcp:8545`.
import { type Chain, defineChain } from 'viem';

export type NetworkId = 'monad-testnet' | 'local';

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
    note: 'Public testnet. The phone key pays gas in testnet MON.',
  },
  local: {
    id: 'local',
    label: 'Local dev stack',
    chainId: 10143,
    rpcUrl: 'http://127.0.0.1:8545',
    explorer: null,
    note: 'scripts/dev-stack.sh on a computer (anvil fork of Monad testnet, chain id 10143). Use its LAN address, or adb reverse tcp:8545 tcp:8545.',
  },
};

export function isLocalRpc(url: string): boolean {
  try {
    const u = new URL(url);
    return ['127.0.0.1', 'localhost', '[::1]', '10.0.2.2'].includes(u.hostname) || /^(192\.168|10)\./.test(u.hostname);
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
