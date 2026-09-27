// What the chain says about this setup, read once per change of device / network / mandate and on demand
// (pull-to-refresh, after a write): the device is registered, the vault has code and its balances, the personal
// mandate is live, the phone key's gas balance. Shared by Home, Device and the send flow (ported from
// companion/src/lib/setup.ts). A failed read is shown as unknown (null), never guessed.
import { useEffect, useSyncExternalStore } from 'react';
import { AUSD_10143 } from '@ripar/protocol';
import { publicClientFor } from './clients';
import { hotKeyAddress } from './hotkey';
import { type MandateStatus, type VaultStatus, readDeviceStatus, readMandateStatus, readVaultStatus } from './reads';
import { type AppState, deploymentOf, store } from './store';

export interface ChainSnapshot {
  key: string;
  reading: boolean;
  readAt: number | null;
  error: string | null;
  vault: VaultStatus | null;
  registered: boolean | null;
  /** the on-chain panic floor of the device key */
  minEpoch: bigint | null;
  personal: MandateStatus | null;
  /** personal mandate usable: not revoked / disabled, epoch >= the chain's panic floor */
  personalLive: boolean | null;
  hot: { address: `0x${string}`; balance: bigint | null } | null;
}

const EMPTY: ChainSnapshot = {
  key: '',
  reading: false,
  readAt: null,
  error: null,
  vault: null,
  registered: null,
  minEpoch: null,
  personal: null,
  personalLive: null,
  hot: null,
};

let snap: ChainSnapshot = EMPTY;
const listeners = new Set<() => void>();
let seq = 0;

function publish(s: ChainSnapshot): void {
  snap = s;
  for (const l of [...listeners]) l();
}

export function chainKeyOf(s: AppState): string {
  const d = s.device;
  return `${d?.keyId ?? '-'}:${d?.pinned.vault ?? '-'}:${s.settings.rpcUrl}:${s.settings.chainId}:${s.personal?.delegationHash ?? '-'}:${
    s.settings.deploymentsJson?.length ?? 0
  }`;
}

/** the tokens a vault balance is read for: the deployment's MockUSD and AUSD on Monad testnet */
export function vaultTokens(s: AppState): `0x${string}`[] {
  const dep = deploymentOf(s.settings).deployment;
  const out: `0x${string}`[] = [];
  if (dep && !/^0x0{40}$/i.test(dep.mockUsd)) out.push(dep.mockUsd);
  if (s.settings.chainId === 10143) out.push(AUSD_10143);
  return [...new Set(out)];
}

export async function refreshChain(): Promise<void> {
  const s = store.get();
  const key = chainKeyOf(s);
  const my = ++seq;
  publish({ ...(snap.key === key ? snap : { ...EMPTY, key }), key, reading: true });
  try {
    const pc = publicClientFor(s.settings);
    const dep = deploymentOf(s.settings).deployment;
    const d = s.device;
    const hotAddr = await hotKeyAddress();
    const [hotBal, vault, dev, personal] = await Promise.all([
      pc.getBalance({ address: hotAddr }).catch(() => null),
      d ? readVaultStatus(pc, dep, d.pinned.vault, vaultTokens(s)) : Promise.resolve(null),
      d && dep ? readDeviceStatus(pc, dep, d.keyId) : Promise.resolve(null),
      d && s.personal ? readMandateStatus(pc, d.pinned.enforcer, d.keyId, s.personal.delegationHash, s.personal.pulseTerms) : Promise.resolve(null),
    ]);
    if (my !== seq) return;
    const minEpoch = personal?.minEpoch ?? dev?.minEpoch ?? null;
    publish({
      key,
      reading: false,
      readAt: Date.now(),
      error: null,
      vault,
      registered: dev && d ? (dev.readable ? dev.registeredOwner?.toLowerCase() === d.k1Address.toLowerCase() : null) : null,
      minEpoch,
      personal,
      personalLive:
        !personal || !s.personal || personal.revoked === null || personal.minEpoch === null
          ? null
          : !personal.revoked && !personal.disabled && BigInt(s.personal.epoch) >= personal.minEpoch,
      hot: { address: hotAddr, balance: hotBal },
    });
  } catch (e) {
    if (my === seq) publish({ ...snap, key, reading: false, error: (e as Error).message });
  }
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** the shared chain snapshot; re-read when the device, vault, network or personal mandate changes, and every 30 s */
export function useChain(): ChainSnapshot {
  const s = useSyncExternalStore(subscribe, () => snap);
  const key = useSyncExternalStore(store.subscribe, () => chainKeyOf(store.get()));
  useEffect(() => {
    if (key !== snap.key || snap.readAt === null) void refreshChain();
    const t = setInterval(() => void refreshChain(), 30_000);
    return () => clearInterval(t);
  }, [key]);
  return s;
}
