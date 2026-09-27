// Where the user is in the setup, from real on-chain state (not only from what this browser remembers): the device is
// registered, the vault has code and holds funds, the mandate is live and the agent holds it. Read once per change of
// device / network and whenever a page asks (refreshSetup()), shared by the contents rail and the "Next" buttons.
import { useEffect, useSyncExternalStore } from 'react';
import { publicClientFor } from './clients';
import { readDeviceStatus, readMandateStatus, readVaultStatus } from './reads';
import { type AppState, currentMandate, deploymentOf, store } from './store';

export interface SetupStatus {
  /** the key the status was read for (device keyId + vault + rpc) */
  key: string;
  reading: boolean;
  /** null = unknown (not read yet, or the read failed) */
  registered: boolean | null;
  vaultDeployed: boolean | null;
  /** the vault holds some of the mandate token / MockUSD, or native coin */
  vaultFunded: boolean | null;
  mandateLive: boolean | null;
  error: string | null;
}

const EMPTY: SetupStatus = { key: '', reading: false, registered: null, vaultDeployed: null, vaultFunded: null, mandateLive: null, error: null };

let status: SetupStatus = EMPTY;
const listeners = new Set<() => void>();
let seq = 0;

function publish(s: SetupStatus): void {
  status = s;
  for (const l of [...listeners]) l();
}

function keyOf(s: AppState): string {
  const d = s.device;
  return d ? `${d.keyId}:${d.pinned.vault}:${s.settings.rpcUrl}:${currentMandate(s)?.delegationHash ?? ''}` : '';
}

/** reads the setup state again (after a write, or when a page opens) */
export async function refreshSetup(): Promise<void> {
  const s = store.get();
  const key = keyOf(s);
  const dep = deploymentOf(s.settings).deployment;
  if (!s.device || !dep) {
    publish({ ...EMPTY, key });
    return;
  }
  const my = ++seq;
  publish({ ...(status.key === key ? status : { ...EMPTY, key }), reading: true });
  try {
    const pc = publicClientFor(s.settings);
    const d = s.device;
    const m = currentMandate(s);
    const tokens = [dep.mockUsd, ...(m && !/^0x0{40}$/i.test(m.token) ? [m.token] : [])].filter((t) => !/^0x0{40}$/i.test(t)) as `0x${string}`[];
    const [dev, vault, ms] = await Promise.all([
      readDeviceStatus(pc, dep, d.keyId),
      readVaultStatus(pc, dep, d.pinned.vault, [...new Set(tokens)]),
      m ? readMandateStatus(pc, d.pinned.enforcer, d.keyId, m.delegationHash, m.pulseTerms) : Promise.resolve(null),
    ]);
    if (my !== seq) return;
    const funded =
      vault.native === null && vault.tokens.every((t) => t.balance === null)
        ? null
        : (vault.native ?? 0n) > 0n || vault.tokens.some((t) => (t.balance ?? 0n) > 0n);
    publish({
      key,
      reading: false,
      registered: dev.readable ? dev.registeredOwner?.toLowerCase() === d.k1Address.toLowerCase() : null,
      vaultDeployed: vault.deployed,
      vaultFunded: funded,
      mandateLive:
        ms === null || !m
          ? null
          : ms.revoked === null || ms.minEpoch === null
            ? null
            : !ms.revoked && !ms.disabled && BigInt(m.epoch) >= ms.minEpoch,
      error: null,
    });
  } catch (e) {
    if (my === seq) publish({ ...status, key, reading: false, error: (e as Error).message });
  }
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** the shared setup status; re-read when the device, vault, network or mandate changes */
export function useSetupStatus(): SetupStatus {
  const s = useSyncExternalStore(subscribe, () => status);
  const key = useSyncExternalStore(store.subscribe, () => keyOf(store.get()));
  useEffect(() => {
    if (key !== status.key || (!status.reading && status.registered === null && status.vaultDeployed === null)) void refreshSetup();
  }, [key]);
  return s;
}
