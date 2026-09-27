// The companion's state: settings, the public identity of the paired device, the context it pinned, the mandate it
// signed and the escalations it answered. Persisted to localStorage. Nothing here is secret: no seed, no private key
// (the EMULATOR's demo NVS lives in its own key, see device/emulator.ts).
import { useSyncExternalStore } from 'react';
import { type RiparDeployment, parseDeployment } from '@ripar/protocol';
import { type NetworkId, NETWORKS, ANVIL_DEV_ACCOUNT } from './networks';
import { loadJson, saveJson } from './storage';

export type CourierKind = 'injected' | 'anvil';
export type DeviceMode = 'hardware' | 'emulator';
export type Theme = 'system' | 'light' | 'dark';

export interface Settings {
  network: NetworkId;
  rpcUrl: string;
  chainId: number;
  courier: CourierKind;
  anvilAccount: `0x${string}`;
  agentUrl: string;
  /** the agent's AGENT_API_TOKEN, when it has one (a bearer token for its API, not a key) */
  agentToken: string;
  deploymentsUrl: string;
  /** the deployments JSON text last loaded (URL or paste) */
  deploymentsJson: string | null;
  /** ms per QR frame of a multipart request (the protocol suggests ~300) */
  frameMs: number;
  /** multipart fragment size in bytes (60-80 per the protocol) */
  fragLen: number;
  /** eth_getLogs block range per request, and how far back Activity looks */
  logChunk: number;
  logLookback: number;
  theme: Theme;
}

/** the device keys as the keys-only pairing QR shows them (nothing signed, nothing pinned) */
export interface KeysOnly {
  k1Address: `0x${string}`;
  p1Key: `0x${string}`;
  keyId: `0x${string}`;
  firmwareId: `0x${string}`;
  emulator: boolean;
  readAt: number;
}

/** the context the device pinned at the pairing the user confirmed (= the pair request this companion built) */
export interface PinnedContext {
  chainId: number;
  registry: `0x${string}`;
  manager: `0x${string}`;
  enforcer: `0x${string}`;
  sentinel: `0x${string}`;
  relay: `0x${string}`;
  vault: `0x${string}`;
}

export interface PairedDevice {
  k1Address: `0x${string}`;
  p1Key: `0x${string}`;
  px: `0x${string}`;
  py: `0x${string}`;
  keyId: `0x${string}`;
  firmwareId: `0x${string}`;
  emulator: boolean;
  p1Signature: `0x${string}`;
  k1Signature: `0x${string}`;
  bindDigest: `0x${string}`;
  pinned: PinnedContext;
  pairedAt: number;
  /** the ripar-pair-req UR the device confirmed (to re-verify later) */
  requestUr: string;
  registeredTx?: `0x${string}`;
}

/** JSON-safe framework Delegation (salt as a decimal string) */
export interface DelegationJson {
  delegate: `0x${string}`;
  delegator: `0x${string}`;
  authority: `0x${string}`;
  caveats: { enforcer: `0x${string}`; terms: `0x${string}`; args: `0x${string}` }[];
  salt: string;
  signature: `0x${string}`;
}

export interface MandateRecord {
  delegation: DelegationJson;
  delegationHash: `0x${string}`;
  /** the pulse caveat's 288-byte terms */
  pulseTerms: `0x${string}`;
  agent: `0x${string}`;
  agentId: string | null;
  label: string;
  token: `0x${string}`;
  tokenSymbol: string | null;
  tokenDecimals: number | null;
  epoch: string;
  /** the ripar-mandate-req the device signed and its eth-signature answer (what the agent verifies) */
  requestUr: string;
  signatureUr: string;
  signedAt: number;
  sentToAgentAt?: number;
  agentError?: string;
}

export interface InboxOutcome {
  status: 'cosigned' | 'denied' | 'failed';
  at: number;
  detail: string;
  tx?: `0x${string}`;
}

export interface AppState {
  settings: Settings;
  deviceMode: DeviceMode;
  keysOnly: KeysOnly | null;
  device: PairedDevice | null;
  mandates: MandateRecord[];
  /** co-sign nonces handed out, per delegationHash (never reuse one: v1.2 single-use per mandate) */
  nonces: Record<string, string[]>;
  inbox: Record<string, InboxOutcome>;
}

export const DEFAULT_SETTINGS: Settings = {
  network: 'monad-testnet',
  rpcUrl: NETWORKS['monad-testnet'].rpcUrl,
  chainId: NETWORKS['monad-testnet'].chainId,
  courier: 'injected',
  anvilAccount: ANVIL_DEV_ACCOUNT,
  agentUrl: 'http://127.0.0.1:8787',
  agentToken: '',
  deploymentsUrl: '',
  deploymentsJson: null,
  frameMs: 300,
  fragLen: 70,
  logChunk: 100,
  logLookback: 3000,
  theme: 'system',
};

const INITIAL: AppState = {
  settings: DEFAULT_SETTINGS,
  deviceMode: 'emulator',
  keysOnly: null,
  device: null,
  mandates: [],
  nonces: {},
  inbox: {},
};

const KEY = 'state.v1';

function load(): AppState {
  const s = loadJson<Partial<AppState>>(KEY, {});
  return {
    ...INITIAL,
    ...s,
    settings: { ...DEFAULT_SETTINGS, ...(s.settings ?? {}) },
    mandates: Array.isArray(s.mandates) ? s.mandates : [],
    nonces: s.nonces && typeof s.nonces === 'object' ? s.nonces : {},
    inbox: s.inbox && typeof s.inbox === 'object' ? s.inbox : {},
  };
}

type Listener = () => void;

class Store {
  private state: AppState;
  private listeners = new Set<Listener>();

  constructor(initial?: AppState) {
    this.state = initial ?? load();
  }

  get(): AppState {
    return this.state;
  }

  set(patch: Partial<AppState> | ((s: AppState) => Partial<AppState>)): void {
    const p = typeof patch === 'function' ? patch(this.state) : patch;
    this.state = { ...this.state, ...p };
    saveJson(KEY, this.state);
    for (const l of this.listeners) l();
  }

  setSettings(patch: Partial<Settings>): void {
    this.set((s) => ({ settings: { ...s.settings, ...patch } }));
  }

  subscribe = (l: Listener): (() => void) => {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  };
}

export const store = new Store();

export function useStore<T>(select: (s: AppState) => T): T {
  return useSyncExternalStore(store.subscribe, () => select(store.get()), () => select(store.get()));
}

/** the current mandate: the last one the device signed (the only one the device remembers) */
export function currentMandate(s: AppState): MandateRecord | null {
  return s.mandates.length ? s.mandates[s.mandates.length - 1]! : null;
}

// ------------------------------------------------------------------------------------------ deployments (derived)
export interface DeploymentState {
  deployment: RiparDeployment | null;
  error: string | null;
}

const depCache = new Map<string, DeploymentState>();

/** the parsed deployments JSON for the configured chain (memoized on the raw text) */
export function deploymentOf(settings: Settings): DeploymentState {
  const raw = settings.deploymentsJson;
  if (!raw) return { deployment: null, error: null };
  const k = `${settings.chainId}:${raw}`;
  let v = depCache.get(k);
  if (!v) {
    try {
      v = { deployment: parseDeployment(raw, settings.chainId), error: null };
    } catch (e) {
      v = { deployment: null, error: (e as Error).message };
    }
    depCache.set(k, v);
  }
  return v;
}

export function useDeployment(): DeploymentState {
  const settings = useStore((s) => s.settings);
  return deploymentOf(settings);
}
