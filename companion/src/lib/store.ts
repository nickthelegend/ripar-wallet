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
  /** the Inbox / Mandate pages ask the agent to run a planner step every 30 s while open */
  agentAutoRun: boolean;
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
  /** the payment the agent made with the co-sign, or the attestDenial relay of a deny */
  tx?: `0x${string}`;
  /** a deny: the on-chain relay (attestDenial) is still to be sent */
  relayPending?: boolean;
}

/**
 * One escalation in progress, persisted so a reload or a detour to another page resumes the same round: the request
 * shown to the device (its nonce stays tied to this escalation, so it can be shown again) and the device's verified
 * answer until the agent took it (co-sign) or the relay and the agent both have it (deny).
 */
export interface EscalationWork {
  /** the single-part ripar-cosign-req the device was shown */
  requestUr: string;
  delegationHash: `0x${string}`;
  nonce: string;
  expiry: string;
  /** true: the agent built the request (its nonce), false: this companion did */
  agentBuilt: boolean;
  builtAt: number;
  answer?: { kind: 'cosign' | 'deny'; ur: string; at: number };
  /** the agent accepted the answer */
  agentAt?: number;
  agentError?: string;
  /** attestDenial transaction of a deny */
  relayTx?: `0x${string}`;
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
  /** escalations in progress (request shown, answer not delivered yet), by escalation id */
  work: Record<string, EscalationWork>;
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
  agentAutoRun: false,
};

const INITIAL: AppState = {
  settings: DEFAULT_SETTINGS,
  deviceMode: 'emulator',
  keysOnly: null,
  device: null,
  mandates: [],
  nonces: {},
  inbox: {},
  work: {},
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
    inbox: recordOf<InboxOutcome>(s.inbox),
    work: recordOf<EscalationWork>(s.work),
  };
}

/** a persisted id-keyed record as a prototype-less object (an id such as "__proto__" is only ever an own key) */
function recordOf<T>(v: unknown): Record<string, T> {
  const out = Object.create(null) as Record<string, T>;
  if (v && typeof v === 'object' && !Array.isArray(v)) for (const [k, x] of Object.entries(v)) out[k] = x as T;
  return out;
}

/** the own entry `k` of an id-keyed record (never an inherited Object.prototype member) */
export function ownEntry<T>(rec: Record<string, T> | null | undefined, k: string): T | undefined {
  return rec && Object.prototype.hasOwnProperty.call(rec, k) ? rec[k] : undefined;
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
