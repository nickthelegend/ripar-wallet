// The app's state: settings, the public identity of the paired device, the context it pinned, the mandates it signed
// (the phone's own "personal mandate" and the agents' mandates), the escalations it answered and the payments this
// phone relayed. Persisted with AsyncStorage (app-private storage). Nothing here is secret: no seed, no device key.
// The phone's hot key (gas payer + personal-mandate redeemer) lives apart, in expo-secure-store (lib/hotkey.ts).
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useSyncExternalStore } from 'react';
import { type RiparDeployment, parseDeployment } from '@ripar/protocol';
import { type NetworkId, NETWORKS } from './networks';

export type LinkChoice = 'qr' | 'ble' | 'emulator';

export interface Settings {
  network: NetworkId;
  rpcUrl: string;
  chainId: number;
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
  logChunk: number;
  logLookback: number;
  /** how requests reach the device: QR (default, air-gapped), Bluetooth fallback, or the emulator */
  link: LinkChoice;
  /** the Ripar the app connected to over Bluetooth last (id = MAC on Android) */
  bleDevice: { id: string; name: string } | null;
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

/** the context the device pinned at the pairing the user confirmed (= the pair request this app built) */
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
  relayPending?: boolean;
}

/** one escalation in progress (request shown, answer not delivered yet), persisted so a restart resumes it */
export interface EscalationWork {
  requestUr: string;
  delegationHash: `0x${string}`;
  nonce: string;
  expiry: string;
  agentBuilt: boolean;
  builtAt: number;
  answer?: { kind: 'cosign' | 'deny'; ur: string; at: number };
  agentAt?: number;
  agentError?: string;
  relayTx?: `0x${string}`;
}

/** a payment this phone made from the vault under the personal mandate (device co-signed, hot key redeemed) */
export interface PaymentRecord {
  id: string;
  to: `0x${string}`;
  /** 'native' or the ERC-20 address */
  asset: 'native' | `0x${string}`;
  symbol: string;
  decimals: number;
  amount: string;
  note: string;
  nonce: string;
  requestUr: string;
  cosignUr?: string;
  bpm?: number;
  status: 'building' | 'on-device' | 'cosigned' | 'sent' | 'confirmed' | 'failed' | 'denied';
  tx?: `0x${string}`;
  error?: string;
  createdAt: number;
  doneAt?: number;
}

export interface AppState {
  /** the onboarding carousel was seen */
  onboarded: boolean;
  settings: Settings;
  keysOnly: KeysOnly | null;
  device: PairedDevice | null;
  /** the phone's personal mandate: vault -> this phone's hot key, AUTO caps 0 (every payment needs the device) */
  personal: MandateRecord | null;
  /** the agents' mandates, oldest first (the device remembers only the last mandate it signed) */
  mandates: MandateRecord[];
  /** co-sign nonces handed out, per delegationHash (never reuse one: single-use per mandate on chain) */
  nonces: Record<string, string[]>;
  inbox: Record<string, InboxOutcome>;
  work: Record<string, EscalationWork>;
  payments: PaymentRecord[];
  /** delegationHash of the last mandate the device signed (personal or agent): the one it "remembers" */
  lastSignedMandate: `0x${string}` | null;
}

export const DEFAULT_SETTINGS: Settings = {
  network: 'monad-testnet',
  rpcUrl: NETWORKS['monad-testnet'].rpcUrl,
  chainId: NETWORKS['monad-testnet'].chainId,
  agentUrl: 'http://127.0.0.1:8787',
  agentToken: '',
  deploymentsUrl: '',
  deploymentsJson: null,
  frameMs: 300,
  fragLen: 70,
  logChunk: 100,
  logLookback: 3000,
  link: 'qr',
  bleDevice: null,
};

const INITIAL: AppState = {
  onboarded: false,
  settings: DEFAULT_SETTINGS,
  keysOnly: null,
  device: null,
  personal: null,
  mandates: [],
  nonces: {},
  inbox: {},
  work: {},
  payments: [],
  lastSignedMandate: null,
};

const KEY = 'ripar.mobile.state.v1';

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

export function hydrate(s: Partial<AppState>): AppState {
  return {
    ...INITIAL,
    ...s,
    settings: { ...DEFAULT_SETTINGS, ...(s.settings ?? {}) },
    mandates: Array.isArray(s.mandates) ? s.mandates : [],
    payments: Array.isArray(s.payments) ? s.payments : [],
    nonces: s.nonces && typeof s.nonces === 'object' ? s.nonces : {},
    inbox: recordOf<InboxOutcome>(s.inbox),
    work: recordOf<EscalationWork>(s.work),
  };
}

type Listener = () => void;

export class Store {
  private state: AppState;
  private listeners = new Set<Listener>();
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  loaded = false;

  constructor(
    initial: AppState = INITIAL,
    private readonly persist: ((json: string) => Promise<void>) | null = (json) => AsyncStorage.setItem(KEY, json),
  ) {
    this.state = initial;
  }

  /** loads the persisted state once at startup (a failed read starts clean rather than blocking the app) */
  async load(): Promise<void> {
    try {
      const raw = await AsyncStorage.getItem(KEY);
      if (raw) this.state = hydrate(JSON.parse(raw) as Partial<AppState>);
    } catch {
      /* unreadable state: start clean */
    }
    this.loaded = true;
    this.emit();
  }

  get(): AppState {
    return this.state;
  }

  set(patch: Partial<AppState> | ((s: AppState) => Partial<AppState>)): void {
    const p = typeof patch === 'function' ? patch(this.state) : patch;
    this.state = { ...this.state, ...p };
    this.schedule();
    this.emit();
  }

  setSettings(patch: Partial<Settings>): void {
    this.set((s) => ({ settings: { ...s.settings, ...patch } }));
  }

  /** forgets everything (the hot key is separate: see hotkey.ts) */
  reset(): void {
    this.state = { ...INITIAL, onboarded: true };
    this.schedule();
    this.emit();
  }

  private schedule(): void {
    if (!this.persist) return;
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      void this.persist?.(JSON.stringify(this.state)).catch(() => {});
    }, 150);
  }

  private emit(): void {
    for (const l of [...this.listeners]) l();
  }

  subscribe = (l: Listener): (() => void) => {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  };
}

export const store = new Store();

export function useStore<T>(select: (s: AppState) => T): T {
  return useSyncExternalStore(store.subscribe, () => select(store.get()));
}

/** the mandate the device remembers (the last one it signed), if this app has it */
export function rememberedMandate(s: AppState): MandateRecord | null {
  if (!s.lastSignedMandate) return null;
  const all = [...(s.personal ? [s.personal] : []), ...s.mandates];
  return all.find((m) => m.delegationHash.toLowerCase() === s.lastSignedMandate!.toLowerCase()) ?? null;
}

/** the current agent mandate: the last one the device signed for an agent */
export function currentAgentMandate(s: AppState): MandateRecord | null {
  return s.mandates.length ? s.mandates[s.mandates.length - 1]! : null;
}

// ------------------------------------------------------------------------------------------ deployments (derived)
export interface DeploymentState {
  deployment: RiparDeployment | null;
  error: string | null;
}

const depCache = new Map<string, DeploymentState>();

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
