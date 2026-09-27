// Activity: what happened to this vault and this device, newest first. On-chain events are scanned backwards in small
// block ranges (public RPCs cap eth_getLogs ranges) from the Ripar contracts and the vault's tokens, and kept only
// when they concern THIS vault / device key (the contracts are shared by every Ripar user); the payments this phone
// relayed are merged in from local records. Ported from companion/src/lib/activity.ts, plus ERC-20 transfers.
import { useSyncExternalStore } from 'react';
import { type Hex, type Log, type PublicClient, decodeEventLog, erc20Abi, getAddress } from 'viem';
import {
  DELEGATION_MANAGER,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
  firmwareToken,
  formatUnitsDevice,
  nativeCoin,
} from '@ripar/protocol';
import { vaultTokens } from './chainState';
import { publicClientFor } from './clients';
import { type AppState, type MandateRecord, type PaymentRecord, deploymentOf, store } from './store';

export type FeedKind =
  | 'Payment'
  | 'AutoSpend'
  | 'HumanCosigned'
  | 'TransferIn'
  | 'TransferOut'
  | 'Revoked'
  | 'Panicked'
  | 'LaneChanged'
  | 'Verdict'
  | 'AgentShielded';

export interface FeedAmount {
  value: bigint;
  decimals: number | null;
  symbol: string | null;
  sign: '+' | '-';
}

export interface FeedItem {
  id: string;
  kind: FeedKind;
  title: string;
  subtitle: string;
  /** who acted: this phone (co-signed by you), an agent, the device (kill switch), or someone else */
  actor: 'you' | 'agent' | 'device' | 'network';
  amount: FeedAmount | null;
  /** unix seconds, when known */
  at: number | null;
  block: bigint | null;
  tx: Hex | null;
  /** decoded event args / record fields, as strings, for the detail screen */
  fields: [string, string][];
  paymentId?: string;
}

export function amountLabel(a: FeedAmount): string {
  const n = a.decimals === null ? `${a.value} base units` : formatUnitsDevice(a.value, a.decimals, Math.min(a.decimals, 6));
  return `${a.sign}${n}${a.symbol && a.decimals !== null ? ` ${a.symbol}` : ''}`;
}

const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;

function tokenMeta(chainId: number, token: string, s: AppState): { decimals: number | null; symbol: string | null } {
  if (/^0x0{40}$/i.test(token)) {
    const n = nativeCoin(chainId);
    return { decimals: n?.decimals ?? 18, symbol: n?.symbol ?? 'MON' };
  }
  const t = firmwareToken(chainId, token);
  if (t) return { decimals: t.decimals, symbol: t.symbol };
  const dep = deploymentOf(s.settings).deployment;
  if (dep && dep.mockUsd.toLowerCase() === token.toLowerCase()) return { decimals: 6, symbol: 'mUSD' };
  return { decimals: null, symbol: null };
}

function mandateOf(s: AppState, dh: string): MandateRecord | null {
  const all = [...(s.personal ? [s.personal] : []), ...s.mandates];
  return all.find((m) => m.delegationHash.toLowerCase() === dh.toLowerCase()) ?? null;
}

export function paymentItem(p: PaymentRecord): FeedItem {
  const status =
    p.status === 'confirmed'
      ? 'Co-signed on your Ripar'
      : p.status === 'denied'
        ? 'Denied on the device'
        : p.status === 'failed'
          ? `Failed: ${p.error ?? 'error'}`
          : 'Waiting for the device';
  return {
    id: `pay:${p.id}`,
    kind: 'Payment',
    title: `To ${short(p.to)}`,
    subtitle: status,
    actor: 'you',
    amount: { value: BigInt(p.amount), decimals: p.decimals, symbol: p.symbol, sign: '-' },
    at: Math.floor((p.doneAt ?? p.createdAt) / 1000),
    block: null,
    tx: p.tx ?? null,
    fields: [
      ['Payee', p.to],
      ['Asset', p.asset === 'native' ? 'MON (native)' : p.asset],
      ['Status', p.status],
      ['Nonce', p.nonce],
      ...(p.bpm ? ([['Pulse', `${p.bpm} bpm`]] as [string, string][]) : []),
      ...(p.note ? ([['Note', p.note]] as [string, string][]) : []),
      ...(p.tx ? ([['Transaction', p.tx]] as [string, string][]) : []),
    ],
    paymentId: p.id,
  };
}

/** decodes one log into a feed item for this vault / device; null for anything else */
export function decodeFeedLog(log: Log, s: AppState): FeedItem | null {
  const d = s.device;
  const dep = deploymentOf(s.settings).deployment;
  if (!d || !dep || log.blockNumber === null || log.transactionHash === null) return null;
  const addr = log.address.toLowerCase();
  const vault = d.pinned.vault.toLowerCase();
  const keyId = d.keyId.toLowerCase();
  const base = { block: log.blockNumber, tx: log.transactionHash, at: null, id: `${log.transactionHash}:${log.logIndex}` };
  const str = (v: unknown) => (typeof v === 'bigint' ? v.toString() : String(v));
  const fieldsOf = (args: Record<string, unknown>) => Object.entries(args).map(([k, v]) => [k, str(v)] as [string, string]);

  if (vaultTokens(s).some((t) => t.toLowerCase() === addr)) {
    try {
      const ev = decodeEventLog({ abi: erc20Abi, data: log.data, topics: log.topics });
      if (ev.eventName !== 'Transfer') return null;
      const { from, to, value } = ev.args as { from: string; to: string; value: bigint };
      const inbound = to.toLowerCase() === vault;
      const outbound = from.toLowerCase() === vault;
      if (!inbound && !outbound) return null;
      const meta = tokenMeta(d.pinned.chainId, log.address, s);
      return {
        ...base,
        kind: inbound ? 'TransferIn' : 'TransferOut',
        title: inbound ? (/^0x0{40}$/i.test(from) ? 'Minted into the vault' : `From ${short(from)}`) : `To ${short(to)}`,
        subtitle: `${meta.symbol ?? 'token'} transfer`,
        actor: 'network',
        amount: { value, decimals: meta.decimals, symbol: meta.symbol, sign: inbound ? '+' : '-' },
        fields: [
          ['Token', getAddress(log.address)],
          ['From', getAddress(from)],
          ['To', getAddress(to)],
          ['Amount (base units)', value.toString()],
        ],
      };
    } catch {
      return null;
    }
  }

  const abi =
    addr === dep.enforcer.toLowerCase()
      ? PULSE_COSIGN_ENFORCER_ABI
      : addr === dep.relay.toLowerCase()
        ? RIPAR_REPUTATION_RELAY_ABI
        : addr === dep.sentinel.toLowerCase()
          ? RIPAR_SENTINEL_ABI
          : null;
  if (!abi) return null;
  let ev: { eventName: string; args: Record<string, unknown> };
  try {
    ev = decodeEventLog({ abi, data: log.data, topics: log.topics }) as unknown as { eventName: string; args: Record<string, unknown> };
  } catch {
    return null;
  }
  const a = ev.args ?? {};
  const lc = (v: unknown) => String(v).toLowerCase();
  switch (ev.eventName) {
    case 'AutoSpend':
    case 'HumanCosigned': {
      if (lc(a.delegator) !== vault) return null;
      if (lc(a.delegationManager) !== DELEGATION_MANAGER.toLowerCase()) return null;
      const m = mandateOf(s, String(a.delegationHash));
      const personal = !!s.personal && lc(a.delegationHash) === s.personal.delegationHash.toLowerCase();
      const meta = m ? { decimals: m.tokenDecimals, symbol: m.tokenSymbol } : { decimals: null, symbol: null };
      const auto = ev.eventName === 'AutoSpend';
      return {
        ...base,
        kind: ev.eventName,
        title: `To ${short(String(a.payee))}`,
        subtitle: auto ? `Agent paid on its own${m?.label ? ` · ${m.label}` : ''}` : personal ? 'You, co-signed on your Ripar' : `Agent, co-signed on your Ripar${m?.label ? ` · ${m.label}` : ''}`,
        actor: personal ? 'you' : 'agent',
        // a co-signed call may be in another asset than the mandate's: then the amount is shown in base units
        amount: { value: BigInt(a.amount as bigint), decimals: auto || personal ? meta.decimals : null, symbol: auto ? meta.symbol : null, sign: '-' },
        fields: fieldsOf(a),
      };
    }
    case 'Revoked':
    case 'Panicked':
      if (lc(a.keyId) !== keyId) return null;
      return {
        ...base,
        kind: ev.eventName,
        title: ev.eventName === 'Panicked' ? 'PANIC relayed' : 'Mandate revoked',
        subtitle: ev.eventName === 'Panicked' ? `Every mandate below epoch ${str(a.minEpoch)} is dead` : `Mandate ${short(String(a.delegationHash))}`,
        actor: 'device',
        amount: null,
        fields: fieldsOf(a),
      };
    case 'LaneChanged':
      if (lc(a.vault) !== vault) return null;
      return {
        ...base,
        kind: 'LaneChanged',
        title: a.open ? 'Agent lane reopened' : 'Agent lane closed',
        subtitle: 'RiparSentinel',
        actor: 'network',
        amount: null,
        fields: fieldsOf(a),
      };
    case 'Verdict':
    case 'AgentShielded':
      if (lc(a.keyId) !== keyId) return null;
      return {
        ...base,
        kind: ev.eventName,
        title: ev.eventName === 'AgentShielded' ? 'Agent reported' : a.approved ? 'Approval attested' : 'Denial filed',
        subtitle: `Agent ${str(a.agentId)} · ERC-8004 reputation`,
        actor: 'device',
        amount: null,
        fields: fieldsOf(a),
      };
    default:
      return null;
  }
}

export interface FeedState {
  key: string;
  items: FeedItem[];
  scanning: boolean;
  progress: number;
  fromBlock: bigint | null;
  toBlock: bigint | null;
  errors: string[];
  readAt: number | null;
}

let state: FeedState = { key: '', items: [], scanning: false, progress: 0, fromBlock: null, toBlock: null, errors: [], readAt: null };
const listeners = new Set<() => void>();
const set = (p: Partial<FeedState>) => {
  state = { ...state, ...p };
  for (const l of [...listeners]) l();
};
const blockTimes = new Map<string, number>();
let seq = 0;

function merge(chain: FeedItem[], s: AppState): FeedItem[] {
  const pays = s.payments.map(paymentItem);
  const payTx = new Set(pays.map((p) => p.tx?.toLowerCase()).filter(Boolean));
  // a relayed payment appears once: the local record (it knows the asset), not its HumanCosigned event as well
  const rest = chain.filter((c) => !(c.kind === 'HumanCosigned' && c.tx && payTx.has(c.tx.toLowerCase())));
  const all = [...pays, ...rest];
  return all.sort((x, y) => (y.at ?? Number.MAX_SAFE_INTEGER) - (x.at ?? Number.MAX_SAFE_INTEGER) || Number((y.block ?? 0n) - (x.block ?? 0n)));
}

async function stamp(pc: PublicClient, items: FeedItem[]): Promise<void> {
  const blocks = [...new Set(items.filter((i) => i.block !== null && i.at === null).map((i) => i.block!.toString()))].slice(0, 40);
  await Promise.all(
    blocks
      .filter((b) => !blockTimes.has(b))
      .map(async (b) => {
        try {
          const blk = await pc.getBlock({ blockNumber: BigInt(b) });
          blockTimes.set(b, Number(blk.timestamp));
        } catch {
          /* unknown time */
        }
      }),
  );
  for (const i of items) if (i.block !== null && i.at === null) i.at = blockTimes.get(i.block.toString()) ?? null;
}

/** rescans the recent blocks (settings.logLookback, in settings.logChunk ranges) */
export async function refreshFeed(): Promise<void> {
  const s = store.get();
  const dep = deploymentOf(s.settings).deployment;
  const key = `${s.device?.pinned.vault ?? '-'}:${s.settings.rpcUrl}`;
  const my = ++seq;
  if (!s.device || !dep) {
    set({ key, items: merge([], s), scanning: false, errors: [], readAt: Date.now() });
    return;
  }
  set({ key, scanning: true, progress: 0, errors: [], items: state.key === key ? state.items : merge([], s) });
  const pc = publicClientFor(s.settings);
  const found: FeedItem[] = [];
  const errors: string[] = [];
  try {
    const head = await pc.getBlockNumber({ cacheTime: 0 });
    const chunk = BigInt(Math.max(1, s.settings.logChunk));
    const lookback = BigInt(Math.max(1, s.settings.logLookback));
    const lowest = head - lookback + 1n > 0n ? head - lookback + 1n : 0n;
    const addresses = [dep.enforcer, dep.relay, dep.sentinel, ...vaultTokens(s)];
    const total = Number((head - lowest + chunk) / chunk);
    let done = 0;
    for (let to = head; to >= lowest; to -= chunk) {
      if (my !== seq) return;
      const from = to - chunk + 1n > lowest ? to - chunk + 1n : lowest;
      try {
        const logs = await pc.getLogs({ address: addresses, fromBlock: from, toBlock: to });
        for (const l of logs) {
          const it = decodeFeedLog(l, s);
          if (it) found.push(it);
        }
      } catch (e) {
        errors.push(`blocks ${from}-${to}: ${(e as Error).message.split('\n')[0]}`);
        if (errors.length > 3) break;
      }
      done++;
      if (done % 5 === 0 || to - chunk < lowest) {
        await stamp(pc, found);
        set({ items: merge([...found], store.get()), progress: done / total, fromBlock: from, toBlock: head });
      }
      if (from === 0n) break;
    }
    await stamp(pc, found);
    if (my !== seq) return;
    set({ items: merge(found, store.get()), scanning: false, progress: 1, fromBlock: lowest, toBlock: head, errors, readAt: Date.now() });
  } catch (e) {
    if (my === seq) set({ scanning: false, errors: [(e as Error).message.split('\n')[0] ?? 'error'], items: merge(found, store.get()), readAt: Date.now() });
  }
}

/** re-merges the local payments (after a send) without a rescan */
export function remergePayments(): void {
  const chain = state.items.filter((i) => i.kind !== 'Payment');
  set({ items: merge(chain, store.get()) });
}

export function useFeed(): FeedState {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => state,
  );
}

export function feedItem(id: string): FeedItem | null {
  return state.items.find((i) => i.id === id) ?? (id.startsWith('pay:') ? (store.get().payments.map(paymentItem).find((p) => p.id === id) ?? null) : null);
}

export { insightsOf, type Insights } from './insights';
