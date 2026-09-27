// Recent Ripar events via eth_getLogs, scanned backwards in small block ranges (public RPCs cap the range):
// AutoSpend / HumanCosigned (PulseCosignEnforcer; only those emitted for the canonical DelegationManager),
// Verdict (RiparReputationRelay), LaneChanged (RiparSentinel), plus Revoked / Panicked for the kill switch.
import { type Address, type Hex, type Log, type PublicClient, decodeEventLog } from 'viem';
import {
  type RiparDeployment,
  DELEGATION_MANAGER,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
} from '@ripar/protocol';

export type ActivityKind = 'AutoSpend' | 'HumanCosigned' | 'Verdict' | 'LaneChanged' | 'Revoked' | 'Panicked' | 'AgentShielded';

export interface ActivityItem {
  kind: ActivityKind;
  blockNumber: bigint;
  txHash: Hex;
  logIndex: number;
  args: Record<string, unknown>;
}

const ENF_EVENTS = new Set(['AutoSpend', 'HumanCosigned', 'Revoked', 'Panicked']);

/** decodes one log of a known Ripar contract; null for anything else (and for foreign DelegationManagers) */
export function decodeActivity(log: Log, dep: Pick<RiparDeployment, 'enforcer' | 'relay' | 'sentinel'>): ActivityItem | null {
  const addr = log.address.toLowerCase();
  const abi =
    addr === dep.enforcer.toLowerCase()
      ? PULSE_COSIGN_ENFORCER_ABI
      : addr === dep.relay.toLowerCase()
        ? RIPAR_REPUTATION_RELAY_ABI
        : addr === dep.sentinel.toLowerCase()
          ? RIPAR_SENTINEL_ABI
          : null;
  if (!abi || log.blockNumber === null || log.transactionHash === null) return null;
  let ev: { eventName: string; args: unknown };
  try {
    ev = decodeEventLog({ abi, data: log.data, topics: log.topics }) as { eventName: string; args: unknown };
  } catch {
    return null;
  }
  const kind = ev.eventName as ActivityKind;
  if (abi === PULSE_COSIGN_ENFORCER_ABI && !ENF_EVENTS.has(kind)) return null;
  if (abi === RIPAR_REPUTATION_RELAY_ABI && kind !== 'Verdict' && kind !== 'AgentShielded') return null;
  if (abi === RIPAR_SENTINEL_ABI && kind !== 'LaneChanged') return null;
  const args = (ev.args ?? {}) as Record<string, unknown>;
  // v1.1: indexers keep only the canonical DelegationManager's AutoSpend / HumanCosigned
  if ((kind === 'AutoSpend' || kind === 'HumanCosigned') && String(args.delegationManager).toLowerCase() !== DELEGATION_MANAGER.toLowerCase()) {
    return null;
  }
  return { kind, blockNumber: log.blockNumber, txHash: log.transactionHash, logIndex: log.logIndex ?? 0, args };
}

export interface ScanResult {
  items: ActivityItem[];
  fromBlock: bigint;
  toBlock: bigint;
  errors: string[];
}

/** scans [head - lookback, head] (or below `before`) in `chunk`-block ranges, newest first */
export async function scanActivity(
  pc: PublicClient,
  dep: RiparDeployment,
  opts: { chunk: number; lookback: number; before?: bigint; signal?: AbortSignal; onProgress?: (done: number, total: number) => void },
): Promise<ScanResult> {
  // cacheTime 0: viem caches the block number for 4 s, which would hide the newest blocks (a write just confirmed)
  const head = opts.before !== undefined ? opts.before - 1n : await pc.getBlockNumber({ cacheTime: 0 });
  const chunk = BigInt(Math.max(1, Math.floor(opts.chunk)));
  const lookback = BigInt(Math.max(1, Math.floor(opts.lookback)));
  const lowest = head - lookback + 1n > 0n ? head - lookback + 1n : 0n;
  const addresses: Address[] = [dep.enforcer, dep.relay, dep.sentinel];
  const items: ActivityItem[] = [];
  const errors: string[] = [];
  const total = Number((head - lowest + chunk) / chunk);
  let done = 0;
  for (let to = head; to >= lowest; to -= chunk) {
    if (opts.signal?.aborted) break;
    const from = to - chunk + 1n > lowest ? to - chunk + 1n : lowest;
    try {
      const logs = await pc.getLogs({ address: addresses, fromBlock: from, toBlock: to });
      for (const l of logs) {
        const it = decodeActivity(l, dep);
        if (it) items.push(it);
      }
    } catch (e) {
      errors.push(`blocks ${from}-${to}: ${(e as Error).message.split('\n')[0]}`);
      if (errors.length > 3) break;
    }
    done++;
    opts.onProgress?.(done, total);
    if (from === 0n) break;
  }
  items.sort((a, b) => (a.blockNumber === b.blockNumber ? b.logIndex - a.logIndex : a.blockNumber < b.blockNumber ? 1 : -1));
  return { items, fromBlock: lowest, toBlock: head, errors };
}
