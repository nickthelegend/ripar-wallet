// Activity: recent AutoSpend / HumanCosigned (canonical DelegationManager only), Verdict, LaneChanged, Revoked and
// Panicked events, read with eth_getLogs in small block ranges.
import { useRef, useState } from 'react';
import { PageHead } from '../App';
import { Button, Empty, Mark, Note } from '../components/ui';
import { type ActivityItem, anvilForkBlock, scanActivity } from '../lib/activity';
import { publicClientFor } from '../lib/clients';
import { amountText, errorText } from '../lib/format';
import { NETWORKS, explorerTxUrl } from '../lib/networks';
import { currentMandate, useDeployment, useStore } from '../lib/store';

type Filter = 'mine' | 'all';

const short = (x: unknown) => {
  const s = String(x);
  return s.length > 14 ? `${s.slice(0, 8)}...${s.slice(-4)}` : s;
};

export function Activity() {
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const mandate = useStore(currentMandate);
  const { deployment } = useDeployment();
  const explorer = NETWORKS[settings.network]?.explorer ?? null;
  const [items, setItems] = useState<ActivityItem[] | null>(null);
  const [range, setRange] = useState<{ from: bigint; to: bigint } | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('mine');
  const abort = useRef<AbortController | null>(null);

  const scan = async (older = false) => {
    if (!deployment) return;
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setBusy(true);
    setErrors([]);
    try {
      const pc = publicClientFor(settings);
      // on an anvil fork the Ripar contracts were deployed after the fork block: older blocks come from the public
      // RPC through anvil (slow) and hold nothing of ours
      const fork = settings.network === 'anvil-fork' ? await anvilForkBlock(pc) : null;
      const prev = older && items ? items : [];
      const r = await scanActivity(pc, deployment, {
        chunk: settings.logChunk,
        lookback: settings.logLookback,
        ...(older && range ? { before: range.from } : {}),
        ...(fork !== null ? { floor: fork + 1n } : {}),
        signal: ac.signal,
        onProgress: (d, t) => setProgress(`${d} / ${t} block ranges`),
        onItems: (found, from, to) => {
          if (ac.signal.aborted) return;
          setItems([...prev, ...found]);
          setRange((rg) => ({ from, to: older && rg ? rg.to : to }));
        },
      });
      setItems((xs) => (older && xs ? [...xs, ...r.items] : r.items));
      setRange((rg) => ({ from: r.fromBlock, to: older && rg ? rg.to : r.toBlock }));
      setErrors(r.errors);
    } catch (e) {
      setErrors([errorText(e)]);
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const mine = (it: ActivityItem): boolean => {
    if (!device) return false;
    const a = it.args;
    const v = device.pinned.vault.toLowerCase();
    if (it.kind === 'AutoSpend' || it.kind === 'HumanCosigned') return String(a.delegator).toLowerCase() === v;
    if (it.kind === 'LaneChanged') return String(a.vault).toLowerCase() === v;
    return String(a.keyId).toLowerCase() === device.keyId.toLowerCase();
  };

  const shown = (items ?? []).filter((i) => filter === 'all' || mine(i));
  const tok = (x: unknown) => (typeof x === 'bigint' ? amountText(x, mandate?.tokenDecimals ?? null, mandate?.tokenSymbol ?? null) : String(x));

  const describe = (it: ActivityItem): string => {
    const a = it.args;
    switch (it.kind) {
      case 'AutoSpend':
        return `Agent paid ${tok(a.amount)} to ${short(a.payee)} on its own (period spent ${tok(a.periodSpent)})`;
      case 'HumanCosigned':
        return `Co-signed payment of ${tok(a.amount)} to ${short(a.payee)}`;
      case 'Verdict':
        return `${a.approved ? 'Approval' : 'Denial'} filed for agent ${String(a.agentId)}`;
      case 'AgentShielded':
        return `Denial recorded for shielded agent ${String(a.agentId)}`;
      case 'LaneChanged':
        return `AUTO lane of ${short(a.vault)} ${a.open ? 'reopened' : `closed (reason ${String(a.reason)})`}`;
      case 'Revoked':
        return `Mandate ${short(a.delegationHash)} revoked`;
      case 'Panicked':
        return `PANIC: min epoch raised to ${String(a.minEpoch)}`;
    }
  };

  const TONE: Record<string, 'good' | 'bad' | 'warn' | 'plain' | 'spot'> = {
    AutoSpend: 'spot',
    HumanCosigned: 'good',
    Verdict: 'plain',
    AgentShielded: 'warn',
    LaneChanged: 'warn',
    Revoked: 'bad',
    Panicked: 'bad',
  };

  return (
    <div className="page">
      <PageHead
        title="Activity"
        lede="What happened on-chain: the agent's own spends, co-signed payments, verdicts on the agent, lane changes and kill-switch events."
      />
      {!deployment ? (
        <Empty title="Load the deployments first">The events come from the Ripar contracts listed in the deployments JSON.</Empty>
      ) : (
        <>
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <div className="segmented" role="radiogroup" aria-label="Show">
              <label>
                <input type="radio" name="flt" checked={filter === 'mine'} onChange={() => setFilter('mine')} />
                This vault and device
              </label>
              <label>
                <input type="radio" name="flt" checked={filter === 'all'} onChange={() => setFilter('all')} />
                Everything
              </label>
            </div>
            <div className="row">
              {progress && (
                <span className="small muted" role="status">
                  {progress}
                </span>
              )}
              <Button variant="primary" icon="refresh" busy={busy} onClick={() => void scan(false)}>
                {items ? 'Scan again' : `Scan the last ${settings.logLookback.toLocaleString('en-US')} blocks`}
              </Button>
            </div>
          </div>
          {errors.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <Note kind="caution" title="Some ranges failed">
                {errors.map((e) => (
                  <p key={e}>{e}</p>
                ))}
              </Note>
            </div>
          )}
          <div className="section" style={{ marginTop: 24 }}>
            {items === null ? (
              <Empty title="Not scanned yet">
                Public RPCs cap eth_getLogs, so the scan walks back {settings.logChunk} blocks at a time. Change the range
                on the Connect page.
              </Empty>
            ) : shown.length === 0 ? (
              <Empty title="No events in this range">
                Blocks {range?.from.toString()} to {range?.to.toString()}. Scan further back to look for older events.
              </Empty>
            ) : (
              <div className="ledger-wrap">
                <table className="ledger">
                  <thead>
                    <tr>
                      <th scope="col">Event</th>
                      <th scope="col">What happened</th>
                      <th scope="col" className="num">
                        Block
                      </th>
                      <th scope="col">
                        <span className="sr-only">Transaction</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((it) => {
                      const url = explorerTxUrl(explorer, it.txHash);
                      return (
                        <tr key={`${it.txHash}-${it.logIndex}`}>
                          <td>
                            <Mark tone={TONE[it.kind]}>{it.kind}</Mark>
                          </td>
                          <td>{describe(it)}</td>
                          <td className="num">{it.blockNumber.toString()}</td>
                          <td>
                            {url ? (
                              <a href={url} target="_blank" rel="noreferrer">
                                tx
                              </a>
                            ) : (
                              <code title={it.txHash}>{short(it.txHash)}</code>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {items !== null && range && range.from > 0n && (
              <div className="row" style={{ marginTop: 16 }}>
                <Button icon="chevronDown" busy={busy} onClick={() => void scan(true)}>
                  Older (before block {range.from.toString()})
                </Button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
