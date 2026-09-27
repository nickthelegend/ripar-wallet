// Inbox: the agent's escalations (payments the AUTO path refused). Each one becomes a ripar-cosign-req with a single-use
// nonce; the device answers with a co-sign (HUMAN caveat args, posted back to the agent) or, from its DENY + REPORT
// AGENT review (hold SIGN 2 s on the co-sign review), with a signed deny: handed to the agent at once and relayed to the
// reputation relay. Every round is persisted (store.work), so a reload or a detour resumes it: the request shown to the
// device keeps its nonce for this escalation, and an answer is retried until the agent and the relay have it.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CosignNonceTracker, decodeErc20, firmwareToken, nativeCoin, toChecksumAddress } from '@ripar/protocol';
import { PageHead } from '../App';
import { AgentRun } from '../components/AgentRun';
import { DeviceExchangePanel } from '../components/DeviceExchangePanel';
import { DemoTokenNote, ReviewPanel } from '../components/Review';
import { TxAction } from '../components/TxAction';
import { Button, Empty, Figure, Hex, Mark, Note, Procedure, Spec, Step, type StepState } from '../components/ui';
import { type AgentClient, type Escalation, agentClientOf } from '../lib/agent';
import { attestDenialWrite } from '../lib/chain';
import { publicClientFor } from '../lib/clients';
import { amountText, ago, errorText, utcText } from '../lib/format';
import {
  type CosignOutcome,
  type CosignPlan,
  acceptCosignAnswer,
  adoptAgentRequest,
  answersCosign,
  checkEscalation,
  nonceConflict,
  planCosign,
  resumePlan,
} from '../lib/flows/cosign';
import { NETWORKS, explorerTxUrl } from '../lib/networks';
import { nonceUsed, readMandateStatus, readToken } from '../lib/reads';
import { previewCosign } from '../lib/review-preview';
import { useSetupStatus } from '../lib/setup';
import { type AppState, type EscalationWork, currentMandate, ownEntry, store, useStore } from '../lib/store';

const REASON_TEXT: Record<string, string> = {
  'payee-redirect': 'the payee differs from the invoice of record',
  'chain-human-required': 'the enforcer refused the AUTO path',
  'chain-lane-closed': 'the sentinel closed the AUTO lane',
  'not-meterable': 'not an AUTO-meterable payment',
  'lane-closed': 'the sentinel closed the AUTO lane',
  'per-tx-cap': 'above the per-transaction cap',
  'new-payee': 'a payee never co-signed before',
  'period-cap': 'the period budget is used up',
  other: 'the agent asks for a co-sign',
};

function describe(e: Escalation, s: AppState): { amount: string; payee: string; kind: string } {
  const c = decodeErc20(e.call.callData);
  const m = currentMandate(s);
  const chain = Number(e.chainId);
  if (c.kind === 'none') {
    const n = nativeCoin(chain);
    return { amount: amountText(e.call.value, n?.decimals ?? 18, n?.symbol ?? 'MON'), payee: e.call.target, kind: 'native send' };
  }
  if (c.kind === 'unknown') return { amount: 'unknown call', payee: e.call.target, kind: 'unknown calldata' };
  const listed = firmwareToken(chain, e.call.target);
  const meta = listed
    ? { d: listed.decimals, s: listed.symbol }
    : m && m.token.toLowerCase() === e.call.target.toLowerCase()
      ? { d: m.tokenDecimals, s: m.tokenSymbol }
      : { d: null, s: null };
  return { amount: amountText(c.amount, meta.d, meta.s), payee: toChecksumAddress(c.to), kind: c.kind };
}

const shortAddr = (a: string) => `${a.slice(0, 10)}...${a.slice(-6)}`;

/** persist a change of one escalation's work record */
function setWork(id: string, patch: Partial<EscalationWork> | null): void {
  store.set((s) => {
    const work = { ...s.work };
    if (patch === null) delete work[id];
    else {
      const cur = ownEntry(s.work, id);
      if (!cur && !('requestUr' in patch)) return {};
      work[id] = { ...(cur as EscalationWork), ...patch };
    }
    return { work };
  });
}

function setOutcome(id: string, o: AppState['inbox'][string]): void {
  store.set((s) => ({ inbox: { ...s.inbox, [id]: o } }));
}

export function Inbox() {
  const state = useStore((s) => s);
  const { settings, device, inbox, work } = state;
  const mandate = currentMandate(state);
  const setup = useSetupStatus();
  const explorer = NETWORKS[settings.network]?.explorer ?? null;
  const [items, setItems] = useState<Escalation[]>([]);
  const [rejected, setRejected] = useState<{ raw: unknown; error: string }[]>([]);
  const [agentErr, setAgentErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [selId, setSelId] = useState<string | null>(null);
  const detailRef = useRef<HTMLElement>(null);

  const client = useMemo(() => (settings.agentUrl ? agentClientOf(settings) : null), [settings.agentUrl, settings.agentToken]);

  const poll = useCallback(async () => {
    if (!client) return;
    setLoading(true);
    try {
      const r = await client.escalations();
      setItems(r.items);
      setRejected(r.rejected);
      setAgentErr(null);
      setLoaded(true);
    } catch (e) {
      setAgentErr(errorText(e));
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void poll();
    const t = setInterval(() => void poll(), 5000);
    const close = client?.stream(
      (e) => setItems((xs) => [e, ...xs.filter((x) => x.id !== e.id)]),
      () => {},
    );
    return () => {
      clearInterval(t);
      close?.();
    };
  }, [client, poll]);

  const select = (id: string | null) => {
    setSelId(id);
    if (id) {
      // on a phone the detail replaces the list: bring its heading into view and focus
      requestAnimationFrame(() => {
        const h = detailRef.current?.querySelector('h2');
        if (h instanceof HTMLElement) {
          h.focus({ preventScroll: true });
          h.scrollIntoView({ block: 'start', behavior: 'smooth' });
        }
      });
    }
  };

  const open = (e: Escalation) => e.status === 'pending' || e.status === 'open';
  // waiting: open at the agent and not answered here, or answered here but not yet delivered (never lost from view)
  const pending = items.filter((e) => {
    const o = ownEntry(inbox, e.id);
    const w = ownEntry(work, e.id);
    return (open(e) && !o) || (w?.answer && (!w.agentAt || (w.answer.kind === 'deny' && !w.relayTx)));
  });
  const handled = items.filter((e) => !pending.includes(e));
  const sel = items.find((e) => e.id === selId) ?? null;

  const statusMark = (e: Escalation) => {
    const w = ownEntry(work, e.id);
    const o = ownEntry(inbox, e.id);
    if (w?.answer && !w.agentAt) return <Mark tone="bad">NOT DELIVERED</Mark>;
    if (w?.answer?.kind === 'deny' && !w.relayTx) return <Mark tone="warn">DENIED, RELAY PENDING</Mark>;
    if (o) return <Mark tone={o.status === 'cosigned' ? 'good' : o.status === 'denied' ? 'bad' : 'plain'}>{o.status.toUpperCase()}</Mark>;
    if (!open(e)) return <Mark tone={e.status === 'executed' ? 'good' : e.status === 'denied' ? 'bad' : 'plain'}>{e.status.toUpperCase()}</Mark>;
    if (w) return <Mark tone="warn">ON THE DEVICE</Mark>;
    return <Mark tone="warn">{e.reason === 'other' ? 'ASK' : e.reason.toUpperCase()}</Mark>;
  };

  return (
    <div className="page">
      <PageHead
        title="Inbox"
        lede="Payments your agent could not make on its own. Each one waits for your thumb: approve it on the device, or hold SIGN 2 s on its review to open the device's DENY + REPORT AGENT review and sign a denial that is filed against the agent."
      />
      {!device && <Note kind="caution">Pair a device first: a co-sign names the device's pinned contracts.</Note>}
      {device && !mandate && (
        <Note kind="caution" title="No mandate yet">
          <p>
            The agent pays nothing and asks nothing until it holds a mandate. <a href="#/mandate">Sign one on the Mandate page</a>.
          </p>
        </Note>
      )}
      {mandate && !mandate.sentToAgentAt && (
        <Note kind="caution" title="The agent does not have the mandate">
          <p>
            It was signed but not delivered. <a href="#/mandate">Send it to the agent on the Mandate page</a>.
          </p>
        </Note>
      )}
      {device && setup.vaultDeployed === false && (
        <Note kind="caution" title="Vault not deployed">
          <p>
            The agent cannot pay from a vault without code (neither AUTO nor co-signed). <a href="#/vault">Deploy and fund it</a>.
          </p>
        </Note>
      )}
      {agentErr && (
        <Note kind="warning" alert>
          {agentErr}
        </Note>
      )}

      <div className={`cols-wide inbox-cols${sel ? ' has-detail' : ''}`}>
        <section aria-label="Escalations" className="inbox-listcol">
          <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
            <h2 style={{ fontSize: 'var(--t-lg)' }}>Waiting ({pending.length})</h2>
            <Button size="small" icon="refresh" busy={loading} onClick={() => void poll()}>
              Refresh
            </Button>
          </div>
          {pending.length === 0 ? (
            <Empty title={loaded || !client ? 'Nothing waiting' : 'Reading the agent...'}>
              <p>
                The agent pays due invoices by itself inside the mandate's caps. When one hits a cap, a new payee or a
                closed lane, it lands here. The agent only looks at its invoices when it runs a planner step: ask it now,
                or every 30 s. This page checks the agent every 5 s.
              </p>
              <AgentRun onRan={() => void poll()} />
            </Empty>
          ) : (
            <>
              <ul className="inbox-list">
                {pending.map((e) => {
                  const d = describe(e, state);
                  return (
                    <li key={e.id}>
                      <button type="button" className="inbox-item" aria-current={selId === e.id} onClick={() => select(e.id)}>
                        <span className="amt">{d.amount}</span>
                        {statusMark(e)}
                        <span className="sub">
                          to {shortAddr(d.payee)} · {REASON_TEXT[e.reason]}
                          {e.createdAt ? ` · ${ago(e.createdAt)}` : ''}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              <details className="paste" style={{ marginTop: 12 }}>
                <summary>Ask the agent to run</summary>
                <AgentRun onRan={() => void poll()} />
              </details>
            </>
          )}
          {handled.length > 0 && (
            <>
              <h2 style={{ fontSize: 'var(--t-lg)', margin: '24px 0 8px' }}>Answered</h2>
              <ul className="inbox-list">
                {handled.slice(0, 30).map((e) => {
                  const d = describe(e, state);
                  return (
                    <li key={e.id}>
                      <button type="button" className="inbox-item" aria-current={selId === e.id} onClick={() => select(e.id)}>
                        <span>{d.amount}</span>
                        {statusMark(e)}
                        <span className="sub">to {shortAddr(d.payee)}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </>
          )}
          {rejected.length > 0 && (
            <Note kind="caution" title={`${rejected.length} malformed`}>
              <p>The agent sent escalations this page refuses to act on: {rejected[0]!.error}</p>
            </Note>
          )}
        </section>

        {sel && (
          <section aria-label="Escalation" className="stack inbox-detail" ref={detailRef}>
            <button type="button" className="btn quiet small back-narrow" onClick={() => setSelId(null)}>
              Back to the inbox
            </button>
            {device ? (
              <EscalationDetail key={sel.id} e={sel} explorer={explorer} client={client} onDone={() => void poll()} />
            ) : (
              <Empty title="Pair a device first" />
            )}
          </section>
        )}
      </div>
    </div>
  );
}

function EscalationDetail({
  e,
  explorer,
  client,
  onDone,
}: {
  e: Escalation;
  explorer: string | null;
  client: AgentClient | null;
  onDone: () => void;
}) {
  const state = useStore((s) => s);
  const { settings, device } = state;
  const mandate = currentMandate(state);
  const outcomeRec = ownEntry(state.inbox, e.id);
  const work = ownEntry(state.work, e.id);
  const check = checkEscalation(e, device, mandate);
  const d = describe(e, state);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [posting, setPosting] = useState(false);

  // the persisted round: the request shown before (same req-id, same nonce) and the device's answer, if any
  const resumed = useMemo((): { plan: CosignPlan | null; error: string | null } => {
    if (!work || !device) return { plan: null, error: null };
    try {
      return { plan: resumePlan(work.requestUr, e, device, settings.fragLen), error: null };
    } catch (x) {
      return { plan: null, error: errorText(x) };
    }
  }, [work?.requestUr, e, device, settings.fragLen]);
  const plan = resumed.plan;
  const outcome = useMemo((): CosignOutcome | null => {
    if (!plan || !work?.answer || !device) return null;
    try {
      return acceptCosignAnswer(work.answer.ur, plan, device, mandate);
    } catch {
      return null;
    }
  }, [plan, work?.answer?.ur, device, mandate]);

  const nowSec = Math.floor(Date.now() / 1000);
  const expired = !!plan && plan.expiry <= BigInt(nowSec) && !work?.answer;

  const deliverCosign = useCallback(
    async (o: Extract<CosignOutcome, { kind: 'cosign' }>) => {
      if (!client) {
        setErr('No agent configured (Connect page): the co-sign is kept here until it can be delivered.');
        return;
      }
      setPosting(true);
      try {
        const r = await client.postCosign(e.id, o.answer);
        setOutcome(e.id, { status: 'cosigned', at: Date.now(), detail: `pulse ${o.bpm} bpm`, ...(r.txHash ? { tx: r.txHash } : {}) });
        setWork(e.id, null);
        setErr(null);
        onDone();
      } catch (x) {
        const msg = errorText(x);
        if (/\((already_executed|tx_pending|in_progress)\)/.test(msg)) {
          // the agent already has it (an earlier hand-over whose answer was lost): it redeems or redeemed it
          setOutcome(e.id, { status: 'cosigned', at: Date.now(), detail: `pulse ${o.bpm} bpm; ${msg}` });
          setWork(e.id, null);
          setErr(null);
          onDone();
          return;
        }
        setWork(e.id, { agentError: msg });
        setErr(`Co-signed on the device, but the agent did not take it yet: ${msg}. The co-sign is kept here; retry below.`);
      } finally {
        setPosting(false);
      }
    },
    [client, e.id, onDone],
  );

  const deliverDeny = useCallback(
    async (o: Extract<CosignOutcome, { kind: 'deny' }>, attestTx: `0x${string}` | null) => {
      if (!client) return;
      setPosting(true);
      try {
        await client.postDeny(e.id, { ...o.answer, attestTx });
        const relayTx = attestTx ?? ownEntry(store.get().work, e.id)?.relayTx;
        setOutcome(e.id, { status: 'denied', at: Date.now(), detail: 'device deny', ...(relayTx ? { tx: relayTx } : { relayPending: true }) });
        // done once both the agent and the relay have it; until then the round stays open here
        if (relayTx) setWork(e.id, null);
        else setWork(e.id, { agentAt: Date.now(), agentError: undefined });
        setErr(null);
        onDone();
      } catch (x) {
        setWork(e.id, { agentError: errorText(x) });
      } finally {
        setPosting(false);
      }
    },
    [client, e.id, onDone],
  );

  // an answer that was never delivered (the page was left, the agent was down): try again once on opening it
  const retried = useRef(false);
  useEffect(() => {
    if (retried.current || !outcome || !work?.answer || work.agentAt) return;
    retried.current = true;
    if (outcome.kind === 'cosign') void deliverCosign(outcome);
    else void deliverDeny(outcome, work.relayTx ?? null);
  }, [outcome, work?.answer, work?.agentAt, work?.relayTx, deliverCosign, deliverDeny]);

  if (!device) return null;

  const prepare = async (fresh = false) => {
    setBusy(true);
    setErr(null);
    try {
      const pc = publicClientFor(settings);
      const dh = e.delegationHash;
      const now = Math.floor(Date.now() / 1000);
      // fail closed: a nonce whose on-chain state cannot be read is never shown to the device
      const usedOnChain = async (n: bigint): Promise<boolean> => {
        try {
          return await nonceUsed(pc, device.pinned.enforcer, dh, n);
        } catch (x) {
          throw new Error(`Cannot confirm on-chain that nonce ${n} is unused (${errorText(x)}). Nothing was shown to the device; retry when the RPC answers.`);
        }
      };
      const remember = (p: CosignPlan, agentBuilt: boolean) =>
        store.set((s) => ({
          nonces: { ...s.nonces, [dh.toLowerCase()]: [...new Set([...(s.nonces[dh.toLowerCase()] ?? []), p.nonce.toString()])] },
          work: {
            ...s.work,
            [e.id]: {
              requestUr: p.request.ur,
              delegationHash: dh,
              nonce: p.nonce.toString(),
              expiry: p.expiry.toString(),
              agentBuilt,
              builtAt: Date.now(),
            },
          },
        }));
      if (e.request) {
        // the agent built the request (and verifies the device's answer against exactly it): check it, then relay it.
        // Showing it again for the SAME escalation is fine (after a reload or a detour): one nonce, one redemption.
        const p = adoptAgentRequest(e, device, { now, fragLen: settings.fragLen });
        if (await usedOnChain(p.nonce)) {
          throw new Error(`Nonce ${p.nonce} was already used on-chain for this mandate: this request can only revert (CosignReplayed). Ask the agent to run again; it closes this escalation and asks with a new nonce.`);
        }
        const clash = nonceConflict(e.id, dh, p.nonce, store.get().work);
        if (clash) throw new Error(`The agent reuses a nonce: ${clash}. Not shown to the device.`);
        remember(p, true);
        return;
      }
      // the companion builds it: a fresh single-use nonce, never one handed out before, never one the chain has seen
      const tracker = new CosignNonceTracker();
      for (const n of store.get().nonces[dh.toLowerCase()] ?? []) tracker.markUsed(dh, n);
      for (const w of Object.values(store.get().work)) if (w.delegationHash.toLowerCase() === dh.toLowerCase()) tracker.markUsed(dh, w.nonce);
      if (fresh && work) tracker.markUsed(dh, work.nonce);
      const nonce = await tracker.nextUnused(dh, usedOnChain);
      const budget =
        mandate && mandate.delegationHash.toLowerCase() === dh.toLowerCase()
          ? (await readMandateStatus(pc, device.pinned.enforcer, device.keyId, dh, mandate.pulseTerms)).budget
          : null;
      const call = decodeErc20(e.call.callData);
      const tokenMeta =
        call.kind !== 'none' && call.kind !== 'unknown' && !firmwareToken(Number(e.chainId), e.call.target)
          ? await readToken(pc, e.call.target, device.pinned.vault).then((t) => ({ decimals: t.decimals, symbol: t.symbol }))
          : null;
      remember(planCosign(e, { device, nonce, now, budget, tokenMeta, fragLen: settings.fragLen }), false);
    } catch (x) {
      setErr(errorText(x));
    } finally {
      setBusy(false);
    }
  };

  const onAnswer = (ur: string) => {
    if (!plan) return;
    try {
      const o = acceptCosignAnswer(ur, plan, device, mandate);
      // persisted before anything else: a failed hand-over or a reload never loses the device's answer
      setWork(e.id, { answer: { kind: o.kind, ur: ur.trim().toUpperCase(), at: Date.now() }, agentError: undefined });
      setErr(null);
      retried.current = true;
      if (o.kind === 'cosign') void deliverCosign(o);
      else void deliverDeny(o, null);
    } catch (x) {
      setErr(errorText(x));
    }
  };

  const onRelayed = async (hash: `0x${string}`) => {
    if (outcome?.kind !== 'deny') return;
    setWork(e.id, { relayTx: hash });
    // the agent is told again, now with the relay transaction (it records it; the deny itself it has already)
    await deliverDeny(outcome, hash);
  };

  const preview = plan
    ? previewCosign(plan.decoded, {
        p1Key: device.p1Key,
        vault: device.pinned.vault,
        sentinel: device.pinned.sentinel,
        minEpoch: 0n,
        lastDelegationHash: mandate?.delegationHash ?? null,
      })
    : null;
  const call = decodeErc20(e.call.callData);
  const txUrl = (h: string | undefined) => (h ? explorerTxUrl(explorer, h) : null);

  const s1: StepState = check.errors.length ? 'error' : 'done';
  const s2: StepState = outcome || outcomeRec ? 'done' : plan ? 'active' : check.errors.length ? 'pending' : 'active';
  const delivered = outcomeRec && !work;
  const s3: StepState = delivered ? 'done' : outcome ? (work?.agentError ? 'error' : 'active') : 'pending';

  return (
    <>
      <h2 style={{ fontSize: 'var(--t-xl)' }} tabIndex={-1}>
        {d.amount} <span className="muted small">{d.kind}</span>
      </h2>
      <Procedure>
        <Step n={1} title="What the agent asks" state={s1}>
          <Spec
            rows={[
              { k: 'Pays', v: <Hex value={d.payee} explorer={explorer} /> },
              e.display?.vendor && { k: 'Vendor (agent data)', v: e.display.vendor },
              e.display?.memo && { k: 'Memo (untrusted)', v: <q>{e.display.memo}</q> },
              { k: 'Why it escalated', v: e.reasonText ?? REASON_TEXT[e.reason] },
              e.request && { k: 'Request', v: 'built by the agent; checked here against your pinned contracts, its expiry and the on-chain nonce' },
              e.note !== null && { k: 'Agent says', v: <q>{e.note}</q> },
              e.risk && { k: 'Risk (agent data)', v: `${e.risk.src}: ${e.risk.category} / ${e.risk.label}, ${e.risk.ageDays} days old` },
              { k: 'Call target', v: <Hex value={e.call.target} explorer={explorer} /> },
              { k: 'Redeemer', v: <Hex value={e.redeemer} explorer={explorer} /> },
              { k: 'Mandate', v: <Hex value={e.delegationHash} /> },
              e.createdAt !== null && { k: 'Asked', v: utcText(e.createdAt) },
            ]}
          />
          {check.errors.map((x) => (
            <Note key={x} kind="warning">
              <p>{x}</p>
            </Note>
          ))}
          {check.warnings.map((x) => (
            <Note key={x} kind="caution">
              <p>{x}</p>
            </Note>
          ))}
        </Step>
        <Step n={2} title="Review on the device" state={s2}>
          {delivered ? (
            <p className="small">
              Answered: {outcomeRec.status} ({utcText(Math.floor(outcomeRec.at / 1000))}).
            </p>
          ) : outcome ? (
            <p className="small">
              The device answered with a {outcome.kind === 'cosign' ? `co-sign (pulse ${outcome.bpm} bpm)` : 'signed DENY'} (
              {utcText(Math.floor((work?.answer?.at ?? Date.now()) / 1000))}).
            </p>
          ) : !plan ? (
            <>
              {resumed.error && (
                <Note kind="caution">
                  <p>The request shown earlier cannot be used again: {resumed.error}. Build it again.</p>
                </Note>
              )}
              {!open(e) ? (
                <p className="small muted">The agent closed this escalation ({e.status}).</p>
              ) : (
                <div className="row">
                  <Button variant="primary" icon="qr" busy={busy} onClick={() => void prepare()} disabled={check.errors.length > 0}>
                    Build the co-sign request
                  </Button>
                </div>
              )}
              {err && (
                <Note kind="warning" alert>
                  {err}
                </Note>
              )}
            </>
          ) : (
            <>
              {expired ? (
                <Note kind="caution" title="This request expired">
                  <p>
                    {work?.agentBuilt
                      ? 'The agent closes an expired escalation and asks again with a fresh nonce: ask it to run.'
                      : 'Build a new request: it gets a fresh single-use nonce.'}
                  </p>
                  {work?.agentBuilt ? (
                    <AgentRun onRan={onDone} showAuto={false} />
                  ) : (
                    <Button icon="refresh" busy={busy} onClick={() => void prepare(true)}>
                      New request, fresh nonce
                    </Button>
                  )}
                </Note>
              ) : (
                <>
                  <div className="cols">
                    {preview && (
                      <Figure n="6.1" caption="What your device will show. Hold SIGN 2 s on it to open the deny review instead.">
                        <ReviewPanel preview={preview} footer="press = PULSE + SIGN   hold 2s = DENY" />
                      </Figure>
                    )}
                    <div className="stack">
                      <Spec
                        compact
                        rows={[
                          { k: 'Nonce', v: `${plan.nonce} (single-use, kept for this escalation)` },
                          { k: 'Expires', v: utcText(plan.expiry) },
                          { k: 'Deny would file', v: <Hex value={plan.denyRequestHash} label="deny request hash" /> },
                        ]}
                      />
                      {call.kind !== 'none' && call.kind !== 'unknown' && (
                        <DemoTokenNote
                          chainId={Number(e.chainId)}
                          token={e.call.target}
                          decimals={mandate?.token.toLowerCase() === e.call.target.toLowerCase() ? mandate.tokenDecimals : null}
                          symbol={mandate?.token.toLowerCase() === e.call.target.toLowerCase() ? mandate.tokenSymbol : null}
                          amounts={[call.amount]}
                        />
                      )}
                    </div>
                  </div>
                  <DeviceExchangePanel
                    parts={plan.request.parts}
                    expect={['ripar-cosign', 'ripar-deny']}
                    accept={(u) => answersCosign(u, plan.request)}
                    onResponse={onAnswer}
                    runKey={plan.request.reqId}
                    figA="6.2"
                    figB="6.3"
                    round="cosign"
                  />
                  {!work?.agentBuilt && (
                    <div className="row">
                      <Button variant="quiet" size="small" icon="refresh" busy={busy} onClick={() => void prepare(true)}>
                        Replace with a new request (fresh nonce)
                      </Button>
                    </div>
                  )}
                </>
              )}
              {err && (
                <Note kind="warning" alert>
                  {err}
                </Note>
              )}
            </>
          )}
        </Step>
        <Step n={3} title={outcome?.kind === 'deny' || outcomeRec?.status === 'denied' ? 'Deliver the denial' : 'Hand back to the agent'} state={s3}>
          {delivered && outcomeRec.status === 'cosigned' && (
            <Note kind="ok" title="Co-signed and handed to the agent">
              <p>
                {outcomeRec.tx ? (
                  <>
                    Paid by the agent on the HUMAN path:{' '}
                    {txUrl(outcomeRec.tx) ? (
                      <a href={txUrl(outcomeRec.tx)!} target="_blank" rel="noreferrer">
                        transaction {outcomeRec.tx.slice(0, 10)}...
                      </a>
                    ) : (
                      <Hex value={outcomeRec.tx} label="payment transaction" />
                    )}
                  </>
                ) : (
                  'The agent took the co-sign; its payment transaction shows on the Activity page.'
                )}
              </p>
            </Note>
          )}
          {delivered && outcomeRec.status === 'denied' && (
            <Note kind="ok" title="Denied">
              <p>
                The agent recorded the device's signed denial.{' '}
                {outcomeRec.tx && (
                  <>
                    Relayed on-chain (attestDenial):{' '}
                    {txUrl(outcomeRec.tx) ? (
                      <a href={txUrl(outcomeRec.tx)!} target="_blank" rel="noreferrer">
                        transaction {outcomeRec.tx.slice(0, 10)}...
                      </a>
                    ) : (
                      <Hex value={outcomeRec.tx} label="relay transaction" />
                    )}
                  </>
                )}
              </p>
            </Note>
          )}
          {outcome?.kind === 'cosign' && !delivered && (
            <>
              <Note kind="ok" title="Co-signed on the device">
                <p>
                  Pulse {outcome.bpm} bpm. The agent redeems with these caveat args (HUMAN path); the enforcer checks the
                  P-256 signature on-chain.
                </p>
              </Note>
              <Spec compact rows={[{ k: 'Caveat args', v: <Hex value={outcome.answer.caveatArgs} label="caveat args" /> }]} />
              {work?.agentError && (
                <Note kind="warning" alert>
                  The agent has not taken it yet: {work.agentError}
                </Note>
              )}
              <div className="row">
                <Button busy={posting} icon="send" onClick={() => void deliverCosign(outcome)}>
                  {work?.agentError ? 'Send to the agent again' : 'Sending to the agent...'}
                </Button>
                {work?.agentError && (
                  <Button
                    variant="quiet"
                    onClick={() => {
                      if (confirm('Discard this co-sign? The agent never received it; the escalation can be answered again with a new request.')) setWork(e.id, null);
                    }}
                  >
                    Discard
                  </Button>
                )}
              </div>
            </>
          )}
          {outcome?.kind === 'deny' && !delivered && (
            <>
              {outcome.note && <Note kind="caution">{outcome.note}</Note>}
              <Spec
                compact
                rows={[
                  {
                    k: 'Agent',
                    v: work?.agentAt ? (
                      'has the signed denial (verified by the agent)'
                    ) : (
                      <span className="row">
                        <span style={{ color: work?.agentError ? 'var(--bad)' : undefined }}>{work?.agentError ?? 'sending...'}</span>
                        <Button size="small" busy={posting} icon="send" onClick={() => void deliverDeny(outcome, work?.relayTx ?? null)}>
                          Tell the agent again
                        </Button>
                      </span>
                    ),
                  },
                  { k: 'On-chain relay', v: work?.relayTx ? `sent (${work.relayTx.slice(0, 10)}...)` : 'pending: relay it below (files the denial against the agent)' },
                ]}
              />
              {!work?.relayTx && (
                <TxAction
                  variant="danger solid"
                  write={attestDenialWrite(device.pinned.relay, { ...outcome.attest, px: device.px, py: device.py })}
                  label="Relay the denial"
                  onDone={(r) => void onRelayed(r.hash)}
                />
              )}
            </>
          )}
          {!outcome && !delivered && <p className="small muted">After the device answers.</p>}
        </Step>
      </Procedure>
    </>
  );

  function open(x: Escalation) {
    return x.status === 'pending' || x.status === 'open';
  }
}
