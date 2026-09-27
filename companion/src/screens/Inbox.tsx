// Inbox: the agent's escalations (payments the AUTO path refused). Each one becomes a ripar-cosign-req with a fresh
// single-use nonce; the device answers with a co-sign (HUMAN caveat args, posted back to the agent) or, after a 2 s
// hold on its review, with a deny that the companion relays to the reputation relay.
import { useCallback, useEffect, useMemo, useState } from 'react';
import { CosignNonceTracker, decodeErc20, firmwareToken, nativeCoin, toChecksumAddress } from '@ripar/protocol';
import { PageHead } from '../App';
import { DeviceExchangePanel } from '../components/DeviceExchangePanel';
import { ReviewPanel } from '../components/Review';
import { TxAction } from '../components/TxAction';
import { Button, Empty, Figure, Hex, Mark, Note, Procedure, Spec, Step, type StepState } from '../components/ui';
import { type AgentClient, type Escalation, agentClientOf } from '../lib/agent';
import { attestDenialWrite } from '../lib/chain';
import { publicClientFor } from '../lib/clients';
import { amountText, ago, errorText, utcText } from '../lib/format';
import { type CosignOutcome, type CosignPlan, acceptCosignAnswer, adoptAgentRequest, answersCosign, checkEscalation, planCosign } from '../lib/flows/cosign';
import { NETWORKS } from '../lib/networks';
import { nonceUsed, readMandateStatus, readToken } from '../lib/reads';
import { previewCosign } from '../lib/review-preview';
import { type AppState, currentMandate, store, useStore } from '../lib/store';

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

export function Inbox() {
  const state = useStore((s) => s);
  const { settings, device, inbox } = state;
  const explorer = NETWORKS[settings.network]?.explorer ?? null;
  const [items, setItems] = useState<Escalation[]>([]);
  const [rejected, setRejected] = useState<{ raw: unknown; error: string }[]>([]);
  const [agentErr, setAgentErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selId, setSelId] = useState<string | null>(null);

  const client = useMemo(() => (settings.agentUrl ? agentClientOf(settings) : null), [settings.agentUrl, settings.agentToken]);

  const poll = useCallback(async () => {
    if (!client) return;
    setLoading(true);
    try {
      const r = await client.escalations();
      setItems(r.items);
      setRejected(r.rejected);
      setAgentErr(null);
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

  const pending = items.filter((e) => !inbox[e.id] && (e.status === 'pending' || e.status === 'open'));
  const handled = items.filter((e) => inbox[e.id] || !(e.status === 'pending' || e.status === 'open'));
  // the agent lists newest first; keep that order, answered ones below
  const sel = items.find((e) => e.id === selId) ?? null;

  return (
    <div className="page">
      <PageHead
        title="Inbox"
        lede="Payments your agent could not make on its own. Each one waits for your thumb: approve it on the device, or hold SIGN for 2 s on the review to deny it and file that against the agent."
      />
      {!device && <Note kind="caution">Pair a device first: a co-sign names the device's pinned contracts.</Note>}
      {agentErr && <Note kind="warning">{agentErr}</Note>}

      <div className="cols-wide" style={{ gridTemplateColumns: sel ? 'minmax(0, 0.8fr) minmax(0, 1.6fr)' : undefined }}>
        <section aria-label="Escalations">
          <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
            <h2 style={{ fontSize: 'var(--t-lg)' }}>Waiting ({pending.length})</h2>
            <Button size="small" icon="refresh" busy={loading} onClick={() => void poll()}>
              Refresh
            </Button>
          </div>
          {pending.length === 0 ? (
            <Empty title="Nothing waiting">
              When the agent hits a cap, a new payee or a closed lane, the payment appears here. This page checks the
              agent every 5 s.
            </Empty>
          ) : (
            <ul className="inbox-list">
              {pending.map((e) => {
                const d = describe(e, state);
                return (
                  <li key={e.id}>
                    <button type="button" className="inbox-item" aria-current={selId === e.id} onClick={() => setSelId(e.id)}>
                      <span className="amt">{d.amount}</span>
                      <Mark tone="warn">{e.reason === 'other' ? 'ASK' : e.reason.toUpperCase()}</Mark>
                      <span className="sub">
                        to {d.payee.slice(0, 10)}...{d.payee.slice(-6)} · {REASON_TEXT[e.reason]}
                        {e.createdAt ? ` · ${ago(e.createdAt)}` : ''}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {handled.length > 0 && (
            <>
              <h2 style={{ fontSize: 'var(--t-lg)', margin: '24px 0 8px' }}>Answered</h2>
              <ul className="inbox-list">
                {handled.slice(0, 30).map((e) => {
                  const d = describe(e, state);
                  const o = inbox[e.id];
                  return (
                    <li key={e.id}>
                      <button type="button" className="inbox-item" aria-current={selId === e.id} onClick={() => setSelId(e.id)}>
                        <span>{d.amount}</span>
                        <Mark tone={o?.status === 'cosigned' ? 'good' : o?.status === 'denied' ? 'bad' : 'plain'}>
                          {o?.status?.toUpperCase() ?? e.status.toUpperCase()}
                        </Mark>
                        <span className="sub">to {d.payee.slice(0, 10)}...{d.payee.slice(-6)}</span>
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

        {sel && device ? (
          <EscalationDetail key={sel.id} e={sel} explorer={explorer} client={client} onDone={() => void poll()} />
        ) : (
          sel && <Empty title="Pair a device first" />
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
  const outcomeRec = state.inbox[e.id];
  const check = checkEscalation(e, device, mandate);
  const d = describe(e, state);
  const [plan, setPlan] = useState<CosignPlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<CosignOutcome | null>(null);
  const [posting, setPosting] = useState(false);

  if (!device) return null;

  const prepare = async () => {
    setBusy(true);
    setErr(null);
    try {
      const pc = publicClientFor(settings);
      const dh = e.delegationHash;
      const now = Math.floor(Date.now() / 1000);
      const remember = (n: bigint) =>
        store.set((s) => ({ nonces: { ...s.nonces, [dh.toLowerCase()]: [...(s.nonces[dh.toLowerCase()] ?? []), n.toString()] } }));
      if (e.request) {
        // the agent built the request (and verifies the device's answer against exactly it): check it, then relay it
        const p = adoptAgentRequest(e, device, { now, fragLen: settings.fragLen });
        const used = await nonceUsed(pc, device.pinned.enforcer, dh, p.nonce).catch(() => false);
        if (used || (store.get().nonces[dh.toLowerCase()] ?? []).includes(p.nonce.toString())) {
          throw new Error(`The agent reuses nonce ${p.nonce} for this mandate: the redemption would revert (CosignReplayed). Not shown to the device.`);
        }
        remember(p.nonce);
        setPlan(p);
        return;
      }
      // v1.2: a nonce is single-use per mandate. Never reuse one handed out before, and skip any the chain has seen.
      const tracker = new CosignNonceTracker();
      for (const n of store.get().nonces[dh.toLowerCase()] ?? []) tracker.markUsed(dh, n);
      const nonce = await tracker.nextUnused(dh, (n) => nonceUsed(pc, device.pinned.enforcer, dh, n).catch(() => false));
      remember(nonce);
      const budget =
        mandate && mandate.delegationHash.toLowerCase() === dh.toLowerCase()
          ? (await readMandateStatus(pc, device.pinned.enforcer, device.keyId, dh, mandate.pulseTerms)).budget
          : null;
      const call = decodeErc20(e.call.callData);
      const tokenMeta = call.kind !== 'none' && call.kind !== 'unknown' && !firmwareToken(Number(e.chainId), e.call.target)
        ? await readToken(pc, e.call.target, device.pinned.vault).then((t) => ({ decimals: t.decimals, symbol: t.symbol }))
        : null;
      setPlan(planCosign(e, { device, nonce, now, budget, tokenMeta, fragLen: settings.fragLen }));
    } catch (x) {
      setErr(errorText(x));
    } finally {
      setBusy(false);
    }
  };

  const onAnswer = async (ur: string) => {
    if (!plan) return;
    try {
      const o = acceptCosignAnswer(ur, plan, device, mandate);
      setOutcome(o);
      setErr(null);
      if (o.kind === 'cosign') {
        setPosting(true);
        try {
          const r = client ? await client.postCosign(e.id, o.answer) : { txHash: null };
          store.set((s) => ({ inbox: { ...s.inbox, [e.id]: { status: 'cosigned', at: Date.now(), detail: `bpm ${o.bpm}`, ...(r.txHash ? { tx: r.txHash } : {}) } } }));
          onDone();
        } catch (x) {
          setErr(`Co-signed on the device, but the agent did not take it: ${errorText(x)}. Retry below.`);
        } finally {
          setPosting(false);
        }
      }
    } catch (x) {
      setErr(errorText(x));
    }
  };

  const retryPost = async () => {
    if (outcome?.kind !== 'cosign' || !client) return;
    setPosting(true);
    try {
      await client.postCosign(e.id, outcome.answer);
      store.set((s) => ({ inbox: { ...s.inbox, [e.id]: { status: 'cosigned', at: Date.now(), detail: `bpm ${outcome.bpm}` } } }));
      setErr(null);
      onDone();
    } catch (x) {
      setErr(errorText(x));
    } finally {
      setPosting(false);
    }
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

  const s1: StepState = check.errors.length ? 'error' : 'done';
  const s2: StepState = outcome ? 'done' : plan ? 'active' : check.errors.length ? 'pending' : 'active';
  const s3: StepState = outcomeRec ? 'done' : outcome ? 'active' : 'pending';

  return (
    <section aria-label="Escalation" className="stack">
      <h2 style={{ fontSize: 'var(--t-xl)' }}>
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
          {outcomeRec ? (
            <p className="small">
              Answered: {outcomeRec.status} ({new Date(outcomeRec.at).toLocaleString()}).
            </p>
          ) : !plan ? (
            <div className="row">
              <Button variant="primary" icon="qr" busy={busy} onClick={prepare} disabled={check.errors.length > 0}>
                Build the co-sign request
              </Button>
              {err && <span className="small" style={{ color: 'var(--bad)' }}>{err}</span>}
            </div>
          ) : (
            <>
              <div className="cols">
                {preview && (
                  <Figure n="6.1" caption="What your device will show. Hold SIGN 2 s on it to deny instead.">
                    <ReviewPanel preview={preview} footer="press = PULSE + SIGN   hold 2s = DENY" />
                  </Figure>
                )}
                <Spec
                  compact
                  rows={[
                    { k: 'Nonce', v: `${plan.nonce} (fresh, single-use)` },
                    { k: 'Expires', v: utcText(plan.expiry) },
                    { k: 'Deny would file', v: <Hex value={plan.denyRequestHash} /> },
                  ]}
                />
              </div>
              {!outcome && (
                <DeviceExchangePanel
                  parts={plan.request.parts}
                  expect={['ripar-cosign', 'ripar-deny']}
                  accept={(u) => answersCosign(u, plan.request)}
                  onResponse={(u) => void onAnswer(u)}
                  runKey={plan.request.reqId}
                  figA="6.2"
                  figB="6.3"
                />
              )}
              {err && <Note kind="warning">{err}</Note>}
            </>
          )}
        </Step>
        <Step n={3} title={outcome?.kind === 'deny' ? 'Relay the denial' : 'Hand back to the agent'} state={s3}>
          {outcome?.kind === 'cosign' && (
            <>
              <Note kind="ok" title="Co-signed">
                <p>
                  Pulse {outcome.bpm} bpm. The agent redeems with these caveat args (HUMAN path); the enforcer checks the
                  P-256 signature on-chain.
                </p>
              </Note>
              <Spec compact rows={[{ k: 'Caveat args', v: <Hex value={outcome.answer.caveatArgs} /> }]} />
              {!outcomeRec && (
                <Button busy={posting} icon="send" onClick={retryPost}>
                  Send to the agent again
                </Button>
              )}
            </>
          )}
          {outcome?.kind === 'deny' && (
            <>
              {outcome.note && <Note kind="caution">{outcome.note}</Note>}
              <TxAction
                variant="danger solid"
                write={attestDenialWrite(device.pinned.relay, { ...outcome.attest, px: device.px, py: device.py })}
                label="Relay the denial"
                onDone={async (r) => {
                  try {
                    await client?.postDeny(e.id, { ...outcome.answer, attestTx: r.hash });
                  } catch {
                    /* the agent learns it from the Verdict event too */
                  }
                  store.set((s) => ({ inbox: { ...s.inbox, [e.id]: { status: 'denied', at: Date.now(), detail: 'attestDenial', tx: r.hash } } }));
                  onDone();
                }}
              />
            </>
          )}
          {!outcome && !outcomeRec && <p className="small muted">After the device answers.</p>}
        </Step>
      </Procedure>
    </section>
  );
}
