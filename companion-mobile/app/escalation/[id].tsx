// One escalation: a payment the agent could not make on its own. Ported from companion/src/screens/Inbox.tsx
// (EscalationDetail): check it against what the device pinned, build (or adopt the agent's) co-sign request with a
// single-use nonce, the device answers with a co-sign (handed to the agent, which redeems on the HUMAN path) or a
// signed deny (handed to the agent and relayed to the reputation registry).
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { View } from 'react-native';
import { CosignNonceTracker, aiMatches, decodeErc20, firmwareToken } from '@ripar/protocol';
import { Address, Button, DeviceRound, Label, Note, Screen, Spec, Surface, Text, TxButton } from '../../src/components';
import { verifierOf } from '../../src/device/link';
import { agentClientOf } from '../../src/lib/agent';
import { escalationById, pollAgent, useAgent } from '../../src/lib/agentState';
import { attestDenialWrite } from '../../src/lib/chain';
import { publicClientFor } from '../../src/lib/clients';
import { REASON_TEXT, describeEscalation } from '../../src/lib/escalations';
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
} from '../../src/lib/flows/cosign';
import { errorText, utcText } from '../../src/lib/format';
import { nonceUsed, readMandateStatus, readToken } from '../../src/lib/reads';
import { type AppState, type EscalationWork, currentAgentMandate, ownEntry, store, useStore } from '../../src/lib/store';
import { space } from '../../src/theme';

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

export default function EscalationScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  useAgent();
  const e = id ? escalationById(id) : null;
  const state = useStore((s) => s);
  const { settings, device } = state;
  const mandate = currentAgentMandate(state);
  const work = e ? ownEntry(state.work, e.id) : undefined;
  const outcomeRec = e ? ownEntry(state.inbox, e.id) : undefined;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [posting, setPosting] = useState(false);
  const client = useMemo(() => (settings.agentUrl ? agentClientOf(settings) : null), [settings.agentUrl, settings.agentToken]);

  const plan = useMemo((): CosignPlan | null => {
    if (!work || !device || !e) return null;
    try {
      return resumePlan(work.requestUr, e, device, settings.fragLen);
    } catch {
      return null;
    }
  }, [work?.requestUr, e, device, settings.fragLen]);
  const outcome = useMemo((): CosignOutcome | null => {
    if (!plan || !work?.answer || !device) return null;
    try {
      return acceptCosignAnswer(work.answer.ur, plan, device, mandate);
    } catch {
      return null;
    }
  }, [plan, work?.answer?.ur, device, mandate]);

  const deliverCosign = useCallback(
    async (o: Extract<CosignOutcome, { kind: 'cosign' }>) => {
      if (!client || !e) return;
      setPosting(true);
      try {
        const r = await client.postCosign(e.id, o.answer);
        setOutcome(e.id, { status: 'cosigned', at: Date.now(), detail: `pulse ${o.bpm} bpm`, ...(r.txHash ? { tx: r.txHash } : {}) });
        setWork(e.id, null);
        setErr(null);
        void pollAgent();
      } catch (x) {
        const msg = errorText(x);
        if (/\((already_executed|tx_pending|in_progress)\)/.test(msg)) {
          setOutcome(e.id, { status: 'cosigned', at: Date.now(), detail: `pulse ${o.bpm} bpm; ${msg}` });
          setWork(e.id, null);
          return;
        }
        setWork(e.id, { agentError: msg });
        setErr(`Co-signed on the Ripar, but the agent did not take it yet: ${msg}. The co-sign is kept here; retry below.`);
      } finally {
        setPosting(false);
      }
    },
    [client, e],
  );

  const deliverDeny = useCallback(
    async (o: Extract<CosignOutcome, { kind: 'deny' }>, attestTx: `0x${string}` | null) => {
      if (!client || !e) return;
      setPosting(true);
      try {
        await client.postDeny(e.id, { ...o.answer, attestTx });
        const relayTx = attestTx ?? ownEntry(store.get().work, e.id)?.relayTx;
        setOutcome(e.id, { status: 'denied', at: Date.now(), detail: 'device deny', ...(relayTx ? { tx: relayTx } : { relayPending: true }) });
        if (relayTx) setWork(e.id, null);
        else setWork(e.id, { agentAt: Date.now(), agentError: undefined });
        void pollAgent();
      } catch (x) {
        setWork(e.id, { agentError: errorText(x) });
      } finally {
        setPosting(false);
      }
    },
    [client, e],
  );

  // an answer that was never delivered (the app was closed, the agent was down): try again once on opening
  const retried = useRef(false);
  useEffect(() => {
    if (retried.current || !outcome || !work?.answer || work.agentAt) return;
    retried.current = true;
    if (outcome.kind === 'cosign') void deliverCosign(outcome);
    else void deliverDeny(outcome, work.relayTx ?? null);
  }, [outcome, work?.answer, work?.agentAt, work?.relayTx, deliverCosign, deliverDeny]);

  const verifier = useMemo(
    () => (plan && device ? verifierOf<CosignOutcome>(['ripar-cosign', 'ripar-deny'], (ur) => acceptCosignAnswer(ur, plan, device, mandate), (ur) => answersCosign(ur, plan.request)) : null),
    [plan, device, mandate],
  );

  if (!e || !device) {
    return (
      <Screen back title="Escalation" tabs={false}>
        <Note tone="info">{device ? 'This escalation is not in the agent’s list any more.' : 'Pair your Ripar first.'}</Note>
        <Button label="Back to Agents" variant="secondary" style={{ marginTop: space.lg }} onPress={() => router.back()} />
      </Screen>
    );
  }

  const check = checkEscalation(e, device, mandate);
  const d = describeEscalation(e, state);
  const call = decodeErc20(e.call.callData);
  const claimsMatch = e.claims && plan ? aiMatches(plan.decoded) : null;
  const open = e.status === 'pending' || e.status === 'open';
  const expired = !!plan && plan.expiry <= BigInt(Math.floor(Date.now() / 1000)) && !work?.answer;

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
          throw new Error(`Cannot confirm on-chain that nonce ${n} is unused (${errorText(x)}). Nothing was shown to the device.`);
        }
      };
      const remember = (p: CosignPlan, agentBuilt: boolean) =>
        store.set((s) => ({
          nonces: { ...s.nonces, [dh.toLowerCase()]: [...new Set([...(s.nonces[dh.toLowerCase()] ?? []), p.nonce.toString()])] },
          work: { ...s.work, [e.id]: { requestUr: p.request.ur, delegationHash: dh, nonce: p.nonce.toString(), expiry: p.expiry.toString(), agentBuilt, builtAt: Date.now() } },
        }));
      if (e.request) {
        const p = adoptAgentRequest(e, device, { now, fragLen: settings.fragLen });
        if (await usedOnChain(p.nonce)) throw new Error(`Nonce ${p.nonce} was already used on-chain: this request can only revert. Ask the agent to run again.`);
        const clash = nonceConflict(e.id, dh, p.nonce, store.get().work);
        if (clash) throw new Error(`The agent reuses a nonce: ${clash}. Not shown to the device.`);
        remember(p, true);
        return;
      }
      const tracker = new CosignNonceTracker();
      for (const n of store.get().nonces[dh.toLowerCase()] ?? []) tracker.markUsed(dh, n);
      for (const w of Object.values(store.get().work)) if (w.delegationHash.toLowerCase() === dh.toLowerCase()) tracker.markUsed(dh, w.nonce);
      if (fresh && work) tracker.markUsed(dh, work.nonce);
      const nonce = await tracker.nextUnused(dh, usedOnChain);
      const budget = mandate && mandate.delegationHash.toLowerCase() === dh.toLowerCase() ? (await readMandateStatus(pc, device.pinned.enforcer, device.keyId, dh, mandate.pulseTerms)).budget : null;
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

  const delivered = outcomeRec && !work;
  return (
    <Screen back eyebrow={d.kind} title={d.amount} lede={`to ${d.payee.slice(0, 10)}…${d.payee.slice(-6)} · ${e.reasonText ?? REASON_TEXT[e.reason]}`} tabs={false}>
      <View style={{ gap: space.lg }}>
        <Surface padded={16}>
          <Spec
            rows={[
              { k: 'Pays', v: <Address value={d.payee} label="Payee" /> },
              e.display?.vendor ? { k: 'Vendor (agent data)', v: e.display.vendor } : null,
              e.display?.memo ? { k: 'Memo (untrusted: could be an injection)', v: `“${e.display.memo}”` } : null,
              e.note !== null ? { k: 'The agent says', v: `“${e.note}”` } : null,
              e.risk ? { k: 'Risk (agent data)', v: `${e.risk.src}: ${e.risk.category} / ${e.risk.label}, ${e.risk.ageDays} days old` } : null,
              { k: 'Call target', v: <Address value={e.call.target} label="Target" tone="soft" /> },
              { k: 'Mandate', v: <Address value={e.delegationHash} label="Mandate" tone="soft" /> },
              e.createdAt !== null ? { k: 'Asked', v: utcText(e.createdAt) } : null,
            ]}
          />
        </Surface>

        {e.claims && (
          <Note tone={claimsMatch === false ? 'bad' : 'info'} title="What the AI claims">
            {`The agent claims it pays ${e.claims.amount} base units of ${/^0x0{40}$/i.test(e.claims.token) ? 'MON' : e.claims.token} to ${e.claims.to}. Your Ripar decodes the call itself and compares: a mismatch is flagged on its screen as AI CLAIM MISMATCH. Trust the Ripar's decoding, never the claim.${claimsMatch === false ? ' This claim does NOT match the call.' : ''}`}
          </Note>
        )}
        {check.errors.map((x) => (
          <Note key={x} tone="bad">
            {x}
          </Note>
        ))}
        {check.warnings.map((x) => (
          <Note key={x} tone="warn">
            {x}
          </Note>
        ))}

        {delivered ? (
          <Note tone={outcomeRec.status === 'cosigned' ? 'good' : 'bad'} title={outcomeRec.status === 'cosigned' ? 'Co-signed and handed to the agent' : 'Denied'}>
            {outcomeRec.status === 'cosigned'
              ? outcomeRec.tx
                ? `The agent paid on the HUMAN path: ${outcomeRec.tx}`
                : 'The agent took the co-sign; its payment shows in Activity.'
              : `The agent recorded the Ripar's signed denial.${outcomeRec.tx ? ` Relayed on-chain: ${outcomeRec.tx}` : ''}`}
          </Note>
        ) : outcome ? (
          outcome.kind === 'cosign' ? (
            <Surface padded={16} style={{ gap: space.md }}>
              <Label>Co-signed on your Ripar · pulse {outcome.bpm} bpm</Label>
              {work?.agentError && <Note tone="bad">{`The agent has not taken it yet: ${work.agentError}`}</Note>}
              <Button label={work?.agentError ? 'Send to the agent again' : 'Sending to the agent...'} loading={posting} onPress={() => void deliverCosign(outcome)} />
            </Surface>
          ) : (
            <Surface padded={16} style={{ gap: space.md }}>
              <Label tone="danger">Denied on your Ripar</Label>
              {outcome.note && <Note tone="warn">{outcome.note}</Note>}
              <Text variant="bodySmall" tone="soft">
                Agent: {work?.agentAt ? 'has the signed denial' : (work?.agentError ?? 'sending...')}
              </Text>
              {!work?.agentAt && <Button label="Tell the agent again" size="sm" variant="secondary" loading={posting} onPress={() => void deliverDeny(outcome, work?.relayTx ?? null)} />}
              {!work?.relayTx && (
                <TxButton
                  variant="danger"
                  write={attestDenialWrite(device.pinned.relay, { ...outcome.attest, px: device.px, py: device.py })}
                  label="File the denial on-chain"
                  onDone={(r) => {
                    setWork(e.id, { relayTx: r.hash });
                    void deliverDeny(outcome, r.hash);
                  }}
                />
              )}
            </Surface>
          )
        ) : !plan ? (
          open ? (
            <Button label="Review on my Ripar" size="lg" loading={busy} disabled={check.errors.length > 0} onPress={() => void prepare()} />
          ) : (
            <Text tone="soft">The agent closed this escalation ({e.status}).</Text>
          )
        ) : expired ? (
          <>
            <Note tone="warn" title="This request expired">
              {work?.agentBuilt ? 'The agent asks again with a fresh nonce: ask it to run.' : 'Build a new one: it gets a fresh nonce.'}
            </Note>
            {!work?.agentBuilt && <Button label="New request" loading={busy} onPress={() => void prepare(true)} />}
          </>
        ) : (
          verifier && (
            <DeviceRound
              request={plan.request}
              verifier={verifier}
              kind="cosign"
              runKey={plan.request.reqId}
              onVerified={(o, ur) => {
                setWork(e.id, { answer: { kind: o.kind, ur, at: Date.now() }, agentError: undefined });
                retried.current = true;
                if (o.kind === 'cosign') void deliverCosign(o);
                else void deliverDeny(o, null);
              }}
            />
          )
        )}
        {err && <Note tone="bad">{err}</Note>}
      </View>
    </Screen>
  );
}
