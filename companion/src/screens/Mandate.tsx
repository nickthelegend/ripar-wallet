// 5 Mandate: the scoped delegation the agent spends under. The form becomes a ripar-mandate-req; the page shows the
// review the device will show, the device signs with K1 after pulse + SIGN, and the signed delegation goes to the agent.
import { useEffect, useMemo, useState } from 'react';
import { AUSD_10143 } from '@ripar/protocol';
import { PageHead } from '../App';
import { AgentRun } from '../components/AgentRun';
import { DeviceExchangePanel } from '../components/DeviceExchangePanel';
import { DemoTokenNote, ReviewPanel } from '../components/Review';
import { Button, Empty, Field, Figure, Hex, Mark, NextStep, Note, Procedure, Spec, Step, type StepState } from '../components/ui';
import { agentClientOf } from '../lib/agent';
import { publicClientFor } from '../lib/clients';
import { amountText, durationText, errorText } from '../lib/format';
import { type MandateForm, type MandatePlan, acceptMandate, answersMandate, mandateEnvelope, planMandate } from '../lib/flows/mandate';
import { NETWORKS } from '../lib/networks';
import { type MandateStatus, readMandateStatus, readMinEpoch, readToken } from '../lib/reads';
import { previewMandate } from '../lib/review-preview';
import { refreshSetup, useSetupStatus } from '../lib/setup';
import { currentMandate, store, useDeployment, useStore } from '../lib/store';

const PERIODS: [string, number][] = [
  ['1 hour', 3600],
  ['1 day', 86400],
  ['7 days', 604800],
  ['30 days', 2592000],
  ['Lifetime cap (no reset)', 0],
];

export function Mandate() {
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const mandate = useStore(currentMandate);
  const { deployment } = useDeployment();
  const explorer = NETWORKS[settings.network]?.explorer ?? null;

  const [form, setForm] = useState<MandateForm>({
    agent: '',
    agentId: '',
    label: 'treasury agent',
    token: '',
    tokenDecimals: 6,
    tokenSymbol: 'mUSD',
    perTxAutoCap: '5',
    periodAutoCap: '20',
    period: 86400,
    newPayeeNeedsHuman: true,
    redeemerOnly: true,
    validUntil: null,
  });
  const [epoch, setEpoch] = useState<bigint | null>(null);
  const [epochErr, setEpochErr] = useState<string | null>(null);
  const [plan, setPlan] = useState<MandatePlan | null>(null);
  const [formErr, setFormErr] = useState<string | null>(null);
  const [signErr, setSignErr] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [status, setStatus] = useState<MandateStatus | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  /** the new-mandate form is folded away while a mandate exists, until asked for */
  const [showForm, setShowForm] = useState(false);
  /** the user chose to keep the current (live) mandate while signing another */
  const [keepLive, setKeepLive] = useState(false);
  const [justSigned, setJustSigned] = useState<string | null>(null);
  const setup = useSetupStatus();

  const set = (p: Partial<MandateForm>) => {
    setForm((f) => ({ ...f, ...p }));
    setPlan(null);
    setFormErr(null);
  };

  // defaults: MockUSD of the deployment, the agent's address / id from its /health
  useEffect(() => {
    if (deployment && !form.token && !/^0x0{40}$/i.test(deployment.mockUsd)) set({ token: deployment.mockUsd, tokenDecimals: 6, tokenSymbol: 'mUSD' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deployment?.mockUsd]);
  useEffect(() => {
    if (!settings.agentUrl) return;
    agentClientOf(settings).health().then(
      (h) => {
        if (h.agent) setForm((f) => (f.agent ? f : { ...f, agent: h.agent!.address, agentId: h.agent!.agentId?.toString() ?? f.agentId }));
      },
      () => {},
    );
  }, [settings.agentUrl, settings.agentToken]);

  const loadEpoch = async () => {
    if (!device) return;
    setEpochErr(null);
    try {
      setEpoch(await readMinEpoch(publicClientFor(settings), device.pinned.enforcer, device.keyId));
    } catch (e) {
      setEpoch(null);
      setEpochErr(errorText(e));
    }
  };
  useEffect(() => {
    void loadEpoch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device?.keyId]);

  const refreshStatus = async () => {
    if (!device || !mandate) return;
    try {
      setStatus(await readMandateStatus(publicClientFor(settings), device.pinned.enforcer, device.keyId, mandate.delegationHash, mandate.pulseTerms));
      setStatusErr(null);
    } catch (e) {
      setStatusErr(errorText(e));
    }
  };
  useEffect(() => {
    void refreshStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mandate?.delegationHash]);

  const onToken = async (v: string) => {
    if (v === 'native') return set({ token: 'native', tokenDecimals: 18, tokenSymbol: 'MON' });
    if (v === AUSD_10143) return set({ token: v, tokenDecimals: 6, tokenSymbol: 'AUSD' });
    set({ token: v });
    if (/^0x[0-9a-fA-F]{40}$/.test(v) && device) {
      const t = await readToken(publicClientFor(settings), v as `0x${string}`, device.pinned.vault);
      if (t.decimals !== null) setForm((f) => (f.token === v ? { ...f, tokenDecimals: t.decimals!, tokenSymbol: t.symbol } : f));
    }
  };

  const prepare = () => {
    if (!device || epoch === null) return;
    try {
      setPlan(planMandate(form, device, epoch, { fragLen: settings.fragLen }));
      setFormErr(null);
      setSignErr(null);
    } catch (e) {
      setFormErr(errorText(e));
    }
  };

  const preview = useMemo(
    () =>
      plan && device && epoch !== null
        ? previewMandate(plan.decoded, { p1Key: device.p1Key, vault: device.pinned.vault, sentinel: device.pinned.sentinel, minEpoch: epoch })
        : null,
    [plan, device, epoch],
  );

  const sendToAgent = async (rec = mandate) => {
    if (!rec || !device) return;
    setSending(true);
    try {
      await agentClientOf(settings).postMandate(mandateEnvelope(rec));
      store.set((s) => ({ mandates: s.mandates.map((m) => (m.delegationHash === rec.delegationHash ? { ...m, sentToAgentAt: Date.now(), agentError: undefined } : m)) }));
      void refreshSetup();
    } catch (e) {
      store.set((s) => ({ mandates: s.mandates.map((m) => (m.delegationHash === rec.delegationHash ? { ...m, agentError: errorText(e) } : m)) }));
    } finally {
      setSending(false);
    }
  };

  const onSigned = (ur: string) => {
    if (!plan || !device) return;
    try {
      const rec = acceptMandate(ur, plan, form, device);
      store.set((s) => ({ mandates: [...s.mandates.filter((m) => m.delegationHash !== rec.delegationHash), rec] }));
      setPlan(null);
      setSignErr(null);
      setShowForm(false);
      setKeepLive(false);
      setJustSigned(rec.delegationHash);
      void sendToAgent(rec);
    } catch (e) {
      setSignErr(errorText(e));
    }
  };

  if (!device) {
    return (
      <div className="page">
        <PageHead no="5" title="Mandate" lede="What the agent may spend by itself, and when it must ask your thumb." />
        <Empty title="Pair a device first">A mandate names the device's P1 key and the vault it pinned.</Empty>
      </div>
    );
  }

  const tokenOptions: [string, string][] = [
    ...(deployment && !/^0x0{40}$/i.test(deployment.mockUsd) ? ([[deployment.mockUsd, 'MockUSD (mUSD, demo)']] as [string, string][]) : []),
    ...(settings.chainId === 10143 ? ([[AUSD_10143, 'AUSD (Agora USD)']] as [string, string][]) : []),
    ['native', 'MON (native coin)'],
  ];
  const custom = form.token !== '' && !tokenOptions.some(([v]) => v === form.token);
  const killed = !!mandate && !!status && status.minEpoch !== null && BigInt(mandate.epoch) < status.minEpoch;
  const dead = !!status && (status.revoked === true || status.disabled === true || killed);
  /** a mandate that may still be live (unknown counts as live: fail safe) */
  const maybeLive = !!mandate && !dead;
  const formOpen = !mandate || showForm || !!plan;
  const blocked = maybeLive && !keepLive;
  const s1: StepState = plan ? 'done' : formErr ? 'error' : 'active';
  const s2: StepState = plan ? (signErr ? 'error' : 'active') : 'pending';

  return (
    <div className="page">
      <PageHead
        no="5"
        title="Mandate"
        lede="What the agent may spend by itself, and when it must ask your thumb. The device signs it with K1 only if it carries exactly one pulse co-sign rule naming this device."
      />

      {mandate && (
        <section className="section" aria-label="Current mandate">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <h2>Current mandate</h2>
            <div className="row">
              {!status && !statusErr && <Mark>READING</Mark>}
              {statusErr && <Mark tone="warn">STATE UNKNOWN</Mark>}
              {status?.revoked && <Mark tone="bad">REVOKED</Mark>}
              {status?.disabled && <Mark tone="bad">DISABLED</Mark>}
              {killed && <Mark tone="bad">KILLED BY PANIC</Mark>}
              {status && status.revoked === false && !status.disabled && !killed && status.minEpoch !== null && <Mark tone="good">LIVE</Mark>}
              {status && (status.revoked === null || status.minEpoch === null) && <Mark tone="warn">PARTLY UNREADABLE</Mark>}
              <Button size="small" icon="refresh" onClick={refreshStatus}>
                Refresh
              </Button>
            </div>
          </div>
          <Spec
            rows={[
              { k: 'Delegation hash', v: <Hex value={mandate.delegationHash} /> },
              { k: 'Agent', v: <Hex value={mandate.agent} explorer={explorer} /> },
              { k: 'Agent id', v: mandate.agentId ?? 'none' },
              { k: 'Epoch', v: mandate.epoch },
              status?.budget && {
                k: 'AUTO budget left',
                v: `${amountText(status.budget.remaining, mandate.tokenDecimals, mandate.tokenSymbol)} (spent ${amountText(status.budget.spent, mandate.tokenDecimals, mandate.tokenSymbol)} this period)`,
              },
              {
                k: 'Delivered to agent',
                v: mandate.sentToAgentAt ? (
                  'received the signed delegation'
                ) : (
                  <span className="row">
                    <span style={{ color: mandate.agentError ? 'var(--bad)' : undefined }}>{mandate.agentError ?? 'not sent yet'}</span>
                    <Button size="small" busy={sending} icon="send" onClick={() => sendToAgent()}>
                      Send to agent
                    </Button>
                  </span>
                ),
              },
            ]}
          />
        </section>
      )}

      {mandate && justSigned === mandate.delegationHash && (
        <section className="section" aria-label="Signed">
          <Note kind={mandate.sentToAgentAt ? 'ok' : 'caution'} title={mandate.sentToAgentAt ? 'Mandate signed and delivered' : 'Mandate signed'}>
            <p>
              The device signed it with K1 (VERIFIED here).{' '}
              {mandate.sentToAgentAt
                ? 'The agent accepted it after checking the signature, the caps and the vault itself.'
                : sending
                  ? 'Sending it to the agent...'
                  : 'The agent does not have it yet: use Send to agent above.'}
            </p>
            <p>
              Next: the agent pays due invoices inside the caps by itself and sends anything else to your{' '}
              <a href="#/inbox">Inbox</a>. It looks at its invoices when it runs a planner step:
            </p>
            <AgentRun />
          </Note>
        </section>
      )}

      {mandate && setup.vaultDeployed === false && (
        <Note kind="caution" title="The vault is not deployed">
          <p>
            A mandate can name a counterfactual vault, but nothing can be paid from it until it has code.{' '}
            <a href="#/vault">Deploy and fund the vault</a>.
          </p>
        </Note>
      )}
      {mandate && setup.vaultDeployed && setup.vaultFunded === false && (
        <Note kind="caution" title="The vault is empty">
          <p>
            The agent has nothing to pay with. <a href="#/vault">Fund the vault</a> (MockUSD faucet).
          </p>
        </Note>
      )}

      {mandate && !formOpen && (
        <section className="section">
          <div className="row">
            <Button icon="qr" onClick={() => setShowForm(true)}>
              Sign a new mandate...
            </Button>
          </div>
        </section>
      )}

      {formOpen && (
      <section className="section">
        <h2>{mandate ? 'Sign a new mandate' : 'Sign the mandate'}</h2>
        {maybeLive && (
          <Note kind="warning" title="Revoke the current mandate first">
            <p>
              The device remembers only the LAST mandate it signed, and only that one can be revoked from its menu. Sign a
              new one now and the current mandate
              {status?.budget ? ` (AUTO budget left ${amountText(status.budget.remaining, mandate!.tokenDecimals, mandate!.tokenSymbol)})` : ''} stays
              redeemable by the agent, out of reach of REVOKE, until a PANIC.
            </p>
            <p>
              To revoke it: on the device's Home screen hold SIGN 2 s and release (pairing QR), hold 2 s again for the
              device menu, select REVOKE (hold 2 s), page through, pulse + SIGN; then relay that QR on the{' '}
              <a href="#/kill">Kill switch page</a>. To kill every mandate at once: hold SIGN 5 s on Home (PANIC) and
              relay it.
            </p>
            <label className="check">
              <input type="checkbox" checked={keepLive} onChange={(e) => setKeepLive(e.target.checked)} />
              <span>
                Keep the current mandate live and sign another anyway
                <small>Both will be redeemable by the agent; only a PANIC stops the older one.</small>
              </span>
            </label>
          </Note>
        )}
        <Procedure>
          <Step n={1} title="Set the rules" state={s1}>
            <Field label="Agent address (delegate)" htmlFor="agent" hint="The account that redeems the delegation.">
              <input id="agent" className="input data" value={form.agent} spellCheck={false} onChange={(e) => set({ agent: e.target.value })} />
            </Field>
            <div className="field-row">
              <Field label="ERC-8004 agent id" htmlFor="agent-id" hint="Denials are filed against it. Optional.">
                <input id="agent-id" className="input" inputMode="numeric" value={form.agentId} onChange={(e) => set({ agentId: e.target.value })} />
              </Field>
              <Field label="Label" htmlFor="label" hint="Shown as (companion). At most 64 bytes.">
                <input id="label" className="input" value={form.label} maxLength={64} onChange={(e) => set({ label: e.target.value })} />
              </Field>
            </div>
            <div className="field-row">
              <Field label="Metered asset" htmlFor="token">
                <select id="token" className="select" value={custom ? 'custom' : form.token} onChange={(e) => void onToken(e.target.value === 'custom' ? '0x' : e.target.value)}>
                  {tokenOptions.map(([v, l]) => (
                    <option key={v} value={v}>
                      {l}
                    </option>
                  ))}
                  <option value="custom">Other ERC-20...</option>
                </select>
              </Field>
              {custom && (
                <Field label="Token address" htmlFor="token-addr" hint={form.tokenSymbol ? `${form.tokenSymbol}, ${form.tokenDecimals} decimals (read from the token)` : 'decimals are read from the token'}>
                  <input id="token-addr" className="input data" value={form.token} spellCheck={false} onChange={(e) => void onToken(e.target.value.trim())} />
                </Field>
              )}
              <Field label="Period" htmlFor="period">
                <select id="period" className="select" value={form.period} onChange={(e) => set({ period: Number(e.target.value) })}>
                  {PERIODS.map(([l, v]) => (
                    <option key={v} value={v}>
                      {l}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="field-row">
              <Field label={`AUTO cap per transaction (${form.tokenSymbol ?? 'units'})`} htmlFor="pertx">
                <input id="pertx" className="input" inputMode="decimal" value={form.perTxAutoCap} onChange={(e) => set({ perTxAutoCap: e.target.value })} />
              </Field>
              <Field label={`AUTO cap per period (${form.tokenSymbol ?? 'units'})`} htmlFor="perperiod" hint={form.period ? durationText(BigInt(form.period)) : 'never resets'}>
                <input id="perperiod" className="input" inputMode="decimal" value={form.periodAutoCap} onChange={(e) => set({ periodAutoCap: e.target.value })} />
              </Field>
            </div>
            <label className="check">
              <input type="checkbox" checked={form.newPayeeNeedsHuman} onChange={(e) => set({ newPayeeNeedsHuman: e.target.checked })} />
              <span>
                New payees need a pulse co-sign
                <small>A payee becomes known only after you co-signed a transfer to it under this mandate.</small>
              </span>
            </label>
            <label className="check">
              <input type="checkbox" checked={form.redeemerOnly} onChange={(e) => set({ redeemerOnly: e.target.checked })} />
              <span>
                Only the agent may redeem
                <small>Adds a RedeemerEnforcer rule, so the agent cannot re-delegate the mandate.</small>
              </span>
            </label>
            <Field label="Valid until (optional)" htmlFor="until" hint="Adds a TimestampEnforcer rule. Empty = no end.">
              <input
                id="until"
                className="input"
                type="datetime-local"
                onChange={(e) => set({ validUntil: e.target.value ? Math.floor(new Date(e.target.value).getTime() / 1000) : null })}
              />
            </Field>
            <Spec
              compact
              rows={[
                { k: 'Co-sign key', v: <>this device (P1 {device.keyId.slice(0, 10)}...)</> },
                { k: 'Sentinel', v: /^0x0{40}$/i.test(device.pinned.sentinel) ? 'none pinned' : <Hex value={device.pinned.sentinel} /> },
                {
                  k: 'Epoch',
                  v: epochErr ? (
                    <span style={{ color: 'var(--bad)' }}>could not read minEpoch: {epochErr}</span>
                  ) : epoch === null ? (
                    'reading...'
                  ) : (
                    `${epoch} (the on-chain panic floor of this device key)`
                  ),
                },
              ]}
            />
            <Note>
              <p>
                The epoch must equal the device's own panic floor. If a PANIC QR was never relayed, the device's floor
                is higher and it refuses this mandate as stale: relay the panic first.
              </p>
            </Note>
            <div className="row">
              <Button variant="primary" icon="qr" onClick={prepare} disabled={epoch === null || blocked}>
                Prepare the mandate
              </Button>
              {blocked && <span className="small muted">Revoke the current mandate first (see above).</span>}
              {formErr && (
                <span className="small" role="alert" style={{ color: 'var(--bad)' }}>
                  {formErr}
                </span>
              )}
            </div>
          </Step>

          <Step n={2} title="Review and sign on the device" state={s2}>
            {plan && preview ? (
              <>
                <div className="cols">
                  <Figure n="5.1" caption="What your device will show (predicted from the request bytes, line for line).">
                    <ReviewPanel preview={preview} />
                  </Figure>
                  <div className="stack">
                    <Spec
                      compact
                      rows={[
                        { k: 'Rules', v: `${plan.decoded.caveats.length} (pulse co-sign${form.redeemerOnly ? ', redeemer' : ''}${form.validUntil ? ', time window' : ''})` },
                        { k: 'AUTO per tx', v: amountText(plan.perTxAutoCap, form.tokenDecimals, form.tokenSymbol) },
                        { k: 'AUTO per period', v: amountText(plan.periodAutoCap, form.tokenDecimals, form.tokenSymbol) },
                        { k: 'Salt', v: plan.decoded.salt.toString() },
                      ]}
                    />
                    <Note kind="caution">
                      <p>Check the delegate, the vault and every cap on the device's screen, not here. This page is only the courier.</p>
                    </Note>
                    <DemoTokenNote
                      chainId={device.pinned.chainId}
                      token={form.token}
                      decimals={form.tokenDecimals}
                      symbol={form.tokenSymbol}
                      amounts={[plan.perTxAutoCap, plan.periodAutoCap]}
                    />
                  </div>
                </div>
                <DeviceExchangePanel
                  parts={plan.request.parts}
                  expect={['eth-signature']}
                  accept={(u) => answersMandate(u, plan.request)}
                  onResponse={onSigned}
                  runKey={plan.request.reqId}
                  figA="5.2"
                  figB="5.3"
                  round="mandate"
                />
              </>
            ) : (
              <p className="small muted">Prepare the mandate to see the device's review.</p>
            )}
            {signErr && (
              <Note kind="warning" alert>
                {signErr}
              </Note>
            )}
          </Step>
        </Procedure>
      </section>
      )}
      {mandate?.sentToAgentAt && maybeLive && (
        <NextStep to="inbox" label="Inbox">
          The agent holds the mandate. Payments it cannot make alone wait in the Inbox for your device.
        </NextStep>
      )}
    </div>
  );
}
