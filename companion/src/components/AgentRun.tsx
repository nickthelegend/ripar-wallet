// "Ask the agent to run now": one planner step on the agent (POST /run), so due invoices are paid on the AUTO path or
// escalated to the Inbox without a terminal. Optionally repeated every 30 s while the page is open.
import { useEffect, useRef, useState } from 'react';
import { type RunResult, agentClientOf } from '../lib/agent';
import { errorText } from '../lib/format';
import { store, useStore } from '../lib/store';
import { Button } from './ui';

export const AUTO_RUN_MS = 30_000;

export function AgentRun({ onRan, showAuto = true }: { onRan?: () => void; showAuto?: boolean }) {
  const settings = useStore((s) => s.settings);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<RunResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const cb = useRef(onRan);
  cb.current = onRan;

  const run = async () => {
    if (!settings.agentUrl) return;
    setBusy(true);
    setErr(null);
    try {
      setRes(await agentClientOf(settings).run());
      cb.current?.();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    if (!settings.agentAutoRun || !settings.agentUrl) return;
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') void runRef.current();
    }, AUTO_RUN_MS);
    return () => clearInterval(t);
  }, [settings.agentAutoRun, settings.agentUrl]);

  if (!settings.agentUrl) return <p className="small muted">Set the agent URL on the Connect page first.</p>;
  return (
    <div className="agent-run stack">
      <div className="row">
        <Button icon="play" busy={busy} onClick={() => void run()}>
          Ask the agent to run now
        </Button>
        {showAuto && (
          <label className="check inline">
            <input type="checkbox" checked={settings.agentAutoRun} onChange={(e) => store.setSettings({ agentAutoRun: e.target.checked })} />
            <span>Every 30 s while this page is open</span>
          </label>
        )}
      </div>
      {res && (
        <p className="small" role="status">
          <b>Agent ({res.planner ?? 'planner'}):</b> {res.summary}
          {res.error ? ` Error: ${res.error}` : ''}
        </p>
      )}
      {err && (
        <p className="small" role="alert" style={{ color: 'var(--bad)' }}>
          {err}
        </p>
      )}
    </div>
  );
}
