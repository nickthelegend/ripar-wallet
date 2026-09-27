// Kill switch: the device signs REVOKE, PANIC or REOPEN by itself (for the contracts it pinned); this page reads
// that QR, verifies it and relays it. Also the lane, the panic epoch and the state of every mandate recorded here.
import { useEffect, useState } from 'react';
import { PageHead } from '../App';
import { DeviceExchangePanel } from '../components/DeviceExchangePanel';
import { VerifyPanel } from '../components/Review';
import { TxAction } from '../components/TxAction';
import { Button, Empty, Hex, Mark, Note } from '../components/ui';
import { publicClientFor } from '../lib/clients';
import { errorText } from '../lib/format';
import { KILL_TYPES, type KillSwitchMessage, acceptKillSwitch } from '../lib/flows/killswitch';
import { RIPAR_SENTINEL_ABI } from '@ripar/protocol';
import { type MandateStatus, readMandateStatus, readMinEpoch } from '../lib/reads';
import { useStore } from '../lib/store';

export function KillSwitch() {
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const mandates = useStore((s) => s.mandates);
  const [lane, setLane] = useState<{ open: boolean | null; nonce: bigint | null; minEpoch: bigint | null } | null>(null);
  const [mstat, setMstat] = useState<Record<string, MandateStatus>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<KillSwitchMessage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [run, setRun] = useState(0);

  const refresh = async () => {
    if (!device) return;
    setBusy(true);
    try {
      const pc = publicClientFor(settings);
      const p = device.pinned;
      const [open, nonce, minEpoch, ...ms] = await Promise.all([
        pc.readContract({ address: p.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'laneOpen', args: [p.vault] }).catch(() => null),
        pc.readContract({ address: p.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'lastReopenNonce', args: [p.vault] }).catch(() => null),
        readMinEpoch(pc, p.enforcer, device.keyId).catch(() => null),
        ...mandates.map((m) => readMandateStatus(pc, p.enforcer, device.keyId, m.delegationHash, m.pulseTerms)),
      ]);
      setLane({ open: open as boolean | null, nonce: nonce as bigint | null, minEpoch: minEpoch as bigint | null });
      setMstat(Object.fromEntries(mandates.map((m, i) => [m.delegationHash, ms[i] as MandateStatus])));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device?.keyId, mandates.length]);

  if (!device) {
    return (
      <div className="page">
        <PageHead title="Kill switch" lede="Revoke a mandate, PANIC to kill all of them, or reopen the agent lane. The device signs; anyone can relay." />
        <Empty title="Pair a device first">The kill-switch messages are signed for the contracts the device pinned at pairing.</Empty>
      </div>
    );
  }

  const minEpoch = lane?.minEpoch ?? null;
  const onRead = (ur: string) => {
    try {
      setMsg(acceptKillSwitch(ur, device));
      setErr(null);
    } catch (e) {
      setErr(errorText(e));
      setRun((r) => r + 1);
    }
  };

  return (
    <div className="page">
      <PageHead
        title="Kill switch"
        lede="The device signs these by itself, for the contracts it pinned at pairing. This page reads the QR, checks the signature and relays it: relay it at once."
      />

      <section className="section" aria-label="Status">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
          <h2>Now</h2>
          <Button size="small" icon="refresh" busy={busy} onClick={refresh}>
            Refresh
          </Button>
        </div>
        <div className="big-status">
          <div>
            <div className="k">Agent AUTO lane</div>
            <div className={`v ${lane?.open === false ? 'bad' : lane?.open ? 'good' : ''}`}>
              {!lane || lane.open === null ? '?' : lane.open ? 'Open' : 'Closed'}
            </div>
          </div>
          <div>
            <div className="k">Panic epoch (minEpoch)</div>
            <div className="v">{minEpoch === null ? '?' : minEpoch.toString()}</div>
          </div>
          <div>
            <div className="k">Last reopen nonce</div>
            <div className="v">{lane?.nonce == null ? '?' : lane.nonce.toString()}</div>
          </div>
          <div>
            <div className="k">Mandates recorded</div>
            <div className="v">{mandates.length}</div>
          </div>
        </div>
        {mandates.length > 0 && (
          <div className="ledger-wrap" style={{ marginTop: 16 }}>
            <table className="ledger">
              <thead>
                <tr>
                  <th scope="col">Mandate</th>
                  <th scope="col">Agent</th>
                  <th scope="col">Epoch</th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {[...mandates].reverse().map((m) => {
                  const st = mstat[m.delegationHash];
                  const killed = st?.minEpoch != null && BigInt(m.epoch) < st.minEpoch;
                  return (
                    <tr key={m.delegationHash}>
                      <td>
                        <code>{m.delegationHash.slice(0, 18)}...</code>
                      </td>
                      <td>
                        <code>{m.agent.slice(0, 10)}...</code>
                      </td>
                      <td>{m.epoch}</td>
                      <td>
                        {!st ? (
                          '?'
                        ) : st.revoked ? (
                          <Mark tone="bad">REVOKED</Mark>
                        ) : killed ? (
                          <Mark tone="bad">KILLED BY PANIC</Mark>
                        ) : (
                          <Mark tone="good">LIVE</Mark>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section">
        <h2>On the device</h2>
        <div className="ledger-wrap">
          <table className="ledger keys-table">
            <thead>
              <tr>
                <th scope="col">Action</th>
                <th scope="col">How</th>
                <th scope="col">Effect</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>PANIC</td>
                <td>Home: hold SIGN 5 s. Signed at once, no pulse.</td>
                <td>Raises the epoch: every mandate this device signed dies.</td>
              </tr>
              <tr>
                <td>Revoke</td>
                <td>Home: hold 2 s, release (pairing QR), hold 2 s: menu, REVOKE (hold 2 s), pulse + SIGN.</td>
                <td>Kills the last mandate. Scan the QR before leaving it: it is shown once.</td>
              </tr>
              <tr>
                <td>Reopen</td>
                <td>Same menu, press to REOPEN, hold 2 s, pulse + SIGN.</td>
                <td>Opens the AUTO lane the sentinel closed. Valid until a higher nonce lands.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="section">
        <h2>Read and relay</h2>
        {!msg ? (
          <DeviceExchangePanel parts={[]} expect={[...KILL_TYPES]} onResponse={onRead} runKey={`kill-${run}`} figB="7.1" />
        ) : (
          <div className="stack">
            <VerifyPanel report={msg.report} />
            <Note kind={msg.type === 'ripar-reopen' ? 'caution' : 'warning'} title={msg.type.replace('ripar-', '').toUpperCase()}>
              <p>{msg.effect}</p>
            </Note>
            <TxAction variant={msg.type === 'ripar-reopen' ? 'primary' : 'danger solid'} write={msg.write} label="Relay now" onDone={() => void refresh()} />
            <div className="row">
              <Button
                variant="quiet"
                icon="qr"
                onClick={() => {
                  setMsg(null);
                  setRun((r) => r + 1);
                }}
              >
                Read another kill-switch QR
              </Button>
            </div>
            <p className="small muted">
              Device key <Hex value={device.keyId} copy={false} />
            </p>
          </div>
        )}
        {err && <Note kind="warning">{err}</Note>}
      </section>
    </div>
  );
}
