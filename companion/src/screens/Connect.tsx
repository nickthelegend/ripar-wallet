// 1 Connect: the network (RPC URL), the courier wallet that pays gas, the Ripar deployments JSON, the agent service.
import { useEffect, useRef, useState } from 'react';
import { PageHead } from '../App';
import { Button, Field, Hex, NextStep, Note, Procedure, Spec, Step, type StepState } from '../components/ui';
import { devStackState, probeDevStack } from '../lib/devstack';
import type { Settings } from '../lib/store';
import { type AgentHealth, agentClientOf } from '../lib/agent';
import { connectCourier, publicClientFor } from '../lib/clients';
import { errorText } from '../lib/format';
import { type NetworkId, NETWORKS, isLocalRpc } from '../lib/networks';
import { type CodeCheck, checkContracts } from '../lib/reads';
import { store, useDeployment, useStore } from '../lib/store';
import { formatEther } from 'viem';

export function Connect() {
  const settings = useStore((s) => s.settings);
  const { deployment, error: depError } = useDeployment();
  const explorer = NETWORKS[settings.network]?.explorer ?? null;

  const [rpc, setRpc] = useState<{ ok: boolean; text: string } | null>(null);
  const [rpcBusy, setRpcBusy] = useState(false);
  const [courier, setCourier] = useState<{ account: string; balance: string } | null>(null);
  const [courierErr, setCourierErr] = useState<string | null>(null);
  const [courierBusy, setCourierBusy] = useState(false);
  const [depUrl, setDepUrl] = useState(settings.deploymentsUrl);
  const [depText, setDepText] = useState('');
  const [depBusy, setDepBusy] = useState(false);
  const [depLoadErr, setDepLoadErr] = useState<string | null>(null);
  const [codes, setCodes] = useState<CodeCheck[] | null>(null);
  const [agentUrl, setAgentUrl] = useState(settings.agentUrl);
  const [agent, setAgent] = useState<AgentHealth | null>(null);
  const [agentErr, setAgentErr] = useState<string | null>(null);
  const [agentBusy, setAgentBusy] = useState(false);
  /** a dev stack found next to this companion (not applied yet) */
  const [stack, setStack] = useState<Partial<Settings> | null>(null);
  const [fromStack, setFromStack] = useState(devStackState.appliedAt !== null);
  const autoChecked = useRef(false);

  const setNetwork = (id: NetworkId) => {
    const n = NETWORKS[id];
    store.setSettings({ network: id, rpcUrl: n.rpcUrl, chainId: n.chainId, ...(id === 'monad-testnet' ? { courier: 'injected' } : {}) });
    setRpc(null);
    setCourier(null);
  };

  const checkRpc = async () => {
    setRpcBusy(true);
    try {
      const pc = publicClientFor(settings);
      const [cid, block] = await Promise.all([pc.getChainId(), pc.getBlockNumber()]);
      if (cid !== settings.chainId) setRpc({ ok: false, text: `The RPC reports chain ${cid}, expected ${settings.chainId}.` });
      else setRpc({ ok: true, text: `Chain ${cid}, block ${block.toLocaleString('en-US')}.` });
    } catch (e) {
      setRpc({ ok: false, text: `No answer from ${settings.rpcUrl}: ${errorText(e)}` });
    } finally {
      setRpcBusy(false);
    }
  };

  const connect = async () => {
    setCourierBusy(true);
    setCourierErr(null);
    try {
      const c = await connectCourier(settings);
      const bal = await publicClientFor(settings).getBalance({ address: c.account });
      setCourier({ account: c.account, balance: `${formatEther(bal)} MON` });
    } catch (e) {
      setCourierErr(errorText(e));
    } finally {
      setCourierBusy(false);
    }
  };

  const applyJson = (text: string, url = settings.deploymentsUrl) => {
    store.setSettings({ deploymentsJson: text, deploymentsUrl: url });
    setCodes(null);
  };

  const loadUrl = async () => {
    setDepBusy(true);
    setDepLoadErr(null);
    try {
      const r = await fetch(depUrl, { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      applyJson(await r.text(), depUrl);
    } catch (e) {
      setDepLoadErr(`Could not load ${depUrl}: ${errorText(e)}`);
    } finally {
      setDepBusy(false);
    }
  };

  const checkCode = async () => {
    if (!deployment) return;
    setDepBusy(true);
    try {
      setCodes(await checkContracts(publicClientFor(settings), deployment));
    } finally {
      setDepBusy(false);
    }
  };

  const checkAgent = async () => {
    setAgentBusy(true);
    setAgentErr(null);
    store.setSettings({ agentUrl });
    try {
      setAgent(await agentClientOf({ agentUrl, agentToken: settings.agentToken }).health());
    } catch (e) {
      setAgent(null);
      setAgentErr(errorText(e));
    } finally {
      setAgentBusy(false);
    }
  };

  // a companion opened without ?devstack on this machine: offer the local dev stack when one is running
  useEffect(() => {
    if (fromStack) return;
    let live = true;
    void probeDevStack(window.location).then((x) => {
      if (live && x && (x.rpcUrl !== settings.rpcUrl || x.deploymentsJson !== settings.deploymentsJson || x.agentUrl !== settings.agentUrl)) setStack(x);
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const useStack = () => {
    if (!stack) return;
    store.setSettings(stack);
    if (stack.agentUrl) setAgentUrl(stack.agentUrl);
    if (stack.deploymentsUrl !== undefined) setDepUrl(stack.deploymentsUrl);
    setStack(null);
    setRpc(null);
    setCourier(null);
    setAgent(null);
    autoChecked.current = false;
    setFromStack(true);
  };

  // settings that came from the dev stack are checked at once (RPC, courier, contracts, agent)
  useEffect(() => {
    if (!fromStack || autoChecked.current) return;
    autoChecked.current = true;
    void (async () => {
      await checkRpc();
      await connect();
      await checkCode();
      await checkAgent();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fromStack, settings.rpcUrl, settings.agentUrl]);

  const local = isLocalRpc(settings.rpcUrl);
  const states: StepState[] = [
    rpc?.ok ? 'done' : rpc ? 'error' : 'active',
    courier ? 'done' : courierErr ? 'error' : rpc?.ok ? 'active' : 'pending',
    deployment ? 'done' : depError ? 'error' : rpc?.ok ? 'active' : 'pending',
    agent ? 'done' : agentErr ? 'error' : deployment ? 'active' : 'pending',
  ];

  return (
    <div className="page">
      <PageHead
        no="1"
        title="Connect"
        lede="Point the companion at a network, a wallet that only pays gas, the Ripar contracts and your agent. Nothing here can sign for you: that is the device's job."
      />
      {stack && (
        <Note kind="caution" title="A local dev stack is running">
          <p>
            scripts/dev-stack.sh serves its settings next to this page: an anvil fork of Monad testnet at {stack.rpcUrl}, the
            Ripar contracts deployed on it, the agent at {stack.agentUrl} and an unlocked anvil courier. The public network
            selected below has no Ripar contracts to load.
          </p>
          <div className="row">
            <Button variant="primary" icon="link" onClick={useStack}>
              Use the local dev stack
            </Button>
          </div>
        </Note>
      )}
      {fromStack && (
        <Note kind="ok" title="Configured from the local dev stack">
          <p>
            RPC, courier, contracts and agent come from scripts/dev-stack.sh (an anvil fork: nothing here reaches a public
            chain). The checks below run by themselves.
          </p>
        </Note>
      )}
      {!stack && !fromStack && !settings.deploymentsJson && (
        <Note title="Where are the contracts?">
          <p>
            The companion needs a Ripar deployments JSON (step 3). For a local demo, start{' '}
            <code>bash scripts/dev-stack.sh</code> and open the URL it prints (it ends in <code>?devstack</code>): it
            fills this page for you.
          </p>
        </Note>
      )}
      <Procedure>
        <Step n={1} title="Network" state={states[0]!}>
          <div className="segmented" role="radiogroup" aria-label="Network">
            {(Object.keys(NETWORKS) as NetworkId[]).map((id) => (
              <label key={id}>
                <input type="radio" name="net" checked={settings.network === id} onChange={() => setNetwork(id)} />
                {NETWORKS[id].label}
              </label>
            ))}
          </div>
          <p className="small muted">{NETWORKS[settings.network]?.note}</p>
          <div className="field-row">
            <Field label="RPC URL" htmlFor="rpc" hint={`Chain id ${settings.chainId}. The device only knows 10143 and 143.`}>
              <input
                id="rpc"
                className="input data"
                value={settings.rpcUrl}
                spellCheck={false}
                onChange={(e) => {
                  store.setSettings({ rpcUrl: e.target.value.trim() });
                  setRpc(null);
                }}
              />
            </Field>
          </div>
          <div className="row">
            <Button onClick={checkRpc} busy={rpcBusy} icon="refresh">
              Check RPC
            </Button>
            {rpc && (
              <span className="small" role="status" style={{ color: rpc.ok ? 'var(--good)' : 'var(--bad)' }}>
                {rpc.text}
              </span>
            )}
          </div>
        </Step>

        <Step n={2} title="Courier wallet" state={states[1]!}>
          <p className="small muted">
            The courier signs and pays for the chain writes (register the device, deploy the vault, relay kill-switch
            and deny messages). It never owns the vault: K1, on the device, does.
          </p>
          <div className="segmented" role="radiogroup" aria-label="Courier">
            <label>
              <input type="radio" name="courier" checked={settings.courier === 'injected'} onChange={() => store.setSettings({ courier: 'injected' })} />
              Browser wallet
            </label>
            <label>
              <input
                type="radio"
                name="courier"
                checked={settings.courier === 'anvil'}
                disabled={!local}
                onChange={() => store.setSettings({ courier: 'anvil' })}
              />
              Anvil dev account
            </label>
          </div>
          {settings.courier === 'anvil' && (
            <Field label="Unlocked anvil account" htmlFor="anvil-acct" hint="anvil signs for its own unlocked dev accounts; the companion never sees a key.">
              <input
                id="anvil-acct"
                className="input data"
                value={settings.anvilAccount}
                spellCheck={false}
                onChange={(e) => store.setSettings({ anvilAccount: e.target.value.trim() as `0x${string}` })}
              />
            </Field>
          )}
          <div className="row">
            <Button onClick={connect} busy={courierBusy} icon="link">
              {courier ? 'Reconnect' : 'Connect courier'}
            </Button>
            {courierErr && (
              <span className="small" role="alert" style={{ color: 'var(--bad)' }}>
                {courierErr}
              </span>
            )}
          </div>
          {courier && (
            <Spec
              rows={[
                { k: 'Account', v: <Hex value={courier.account} explorer={explorer} /> },
                { k: 'Balance', v: courier.balance },
              ]}
            />
          )}
        </Step>

        <Step n={3} title="Ripar contracts" state={states[2]!}>
          <p className="small muted">
            The addresses come from the deployments JSON that <code>contracts/script/Deploy.s.sol</code> writes (
            <code>deployments/{settings.chainId}.json</code>). They are never built into the companion.
          </p>
          <div className="field-row">
            <Field label="Deployments JSON URL" htmlFor="dep-url" error={depLoadErr}>
              <input
                id="dep-url"
                className="input data"
                placeholder={`https://.../deployments/${settings.chainId}.json`}
                value={depUrl}
                spellCheck={false}
                onChange={(e) => setDepUrl(e.target.value.trim())}
              />
            </Field>
          </div>
          <div className="row">
            <Button onClick={loadUrl} busy={depBusy} disabled={!depUrl} icon="refresh">
              Load
            </Button>
          </div>
          <Field label="Or paste the JSON" htmlFor="dep-json" error={depError}>
            <textarea
              id="dep-json"
              className="textarea data"
              rows={4}
              spellCheck={false}
              placeholder='{"chainId": 10143, "RiparDeviceRegistry": "0x...", ...}'
              value={depText}
              onChange={(e) => setDepText(e.target.value)}
            />
          </Field>
          <div className="row">
            <Button onClick={() => applyJson(depText, '')} disabled={!depText.trim()}>
              Use pasted JSON
            </Button>
            {settings.deploymentsJson && (
              <Button variant="quiet" onClick={() => store.setSettings({ deploymentsJson: null, deploymentsUrl: '' })}>
                Clear
              </Button>
            )}
          </div>
          {deployment && (
            <>
              <Spec
                rows={[
                  { k: 'Chain', v: deployment.chainId.toString() },
                  { k: 'Device registry', v: <Hex value={deployment.registry} explorer={explorer} /> },
                  { k: 'PulseCosignEnforcer', v: <Hex value={deployment.enforcer} explorer={explorer} /> },
                  { k: 'Sentinel', v: <Hex value={deployment.sentinel} explorer={explorer} /> },
                  { k: 'Reputation relay', v: <Hex value={deployment.relay} explorer={explorer} /> },
                  { k: 'MockUSD', v: <Hex value={deployment.mockUsd} explorer={explorer} /> },
                  { k: 'DelegationManager', v: <Hex value={deployment.delegationManager} explorer={explorer} /> },
                ]}
              />
              <div className="row">
                <Button onClick={checkCode} busy={depBusy} icon="check">
                  Check the code on this RPC
                </Button>
              </div>
              {codes && (
                <Spec
                  compact
                  rows={codes.map((c) => ({
                    k: c.name,
                    v:
                      c.bytes === null ? (
                        <span style={{ color: 'var(--warn)' }}>could not read</span>
                      ) : c.bytes === 0 ? (
                        <span style={{ color: 'var(--bad)' }}>no code at this address on this network</span>
                      ) : (
                        <span style={{ color: 'var(--good)' }}>{c.bytes.toLocaleString('en-US')} bytes of code</span>
                      ),
                  }))}
                />
              )}
            </>
          )}
        </Step>

        <Step n={4} title="Agent service" state={states[3]!}>
          <p className="small muted">
            The agent redeems the mandate by itself inside its caps and asks you (through this inbox) for anything
            bigger. It is as untrusted as this page: the device checks everything it signs.
          </p>
          <div className="field-row">
            <Field label="Agent URL" htmlFor="agent-url" error={agentErr}>
              <input id="agent-url" className="input data" value={agentUrl} spellCheck={false} onChange={(e) => setAgentUrl(e.target.value.trim())} />
            </Field>
          </div>
          <Field label="API token (optional)" htmlFor="agent-token" hint="Only when the agent runs with AGENT_API_TOKEN. Kept in this browser; it is not a wallet key.">
            <input
              id="agent-token"
              className="input data"
              type="password"
              autoComplete="off"
              value={settings.agentToken}
              onChange={(e) => store.setSettings({ agentToken: e.target.value.trim() })}
            />
          </Field>
          <div className="row">
            <Button onClick={checkAgent} busy={agentBusy} icon="refresh">
              Check agent
            </Button>
          </div>
          {agent && (
            <Spec
              rows={[
                { k: 'Status', v: agent.ok ? 'answering' : 'reports a problem' },
                agent.agent && { k: 'Agent address', v: <Hex value={agent.agent.address} explorer={explorer} /> },
                agent.agent && { k: 'ERC-8004 agent id', v: agent.agent.agentId?.toString() ?? 'not registered' },
                agent.chainId !== null && {
                  k: 'Agent chain',
                  v: agent.chainId === settings.chainId ? String(agent.chainId) : <span style={{ color: 'var(--bad)' }}>{agent.chainId}: not this network's chain</span>,
                },
                agent.mandate && { k: 'Agent holds mandate', v: <><Hex value={agent.mandate.delegationHash} /> {agent.mandate.status}</> },
              ]}
            />
          )}
        </Step>
      </Procedure>

      <details className="section paste">
        <summary>Transport and scanning settings</summary>
        <div className="field-row" style={{ marginTop: 12 }}>
          <Field label="QR frame time (ms)" htmlFor="frame-ms" hint="About 300 ms per multipart frame.">
            <input
              id="frame-ms"
              className="input"
              type="number"
              min={120}
              max={2000}
              value={settings.frameMs}
              onChange={(e) => store.setSettings({ frameMs: Math.min(2000, Math.max(120, Number(e.target.value) || 300)) })}
            />
          </Field>
          <Field label="Fragment size (bytes)" htmlFor="frag" hint="60 to 80 bytes per part.">
            <input
              id="frag"
              className="input"
              type="number"
              min={40}
              max={200}
              value={settings.fragLen}
              onChange={(e) => store.setSettings({ fragLen: Math.min(200, Math.max(40, Number(e.target.value) || 70)) })}
            />
          </Field>
          <Field label="Log range per request (blocks)" htmlFor="chunk">
            <input
              id="chunk"
              className="input"
              type="number"
              min={10}
              max={10000}
              value={settings.logChunk}
              onChange={(e) => store.setSettings({ logChunk: Math.max(10, Number(e.target.value) || 100) })}
            />
          </Field>
          <Field label="Activity look-back (blocks)" htmlFor="lookback">
            <input
              id="lookback"
              className="input"
              type="number"
              min={100}
              max={1000000}
              value={settings.logLookback}
              onChange={(e) => store.setSettings({ logLookback: Math.max(100, Number(e.target.value) || 3000) })}
            />
          </Field>
        </div>
      </details>

      {deployment && agent && rpc?.ok && (
        <NextStep to="device" label="Device">Network, contracts and agent answer. Choose the signer next.</NextStep>
      )}

      {!local && settings.network === 'anvil-fork' && (
        <div className="section">
          <Note kind="caution">The anvil preset expects a local RPC (127.0.0.1).</Note>
        </div>
      )}
    </div>
  );
}
