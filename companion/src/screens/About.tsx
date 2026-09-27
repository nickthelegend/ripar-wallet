// About and proof: every contract address in use, the security model, and the EMULATOR disclaimer.
import {
  DELEGATION_MANAGER,
  ENTRY_POINT_V07,
  ERC8004_TESTNET,
  EMULATOR_FIRMWARE_ID,
  HYBRID_DELEGATOR_IMPL,
  SIMPLE_FACTORY,
} from '@ripar/protocol';
import { PageHead } from '../App';
import { EmulatorMark, Hex, Note, Spec } from '../components/ui';
import { GAS_LIMITS } from '../lib/chain';
import { NETWORKS } from '../lib/networks';
import { useDeployment, useStore } from '../lib/store';

export function About() {
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const { deployment } = useDeployment();
  const explorer = NETWORKS[settings.network]?.explorer ?? null;
  const H = (a: string) => <Hex value={a} explorer={explorer} />;
  return (
    <div className="page">
      <PageHead
        title="About and proof"
        lede="Every address this companion talks to, why it cannot move your funds, and what the EMULATOR is and is not."
      />

      <section className="section prose">
        <h2>Security model</h2>
        <p>
          The Ripar device decides; everything else carries bytes. The device has no radio: requests reach it only as QR
          codes through its camera, and it answers with one QR on its screen. It parses every request strictly, checks it
          against the chain and contracts it pinned when you paired it, shows every field it signs, rebuilds every digest
          itself, and signs only while a live pulse is on its sensor and you press SIGN. K1, the key that owns your vault,
          signs nothing but mandates; P1 co-signs the payments the agent cannot make alone.
        </p>
        <p>
          This companion and your AI agent are untrusted couriers. This page never asks for, stores or logs a seed or a
          private key; the courier wallet only pays gas. A malicious companion can refuse to relay, or show you the wrong
          text, but it cannot make the device sign anything its own screen did not show you: read the device, not this
          page. The chain enforces the rest: the PulseCosignEnforcer caps what the agent spends alone, the sentinel can
          only close its lane, and a PANIC from the device kills every mandate it ever signed.
        </p>
      </section>

      <section className="section">
        <h2>The EMULATOR</h2>
        <Note kind="warning" title="EMULATOR - DEMO KEYS">
          <p>
            The in-page device is the Ripar firmware compiled to WebAssembly: the same parsing, policy, review lines and
            signing code as the hardware, driven by a synthetic pulse. Its seed lives in this browser's storage, so it is
            a demo, never a wallet. Its pairing carries the firmware id <code>{EMULATOR_FIRMWARE_ID}</code>{' '}
            (sha256 of "ripar-emulator v1"), and this companion labels everything it signed <EmulatorMark />.
          </p>
        </Note>
      </section>

      <section className="section">
        <h2>Contracts</h2>
        <h3 style={{ margin: '16px 0 8px', fontSize: 'var(--t-md)' }}>MetaMask delegation framework v1.3.0 (canonical)</h3>
        <Spec
          rows={[
            { k: 'DelegationManager', v: H(DELEGATION_MANAGER) },
            { k: 'SimpleFactory', v: H(SIMPLE_FACTORY) },
            { k: 'HybridDeleGator implementation', v: H(HYBRID_DELEGATOR_IMPL) },
            { k: 'EntryPoint v0.7', v: H(ENTRY_POINT_V07) },
          ]}
        />
        <h3 style={{ margin: '24px 0 8px', fontSize: 'var(--t-md)' }}>ERC-8004 on Monad testnet</h3>
        <Spec
          rows={[
            { k: 'Identity registry', v: H(ERC8004_TESTNET.identity) },
            { k: 'Reputation registry', v: H(ERC8004_TESTNET.reputation) },
          ]}
        />
        <h3 style={{ margin: '24px 0 8px', fontSize: 'var(--t-md)' }}>Ripar (from the deployments JSON)</h3>
        {deployment ? (
          <Spec
            rows={[
              { k: 'RiparDeviceRegistry', v: H(deployment.registry) },
              { k: 'PulseCosignEnforcer', v: H(deployment.enforcer) },
              { k: 'RiparSentinel', v: H(deployment.sentinel) },
              { k: 'RiparReputationRelay', v: H(deployment.relay) },
              { k: 'MockUSD (demo token)', v: H(deployment.mockUsd) },
              { k: 'CREATE2 salt', v: <Hex value={deployment.salt} /> },
            ]}
          />
        ) : (
          <p className="small muted">Not loaded. Ripar addresses are never built in: load them on the Connect page.</p>
        )}
        {device && (
          <>
            <h3 style={{ margin: '24px 0 8px', fontSize: 'var(--t-md)' }}>Your device and vault</h3>
            <Spec
              rows={[
                { k: 'K1 (vault owner)', v: H(device.k1Address) },
                { k: 'P1 key id', v: <Hex value={device.keyId} /> },
                { k: 'Vault', v: H(device.pinned.vault) },
                { k: 'Signer', v: device.emulator ? <EmulatorMark /> : 'Ripar hardware' },
              ]}
            />
          </>
        )}
      </section>

      <section className="section">
        <h2>Chain writes and their gas limits</h2>
        <p>Every write is simulated first and sent with an explicit limit: Monad charges for the limit, not the use.</p>
        <div style={{ marginTop: 12 }}>
          <Spec compact rows={Object.entries(GAS_LIMITS).map(([k, v]) => ({ k, v: <span className="data">{v.toLocaleString('en-US')}</span> }))} />
        </div>
      </section>

      <section className="section prose">
        <h2>Sources</h2>
        <p>
          Protocol: <code>docs/PROTOCOL.md</code>. Device screens and keys: <code>docs/FIRMWARE.md</code>. Contract
          behaviour: <code>contracts/SPEC.md</code>. The companion's protocol code is <code>@ripar/protocol</code>, a
          byte-for-byte port of the firmware's reference tool <code>make_request.py</code>.
        </p>
      </section>
    </div>
  );
}
