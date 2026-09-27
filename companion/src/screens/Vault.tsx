// 4 Vault: the canonical HybridDeleGator of K1 (derived twice, must agree), deployed through SimpleFactory by the
// courier, funded from the MockUSD faucet, with its balances and agent lane.
import { useEffect, useState } from 'react';
import { formatEther } from 'viem';
import { AUSD_10143 } from '@ripar/protocol';
import { PageHead } from '../App';
import { TxAction } from '../components/TxAction';
import { Button, Empty, Field, Hex, Mark, NextStep, Note, Procedure, Spec, Step, type StepState } from '../components/ui';
import { FAUCET_MAX, deployVaultWrite, faucetWrite } from '../lib/chain';
import { publicClientFor } from '../lib/clients';
import { amountText, errorText, parseUnits } from '../lib/format';
import { type VaultDerivation, deriveVault } from '../lib/flows/vault';
import { NETWORKS } from '../lib/networks';
import { type VaultStatus, readVaultStatus } from '../lib/reads';
import { useDeployment, useStore } from '../lib/store';

export function Vault() {
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const { deployment } = useDeployment();
  const explorer = NETWORKS[settings.network]?.explorer ?? null;
  const [deriv, setDeriv] = useState<VaultDerivation | null>(null);
  const [derivErr, setDerivErr] = useState<string | null>(null);
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [amount, setAmount] = useState('500');

  const k1 = device?.k1Address;
  useEffect(() => {
    if (!k1) return;
    deriveVault(k1, settings.chainId).then(setDeriv, (e) => setDerivErr(errorText(e)));
  }, [k1, settings.chainId]);

  const refresh = async () => {
    if (!deriv) return;
    setBusy(true);
    try {
      const tokens = [deployment?.mockUsd, settings.chainId === 10143 ? AUSD_10143 : undefined].filter(Boolean) as `0x${string}`[];
      setStatus(await readVaultStatus(publicClientFor(settings), deployment, deriv.address, tokens));
      setStatusErr(null);
    } catch (e) {
      setStatusErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deriv?.address, deployment?.mockUsd]);

  if (!device) {
    return (
      <div className="page">
        <PageHead no="4" title="Vault" lede="The vault is a MetaMask HybridDeleGator owned by the device's K1 alone." />
        <Empty title="Pair a device first">The vault address is derived from the device's K1 key, which the pairing reveals.</Empty>
      </div>
    );
  }

  let faucetAmount: bigint | null = null;
  let faucetErr: string | null = null;
  try {
    faucetAmount = parseUnits(amount, 6);
    if (faucetAmount <= 0n || faucetAmount > FAUCET_MAX) faucetErr = 'Between 0 and 1,000 mUSD per call.';
  } catch (e) {
    faucetErr = (e as Error).message;
  }

  const pinnedOk = deriv ? deriv.address === device.pinned.vault : true;
  const s1: StepState = deriv ? (deriv.matches && pinnedOk ? 'done' : 'error') : 'active';
  const s2: StepState = status?.deployed ? 'done' : deriv?.matches ? 'active' : 'pending';
  const mock = status?.tokens.find((t) => deployment && t.address.toLowerCase() === deployment.mockUsd.toLowerCase());
  const s3: StepState = mock?.balance ? 'done' : status?.deployed ? 'active' : 'pending';

  return (
    <div className="page">
      <PageHead
        no="4"
        title="Vault"
        lede="A MetaMask HybridDeleGator owned by K1 alone, behind the canonical SimpleFactory. Its address follows from K1, so the device can refuse any other vault."
      />
      <Procedure>
        <Step n={1} title="Derive the address" state={s1} aside={deriv ? <Mark tone={deriv.matches ? 'good' : 'bad'}>{deriv.matches ? 'BOTH AGREE' : 'MISMATCH'}</Mark> : undefined}>
          {derivErr && (
            <Note kind="warning" alert>
              {derivErr}
            </Note>
          )}
          {!deriv && !derivErr && <p className="small muted">Deriving the vault address from K1 (two independent derivations)...</p>}
          {deriv && (
            <Spec
              rows={[
                { k: 'Owner (K1)', v: <Hex value={deriv.owner} explorer={explorer} /> },
                { k: '@ripar/protocol', v: <Hex value={deriv.address} explorer={explorer} /> },
                { k: 'smart-accounts-kit', v: <Hex value={deriv.kitAddress} /> },
                { k: 'Pinned on the device', v: <Hex value={device.pinned.vault} /> },
                { k: 'Factory', v: <Hex value={deriv.factory} /> },
                { k: 'Deploy parameters', v: <code>[K1, [], [], []], salt 0</code> },
              ]}
            />
          )}
          {deriv && !pinnedOk && <Note kind="warning">The device pinned another vault. Pair again.</Note>}
        </Step>

        <Step n={2} title="Deploy" state={s2} aside={status?.deployed ? <Mark tone="good">DEPLOYED</Mark> : undefined}>
          {status?.deployed ? (
            <Spec
              compact
              rows={[
                { k: 'Code', v: `${status.codeBytes} bytes (ERC1967 proxy)` },
                { k: 'owner()', v: status.owner ? <Hex value={status.owner} /> : 'could not read' },
              ]}
            />
          ) : status === null && deriv?.matches ? (
            <p className="small muted">{statusErr ? `Could not read the vault's code: ${statusErr}` : 'Reading the vault...'}</p>
          ) : deriv?.matches ? (
            <>
              <p className="small muted">
                Counterfactual until deployed: the address already works as the mandate's delegator. The courier pays the
                deployment; the vault is K1's from the first block.
              </p>
              <TxAction write={deployVaultWrite(deriv.factory, deriv.factoryData, deriv.address)} label="Deploy the vault" onDone={() => void refresh()} />
            </>
          ) : (
            <p className="small muted">Waiting for a matching derivation.</p>
          )}
        </Step>

        <Step n={3} title="Fund" state={s3}>
          {deployment && !/^0x0{40}$/i.test(deployment.mockUsd) ? (
            <>
              <div className="field-row">
                <Field label="MockUSD to mint into the vault" htmlFor="faucet" error={faucetErr} hint="Testnet demo token, 6 decimals, at most 1,000 per call.">
                  <input id="faucet" className="input" inputMode="decimal" value={amount} onChange={(e) => setAmount(e.target.value)} aria-invalid={!!faucetErr} />
                </Field>
              </div>
              {faucetAmount !== null && !faucetErr && (
                <TxAction key={amount} write={faucetWrite(deployment.mockUsd, deriv?.address ?? device.pinned.vault, faucetAmount)} label="Mint MockUSD" onDone={() => void refresh()} />
              )}
            </>
          ) : (
            <p className="small muted">This deployment has no MockUSD faucet.</p>
          )}
          <p className="small muted">For native MON, send it to the vault address from any wallet.</p>
        </Step>
      </Procedure>

      <section className="section">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2>Balances and lane</h2>
          <Button size="small" icon="refresh" busy={busy} onClick={refresh}>
            Refresh
          </Button>
        </div>
        {statusErr && (
          <Note kind="warning" alert>
            Could not read the vault: {statusErr}
          </Note>
        )}
        {status ? (
          <div className="big-status" style={{ marginTop: 12 }}>
            <div>
              <div className="k">MON</div>
              <div className={`v${status.native === null ? ' unknown' : ''}`}>{status.native === null ? 'could not read' : formatEther(status.native)}</div>
            </div>
            {status.tokens.map((t) => (
              <div key={t.address}>
                <div className="k">{t.symbol ?? 'token'}</div>
                <div className={`v${t.balance === null ? ' unknown' : ''}`}>{t.balance === null ? 'could not read' : amountText(t.balance, t.decimals, '').trim()}</div>
              </div>
            ))}
            <div>
              <div className="k">Agent lane (sentinel)</div>
              <div className={`v ${status.laneOpen === false ? 'bad' : status.laneOpen ? 'good' : ''}`}>
                {status.laneOpen === null ? 'could not read' : status.laneOpen ? 'Open' : 'Closed'}
              </div>
            </div>
          </div>
        ) : (
          !statusErr && <p className="small muted">Reading...</p>
        )}
      </section>
      {status?.deployed && (mock?.balance ?? 0n) > 0n && (
        <NextStep to="mandate" label="Mandate">The vault is deployed and funded. Next, tell the agent what it may spend by itself.</NextStep>
      )}
    </div>
  );
}
