// 3 Pair: learn K1 from the keys-only pairing QR, derive the canonical vault, send the full pairing request (the
// device pins the contracts after pulse + SIGN and signs BindDevice with P1 and K1), verify, register on-chain.
import { useEffect, useState } from 'react';
import { type VerifyReport, parseResponse, checkDeploymentPins, type RiparDeployment } from '@ripar/protocol';
import { PageHead } from '../App';
import { DeviceExchangePanel } from '../components/DeviceExchangePanel';
import { VerifyPanel } from '../components/Review';
import { TxAction } from '../components/TxAction';
import { Button, EmulatorMark, Hex, Mark, NextStep, Note, Procedure, Spec, Step, type StepState } from '../components/ui';
import { registerDeviceWrite } from '../lib/chain';
import { publicClientFor } from '../lib/clients';
import { errorText, utcText } from '../lib/format';
import { type PairPlan, acceptPairing, answersRequest, isKeysOnlyPair, planPairing, readKeysOnly } from '../lib/flows/pairing';
import { NETWORKS } from '../lib/networks';
import { readDeviceStatus, readMinEpoch } from '../lib/reads';
import { currentMandate, store, useDeployment, useStore } from '../lib/store';
import { computeVaultAddress, RIPAR_SENTINEL_ABI } from '@ripar/protocol';

export function Pair() {
  const settings = useStore((s) => s.settings);
  const keys = useStore((s) => s.keysOnly);
  const device = useStore((s) => s.device);
  const mandate = useStore(currentMandate);
  const { deployment } = useDeployment();
  const explorer = NETWORKS[settings.network]?.explorer ?? null;

  const [readKeys, setReadKeys] = useState(!keys);
  const [keysErr, setKeysErr] = useState<string | null>(null);
  const [plan, setPlan] = useState<PairPlan | null>(null);
  const [planBusy, setPlanBusy] = useState(false);
  const [planErr, setPlanErr] = useState<string | null>(null);
  const [floors, setFloors] = useState<{ minEpoch: bigint | null; reopenNonce: bigint | null } | null>(null);
  const [report, setReport] = useState<VerifyReport | null>(null);
  const [pairErr, setPairErr] = useState<string | null>(null);
  const [owner, setOwner] = useState<{ owner: string | null; readable: boolean } | null>(null);

  const paired = !!device && !!keys && device.k1Address === keys.k1Address;

  const refreshOwner = async () => {
    if (!device || !deployment) return;
    const st = await readDeviceStatus(publicClientFor(settings), deployment, device.keyId);
    setOwner({ owner: st.registeredOwner, readable: st.readable });
  };
  useEffect(() => {
    void refreshOwner();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device?.keyId, deployment?.registry]);

  const onKeys = (ur: string) => {
    try {
      const k = readKeysOnly(ur);
      store.set({ keysOnly: k });
      setReadKeys(false);
      setKeysErr(null);
      setPlan(null);
    } catch (e) {
      setKeysErr(errorText(e));
    }
  };

  const prepare = async () => {
    if (!deployment || !keys) return;
    setPlanBusy(true);
    setPlanErr(null);
    setReport(null);
    setPairErr(null);
    try {
      const pc = publicClientFor(settings);
      const vault = computeVaultAddress(keys.k1Address);
      // floors: the on-chain panic epoch of this key and the sentinel's last reopen nonce (restrict-only)
      const [minEpoch, reopenNonce] = await Promise.all([
        readMinEpoch(pc, deployment.enforcer, keys.keyId).catch(() => null),
        pc
          .readContract({ address: deployment.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'lastReopenNonce', args: [vault] })
          .catch(() => null),
      ]);
      setFloors({ minEpoch, reopenNonce });
      setPlan(planPairing(deployment, keys.k1Address, { now: Math.floor(Date.now() / 1000), minEpoch, reopenNonce, fragLen: settings.fragLen }));
    } catch (e) {
      setPlanErr(errorText(e));
    } finally {
      setPlanBusy(false);
    }
  };

  const onPair = (ur: string) => {
    if (!plan) return;
    try {
      setReport(parseResponse(ur, { request: plan.request }));
      const d = acceptPairing(ur, plan, keys);
      store.set({ device: d });
      setPairErr(null);
      setPlan(null);
      void refreshOwner();
    } catch (e) {
      setPairErr(errorText(e));
    }
  };

  const s1: StepState = keys && !readKeys ? 'done' : keysErr ? 'error' : 'active';
  const s2: StepState = paired && !plan ? 'done' : pairErr ? 'error' : keys && !readKeys ? 'active' : 'pending';
  const registered = !!device && owner?.owner?.toLowerCase() === device.k1Address.toLowerCase();
  const s3: StepState = registered ? 'done' : paired ? 'active' : 'pending';

  return (
    <div className="page">
      <PageHead
        no="3"
        title="Pair the device"
        lede="Two rounds. First the device shows its public keys, so the companion can derive the one vault firmware v1.2 accepts. Then the device pins your contracts and vault, and signs that binding with both keys."
      />
      <Procedure>
        <Step n={1} title="Read the device keys" state={s1} aside={keys?.emulator ? <EmulatorMark /> : undefined}>
          {keys && !readKeys ? (
            <>
              <Spec
                rows={[
                  { k: 'K1, vault owner', v: <Hex value={keys.k1Address} explorer={explorer} /> },
                  { k: 'P1 key id', v: <Hex value={keys.keyId} /> },
                  { k: 'Firmware id', v: <code>{keys.firmwareId}</code> },
                  { k: 'Signer', v: keys.emulator ? <EmulatorMark /> : 'Ripar hardware' },
                ]}
              />
              <div className="row">
                <Button variant="quiet" icon="refresh" onClick={() => setReadKeys(true)}>
                  Read another device
                </Button>
              </div>
            </>
          ) : (
            <DeviceExchangePanel
              parts={[]}
              expect={['ripar-pair']}
              accept={isKeysOnlyPair}
              onResponse={onKeys}
              runKey="keys-only"
              figB="3.1"
              round="keys"
            />
          )}
          {keysErr && <Note kind="warning">{keysErr}</Note>}
        </Step>

        <Step n={2} title="Pin contracts and vault" state={s2}>
          {!deployment && <Note kind="caution">Load the Ripar deployments JSON on the Connect page first.</Note>}
          {deployment && !keys && <p className="small muted">After the device keys are read (step 1): the vault follows from K1.</p>}
          {deployment && keys && !plan && (
            <>
              <Spec
                rows={[
                  { k: 'Chain', v: `${deployment.chainId}` },
                  { k: 'Vault (derived by the device from K1; key 8 not sent)', v: <Hex value={computeVaultAddress(keys.k1Address)} explorer={explorer} /> },
                  { k: 'Registry', v: <>{<Hex value={deployment.registry} />} {pinMark(deployment, 'registry')}</> },
                  { k: 'DelegationManager', v: <>{<Hex value={deployment.delegationManager} />} {pinMark(deployment, 'delegationManager')}</> },
                  { k: 'PulseCosignEnforcer', v: <>{<Hex value={deployment.enforcer} />} {pinMark(deployment, 'enforcer')}</> },
                  { k: 'Sentinel', v: <Hex value={deployment.sentinel} /> },
                  { k: 'Reputation relay', v: <>{<Hex value={deployment.relay} />} {pinMark(deployment, 'relay')}</> },
                ]}
              />
              {checkDeploymentPins(deployment).some((x) => x.key !== 0) && (
                <Note kind="warning">
                  Firmware v1.2 refuses these contracts (WRONG REGISTRY / PULSE CO-SIGN ENFORCER / REPUTATION RELAY): it
                  only pairs with the addresses compiled into it. Load the CREATE2 deployment on the Connect page.
                </Note>
              )}
              {mandate && device && device.pinned.chainId !== Number(deployment.chainId) && (
                <Note kind="caution">
                  The device signed mandates on chain {device.pinned.chainId}. Moving it to chain {deployment.chainId.toString()}{' '}
                  is refused (PANIC FIRST) until it signs a PANIC that covers them: on Home hold SIGN 5 s, relay the QR
                  on the Kill switch page, then pair again. A revoke is not enough.
                </Note>
              )}
              <div className="row">
                <Button variant="primary" busy={planBusy} onClick={prepare} icon="qr">
                  {paired ? 'Pair again' : 'Build the pairing request'}
                </Button>
                {planErr && <span className="small" style={{ color: 'var(--bad)' }}>{planErr}</span>}
              </div>
            </>
          )}
          {plan && (
            <>
              <Spec
                compact
                rows={[
                  { k: 'Companion clock', v: `${utcText(Math.floor(Date.now() / 1000))} (the device shows it; check it)` },
                  { k: 'Panic floor', v: floors?.minEpoch === null ? 'could not read (not sent)' : `${floors?.minEpoch ?? 0n}${floors?.minEpoch ? ' (sent as floor)' : ''}` },
                  { k: 'Reopen floor', v: floors?.reopenNonce === null ? 'could not read (not sent)' : `${floors?.reopenNonce ?? 0n}${floors?.reopenNonce ? ' (sent as floor)' : ''}` },
                  { k: 'Request', v: `${plan.request.parts.length} QR parts, ${plan.request.cbor.length} bytes` },
                ]}
              />
              <DeviceExchangePanel
                parts={plan.request.parts}
                expect={['ripar-pair']}
                accept={(u) => answersRequest(u, plan.request)}
                onResponse={onPair}
                runKey={plan.request.reqId}
                figA="3.2"
                figB="3.3"
                round="pair"
              />
              <p className="small muted">
                The device derives its vault itself: firmware v1.2 pins only the SimpleFactory vault of its own K1, the one
                shown above (key 8 is left out of the request). It also pins only the registry, enforcer and relay compiled
                into it (WRONG REGISTRY / PULSE CO-SIGN ENFORCER / REPUTATION RELAY otherwise: load the CREATE2 deployment on
                the Connect page). PANIC FIRST: sign and relay a PANIC on the Kill switch page, then pair again.
              </p>
            </>
          )}
          {report && <VerifyPanel report={report} extra={report.type === 'ripar-pair' && report.fields.emulator ? 'EMULATOR' : undefined} />}
          {pairErr && (
            <Note kind="warning" alert>
              {pairErr}
            </Note>
          )}
          {paired && !plan && device && (
            <Note kind="ok" title="Paired">
              <p>
                Chain {device.pinned.chainId}, vault <Hex value={device.pinned.vault} label="pinned vault" />. Both BindDevice
                signatures verified.
              </p>
            </Note>
          )}
        </Step>

        <Step n={3} title="Register on-chain" state={s3} aside={registered ? <Mark tone="good">REGISTERED</Mark> : undefined}>
          {device && deployment ? (
            <>
              <p className="small muted">
                The registry binds P1 to K1 (both signatures checked on-chain). The sentinel and the relay find your
                device through it.
              </p>
              {owner && (
                <Spec
                  compact
                  rows={[
                    {
                      k: 'Registry says',
                      v: !owner.readable ? 'could not read' : owner.owner ? <Hex value={owner.owner} /> : 'this key is not registered',
                    },
                  ]}
                />
              )}
              {!registered && (
                <TxAction
                  write={registerDeviceWrite(deployment.registry, device)}
                  label="Register the device"
                  onDone={(r) => {
                    store.set((s) => ({ device: s.device ? { ...s.device, registeredTx: r.hash } : s.device }));
                    void refreshOwner();
                  }}
                />
              )}
            </>
          ) : (
            <p className="small muted">After pairing.</p>
          )}
        </Step>
      </Procedure>
      {registered && <NextStep to="vault" label="Vault">The device is paired and registered. Deploy and fund its vault next.</NextStep>}
    </div>
  );
}

/** "(firmware table)" when the deployment's contract is the one compiled into firmware v1.2, else a warning mark */
function pinMark(d: RiparDeployment, field: 'registry' | 'enforcer' | 'relay' | 'delegationManager') {
  const bad = checkDeploymentPins(d).find((x) => x.field === field);
  return bad ? <Mark tone="bad">NOT THE FIRMWARE'S</Mark> : <span className="small muted">(firmware table)</span>;
}
