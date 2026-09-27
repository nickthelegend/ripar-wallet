// Pairing, in two rounds (ported from companion/src/screens/Pair.tsx + Vault.tsx), then the on-chain setup:
//   1. keys only: the device shows K1, P1 and its firmware id (nothing signed); the app derives the vault from K1
//   2. full pairing: the device pins chain + contracts (firmware v1.2: its compiled-in ones) + its own vault, and signs
//      BindDevice with P1 and K1 after pulse + SIGN; the app verifies both signatures
//   3. register the binding in the RiparDeviceRegistry, 4. deploy the vault (SimpleFactory, salt 0), 5. fund it
import { useRouter } from 'expo-router';
import { type ReactNode, useMemo, useState } from 'react';
import { View } from 'react-native';
import { RIPAR_SENTINEL_ABI, SIMPLE_FACTORY, checkDeploymentPins, computeVaultAddress, vaultFactoryData } from '@ripar/protocol';
import { Address, Button, DeviceRound, Icon, Label, Note, Screen, Spec, Surface, Text, TxButton } from '../src/components';
import { verifierOf } from '../src/device/link';
import { FAUCET_MAX, deployVaultWrite, faucetWrite, registerDeviceWrite } from '../src/lib/chain';
import { refreshChain, useChain } from '../src/lib/chainState';
import { publicClientFor } from '../src/lib/clients';
import { type PairPlan, acceptPairing, answersRequest, isKeysOnlyPair, planPairing, readKeysOnly } from '../src/lib/flows/pairing';
import { errorText, utcText } from '../src/lib/format';
import { readMinEpoch } from '../src/lib/reads';
import { type KeysOnly, type PairedDevice, store, useDeployment, useStore } from '../src/lib/store';
import { ink, palette, radius, space } from '../src/theme';

type StepState = 'done' | 'active' | 'pending' | 'error';

function Step({ n, title, state, summary, children }: { n: number; title: string; state: StepState; summary?: string; children?: ReactNode }) {
  const done = state === 'done';
  return (
    <Surface padded={16} variant={state === 'active' ? 'selected' : 'raised'} style={{ opacity: state === 'pending' ? 0.55 : 1 }}>
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: space.md }}>
        <View
          style={{
            width: 30,
            height: 30,
            borderRadius: 15,
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: done ? palette.success : state === 'active' ? palette.primary : state === 'error' ? palette.danger : 'transparent',
            borderWidth: done || state === 'active' || state === 'error' ? 0 : 1,
            borderColor: ink.hairlineStrong,
          }}
        >
          {done ? (
            <Icon name="check" size={16} color={palette.background} strokeWidth={2.6} />
          ) : (
            <Text variant="label" style={{ color: state === 'active' ? palette.primaryForeground : ink.soft, letterSpacing: 0 }}>
              {n}
            </Text>
          )}
        </View>
        <View style={{ flex: 1 }}>
          <Text variant="bodyMedium">{title}</Text>
          {summary ? (
            <Text variant="bodySmall" tone="soft" numberOfLines={2}>
              {summary}
            </Text>
          ) : null}
        </View>
      </View>
      {state === 'active' || state === 'error' ? <View style={{ marginTop: space.lg, gap: space.md }}>{children}</View> : null}
    </Surface>
  );
}

export default function Pair() {
  const router = useRouter();
  const settings = useStore((s) => s.settings);
  const keys = useStore((s) => s.keysOnly);
  const device = useStore((s) => s.device);
  const personal = useStore((s) => s.personal);
  const { deployment, error: depError } = useDeployment();
  const chain = useChain();

  const [reread, setReread] = useState(!keys);
  const [plan, setPlan] = useState<PairPlan | null>(null);
  const [floors, setFloors] = useState<{ minEpoch: bigint | null; reopenNonce: bigint | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [repair, setRepair] = useState(false);

  const paired = !!device && !!keys && device.k1Address === keys.k1Address && !repair;
  const vault = keys ? computeVaultAddress(keys.k1Address) : null;
  const stable = chain.vault?.tokens.find((t) => deployment && t.address.toLowerCase() === deployment.mockUsd.toLowerCase());
  const funded = (stable?.balance ?? 0n) > 0n || (chain.vault?.native ?? 0n) > 0n;

  const s1: StepState = keys && !reread ? 'done' : 'active';
  const s2: StepState = paired && !plan ? 'done' : s1 === 'done' ? 'active' : 'pending';
  const s3: StepState = chain.registered ? 'done' : s2 === 'done' ? 'active' : 'pending';
  const s4: StepState = chain.vault?.deployed ? 'done' : s2 === 'done' ? (s3 === 'done' ? 'active' : 'pending') : 'pending';
  const s5: StepState = funded ? 'done' : s4 === 'done' ? 'active' : 'pending';

  const keysVerifier = useMemo(() => verifierOf<KeysOnly>(['ripar-pair'], (ur) => readKeysOnly(ur), isKeysOnlyPair), []);
  const pairVerifier = useMemo(
    () => (plan ? verifierOf<PairedDevice>(['ripar-pair'], (ur) => acceptPairing(ur, plan, keys), (ur) => answersRequest(ur, plan.request)) : null),
    [plan, keys],
  );

  const prepare = async () => {
    if (!deployment || !keys) return;
    setBusy(true);
    setErr(null);
    try {
      const pc = publicClientFor(settings);
      const v = computeVaultAddress(keys.k1Address);
      // floors: the on-chain panic epoch of this key and the sentinel's last reopen nonce (they can only raise)
      const [minEpoch, reopenNonce] = await Promise.all([
        readMinEpoch(pc, deployment.enforcer, keys.keyId).catch(() => null),
        pc.readContract({ address: deployment.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'lastReopenNonce', args: [v] }).catch(() => null),
      ]);
      setFloors({ minEpoch, reopenNonce });
      setPlan(planPairing(deployment, keys.k1Address, { now: Math.floor(Date.now() / 1000), minEpoch, reopenNonce, fragLen: settings.fragLen }));
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const pins = deployment ? checkDeploymentPins(deployment).filter((x) => x.key !== 0) : [];

  return (
    <Screen back eyebrow="Device" title="Pair your Ripar" lede="Two rounds with the device, then three small transactions this phone relays. No seed words: the keys stay on the Ripar." tabs={false}>
      <View style={{ gap: space.md }}>
        {!deployment && (
          <Note tone="warn" title="Load the Ripar deployment first">
            {depError ?? 'The pairing names the Ripar contracts: paste or fetch the deployments JSON in Settings > Network.'}
          </Note>
        )}
        {!deployment && <Button label="Open network settings" variant="secondary" onPress={() => router.push('/network')} />}

        <Step n={1} title="Read the device keys" state={s1} summary={keys && !reread ? `K1 ${keys.k1Address.slice(0, 10)}… · ${keys.emulator ? 'EMULATOR (demo keys)' : 'Ripar hardware'}` : 'The Ripar shows its public keys. Nothing is signed.'}>
          <DeviceRound
            request={null}
            verifier={keysVerifier}
            kind="keys"
            runKey="keys-only"
            onVerified={(k) => {
              store.set({ keysOnly: k });
              setReread(false);
              setPlan(null);
              setRepair(false);
            }}
          />
        </Step>
        {keys && !reread && (
          <Button label="Read another device" variant="ghost" size="sm" onPress={() => setReread(true)} />
        )}

        <Step
          n={2}
          title="Pin contracts and vault"
          state={s2}
          summary={paired && !plan && device ? `Chain ${device.pinned.chainId}. Both BindDevice signatures verified.` : 'The Ripar confirms your contracts and its own vault with your pulse.'}
        >
          {deployment && keys && vault && !plan && (
            <>
              <Spec
                rows={[
                  { k: 'Chain', v: `${deployment.chainId === 10143n ? 'Monad testnet' : 'Monad'} (${deployment.chainId})` },
                  { k: 'Vault (derived by the device from K1)', v: <Address value={vault} label="Vault" /> },
                  { k: 'Sentinel (the one address you confirm)', v: <Address value={deployment.sentinel} label="Sentinel" tone="soft" /> },
                  { k: 'Registry · enforcer · relay', v: pins.length ? 'NOT the ones compiled into the firmware' : 'the ones compiled into the firmware' },
                ]}
              />
              {pins.length > 0 && (
                <Note tone="bad" title="The Ripar would refuse this deployment">
                  {pins.map((x) => `${x.name} ${x.deployed} is not the firmware's ${x.firmware}`).join('\n')}
                </Note>
              )}
              <Button label={busy ? 'Reading floors...' : 'Build the pairing request'} loading={busy} onPress={() => void prepare()} disabled={pins.length > 0} />
            </>
          )}
          {plan && pairVerifier && (
            <>
              <Spec
                rows={[
                  { k: 'Phone clock (the Ripar shows it)', v: utcText(Math.floor(Date.now() / 1000)) },
                  { k: 'Panic floor', v: floors?.minEpoch === null ? 'could not read (not sent)' : `${floors?.minEpoch ?? 0n}` },
                  { k: 'Reopen floor', v: floors?.reopenNonce === null ? 'could not read (not sent)' : `${floors?.reopenNonce ?? 0n}` },
                  { k: 'Request', v: `${plan.request.parts.length} QR parts, ${plan.request.cbor.length} bytes` },
                ]}
              />
              <DeviceRound
                request={plan.request}
                verifier={pairVerifier}
                kind="pair"
                runKey={plan.request.reqId}
                onVerified={(d) => {
                  store.set({ device: d });
                  setPlan(null);
                  setRepair(false);
                  void refreshChain();
                }}
              />
            </>
          )}
          {err && <Note tone="bad">{err}</Note>}
        </Step>
        {paired && !plan && (
          <Button label="Pair again (update the device clock / contracts)" variant="ghost" size="sm" onPress={() => setRepair(true)} />
        )}

        <Step n={3} title="Register on-chain" state={s3} summary={chain.registered ? 'The registry binds P1 to K1.' : 'Binds the device key to its owner (both signatures checked on-chain).'}>
          {device && deployment && <TxButton write={registerDeviceWrite(deployment.registry, device)} label="Register the device" onDone={() => void refreshChain()} />}
        </Step>

        <Step n={4} title="Deploy your vault" state={s4} summary={chain.vault?.deployed ? `${chain.vault.codeBytes} bytes of code; owner = your Ripar's K1.` : "A MetaMask smart account owned by the Ripar's K1 alone."}>
          {device && (
            <>
              {computeVaultAddress(device.k1Address) !== device.pinned.vault ? (
                <Note tone="bad">The device pinned another vault than the one derived from its K1: pair again.</Note>
              ) : (
                <TxButton
                  write={deployVaultWrite(SIMPLE_FACTORY, vaultFactoryData(device.k1Address), device.pinned.vault)}
                  label="Deploy the vault"
                  onDone={() => void refreshChain()}
                />
              )}
            </>
          )}
        </Step>

        <Step n={5} title="Fund it" state={s5} summary={funded ? 'The vault holds funds.' : 'Testnet: mint MockUSD from the faucet, or send MON to the vault.'}>
          {device && deployment && !/^0x0{40}$/i.test(deployment.mockUsd) ? (
            <TxButton write={faucetWrite(deployment.mockUsd, device.pinned.vault, FAUCET_MAX / 2n)} label="Mint 500 mUSD into the vault" onDone={() => void refreshChain()} />
          ) : (
            <Text variant="bodySmall" tone="soft">
              This deployment has no MockUSD faucet: send MON or tokens to the vault (Receive).
            </Text>
          )}
          <Button label="Skip for now" variant="ghost" size="sm" onPress={() => router.push('/personal')} />
        </Step>

        {device && s4 === 'done' && (
          <Surface variant="signal" padded={18} style={{ marginTop: space.md }}>
            <Label tone="onSignal">Last step</Label>
            <Text variant="heading" tone="onSignal" style={{ marginTop: 4 }}>
              {personal ? 'Sending is enabled' : 'Enable sending from this phone'}
            </Text>
            <Text variant="bodySmall" tone="onSignal" style={{ marginTop: 4, opacity: 0.85 }}>
              One mandate, signed once on the Ripar, lets this phone relay payments that your Ripar co-signs one by one.
            </Text>
            <Button label={personal ? 'Review' : 'Set it up'} variant="secondary" style={{ marginTop: space.md, borderRadius: radius.pill }} onPress={() => router.push('/personal')} />
          </Surface>
        )}
      </View>
    </Screen>
  );
}
