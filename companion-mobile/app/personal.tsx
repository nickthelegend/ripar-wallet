// The personal mandate: set up once, then every Send is one review + pulse + SIGN on the Ripar. See
// src/lib/flows/personal.ts for why a payment from the vault is a co-signed redemption.
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { View } from 'react-native';
import { Address, Button, DeviceRound, Label, Note, Pill, Screen, Spec, Steps, Surface, Text } from '../src/components';
import { verifierOf } from '../src/device/link';
import { refreshChain, useChain } from '../src/lib/chainState';
import { publicClientFor } from '../src/lib/clients';
import { type MandatePlan, acceptMandate, answersMandate } from '../src/lib/flows/mandate';
import { personalMandateForm, planPersonalMandate } from '../src/lib/flows/personal';
import { errorText } from '../src/lib/format';
import { hotKeyAddress } from '../src/lib/hotkey';
import { readMinEpoch } from '../src/lib/reads';
import { previewMandate } from '../src/lib/review-preview';
import { type MandateRecord, store, useStore } from '../src/lib/store';
import { space } from '../src/theme';

export default function Personal() {
  const router = useRouter();
  const device = useStore((s) => s.device);
  const personal = useStore((s) => s.personal);
  const agentAfter = useStore((s) => !!s.personal && s.lastSignedMandate?.toLowerCase() !== s.personal.delegationHash.toLowerCase());
  const settings = useStore((s) => s.settings);
  const chain = useChain();
  const [hot, setHot] = useState<`0x${string}` | null>(null);
  const [epoch, setEpoch] = useState<bigint | null>(null);
  const [plan, setPlan] = useState<MandatePlan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void hotKeyAddress().then(setHot);
  }, []);

  const build = async () => {
    if (!device || !hot) return;
    setBusy(true);
    setErr(null);
    try {
      // the mandate's epoch must equal the device's panic floor (the chain's minEpoch for its key)
      const e = await readMinEpoch(publicClientFor(settings), device.pinned.enforcer, device.keyId);
      setEpoch(e);
      setPlan(planPersonalMandate(hot, device, e, settings.fragLen));
    } catch (x) {
      setErr(errorText(x));
    } finally {
      setBusy(false);
    }
  };

  const verifier = useMemo(
    () =>
      plan && device && hot
        ? verifierOf<MandateRecord>(['eth-signature'], (ur) => acceptMandate(ur, plan, personalMandateForm(hot), device), (ur) => answersMandate(ur, plan.request))
        : null,
    [plan, device, hot],
  );
  const preview = useMemo(
    () => (plan && device && epoch !== null ? previewMandate(plan.decoded, { p1Key: device.p1Key, vault: device.pinned.vault, sentinel: device.pinned.sentinel, minEpoch: epoch }) : null),
    [plan, device, epoch],
  );

  if (!device) {
    return (
      <Screen back title="Enable sending" tabs={false}>
        <Note tone="info">Pair your Ripar first.</Note>
        <Button label="Pair your Ripar" style={{ marginTop: space.lg }} onPress={() => router.replace('/pair')} />
      </Screen>
    );
  }

  const live = chain.personalLive;
  return (
    <Screen
      back
      eyebrow="Personal mandate"
      title="Enable sending"
      lede="Your vault belongs to the Ripar's key, and that key only signs mandates. So this phone pays from the vault under a mandate of its own, one that can never spend without your Ripar."
      tabs={false}
    >
      <View style={{ gap: space.lg }}>
        <Surface padded={18} style={{ gap: space.md }}>
          <Label>How it works</Label>
          <Steps
            steps={[
              'Once: your Ripar signs a delegation from your vault to this phone’s key, with automatic spending capped at 0.',
              'Every Send: the phone asks, your Ripar shows the exact payment, you give a pulse and press SIGN.',
              'The phone key redeems that one co-signed payment and pays the gas. It cannot move a single token on its own: without a fresh SIGN the chain refuses it (HumanRequired).',
            ]}
          />
        </Surface>

        {personal && !plan && (
          <Surface padded={18} style={{ gap: space.md }}>
            <View style={{ flexDirection: 'row', gap: space.sm, flexWrap: 'wrap' }}>
              <Pill label={live === false ? 'Not live' : live ? 'Live' : 'Signed'} tone={live === false ? 'bad' : 'good'} icon={live === false ? 'alert' : 'check'} />
              <Pill label="AUTO cap 0" tone="info" />
              <Pill label="Redeemer: this phone" tone="plain" />
            </View>
            <Spec
              rows={[
                { k: 'Mandate', v: <Address value={personal.delegationHash} label="Mandate hash" tone="soft" /> },
                { k: 'Phone key (delegate, redeemer)', v: <Address value={personal.agent} label="Phone key" tone="soft" /> },
                { k: 'Epoch', v: personal.epoch },
              ]}
            />
            {live === false && (
              <Note tone="bad" title="This mandate is dead">
                A PANIC or a revoke killed it (or it was signed before one). Sign a new one below.
              </Note>
            )}
            {hot && personal.agent.toLowerCase() !== hot.toLowerCase() && (
              <Note tone="warn" title="The phone key changed">
                This mandate names another phone key. Sign a new one below.
              </Note>
            )}
            {agentAfter && (
              <Note tone="info" title="Your Ripar remembers an agent mandate now">
                The device keeps the terms of the last mandate it signed only. On a Send it will show UNKNOWN MANDATE and a
                &quot;may become an AUTO payee&quot; line: expected here, because this mandate's AUTO caps are 0.
              </Note>
            )}
          </Surface>
        )}

        {!plan ? (
          <Button label={personal ? 'Sign a new personal mandate' : 'Sign it on my Ripar'} size="lg" loading={busy} onPress={() => void build()} disabled={!hot} full />
        ) : (
          <>
            {preview && (
              <Surface padded={16} style={{ gap: 4 }}>
                <Label style={{ marginBottom: space.sm }}>What your Ripar will show</Label>
                {preview.lines.slice(0, 18).map((l, i) => (
                  <View key={`${i}:${l.label}`} style={{ flexDirection: 'row', gap: space.sm }}>
                    <Text variant="monoSmall" tone="faint" style={{ width: 92 }}>
                      {l.label}
                    </Text>
                    <Text variant="monoSmall" tone={l.tone === 'bad' ? 'danger' : l.tone === 'warn' ? 'warn' : l.tone === 'good' ? 'success' : 'default'} style={{ flex: 1 }}>
                      {l.value}
                    </Text>
                  </View>
                ))}
              </Surface>
            )}
            {verifier && (
              <DeviceRound
                request={plan.request}
                verifier={verifier}
                kind="mandate"
                runKey={plan.request.reqId}
                onVerified={(rec) => {
                  store.set({ personal: rec, lastSignedMandate: rec.delegationHash });
                  setPlan(null);
                  void refreshChain();
                }}
              />
            )}
            <Button label="Cancel" variant="ghost" onPress={() => setPlan(null)} />
          </>
        )}
        {err && <Note tone="bad">{err}</Note>}
        {personal && !plan && live !== false && <Button label="Send a payment" variant="light" size="lg" full onPress={() => router.replace('/send')} />}
      </View>
    </Screen>
  );
}
