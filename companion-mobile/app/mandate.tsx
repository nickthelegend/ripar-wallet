// An agent mandate (ported from companion/src/screens/Mandate.tsx): the scoped delegation an AI agent spends under.
// The form becomes a ripar-mandate-req; the Ripar shows every caveat, signs with K1 after pulse + SIGN, and the signed
// delegation goes to the agent (which rebuilds it from the device's request and recovers K1 itself).
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Switch, TextInput, View } from 'react-native';
import { AUSD_10143 } from '@ripar/protocol';
import { Button, DeviceRound, Label, Note, Pill, Screen, Surface, Text } from '../src/components';
import { verifierOf } from '../src/device/link';
import { agentClientOf } from '../src/lib/agent';
import { publicClientFor } from '../src/lib/clients';
import { type MandateForm, type MandatePlan, acceptMandate, answersMandate, mandateEnvelope, planMandate } from '../src/lib/flows/mandate';
import { errorText } from '../src/lib/format';
import { readMinEpoch } from '../src/lib/reads';
import { previewMandate } from '../src/lib/review-preview';
import { type MandateRecord, deploymentOf, store, useStore } from '../src/lib/store';
import { ink, palette, radius, space } from '../src/theme';

const PERIODS: [string, number][] = [
  ['1 hour', 3600],
  ['1 day', 86400],
  ['7 days', 604800],
  ['Lifetime', 0],
];

function Input({ label, value, onChange, numeric, placeholder }: { label: string; value: string; onChange: (v: string) => void; numeric?: boolean; placeholder?: string }) {
  return (
    <View style={{ gap: 6, flex: 1 }}>
      <Label>{label}</Label>
      <TextInput
        value={value}
        onChangeText={onChange}
        keyboardType={numeric ? 'decimal-pad' : 'default'}
        autoCapitalize="none"
        autoCorrect={false}
        placeholder={placeholder}
        placeholderTextColor={ink.faint}
        style={styles.input}
        accessibilityLabel={label}
      />
    </View>
  );
}

export default function Mandate() {
  const router = useRouter();
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const dep = deploymentOf(settings).deployment;
  const [form, setForm] = useState<MandateForm>({
    agent: '',
    agentId: '',
    label: 'treasury agent',
    token: dep && !/^0x0{40}$/i.test(dep.mockUsd) ? dep.mockUsd : 'native',
    tokenDecimals: dep && !/^0x0{40}$/i.test(dep.mockUsd) ? 6 : 18,
    tokenSymbol: dep && !/^0x0{40}$/i.test(dep.mockUsd) ? 'mUSD' : 'MON',
    perTxAutoCap: '5',
    periodAutoCap: '20',
    period: 86400,
    newPayeeNeedsHuman: true,
    redeemerOnly: true,
    validUntil: null,
  });
  const [epoch, setEpoch] = useState<bigint | null>(null);
  const [plan, setPlan] = useState<MandatePlan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [signed, setSigned] = useState<MandateRecord | null>(null);
  const [sending, setSending] = useState(false);
  const set = (p: Partial<MandateForm>) => {
    setForm((f) => ({ ...f, ...p }));
    setPlan(null);
    setErr(null);
  };

  // the agent's address and ERC-8004 id from its /health
  useEffect(() => {
    if (!settings.agentUrl) return;
    agentClientOf(settings)
      .health()
      .then(
        (h) => {
          if (h.agent) setForm((f) => (f.agent ? f : { ...f, agent: h.agent!.address, agentId: h.agent!.agentId?.toString() ?? f.agentId }));
        },
        () => {},
      );
  }, [settings.agentUrl, settings.agentToken]);

  useEffect(() => {
    if (!device) return;
    readMinEpoch(publicClientFor(settings), device.pinned.enforcer, device.keyId).then(setEpoch, (e) => setErr(`Cannot read the panic floor: ${errorText(e)}`));
  }, [device, settings]);

  const verifier = useMemo(
    () => (plan && device ? verifierOf<MandateRecord>(['eth-signature'], (ur) => acceptMandate(ur, plan, form, device), (ur) => answersMandate(ur, plan.request)) : null),
    [plan, device, form],
  );
  const preview = useMemo(
    () => (plan && device && epoch !== null ? previewMandate(plan.decoded, { p1Key: device.p1Key, vault: device.pinned.vault, sentinel: device.pinned.sentinel, minEpoch: epoch }) : null),
    [plan, device, epoch],
  );

  if (!device) {
    return (
      <Screen back title="Agent mandate" tabs={false}>
        <Note tone="info">Pair your Ripar first.</Note>
      </Screen>
    );
  }

  const tokens: { id: string; label: string; decimals: number; symbol: string }[] = [
    ...(dep && !/^0x0{40}$/i.test(dep.mockUsd) ? [{ id: dep.mockUsd as string, label: 'mUSD', decimals: 6, symbol: 'mUSD' }] : []),
    { id: 'native', label: 'MON', decimals: 18, symbol: 'MON' },
    ...(settings.chainId === 10143 ? [{ id: AUSD_10143 as string, label: 'AUSD', decimals: 6, symbol: 'AUSD' }] : []),
  ];

  if (signed) {
    return (
      <Screen back eyebrow="Agent mandate" title="Signed on your Ripar" tabs={false}>
        <View style={{ gap: space.lg }}>
          <Note tone="good" title={signed.label || 'Mandate'}>
            {`The agent may now pay up to ${form.perTxAutoCap} ${form.tokenSymbol} per payment and ${form.periodAutoCap} per ${PERIODS.find((p) => p[1] === form.period)?.[0] ?? 'period'} on its own. Anything else waits for your Ripar.`}
          </Note>
          <Button
            label={signed.sentToAgentAt ? 'Sent to the agent' : 'Send it to the agent'}
            loading={sending}
            disabled={!!signed.sentToAgentAt}
            onPress={async () => {
              setSending(true);
              setErr(null);
              try {
                await agentClientOf(settings).postMandate(mandateEnvelope(signed));
                const rec = { ...signed, sentToAgentAt: Date.now() };
                store.set((s) => ({ mandates: s.mandates.map((m) => (m.delegationHash === rec.delegationHash ? rec : m)) }));
                setSigned(rec);
              } catch (e) {
                setErr(errorText(e));
              } finally {
                setSending(false);
              }
            }}
          />
          <Button label="Back to Agents" variant="secondary" onPress={() => router.replace('/(tabs)/agents')} />
          {err && <Note tone="bad">{err}</Note>}
        </View>
      </Screen>
    );
  }

  return (
    <Screen back eyebrow="Agents" title="Agent mandate" lede="What an AI agent may spend from your vault by itself. Every field is shown on your Ripar before it signs." tabs={false}>
      <View style={{ gap: space.lg }}>
        {!plan ? (
          <>
            <Surface padded={16} style={{ gap: space.md }}>
              <Input label="Agent address" value={form.agent} onChange={(v) => set({ agent: v.trim() })} placeholder="0x..." />
              <View style={{ flexDirection: 'row', gap: space.md }}>
                <Input label="ERC-8004 agent id" value={form.agentId} onChange={(v) => set({ agentId: v })} numeric />
                <Input label="Label" value={form.label} onChange={(v) => set({ label: v })} />
              </View>
              <Label>Asset it may spend</Label>
              <View style={{ flexDirection: 'row', gap: space.sm }}>
                {tokens.map((t) => (
                  <Pill key={t.id} label={t.label} tone={form.token === t.id ? 'signal' : 'plain'} onPress={() => set({ token: t.id, tokenDecimals: t.decimals, tokenSymbol: t.symbol })} />
                ))}
              </View>
              <View style={{ flexDirection: 'row', gap: space.md }}>
                <Input label={`Per payment (${form.tokenSymbol})`} value={form.perTxAutoCap} onChange={(v) => set({ perTxAutoCap: v })} numeric />
                <Input label={`Per period (${form.tokenSymbol})`} value={form.periodAutoCap} onChange={(v) => set({ periodAutoCap: v })} numeric />
              </View>
              <Label>Period</Label>
              <View style={{ flexDirection: 'row', gap: space.sm, flexWrap: 'wrap' }}>
                {PERIODS.map(([l, s]) => (
                  <Pill key={l} label={l} tone={form.period === s ? 'signal' : 'plain'} onPress={() => set({ period: s })} />
                ))}
              </View>
              <View style={styles.switchRow}>
                <Text variant="bodySmall" style={{ flex: 1 }}>
                  New payees need your Ripar (recommended)
                </Text>
                <Switch value={form.newPayeeNeedsHuman} onValueChange={(v) => set({ newPayeeNeedsHuman: v })} trackColor={{ true: palette.primary }} />
              </View>
              <View style={styles.switchRow}>
                <Text variant="bodySmall" style={{ flex: 1 }}>
                  Only this agent may redeem it
                </Text>
                <Switch value={form.redeemerOnly} onValueChange={(v) => set({ redeemerOnly: v })} trackColor={{ true: palette.primary }} />
              </View>
            </Surface>
            <Note tone="info" title="The device remembers one mandate">
              Your Ripar keeps the terms of the last mandate it signed. After this one, your own Sends show UNKNOWN MANDATE on the device: expected, their caps are 0.
            </Note>
            <Button
              label="Review on my Ripar"
              size="lg"
              disabled={epoch === null}
              onPress={() => {
                try {
                  setPlan(planMandate(form, device, epoch!, { fragLen: settings.fragLen }));
                } catch (e) {
                  setErr(errorText(e));
                }
              }}
            />
          </>
        ) : (
          <>
            {preview && (
              <Surface padded={16} style={{ gap: 4 }}>
                <Label style={{ marginBottom: space.sm }}>What your Ripar will show</Label>
                {preview.lines.slice(0, 22).map((l, i) => (
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
                  store.set((s) => ({ mandates: [...s.mandates, rec], lastSignedMandate: rec.delegationHash }));
                  setSigned(rec);
                  setPlan(null);
                }}
              />
            )}
            <Button label="Edit" variant="ghost" onPress={() => setPlan(null)} />
          </>
        )}
        {err && <Note tone="bad">{err}</Note>}
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  input: {
    backgroundColor: palette.cardHigh,
    color: palette.foreground,
    borderRadius: radius.md,
    borderWidth: 1,
    borderColor: ink.hairline,
    paddingHorizontal: space.md,
    paddingVertical: 10,
    fontFamily: 'GeistMono_400Regular',
    fontSize: 12,
  },
  switchRow: { flexDirection: 'row', alignItems: 'center', gap: space.md },
});
