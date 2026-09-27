import { useFocusEffect, useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { View } from 'react-native';
import { Button, Label, ListRow, Note, Pill, Screen, SectionHead, Surface, Text } from '../../src/components';
import type { Escalation } from '../../src/lib/agent';
import { pollAgent, runAgent, useAgent } from '../../src/lib/agentState';
import { agentClientOf } from '../../src/lib/agent';
import { ago, errorText } from '../../src/lib/format';
import { REASON_TEXT, describeEscalation } from '../../src/lib/escalations';
import { mandateEnvelope } from '../../src/lib/flows/mandate';
import { currentAgentMandate, ownEntry, store, useStore } from '../../src/lib/store';
import { space } from '../../src/theme';

const open = (e: Escalation) => e.status === 'pending' || e.status === 'open';

export default function Agents() {
  const router = useRouter();
  const agent = useAgent();
  const state = useStore((s) => s);
  const { mandates, inbox, work, device } = state;
  const [running, setRunning] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [sending, setSending] = useState<string | null>(null);

  useFocusEffect(
    useCallback(() => {
      void pollAgent();
      const t = setInterval(() => void pollAgent(), 5000);
      return () => clearInterval(t);
    }, []),
  );

  const pending = agent.items.filter((e) => {
    const o = ownEntry(inbox, e.id);
    const w = ownEntry(work, e.id);
    return (open(e) && !o) || (w?.answer && (!w.agentAt || (w.answer.kind === 'deny' && !w.relayTx)));
  });
  const handled = agent.items.filter((e) => !pending.includes(e)).slice(0, 20);
  const mandate = currentAgentMandate(state);

  return (
    <Screen
      eyebrow="Optional"
      title="Agents"
      lede="An AI agent can pay small bills from your vault inside caps your Ripar signed. Anything outside them lands here and waits for your thumb."
      onRefresh={pollAgent}
    >
      <Surface padded={18} style={{ gap: space.md }}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
          <Label>Agent service</Label>
          <Pill label={agent.error ? 'unreachable' : agent.health ? 'online' : agent.loading ? 'checking' : 'unknown'} tone={agent.error ? 'bad' : agent.health ? 'good' : 'plain'} />
        </View>
        {agent.health?.agent ? (
          <Text variant="bodySmall" tone="soft">
            Agent {agent.health.agent.address.slice(0, 10)}…{agent.health.agent.agentId !== null ? ` · ERC-8004 id ${agent.health.agent.agentId}` : ''}
            {agent.health.mandate ? ` · holds mandate ${agent.health.mandate.delegationHash.slice(0, 10)}… (${agent.health.mandate.status})` : ' · no mandate'}
          </Text>
        ) : (
          <Text variant="bodySmall" tone={agent.error ? 'danger' : 'soft'}>
            {agent.error ?? `Agent URL ${state.settings.agentUrl}`}
          </Text>
        )}
        <View style={{ flexDirection: 'row', gap: space.md }}>
          <Button
            label="Ask the agent to run"
            size="sm"
            loading={running}
            onPress={async () => {
              setRunning(true);
              setMsg(null);
              try {
                const r = await runAgent();
                setMsg(`${r.summary}${r.error ? ` (error: ${r.error})` : ''}`);
              } catch (e) {
                setMsg(errorText(e));
              } finally {
                setRunning(false);
              }
            }}
          />
          <Button label="Settings" size="sm" variant="ghost" onPress={() => router.push('/network')} />
        </View>
        {msg && (
          <Text variant="bodySmall" tone="soft">
            {msg}
          </Text>
        )}
      </Surface>

      <SectionHead title={`Waiting for you (${pending.length})`} />
      <Surface padded={6}>
        {pending.length === 0 ? (
          <View style={{ padding: space.lg }}>
            <Text variant="bodySmall" tone="soft">
              Nothing waiting. The agent pays due invoices by itself inside the caps; a new payee, a cap or a closed lane brings one here.
            </Text>
          </View>
        ) : (
          pending.map((e) => {
            const d = describeEscalation(e, state);
            const w = ownEntry(work, e.id);
            return (
              <View key={e.id} style={{ paddingHorizontal: 10 }}>
                <ListRow
                  icon="agents"
                  iconTone="warn"
                  title={d.amount}
                  subtitle={`to ${d.payee.slice(0, 8)}… · ${REASON_TEXT[e.reason]}${e.createdAt ? ` · ${ago(e.createdAt)}` : ''}`}
                  value={w?.answer && !w.agentAt ? 'not delivered' : w ? 'on the device' : 'review'}
                  valueTone={w?.answer && !w.agentAt ? 'danger' : 'signal'}
                  onPress={() => router.push({ pathname: '/escalation/[id]', params: { id: e.id } })}
                />
              </View>
            );
          })
        )}
      </Surface>
      {agent.rejected.length > 0 && (
        <Note tone="warn" title={`${agent.rejected.length} malformed escalation(s) refused`} style={{ marginTop: space.md }}>
          {agent.rejected[0]!.error}
        </Note>
      )}

      <SectionHead title="Mandates" action={<Text variant="bodySmall" tone="signal" onPress={() => router.push('/mandate')}>New</Text>} />
      <Surface padded={6}>
        {mandates.length === 0 ? (
          <View style={{ padding: space.lg, gap: space.md }}>
            <Text variant="bodySmall" tone="soft">
              No agent mandate. Your vault and your own sends work without one.
            </Text>
            {device && <Button label="Give an agent a mandate" size="sm" variant="secondary" onPress={() => router.push('/mandate')} />}
          </View>
        ) : (
          [...mandates].reverse().map((m) => {
            const current = m === mandate;
            return (
              <View key={m.delegationHash} style={{ paddingHorizontal: 10 }}>
                <ListRow
                  icon="shield"
                  iconTone={current ? 'signal' : 'plain'}
                  title={m.label || 'Agent mandate'}
                  subtitle={`${m.agent.slice(0, 10)}… · ${m.sentToAgentAt ? 'held by the agent' : 'not sent to the agent'}${current ? ' · current' : ''}`}
                  right={
                    current && !m.sentToAgentAt ? (
                      <Button
                        label="Send"
                        size="sm"
                        loading={sending === m.delegationHash}
                        onPress={async () => {
                          setSending(m.delegationHash);
                          try {
                            await agentClientOf(state.settings).postMandate(mandateEnvelope(m));
                            store.set((s) => ({ mandates: s.mandates.map((x) => (x.delegationHash === m.delegationHash ? { ...x, sentToAgentAt: Date.now(), agentError: undefined } : x)) }));
                          } catch (e) {
                            const err = errorText(e);
                            store.set((s) => ({ mandates: s.mandates.map((x) => (x.delegationHash === m.delegationHash ? { ...x, agentError: err } : x)) }));
                            setMsg(err);
                          } finally {
                            setSending(null);
                          }
                        }}
                      />
                    ) : undefined
                  }
                />
              </View>
            );
          })
        )}
      </Surface>

      {handled.length > 0 && (
        <>
          <SectionHead title="Answered" />
          <Surface padded={6}>
            {handled.map((e) => {
              const d = describeEscalation(e, state);
              const o = ownEntry(inbox, e.id);
              return (
                <View key={e.id} style={{ paddingHorizontal: 10 }}>
                  <ListRow
                    icon={o?.status === 'denied' || e.status === 'denied' ? 'deny' : 'check'}
                    iconTone={o?.status === 'denied' || e.status === 'denied' ? 'bad' : 'good'}
                    title={d.amount}
                    subtitle={`to ${d.payee.slice(0, 8)}… · ${(o?.status ?? e.status).toUpperCase()}`}
                    onPress={() => router.push({ pathname: '/escalation/[id]', params: { id: e.id } })}
                  />
                </View>
              );
            })}
          </Surface>
        </>
      )}
      <Text variant="bodySmall" tone="faint" style={{ marginTop: space.lg }}>
        PANIC on the Ripar (hold SIGN 5 s) kills every agent mandate at once. Relay it from the Device tab.
      </Text>
    </Screen>
  );
}
