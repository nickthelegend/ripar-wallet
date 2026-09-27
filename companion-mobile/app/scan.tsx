// Scan the Ripar: read a message the device starts itself (PANIC, revoke, reopen: the kill switch), verify it against
// the pinned context and the device's P1 key, and relay it on-chain (anyone may: the signature is the authorization).
// Ported from companion/src/screens/KillSwitch.tsx.
import { useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { View } from 'react-native';
import { Button, DeviceRound, IconCircle, Label, Note, Screen, Surface, Text, TxButton } from '../src/components';
import { verifierOf } from '../src/device/link';
import { refreshChain } from '../src/lib/chainState';
import { refreshFeed } from '../src/lib/feed';
import { KILL_TYPES, type KillSwitchMessage, acceptKillSwitch } from '../src/lib/flows/killswitch';
import { store, useStore } from '../src/lib/store';
import { space } from '../src/theme';

const WHAT = [
  { icon: 'power' as const, tone: 'bad' as const, title: 'PANIC', body: 'Hold SIGN 5 s on Home. Kills every mandate this device ever signed (all agents and this phone), at once, when relayed.' },
  { icon: 'deny' as const, tone: 'warn' as const, title: 'Revoke', body: 'Device menu > REVOKE: kills only the last mandate the device signed.' },
  { icon: 'refresh' as const, tone: 'info' as const, title: 'Reopen', body: 'Device menu > REOPEN: reopens the agent lane after the sentinel closed it.' },
];

export default function Scan() {
  const router = useRouter();
  const device = useStore((s) => s.device);
  const [msg, setMsg] = useState<KillSwitchMessage | null>(null);
  const [round, setRound] = useState(0);
  const verifier = useMemo(() => (device ? verifierOf<KillSwitchMessage>(KILL_TYPES, (ur) => acceptKillSwitch(ur, device)) : null), [device]);

  if (!device) {
    return (
      <Screen back title="Scan the Ripar" tabs={false}>
        <Note tone="info">Pair your Ripar first: kill-switch messages are checked against the contracts it pinned.</Note>
        <Button label="Pair your Ripar" style={{ marginTop: space.lg }} onPress={() => router.replace('/pair')} />
      </Screen>
    );
  }

  return (
    <Screen back eyebrow="Kill switch" title="Scan the Ripar" lede="The device signs these by itself, from its own screens. This phone only relays them." tabs={false}>
      <View style={{ gap: space.lg }}>
        {!msg && (
          <Surface padded={16} style={{ gap: space.md }}>
            {WHAT.map((w) => (
              <View key={w.title} style={{ flexDirection: 'row', gap: space.md }}>
                <IconCircle name={w.icon} tone={w.tone} size={38} />
                <View style={{ flex: 1 }}>
                  <Text variant="bodyMedium">{w.title}</Text>
                  <Text variant="bodySmall" tone="soft">
                    {w.body}
                  </Text>
                </View>
              </View>
            ))}
          </Surface>
        )}
        {!msg && verifier && <DeviceRound request={null} verifier={verifier} kind="kill" runKey={`kill-${round}`} onVerified={(m) => setMsg(m)} />}
        {msg && (
          <Surface variant={msg.type === 'ripar-panic' ? 'danger' : 'raised'} padded={18} style={{ gap: space.md }}>
            <Label tone={msg.type === 'ripar-panic' ? 'danger' : 'label'}>{msg.type.replace('ripar-', '').toUpperCase()} · verified</Label>
            <Text variant="bodyMedium">{msg.effect}</Text>
            <TxButton
              write={msg.write}
              label={msg.type === 'ripar-panic' ? 'Relay the PANIC now' : msg.type === 'ripar-revoke' ? 'Relay the revoke' : 'Relay the reopen'}
              variant={msg.type === 'ripar-panic' ? 'danger' : 'primary'}
              onDone={() => {
                if (msg.type === 'ripar-revoke') {
                  // the device forgot that mandate when it signed the revoke
                  store.set({ lastSignedMandate: null });
                }
                void refreshChain();
                void refreshFeed();
              }}
            />
            <Button
              label="Scan another"
              variant="ghost"
              onPress={() => {
                setMsg(null);
                setRound((r) => r + 1);
              }}
            />
          </Surface>
        )}
      </View>
    </Screen>
  );
}
