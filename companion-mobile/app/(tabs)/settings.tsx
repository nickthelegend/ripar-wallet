import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { Alert, View } from 'react-native';
import { formatEther, numberToHex, parseEther } from 'viem';
import { Address, Button, Label, ListRow, Note, Pill, QrCode, Screen, SectionHead, Surface, Text } from '../../src/components';
import { refreshChain, useChain } from '../../src/lib/chainState';
import { publicClientFor } from '../../src/lib/clients';
import { errorText } from '../../src/lib/format';
import { hotKeyAddress, rotateHotKey } from '../../src/lib/hotkey';
import { NETWORKS } from '../../src/lib/networks';
import { store, useStore } from '../../src/lib/store';
import { space } from '../../src/theme';

export default function Settings() {
  const router = useRouter();
  const settings = useStore((s) => s.settings);
  const personal = useStore((s) => s.personal);
  const chain = useChain();
  const [hot, setHot] = useState<`0x${string}` | null>(null);
  const [showQr, setShowQr] = useState(false);
  const [msg, setMsg] = useState<{ tone: 'good' | 'bad'; text: string } | null>(null);

  useEffect(() => {
    void hotKeyAddress().then(setHot);
  }, []);

  const topUpAnvil = async () => {
    if (!hot) return;
    setMsg(null);
    try {
      const pc = publicClientFor(settings);
      // anvil only: sets the balance of the phone key (a dev chain; refused by any real node)
      await pc.request({ method: 'anvil_setBalance', params: [hot, numberToHex(parseEther('10'))] } as never);
      setMsg({ tone: 'good', text: 'The phone key now holds 10 MON on the local chain.' });
      void refreshChain();
    } catch (e) {
      setMsg({ tone: 'bad', text: `Not an anvil RPC: ${errorText(e)}` });
    }
  };

  const setNum = (k: 'frameMs' | 'fragLen' | 'logLookback', v: number) => store.setSettings({ [k]: v } as never);

  return (
    <Screen eyebrow="Ripar" title="Settings" onRefresh={refreshChain}>
      <Surface padded={18} style={{ gap: space.md }}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
          <Label>Phone key (gas + your sends)</Label>
          <Pill label="Testnet only" tone="warn" icon="alert" />
        </View>
        {hot && <Address value={hot} label="Phone key" />}
        <Text variant="stat">
          {chain.hot?.balance === null || chain.hot?.balance === undefined ? '— MON' : `${Number(formatEther(chain.hot.balance)).toLocaleString('en-US', { maximumFractionDigits: 5 })} MON`}
        </Text>
        <Text variant="bodySmall" tone="soft">
          Made on this phone, kept in Android's secure storage. It pays the gas of everything this app relays and redeems your co-signed payments. It is not the vault owner: without a fresh SIGN on your Ripar it cannot move anything from the vault. Fund it with a little testnet MON; never put real funds on it.
        </Text>
        {showQr && hot && (
          <View style={{ alignItems: 'center' }}>
            <QrCode text={hot} size={200} label="Phone key address" />
          </View>
        )}
        <View style={{ flexDirection: 'row', gap: space.sm, flexWrap: 'wrap' }}>
          <Button label={showQr ? 'Hide QR' : 'Show QR'} size="sm" variant="secondary" onPress={() => setShowQr((x) => !x)} />
          {settings.network === 'local' && <Button label="Top up (anvil)" size="sm" variant="secondary" onPress={() => void topUpAnvil()} />}
          <Button
            label="New phone key"
            size="sm"
            variant="ghost"
            onPress={() =>
              Alert.alert(
                'Replace the phone key?',
                `The old key keeps any MON it holds.${personal ? ' Your personal mandate names the old key: sign a new one to send again.' : ''}`,
                [
                  { text: 'Cancel', style: 'cancel' },
                  {
                    text: 'Replace',
                    style: 'destructive',
                    onPress: async () => {
                      setHot(await rotateHotKey());
                      void refreshChain();
                    },
                  },
                ],
              )
            }
          />
        </View>
        {msg && <Note tone={msg.tone}>{msg.text}</Note>}
      </Surface>

      <SectionHead title="Connection" />
      <Surface padded={6}>
        <View style={{ paddingHorizontal: 10 }}>
          <ListRow icon="link" iconTone="signal" title="Network and deployment" subtitle={`${NETWORKS[settings.network].label} · ${settings.deploymentsJson ? 'deployment loaded' : 'no deployment'}`} onPress={() => router.push('/network')} />
          <ListRow
            icon={settings.link === 'ble' ? 'bluetooth' : settings.link === 'qr' ? 'qr' : 'device'}
            iconTone={settings.link === 'ble' ? 'warn' : 'signal'}
            title="Device link"
            subtitle={settings.link === 'qr' ? 'QR codes (air-gapped)' : settings.link === 'ble' ? 'Bluetooth fallback: not air-gapped' : 'Emulator (demo keys)'}
            onPress={() => router.push('/link')}
          />
          <ListRow icon="agents" iconTone="info" title="Agent service" subtitle={settings.agentUrl || 'not set'} onPress={() => router.push('/network')} />
        </View>
      </Surface>

      <SectionHead title="Advanced" />
      <Surface padded={16} style={{ gap: space.md }}>
        {(
          [
            ['QR frame time', 'frameMs', [200, 300, 450], 'ms'],
            ['QR part size', 'fragLen', [60, 70, 80], 'bytes'],
            ['Activity lookback', 'logLookback', [1000, 3000, 10000], 'blocks'],
          ] as const
        ).map(([label, key, opts, unit]) => (
          <View key={key} style={{ gap: 6 }}>
            <Label>{label}</Label>
            <View style={{ flexDirection: 'row', gap: space.sm }}>
              {opts.map((o) => (
                <Pill key={o} label={`${o} ${unit}`} tone={settings[key] === o ? 'signal' : 'plain'} onPress={() => setNum(key, o)} />
              ))}
            </View>
          </View>
        ))}
      </Surface>

      <SectionHead title="Security model" />
      <Surface padded={16} style={{ gap: space.sm }}>
        {[
          'Keys are born on the Ripar and never leave it. This app never asks for, sees or stores a seed.',
          'This phone is an untrusted courier: the Ripar parses every request itself, checks it against the contracts it pinned at pairing and shows every signed field.',
          'Every answer the Ripar gives is verified here (signatures, request id, pinned contracts) before the app uses it.',
          'QR codes by default: no radio. Bluetooth is a fallback you turn on from the device menu, and it says NOT AIR-GAPPED while on.',
          'Your sends use a mandate with automatic caps of 0: the phone key can relay a payment only with a fresh co-sign.',
        ].map((t) => (
          <Text key={t} variant="bodySmall" tone="soft">
            {`• ${t}`}
          </Text>
        ))}
      </Surface>

      <View style={{ gap: space.md, marginTop: space.xl }}>
        <Button label="Show the introduction again" variant="ghost" onPress={() => router.push('/onboarding')} />
        <Button
          label="Reset app data"
          variant="ghost"
          onPress={() =>
            Alert.alert('Reset app data?', 'Forgets the paired device, mandates and records on this phone (not the phone key, not anything on-chain).', [
              { text: 'Cancel', style: 'cancel' },
              { text: 'Reset', style: 'destructive', onPress: () => store.reset() },
            ])
          }
        />
        <Text variant="bodySmall" tone="faint" style={{ textAlign: 'center' }}>
          Ripar companion 0.1.0 · chain {settings.chainId}
        </Text>
      </View>
    </Screen>
  );
}
