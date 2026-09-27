// Choosing the device link: QR (the default, air-gapped), the Bluetooth fallback (docs/BLE_LINK.md §2, §3, §5), the
// emulator, and the Wi-Fi link (TEMPORARY, for testing: the device's Wi-Fi is on, so it is not air-gapped).
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { Platform, View } from 'react-native';
import { BleConnect, Button, DeviceStatusLine, Icon, IconCircle, Label, Note, Pill, Screen, Steps, Surface, Text, WebPreviewNote } from '../src/components';
import { useDeviceLink, useObservable } from '../src/device/DeviceLinkProvider';
import { BLE_SETUP_STEPS, RADIO_ON_TEXT, WIFI_ON_TEXT } from '../src/device/guide';
import { errorText } from '../src/lib/format';
import { type LinkChoice, store, useStore } from '../src/lib/store';
import { palette, space } from '../src/theme';

const CHOICES: { id: LinkChoice; title: string; body: string; icon: 'qr' | 'bluetooth' | 'device' | 'wifi'; tone: 'signal' | 'warn' | 'info'; badge?: string }[] = [
  { id: 'qr', title: 'QR codes', body: 'Air-gapped. The phone shows a QR, the Ripar shows one back. The default, always.', icon: 'qr', tone: 'signal', badge: 'Recommended' },
  { id: 'ble', title: 'Bluetooth fallback', body: "Turns the device's radio on. Use it if the camera cannot read.", icon: 'bluetooth', tone: 'warn' },
  { id: 'emulator', title: 'Emulator', body: 'The Ripar firmware compiled to WebAssembly, on this phone. Demo keys only.', icon: 'device', tone: 'info' },
  { id: 'wifi', title: 'Wi-Fi (testing)', body: "Turns the device's Wi-Fi on - Ripar is NOT air-gapped while it is on. For testing.", icon: 'wifi', tone: 'warn', badge: 'Temporary' },
];

export default function LinkScreen() {
  const router = useRouter();
  const choice = useStore((s) => s.settings.link);

  return (
    <Screen back eyebrow="Device link" title="How the phone reaches your Ripar" tabs={false}>
      <View style={{ gap: space.md }}>
        {CHOICES.map((c) => (
          <Surface key={c.id} variant={choice === c.id ? 'selected' : 'raised'} padded={16} onPress={() => store.setSettings({ link: c.id })} accessibilityLabel={`${c.title}. ${c.body}`}>
            <View style={{ flexDirection: 'row', gap: space.md, alignItems: 'center' }}>
              <IconCircle name={c.icon} tone={c.tone} />
              <View style={{ flex: 1, gap: 2 }}>
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: space.sm, flexWrap: 'wrap' }}>
                  <Text variant="bodyMedium">{c.title}</Text>
                  {c.badge ? <Pill label={c.badge} tone={c.id === 'qr' ? 'good' : 'warn'} /> : null}
                </View>
                <Text variant="bodySmall" tone="soft">
                  {c.body}
                </Text>
              </View>
              {choice === c.id && <Icon name="check" size={20} color={palette.primary} strokeWidth={2.4} />}
            </View>
          </Surface>
        ))}

        {choice === 'ble' && (
          <>
            <Note tone="warn" icon="radio" title="Not air-gapped while it runs">
              {RADIO_ON_TEXT}
            </Note>
            <Surface padded={18} style={{ gap: space.md }}>
              <Label>Turn it on and pair this phone</Label>
              <Steps steps={[...BLE_SETUP_STEPS]} />
              <Text variant="bodySmall" tone="faint">
                One phone at a time: a new pairing replaces the old one. FORGET PHONE in the device menu removes it.
              </Text>
            </Surface>
            <BleConnect />
          </>
        )}

        {choice === 'wifi' && (
          <>
            <Note tone="warn" icon="wifi" title="NOT AIR-GAPPED while Wi-Fi is on · testing only">
              {WIFI_ON_TEXT}
            </Note>
            <WifiCard onSetup={() => router.push('/wifi')} />
          </>
        )}

        {choice === 'emulator' && (
          <Note tone="warn" title="Demo keys">
            The emulator runs the real firmware (policy, review, pulse gate, signatures) with a synthetic thumb. Its seed lives in this app: never put real funds behind it.
          </Note>
        )}
        {choice === 'qr' && (
          <Note tone="good" title="Air-gapped">
            Nothing but light between the phone and your Ripar. Keep the phone's screen bright and hold the Ripar about 15 cm away.
          </Note>
        )}
      </View>
    </Screen>
  );
}

/** the Wi-Fi link's connection: its health, the device status, reconnect / set up / disconnect */
function WifiCard({ onSetup }: { onSetup: () => void }) {
  const saved = useStore((s) => s.settings.wifiHost);
  const { wifi, wifiConn, reconnectWifi, disconnectWifi } = useDeviceLink();
  const conn = useObservable(wifi?.conn ?? null);
  const status = useObservable(wifi?.status ?? null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const reconnect = async () => {
    setBusy(true);
    setErr(null);
    try {
      await reconnectWifi();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const online = wifi && conn?.state === 'online';
  const pill =
    wifiConn.state === 'connected'
      ? conn?.state === 'offline'
        ? { label: `Unreachable · ${wifiConn.host}`, tone: 'bad' as const }
        : conn?.state === 'locked'
          ? { label: 'Locked · wrong codes', tone: 'bad' as const }
          : { label: `Connected · ${wifiConn.host}`, tone: 'good' as const }
      : wifiConn.state === 'connecting'
        ? { label: 'Connecting...', tone: 'plain' as const }
        : { label: 'Not connected', tone: wifiConn.state === 'error' ? ('bad' as const) : ('plain' as const) };

  return (
    <Surface padded={18} style={{ gap: space.md }}>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: space.sm }}>
        <Label>Wi-Fi link</Label>
        <Pill label={pill.label} tone={pill.tone} icon="wifi" />
      </View>
      {Platform.OS === 'web' && <WebPreviewNote />}
      {wifi ? (
        <>
          <DeviceStatusLine status={status} />
          {(conn?.state === 'offline' || conn?.state === 'locked') && <Note tone="bad">{conn.message}</Note>}
          {status?.note ? (
            <Text variant="bodySmall" tone="warn">
              Device: {status.note}
            </Text>
          ) : null}
          {online && (
            <Text variant="bodySmall" tone="soft">
              Requests go over Wi-Fi: on the Ripar, press SIGN on Home to start scanning, as with a QR.
            </Text>
          )}
          <Button label="Disconnect and forget the code" variant="secondary" onPress={disconnectWifi} />
        </>
      ) : (
        <>
          <Text variant="bodySmall" tone="soft">
            The Ripar needs your Wi-Fi network once (sent over Bluetooth), then WI-FI ON from its menu. It shows an IP address and an 8-digit code.
          </Text>
          <Button label="Set up the Wi-Fi link" onPress={onSetup} icon={<Icon name="wifi" size={18} color={palette.primaryForeground} />} />
          {!!saved && <Button label={`Reconnect ${saved}`} variant="secondary" loading={busy || wifiConn.state === 'connecting'} onPress={() => void reconnect()} />}
        </>
      )}
      {wifi && (
        <Button label="Wi-Fi setup (network, code)" variant="ghost" size="sm" onPress={onSetup} />
      )}
      {(err || wifiConn.state === 'error') && <Note tone="bad">{err ?? (wifiConn.state === 'error' ? wifiConn.message : '')}</Note>}
    </Surface>
  );
}
