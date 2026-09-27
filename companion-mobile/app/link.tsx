// Choosing the device link and connecting the Bluetooth fallback (docs/BLE_LINK.md §2, §3, §5).
import { useEffect, useRef, useState } from 'react';
import { Linking, View } from 'react-native';
import { Button, DeviceStatusLine, Icon, IconCircle, Label, ListRow, Note, Pill, Screen, Steps, Surface, Text } from '../src/components';
import { useDeviceLink, useObservable } from '../src/device/DeviceLinkProvider';
import type { FoundDevice } from '../src/device/ble-plx';
import { BLE_SETUP_STEPS, RADIO_ON_TEXT } from '../src/device/guide';
import { type LinkChoice, store, useStore } from '../src/lib/store';
import { palette, space } from '../src/theme';

const CHOICES: { id: LinkChoice; title: string; body: string; icon: 'qr' | 'bluetooth' | 'device'; tone: 'signal' | 'warn' | 'info' }[] = [
  { id: 'qr', title: 'QR codes', body: 'Air-gapped. The phone shows a QR, the Ripar shows one back. The default, always.', icon: 'qr', tone: 'signal' },
  { id: 'ble', title: 'Bluetooth fallback', body: "Turns the device's radio on. Use it if the camera cannot read.", icon: 'bluetooth', tone: 'warn' },
  { id: 'emulator', title: 'Emulator', body: 'The Ripar firmware compiled to WebAssembly, on this phone. Demo keys only.', icon: 'device', tone: 'info' },
];

export default function LinkScreen() {
  const choice = useStore((s) => s.settings.link);
  const last = useStore((s) => s.settings.bleDevice);
  const { bleConn, connectBle, disconnectBle, ble } = useDeviceLink();
  const status = useObservable(ble?.status ?? null);
  const [found, setFound] = useState<FoundDevice[]>([]);
  const [scanning, setScanning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const stop = useRef<(() => void) | null>(null);

  useEffect(() => () => stop.current?.(), []);

  const scan = async () => {
    setErr(null);
    setFound([]);
    const { ensureBlePermissions, scanForRipar, bluetoothState } = await import('../src/device/ble-plx');
    const perm = await ensureBlePermissions();
    if (perm !== 'granted') {
      setErr(perm === 'blocked' ? 'Bluetooth permission is blocked: allow "Nearby devices" for Ripar in Android settings.' : 'Bluetooth permission was not granted.');
      return;
    }
    const st = await bluetoothState();
    if (st !== 'PoweredOn') {
      setErr(`Bluetooth is ${st.toLowerCase()} on this phone: turn it on.`);
      return;
    }
    setScanning(true);
    stop.current?.();
    stop.current = scanForRipar(
      (d) => setFound((xs) => (xs.some((x) => x.id === d.id) ? xs : [...xs, d])),
      (m) => setErr(m),
      20_000,
    );
    setTimeout(() => setScanning(false), 20_000);
  };

  const connect = async (d: { id: string; name: string }) => {
    stop.current?.();
    setScanning(false);
    setErr(null);
    try {
      await connectBle(d.id, d.name);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <Screen back eyebrow="Device link" title="How the phone reaches your Ripar" tabs={false}>
      <View style={{ gap: space.md }}>
        {CHOICES.map((c) => (
          <Surface key={c.id} variant={choice === c.id ? 'selected' : 'raised'} padded={16} onPress={() => store.setSettings({ link: c.id })} accessibilityLabel={`${c.title}. ${c.body}`}>
            <View style={{ flexDirection: 'row', gap: space.md, alignItems: 'center' }}>
              <IconCircle name={c.icon} tone={c.tone} />
              <View style={{ flex: 1 }}>
                <Text variant="bodyMedium">{c.title}</Text>
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

            <Surface padded={18} style={{ gap: space.md }}>
              <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
                <Label>Bluetooth</Label>
                <Pill
                  label={bleConn.state === 'connected' ? `Connected · ${bleConn.name}` : bleConn.state === 'pairing' ? 'Pairing...' : bleConn.state === 'connecting' ? 'Connecting...' : 'Not connected'}
                  tone={bleConn.state === 'connected' ? 'good' : bleConn.state === 'error' ? 'bad' : 'plain'}
                  icon="bluetooth"
                />
              </View>
              {bleConn.state === 'pairing' && (
                <Note tone="warn" title="Confirm the code">
                  Android shows a 6-digit code. It must match the one on the Ripar (BLE PAIRING screen): press SIGN on the Ripar, then confirm on the phone.
                </Note>
              )}
              {bleConn.state === 'connected' ? (
                <>
                  <DeviceStatusLine status={status} />
                  {status?.note ? (
                    <Text variant="bodySmall" tone="warn">
                      Device: {status.note}
                    </Text>
                  ) : null}
                  <Button label="Disconnect" variant="secondary" onPress={disconnectBle} />
                </>
              ) : (
                <>
                  <Button label={scanning ? 'Scanning...' : 'Scan for RIPAR-XXXX'} loading={scanning} onPress={() => void scan()} icon={<Icon name="bluetooth" size={18} color={palette.primaryForeground} />} />
                  {last && bleConn.state !== 'connecting' && (
                    <Button label={`Reconnect ${last.name}`} variant="secondary" onPress={() => void connect(last)} />
                  )}
                  {found.map((d) => (
                    <ListRow key={d.id} icon="device" iconTone="warn" title={d.name} subtitle={`${d.id}${d.rssi !== null ? ` · ${d.rssi} dBm` : ''}`} onPress={() => void connect(d)} />
                  ))}
                  {!scanning && found.length === 0 && (
                    <Text variant="bodySmall" tone="faint">
                      Nothing found yet. The Ripar advertises only while BLE LINK is on (it turns off after 5 min without traffic).
                    </Text>
                  )}
                </>
              )}
              {(err || bleConn.state === 'error') && (
                <Note tone="bad">{err ?? (bleConn.state === 'error' ? bleConn.message : '')}</Note>
              )}
              {err?.includes('blocked') && <Button label="Open Android settings" variant="ghost" onPress={() => void Linking.openSettings()} />}
            </Surface>
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
