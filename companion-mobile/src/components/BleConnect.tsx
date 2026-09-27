// Finding, connecting and pairing a Ripar over Bluetooth (docs/BLE_LINK.md §3, §5): the card the link screen uses for
// the Bluetooth fallback and the Wi-Fi setup screen uses to send the Wi-Fi network. The connection itself lives in
// DeviceLinkProvider (connectBle), so it is shared by every screen.
import { useEffect, useRef, useState } from 'react';
import { Linking, View } from 'react-native';
import { useDeviceLink, useObservable } from '../device/DeviceLinkProvider';
import type { FoundDevice } from '../device/ble-plx';
import { useStore } from '../lib/store';
import { palette, space } from '../theme';
import { Button } from './Button';
import { DeviceStatusLine } from './DeviceRound';
import { Icon } from './Icon';
import { ListRow, Note, Pill } from './Rows';
import { Surface } from './Surface';
import { Label, Text } from './Text';

/**
 * The web preview cannot reach a Ripar over Wi-Fi: the device's HTTP server sends no CORS headers, so a browser refuses
 * the X-Ripar-Code request (docs/WIFI_LINK.md §5.1). Bluetooth does not run there either. The Android app is fine.
 */
export function WebPreviewNote() {
  return (
    <Note tone="info" title="Web preview">
      A browser cannot reach the Ripar over Wi-Fi (the device sends no CORS headers) or Bluetooth: use the Android app.
    </Note>
  );
}

/** `bare`: no card of its own (inside another card) */
export function BleConnect({ title = 'Bluetooth', bare = false }: { title?: string; bare?: boolean }) {
  const last = useStore((s) => s.settings.bleDevice);
  const { bleConn, connectBle, disconnectBle, ble } = useDeviceLink();
  const status = useObservable(ble?.status ?? null);
  const [found, setFound] = useState<FoundDevice[]>([]);
  const [scanning, setScanning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const stop = useRef<(() => void) | null>(null);
  const scanTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      stop.current?.();
      if (scanTimer.current) clearTimeout(scanTimer.current);
    },
    [],
  );

  const scan = async () => {
    setErr(null);
    setFound([]);
    try {
      const { ensureBlePermissions, scanForRipar, bluetoothState } = await import('../device/ble-plx');
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
      if (scanTimer.current) clearTimeout(scanTimer.current);
      scanTimer.current = setTimeout(() => setScanning(false), 20_000);
    } catch (e) {
      setScanning(false);
      setErr((e as Error).message);
    }
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

  const body = (
    <>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: space.sm }}>
        <Label>{title}</Label>
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
          {last && bleConn.state !== 'connecting' && <Button label={`Reconnect ${last.name}`} variant="secondary" onPress={() => void connect(last)} />}
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
      {(err || bleConn.state === 'error') && <Note tone="bad">{err ?? (bleConn.state === 'error' ? bleConn.message : '')}</Note>}
      {err?.includes('blocked') && <Button label="Open Android settings" variant="ghost" onPress={() => void Linking.openSettings()} />}
    </>
  );
  return bare ? (
    <View style={{ gap: space.md }}>{body}</View>
  ) : (
    <Surface padded={18} style={{ gap: space.md }}>
      {body}
    </Surface>
  );
}
