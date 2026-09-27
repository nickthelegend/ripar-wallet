// Wi-Fi link setup: TEMPORARY, for testing only. While the device's Wi-Fi is on, the Ripar is NOT air-gapped; QR stays
// the default and the recommended link.
//   1. connect over Bluetooth (the existing BLE LINK pairing), only to hand the device the Wi-Fi network
//   2. send the SSID + password to the PROV characteristic (src/device/wifi-prov.ts); the password is never stored
//   3. on the device: confirm JOIN WI-FI <ssid>? with SIGN, then device menu > WI-FI ON; Home shows the IP and the code
//   4. type the code (the IP is prefilled from STATUS "ip"), test the link (GET /status) and use it
// The device side is firmware/src/flows.cpp (docs/WIFI_LINK.md); the link itself is src/device/wifi-link.ts.
import { useRouter } from 'expo-router';
import { type ReactNode, useEffect, useState } from 'react';
import { Platform, StyleSheet, TextInput, type TextInputProps, View } from 'react-native';
import { BleConnect, Button, DeviceStatusLine, Icon, Label, Note, Screen, Steps, Surface, Text, WebPreviewNote } from '../src/components';
import { useDeviceLink, useObservable } from '../src/device/DeviceLinkProvider';
import { BLE_SETUP_STEPS, WIFI_ON_TEXT, wifiDeviceSteps } from '../src/device/guide';
import { isLanIpv4, normalizeWifiCode, wifiBaseUrl } from '../src/device/wifi-link';
import { credentialsProblem, ssidShownAltered } from '../src/device/wifi-prov';
import { errorText } from '../src/lib/format';
import { store, useStore } from '../src/lib/store';
import { ink, palette, radius, space, withAlpha } from '../src/theme';

function Section({ n, title, done, hint, children }: { n: number; title: string; done?: boolean; hint?: string; children?: ReactNode }) {
  return (
    <Surface padded={18} style={{ gap: space.md }}>
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: space.md }}>
        <View style={[styles.stepN, done && { backgroundColor: palette.success, borderColor: palette.success }]}>
          {done ? (
            <Icon name="check" size={15} color={palette.background} strokeWidth={2.6} />
          ) : (
            <Text variant="label" style={{ color: palette.primary, letterSpacing: 0 }}>
              {n}
            </Text>
          )}
        </View>
        <View style={{ flex: 1 }}>
          <Text variant="bodyMedium">{title}</Text>
          {hint ? (
            <Text variant="bodySmall" tone="soft">
              {hint}
            </Text>
          ) : null}
        </View>
      </View>
      {children}
    </Surface>
  );
}

function Field({ label, ...props }: { label: string } & TextInputProps) {
  return (
    <View style={{ gap: 6 }}>
      <Label>{label}</Label>
      <TextInput
        placeholderTextColor={ink.faint}
        autoCapitalize="none"
        autoCorrect={false}
        style={styles.input}
        accessibilityLabel={label}
        {...props}
      />
    </View>
  );
}

type Prov = { kind: 'idle' } | { kind: 'sending' } | { kind: 'sent'; ssid: string } | { kind: 'error'; message: string };

export default function WifiSetup() {
  const router = useRouter();
  const savedHost = useStore((s) => s.settings.wifiHost);
  const savedSsid = useStore((s) => s.settings.wifiSsid);
  const linkChoice = useStore((s) => s.settings.link);
  const { ble, bleConn, disconnectBle, wifi, wifiConn, connectWifi, disconnectWifi } = useDeviceLink();
  const bleStatus = useObservable(ble?.status ?? null);
  const wifiStatus = useObservable(wifi?.status ?? null);
  const wifiHealth = useObservable(wifi?.conn ?? null);

  const [ssid, setSsid] = useState(savedSsid ?? '');
  // the password lives only in this screen's state until it is sent, then it is cleared
  const [pass, setPass] = useState('');
  const [prov, setProv] = useState<Prov>({ kind: 'idle' });
  const [host, setHost] = useState(savedHost ?? '');
  const [code, setCode] = useState('');
  const [testing, setTesting] = useState(false);
  const [testErr, setTestErr] = useState<string | null>(null);
  const [showBleSteps, setShowBleSteps] = useState(false);

  // the IP the device reports (Bluetooth STATUS while provisioning, or the Wi-Fi link's own STATUS). Kept once seen:
  // a STATUS with a long note leaves "ip" out for that one time (docs/WIFI_LINK.md §5.4).
  const ipNow = bleStatus?.ip ?? wifiStatus?.ip ?? null;
  const [deviceIp, setDeviceIp] = useState<string | null>(null);
  useEffect(() => {
    if (ipNow) setDeviceIp(ipNow);
  }, [ipNow]);
  useEffect(() => {
    if (deviceIp && !host.trim()) setHost(deviceIp);
    // only when the device reports a (new) address
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceIp]);

  // The device answers a PROV value it did not take with a STATUS note ("wifi setup refused: ..." / "... ignored ...");
  // one it took opens the JOIN WI-FI review (screen REVIEW). The note can be left over from an earlier attempt, so it
  // counts only when no review was seen since the send and the status is newer than the device's first loop pass.
  const [sentAt, setSentAt] = useState(0);
  const [sawReview, setSawReview] = useState(false);
  useEffect(() => {
    if (prov.kind === 'sent' && bleStatus?.screen === 'REVIEW') setSawReview(true);
  }, [prov.kind, bleStatus?.screen]);
  const provNote =
    prov.kind === 'sent' && !sawReview && !!bleStatus?.note && /wifi setup/i.test(bleStatus.note) && bleStatus.at > sentAt + 800 ? bleStatus.note : null;
  const touched = ssid.length > 0 || pass.length > 0;
  const problem = touched ? credentialsProblem({ ssid, pass }) : null;
  const bleUp = bleConn.state === 'connected' && !!ble;
  // docs/WIFI_LINK.md §3.3: PROV is taken only while the device shows HOME or BLE PAIRING (no pairing code waiting)
  const provScreenOk = !bleStatus || bleStatus.screen === 'HOME' || bleStatus.screen === 'BLE_PAIR';

  const sendNetwork = async () => {
    if (!ble) return;
    const creds = { ssid, pass };
    if (credentialsProblem(creds)) return;
    setProv({ kind: 'sending' });
    setSawReview(false);
    try {
      setSentAt(Date.now());
      await ble.provisionWifi(creds);
      setPass('');
      setProv({ kind: 'sent', ssid });
      store.setSettings({ wifiSsid: ssid });
      // STATUS notifies changes; read it again once the device's loop has handled the value (a refusal may not change it)
      void ble.refreshStatus().catch(() => {});
      setTimeout(() => void ble.refreshStatus().catch(() => {}), 1200);
    } catch (e) {
      // the message never contains the password (wifi-prov.ts, ble-plx.ts)
      setProv({ kind: 'error', message: errorText(e) });
    }
  };

  let addrProblem: string | null = null;
  let lanWarning = false;
  if (host.trim()) {
    try {
      const base = wifiBaseUrl(host);
      const h = base.replace(/^http:\/\//, '').replace(/:\d+$/, '');
      lanWarning = /^[\d.]+$/.test(h) && !isLanIpv4(h);
    } catch (e) {
      addrProblem = errorText(e);
    }
  }
  const codeOk = normalizeWifiCode(code) !== null;

  const test = async () => {
    setTesting(true);
    setTestErr(null);
    try {
      await connectWifi(host, code);
      setCode('');
    } catch (e) {
      setTestErr(errorText(e));
    } finally {
      setTesting(false);
    }
  };

  const connected = wifiConn.state === 'connected' && !!wifi;
  const sentSsid = prov.kind === 'sent' ? prov.ssid : savedSsid;
  const deviceStep = bleStatus?.wifi === 'on' || connected ? 3 : bleStatus?.wifi === 'connecting' ? 2 : prov.kind === 'sent' ? 0 : undefined;

  return (
    <Screen back eyebrow="Device link · testing" title="Wi-Fi link" lede="A temporary way to test the phone and your Ripar over Wi-Fi. QR stays the default and the recommended link." tabs={false}>
      <View style={{ gap: space.md }}>
        <Note tone="warn" icon="wifi" title="NOT AIR-GAPPED while Wi-Fi is on · testing only">
          {WIFI_ON_TEXT}
        </Note>

        <Section n={1} title="Connect over Bluetooth" done={bleUp} hint="Only to hand the Ripar your Wi-Fi network. If it already knows it, go to step 3.">
          {!bleUp && (
            <>
              <Button
                label={showBleSteps ? 'Hide the Bluetooth steps' : 'How to turn BLE LINK on (device menu)'}
                variant="ghost"
                size="sm"
                onPress={() => setShowBleSteps((v) => !v)}
              />
              {showBleSteps && <Steps steps={[...BLE_SETUP_STEPS]} />}
            </>
          )}
          <BleConnect bare />
        </Section>

        <Section
          n={2}
          title="Send your Wi-Fi network"
          done={prov.kind === 'sent'}
          hint="With the Ripar on its Home screen. 2.4 GHz networks only. The password goes to the Ripar over the paired Bluetooth link; this phone does not keep it."
        >
          <Field label="Network name (SSID)" value={ssid} onChangeText={setSsid} placeholder="My Wi-Fi" autoComplete="off" importantForAutofill="no" maxLength={64} />
          <Field
            label="Password"
            value={pass}
            onChangeText={setPass}
            placeholder="empty for an open network"
            secureTextEntry
            autoComplete="off"
            importantForAutofill="no"
            textContentType="none"
            maxLength={128}
          />
          {problem && (
            <Text variant="bodySmall" tone="warn">
              {problem}
            </Text>
          )}
          {bleUp && !!bleStatus && !provScreenOk && (
            <Note tone="warn" title={`The Ripar is on ${bleStatus.screen}`}>
              It takes a Wi-Fi network only on its Home screen (or BLE PAIRING). Go back to Home on the Ripar first (a scan or review: hold SIGN 2 s; a QR or a message: press SIGN; the menu: BACK), then send.
            </Note>
          )}
          {!problem && !!ssid && ssidShownAltered(ssid) && (
            <Text variant="bodySmall" tone="faint">
              The Ripar shows characters outside plain ASCII as ? on its screen; the network name itself is sent as typed.
            </Text>
          )}
          <Button
            label={prov.kind === 'sending' ? 'Sending...' : 'Send to the Ripar'}
            loading={prov.kind === 'sending'}
            disabled={!bleUp || !ssid || !!problem}
            onPress={() => void sendNetwork()}
            icon={<Icon name="send" size={18} color={palette.primaryForeground} />}
          />
          {!bleUp && (
            <Text variant="bodySmall" tone="faint">
              Connect over Bluetooth first (step 1).
            </Text>
          )}
          {prov.kind === 'sent' && !provNote && (
            <Note tone="good" title="Sent">
              {`The Ripar now asks JOIN WI-FI ${prov.ssid}? Confirm it there (step 3).`}
            </Note>
          )}
          {provNote && (
            <Note tone="bad" title="The Ripar did not take it">
              {`${provNote}${/HOME/.test(provNote) ? ' Go back to its Home screen, then send again.' : ''}`}
            </Note>
          )}
          {prov.kind === 'error' && <Note tone="bad">{prov.message}</Note>}
        </Section>

        <Section n={3} title="On the Ripar: confirm, then WI-FI ON" done={bleStatus?.wifi === 'on' || connected}>
          <Steps steps={wifiDeviceSteps(sentSsid)} current={deviceStep} />
          {bleStatus && (
            <>
              <DeviceStatusLine status={bleStatus} />
              {bleStatus.note ? (
                <Text variant="bodySmall" tone="warn">
                  Device: {bleStatus.note}
                </Text>
              ) : null}
            </>
          )}
        </Section>

        <Section n={4} title="Connect over Wi-Fi" done={connected} hint="The phone must be on the same Wi-Fi network as the Ripar.">
          {Platform.OS === 'web' && <WebPreviewNote />}
          {!!deviceIp && deviceIp !== host.trim() && (
            <Button label={`Use ${deviceIp} (reported by the Ripar)`} variant="ghost" size="sm" onPress={() => setHost(deviceIp)} />
          )}
          <Field label="Ripar address (IP)" value={host} onChangeText={setHost} placeholder="192.168.1.23 or ripar-XXXX.local" keyboardType="url" autoComplete="off" />
          {addrProblem && (
            <Text variant="bodySmall" tone="warn">
              {addrProblem}
            </Text>
          )}
          {lanWarning && (
            <Text variant="bodySmall" tone="warn">
              This is not a local-network address: the code would travel over the internet. Use the IP the Ripar shows.
            </Text>
          )}
          <Field
            label="Code on the Ripar screen (8 digits)"
            value={code}
            onChangeText={setCode}
            placeholder="1234 5678"
            keyboardType="number-pad"
            autoComplete="off"
            importantForAutofill="no"
            maxLength={10}
          />
          <Text variant="bodySmall" tone="faint">
            On the Ripar's Home screen next to its address (CODE 1234 5678); new after every restart of the Ripar. This phone keeps it only in its secure storage, until you disconnect.
          </Text>
          <Button
            label={testing ? 'Testing...' : connected ? 'Test again' : 'Test the link'}
            loading={testing}
            disabled={!host.trim() || !!addrProblem || !codeOk}
            onPress={() => void test()}
            icon={<Icon name="wifi" size={18} color={palette.primaryForeground} />}
          />
          {testErr && <Note tone="bad">{testErr}</Note>}
          {connected && (
            <>
              {wifiHealth?.state === 'offline' || wifiHealth?.state === 'locked' ? (
                <Note tone="bad" title={wifiHealth.state === 'locked' ? 'Locked after wrong codes' : 'Stopped answering'}>
                  {wifiHealth.message}
                </Note>
              ) : (
                <Note tone="good" title={`The Ripar answers at ${wifiConn.host}`}>
                  Code accepted. The device status is read every 0.7 s while the link is up.
                </Note>
              )}
              <DeviceStatusLine status={wifiStatus} />
              {linkChoice === 'wifi' ? (
                <>
                  <Note tone="warn" icon="wifi" title="Wi-Fi is the active link">
                    Requests go over Wi-Fi. On the Ripar, press SIGN on Home to start scanning, as with a QR.
                  </Note>
                  <Button label="Back to QR (air-gapped)" variant="secondary" onPress={() => store.setSettings({ link: 'qr' })} />
                </>
              ) : (
                <Button
                  label="Use Wi-Fi for requests"
                  onPress={() => {
                    store.setSettings({ link: 'wifi' });
                    router.back();
                  }}
                />
              )}
              {bleUp && (
                <Button label="Disconnect Bluetooth (no longer needed)" variant="ghost" size="sm" onPress={disconnectBle} />
              )}
              <Button label="Disconnect Wi-Fi and forget the code" variant="ghost" size="sm" onPress={disconnectWifi} />
            </>
          )}
        </Section>
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
    paddingVertical: 11,
    fontFamily: 'GeistMono_400Regular',
    fontSize: 13,
  },
  stepN: {
    width: 32,
    height: 32,
    borderRadius: 16,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: withAlpha(palette.primary, 0.45),
    backgroundColor: withAlpha(palette.primary, 0.12),
  },
});
