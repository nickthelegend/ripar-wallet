import { useRouter } from 'expo-router';
import { StyleSheet, View } from 'react-native';
import { Address, Button, DeviceStatusLine, IconCircle, Label, ListRow, Note, Pill, Screen, SectionHead, Spec, Surface, Text } from '../../src/components';
import { useDeviceLink, useObservable } from '../../src/device/DeviceLinkProvider';
import { emulatorHostState, resetEmulator } from '../../src/device/emulator/EmulatorHost';
import { RADIO_ON_TEXT, WIFI_ON_TEXT, linkMeta } from '../../src/device/guide';
import { refreshChain, useChain } from '../../src/lib/chainState';
import { rememberedMandate, store, useStore } from '../../src/lib/store';
import { ink, space } from '../../src/theme';

/** docs/FIRMWARE.md §5: one key, three events; a press or hold belongs to the screen on which it began */
const KEYS: [string, string, string, string][] = [
  ['Home', 'scan a request', 'Hold screen (release = pairing QR)', 'PANIC, signed at once'],
  ['Scan', '-', 'cancel → Home', '-'],
  ['Review', 'next page; last page → pulse', 'co-sign: DENY; else cancel', '-'],
  ['Pulse', 'ignored', 'cancel → Home', '-'],
  ['Armed', 'SIGN', 'cancel → Home', '-'],
  ['QR', 'done → Home', 'done → Home', '-'],
  ['Pairing QR', '→ Home', 'device menu', '-'],
  ['Menu', 'next item', 'select', '-'],
];

export default function Device() {
  const router = useRouter();
  const device = useStore((s) => s.device);
  const keys = useStore((s) => s.keysOnly);
  const linkChoice = useStore((s) => s.settings.link);
  const remembered = useStore(rememberedMandate);
  const chain = useChain();
  const { link, bleConn, wifi, wifiConn } = useDeviceLink();
  const status = useObservable(link?.status ?? null);
  const wifiHealth = useObservable(wifi?.conn ?? null);
  const meta = linkMeta(linkChoice);
  const emu = useObservable(emulatorHostState);

  return (
    <Screen eyebrow="Your Ripar" title="Device" onRefresh={refreshChain}>
      <Surface variant="steel" padded={20} radiusSize={26}>
        <View style={styles.rowBetween}>
          <Label tone="onSteel">{device?.emulator ? 'Emulated Ripar · demo keys' : 'Ripar hardware wallet'}</Label>
          <Pill label={meta.radio ? 'Not air-gapped' : 'Air-gapped'} icon={meta.radio ? 'radio' : 'noRadio'} onDark />
        </View>
        <Text variant="title" tone="onSteel" style={{ marginTop: space.md }}>
          {device ? `K1 ${device.k1Address.slice(0, 6)}…${device.k1Address.slice(-4)}` : keys ? 'Keys read, not paired' : 'Not paired'}
        </Text>
        <Text variant="bodySmall" tone="onSteel" style={{ opacity: 0.8, marginTop: 4 }}>
          {device
            ? `Paired on ${device.pinned.chainId === 10143 ? 'Monad testnet' : 'Monad'} · ${chain.registered === true ? 'registered' : chain.registered === false ? 'not registered' : 'registry unknown'} · firmware ${device.firmwareId.slice(2, 10)}`
            : 'Keys are born on the device and never leave it. Pairing reads only its public keys.'}
        </Text>
        <View style={{ flexDirection: 'row', gap: space.md, marginTop: space.lg }}>
          <Button label={device ? 'Pair again' : 'Pair your Ripar'} variant="secondary" size="sm" onPress={() => router.push('/pair')} />
          <Button label="Kill switch" variant="danger" size="sm" onPress={() => router.push('/scan')} />
        </View>
      </Surface>

      {linkChoice === 'ble' && (
        <Note tone="warn" icon="radio" title="NOT AIR-GAPPED · RADIO ON" style={{ marginTop: space.lg }}>
          {RADIO_ON_TEXT}
        </Note>
      )}
      {linkChoice === 'wifi' && (
        <Note tone="warn" icon="wifi" title="NOT AIR-GAPPED · WI-FI ON · TESTING" style={{ marginTop: space.lg }}>
          {WIFI_ON_TEXT}
        </Note>
      )}

      <SectionHead title="Link" action={<Text variant="bodySmall" tone="signal" onPress={() => router.push('/link')}>Change</Text>} />
      <Surface padded={6}>
        <View style={{ paddingHorizontal: 10 }}>
          <ListRow
            icon={meta.icon}
            iconTone={meta.tone}
            title={meta.title}
            subtitle={
              linkChoice === 'qr'
                ? 'The default: nothing but light between the phone and the Ripar'
                : linkChoice === 'ble'
                  ? bleConn.state === 'connected'
                    ? `Connected to ${bleConn.name}`
                    : 'Not connected: tap to connect'
                  : linkChoice === 'wifi'
                    ? wifiConn.state === 'connected'
                      ? wifiHealth?.state === 'offline'
                        ? `Not answering at ${wifiConn.host}`
                        : wifiHealth?.state === 'locked'
                          ? 'Locked after wrong codes: wait'
                          : `Connected to ${wifiConn.host}`
                      : 'Not connected: tap to connect'
                  : emu?.phase === 'ready'
                    ? `Running (${emu.mode === 'demo-seed' ? 'public demo seed' : 'random demo keys'})`
                    : emu?.phase === 'error'
                      ? emu.message
                      : 'Starting...'
            }
            onPress={() => router.push(linkChoice === 'wifi' && wifiConn.state !== 'connected' ? '/wifi' : '/link')}
          />
        </View>
        {status && (
          <View style={{ paddingHorizontal: 14, paddingBottom: 12 }}>
            <DeviceStatusLine status={status} />
          </View>
        )}
      </Surface>
      {linkChoice !== 'wifi' && (
        <Surface padded={6} style={{ marginTop: space.md }}>
          <View style={{ paddingHorizontal: 10 }}>
            <ListRow
              icon="wifi"
              iconTone="warn"
              title="Wi-Fi link (testing)"
              subtitle={wifiConn.state === 'connected' ? `Connected to ${wifiConn.host} · not the active link` : 'Set up · not air-gapped while it is on'}
              onPress={() => router.push('/wifi')}
            />
          </View>
        </Surface>
      )}
      {linkChoice === 'emulator' && (
        <View style={{ flexDirection: 'row', gap: space.md, marginTop: space.md }}>
          <Button label="New demo device" variant="secondary" size="sm" onPress={() => void resetEmulator('random')} />
          <Button label="Public demo seed" variant="ghost" size="sm" onPress={() => void resetEmulator('demo-seed')} />
        </View>
      )}

      {device && (
        <>
          <SectionHead title="Pinned at pairing" />
          <Surface padded={16}>
            <Spec
              rows={[
                { k: 'Vault (derived from K1)', v: <Address value={device.pinned.vault} label="Vault" /> },
                { k: 'K1 (owns the vault, signs mandates only)', v: <Address value={device.k1Address} label="K1" tone="soft" /> },
                { k: 'P1 key id (co-signs, kill switch)', v: <Address value={device.keyId} label="Key id" tone="soft" /> },
                { k: 'PulseCosignEnforcer', v: <Address value={device.pinned.enforcer} label="Enforcer" tone="soft" /> },
                { k: 'Sentinel', v: <Address value={device.pinned.sentinel} label="Sentinel" tone="soft" /> },
                {
                  k: 'Mandate the device remembers',
                  v: remembered ? `${remembered.label || 'mandate'} (${remembered.delegationHash.slice(0, 10)}…)` : 'none this app knows',
                },
                { k: 'Panic floor on-chain', v: chain.minEpoch === null ? 'unknown' : chain.minEpoch.toString() },
              ]}
            />
          </Surface>
        </>
      )}

      <SectionHead title="The SIGN key" />
      <Surface padded={14}>
        <View style={styles.tableRow}>
          {['Screen', 'Press', 'Hold 2 s', 'Hold 5 s'].map((h) => (
            <Text key={h} variant="label" tone="label" style={styles.cell}>
              {h}
            </Text>
          ))}
        </View>
        {KEYS.map((r) => (
          <View key={r[0]} style={[styles.tableRow, styles.tableLine]}>
            {r.map((c, i) => (
              <Text key={`${r[0]}${i}`} variant="bodySmall" tone={i === 0 ? 'default' : c.includes('PANIC') ? 'danger' : 'soft'} style={styles.cell}>
                {c}
              </Text>
            ))}
          </View>
        ))}
        <Text variant="bodySmall" tone="faint" style={{ marginTop: space.md }}>
          A press or hold belongs to the screen it began on. Every screen but Home returns Home after 120 s.
        </Text>
      </Surface>

      <SectionHead title="What stays on the device" />
      <Surface padded={16} style={{ gap: space.md }}>
        {[
          ['key', 'The seed and both keys are made and kept on the Ripar. This app never sees or stores a seed.'],
          ['eye', 'The Ripar decodes and shows every field it signs, and rebuilds every digest itself.'],
          ['heart', 'Signing needs a live pulse (5 beats, anti-spoof checks) and a press of SIGN.'],
          ['noRadio', 'No radio by default. Bluetooth (and the Wi-Fi test link) only when you turn it on from the device menu.'],
        ].map(([ic, t]) => (
          <View key={t} style={{ flexDirection: 'row', gap: space.md, alignItems: 'center' }}>
            <IconCircle name={ic as 'key'} tone="signal" size={36} />
            <Text variant="bodySmall" tone="soft" style={{ flex: 1 }}>
              {t}
            </Text>
          </View>
        ))}
      </Surface>
      {device && (
        <Button
          label="Forget this device on the phone"
          variant="ghost"
          style={{ marginTop: space.xl }}
          onPress={() => store.set({ device: null, keysOnly: null, personal: null, lastSignedMandate: null })}
        />
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  rowBetween: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: space.sm, flexWrap: 'wrap' },
  tableRow: { flexDirection: 'row', gap: 6, paddingVertical: 6 },
  tableLine: { borderTopWidth: 1, borderTopColor: ink.hairline },
  cell: { flex: 1 },
});
