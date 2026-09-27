// The emulated Ripar, drawn from the firmware's own screen model (EmuDisplay: the same rows, colours and footer the
// 320x240 LCD shows), with the one SIGN key (press / hold, real timing) and the synthetic thumb on the pulse sensor.
// Always labelled EMULATOR - DEMO KEYS.
import { useRef } from 'react';
import { Pressable, ScrollView, StyleSheet, View } from 'react-native';
import { Icon } from '../../components/Icon';
import { QrCode } from '../../components/Qr';
import { Pill } from '../../components/Rows';
import { Text } from '../../components/Text';
import { press, tap } from '../../lib/haptics';
import { ink, palette, radius, space } from '../../theme';
import { useDeviceLink, useObservable } from '../DeviceLinkProvider';
import type { EmuDisplay, EmulatorLink } from '../emulator-link';
import { emulatorHostState } from './EmulatorHost';

const LCD_BG = '#05070A';

function Lcd({ d, width }: { d: EmuDisplay | null; width: number }) {
  const h = Math.round(width * 0.75);
  return (
    <View style={[styles.lcd, { width, minHeight: h }]} accessibilityLabel="Emulated device screen">
      {!d ? (
        <Text variant="bodySmall" tone="faint">
          booting...
        </Text>
      ) : d.kind === 'home' ? (
        <View style={{ gap: 6 }}>
          <View style={styles.rowBetween}>
            <Text variant="label" style={{ color: '#8FA3B8' }}>
              RIPAR
            </Text>
            <Text variant="monoSmall" style={{ color: '#8FA3B8' }}>
              {d.battery}%
            </Text>
          </View>
          <Text variant="heading" style={{ color: '#E8EEF4' }}>
            K1 {d.k1Short}
          </Text>
          <Text variant="label" style={{ color: d.badgeColorHex || '#9BE39B' }}>
            {d.badge}
          </Text>
          {d.hints.map((x) => (
            <Text key={x} variant="monoSmall" style={{ color: '#8FA3B8' }}>
              {x}
            </Text>
          ))}
        </View>
      ) : d.kind === 'scan' ? (
        <View style={{ gap: 8 }}>
          <Text variant="label" style={{ color: '#E8EEF4' }}>
            SCAN
          </Text>
          <View style={styles.bar}>
            <View style={[styles.barFill, { width: `${Math.round(Math.max(0, Math.min(1, d.progress)) * 100)}%` }]} />
          </View>
          <Text variant="monoSmall" style={{ color: '#8FA3B8' }}>
            {d.progressText || d.hint}
          </Text>
        </View>
      ) : d.kind === 'review' ? (
        <View style={{ gap: 3 }}>
          <Text variant="label" style={{ color: '#E8EEF4' }}>
            {d.title}
            {d.moreAbove ? '  ▲' : ''}
          </Text>
          {d.rows.map((r, i) => (
            <View key={`${i}:${r.label}:${r.value}`} style={r.full ? undefined : styles.reviewRow}>
              {!r.full && r.label ? (
                <Text variant="monoSmall" style={{ color: '#8FA3B8', width: 74 }}>
                  {r.label}
                </Text>
              ) : null}
              <Text variant="monoSmall" style={{ color: r.colorHex || '#E8EEF4', flex: 1 }}>
                {r.value}
              </Text>
            </View>
          ))}
          <Text variant="monoSmall" style={{ color: '#FFB067', marginTop: 4 }}>
            {d.moreBelow ? '▼ ' : ''}
            {d.footer}
          </Text>
        </View>
      ) : d.kind === 'pulse' ? (
        <View style={{ gap: 6, alignItems: 'center' }}>
          <Text variant="label" style={{ color: '#E8EEF4' }}>
            {d.title}
          </Text>
          <Icon name="heart" size={d.heartBig ? 44 : 36} color={d.ringColorHex || palette.danger} strokeWidth={2.2} />
          <Text variant="stat" style={{ color: '#E8EEF4' }}>
            {d.bpmText}
          </Text>
          <Text variant="monoSmall" style={{ color: '#8FA3B8' }}>
            {d.beatsText} · {d.elapsedText}
          </Text>
          <Text variant="bodySmall" style={{ color: d.statusColorHex || '#E8EEF4' }}>
            {d.status}
          </Text>
        </View>
      ) : d.kind === 'qr' ? (
        <View style={{ gap: 6, alignItems: 'center' }}>
          <Text variant="label" style={{ color: '#E8EEF4' }}>
            {d.title}
          </Text>
          <QrCode text={d.text} size={Math.min(width - 40, 180)} label="The emulated device's answer QR" />
          <Text variant="monoSmall" style={{ color: '#8FA3B8' }}>
            {d.footer}
          </Text>
        </View>
      ) : (
        <View style={{ gap: 4 }}>
          <Text variant="label" style={{ color: d.kind === 'message' ? d.colorHex || '#E8EEF4' : '#E8EEF4' }}>
            {d.title}
          </Text>
          {d.lines.map((x, i) => (
            <Text key={`${i}:${x}`} variant="monoSmall" style={{ color: '#C9D3DD' }}>
              {x}
            </Text>
          ))}
        </View>
      )}
    </View>
  );
}

/** the SIGN key: down on press-in, up on press-out, so a 2 s / 5 s hold works as on the device */
function SignKey({ link }: { link: EmulatorLink }) {
  const down = useRef(false);
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel="SIGN key of the emulated device. Press, or hold 2 or 5 seconds."
      onPressIn={() => {
        down.current = true;
        press();
        link.keyDown();
      }}
      onPressOut={() => {
        if (!down.current) return;
        down.current = false;
        link.keyUp();
      }}
      delayLongPress={100000}
      style={({ pressed }) => [styles.sign, pressed && { transform: [{ scale: 0.96 }], backgroundColor: palette.glow }]}
    >
      <Text variant="action" style={{ color: palette.primaryForeground }}>
        SIGN
      </Text>
    </Pressable>
  );
}

export function EmulatorPanel({ width = 300 }: { width?: number }) {
  const { emulator } = useDeviceLink();
  const host = useObservable(emulatorHostState);
  const link = emulator?.kind === 'emulator' ? (emulator as EmulatorLink) : null;
  const snap = useObservable(link?.snapshot ?? null);

  if (host?.phase === 'error') {
    return (
      <View style={[styles.lcd, { width }]}>
        <Text variant="bodySmall" tone="danger">
          Emulator: {host.message}
        </Text>
      </View>
    );
  }
  if (!link) {
    return (
      <View style={[styles.lcd, { width }]}>
        <Text variant="bodySmall" tone="faint">
          Starting the emulator...
        </Text>
      </View>
    );
  }
  const thumb = !!snap?.thumb;
  return (
    <View style={{ alignItems: 'center', gap: space.md }}>
      <Pill label="Emulator · demo keys" tone="warn" icon="alert" />
      <View style={styles.body}>
        <ScrollView style={{ maxHeight: 360 }} contentContainerStyle={{ alignItems: 'center' }} nestedScrollEnabled>
          <Lcd d={snap?.display ?? null} width={width - 24} />
        </ScrollView>
        <View style={styles.controls}>
          <SignKey link={link} />
          <Pressable
            accessibilityRole="switch"
            accessibilityState={{ checked: thumb }}
            accessibilityLabel="Thumb on the pulse sensor"
            onPress={() => {
              tap();
              link.setThumb(!thumb);
            }}
            style={[styles.thumb, thumb && { backgroundColor: `${palette.danger}33`, borderColor: palette.danger }]}
          >
            <Icon name="thumb" size={18} color={thumb ? palette.danger : palette.foreground} />
            <Text variant="bodySmall">{thumb ? 'Thumb on sensor' : 'Place thumb'}</Text>
          </Pressable>
        </View>
        <Text variant="monoSmall" tone="faint" style={{ textAlign: 'center' }}>
          SIGN: press = next / scan · hold 2 s = cancel, deny, menu · hold 5 s on Home = PANIC
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  body: {
    backgroundColor: '#1B1D21',
    borderRadius: radius['2xl'],
    padding: space.md,
    gap: space.md,
    borderWidth: 1,
    borderColor: ink.hairlineStrong,
  },
  lcd: { backgroundColor: LCD_BG, borderRadius: radius.sm, padding: space.md, borderWidth: 2, borderColor: '#2B2F35' },
  rowBetween: { flexDirection: 'row', justifyContent: 'space-between' },
  reviewRow: { flexDirection: 'row', gap: 6 },
  bar: { height: 8, borderRadius: 4, backgroundColor: '#1F262E', overflow: 'hidden' },
  barFill: { height: 8, backgroundColor: palette.primary },
  controls: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: space.md },
  sign: {
    width: 88,
    height: 52,
    borderRadius: radius.pill,
    backgroundColor: palette.primary,
    alignItems: 'center',
    justifyContent: 'center',
  },
  thumb: {
    flex: 1,
    height: 52,
    borderRadius: radius.pill,
    borderWidth: 1,
    borderColor: ink.hairlineStrong,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: space.sm,
  },
});
