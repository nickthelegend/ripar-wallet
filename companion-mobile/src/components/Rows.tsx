import type { ReactNode } from 'react';
import { Pressable, type StyleProp, StyleSheet, View, type ViewStyle } from 'react-native';
import { tap } from '../lib/haptics';
import { ink, palette, radius, space, tone as tones, type Tone } from '../theme';
import { Icon, type IconName } from './Icon';
import { Label, Text } from './Text';

/** a round icon plate (list rows, the balance card's action buttons) */
export function IconCircle({
  name,
  size = 44,
  tone = 'plain',
  filled = false,
  dark = false,
}: {
  name: IconName;
  size?: number;
  tone?: Tone;
  /** filled with the tone colour (dark glyph) instead of a tinted plate */
  filled?: boolean;
  /** a graphite plate with a cream glyph (on the orange card) */
  dark?: boolean;
}) {
  const c = tones[tone];
  const bg = dark ? 'rgba(26,14,6,0.88)' : filled ? c : `${c}22`;
  const fg = dark ? palette.foreground : filled ? palette.background : c === tones.plain ? palette.foreground : c;
  return (
    <View
      style={{
        width: size,
        height: size,
        borderRadius: size / 2,
        backgroundColor: bg,
        alignItems: 'center',
        justifyContent: 'center',
        borderWidth: dark || filled ? 0 : 1,
        borderColor: ink.hairline,
      }}
    >
      <Icon name={name} size={Math.round(size * 0.46)} color={fg} strokeWidth={2} />
    </View>
  );
}

/** a list row: round icon, title + subtitle, value on the right */
export function ListRow({
  icon,
  iconTone = 'plain',
  title,
  subtitle,
  value,
  valueTone = 'default',
  sub,
  onPress,
  right,
  accessibilityLabel,
}: {
  icon: IconName;
  iconTone?: Tone;
  title: string;
  subtitle?: string;
  value?: string;
  valueTone?: 'default' | 'soft' | 'success' | 'danger' | 'signal' | 'steel' | 'warn';
  sub?: string;
  onPress?: () => void;
  right?: ReactNode;
  accessibilityLabel?: string;
}) {
  const inner = (
    <View style={styles.row}>
      <IconCircle name={icon} tone={iconTone} />
      <View style={styles.mid}>
        <Text variant="bodyMedium" numberOfLines={1}>
          {title}
        </Text>
        {subtitle ? (
          <Text variant="bodySmall" tone="soft" numberOfLines={1}>
            {subtitle}
          </Text>
        ) : null}
      </View>
      {right ??
        (value ? (
          <View style={styles.right}>
            <Text variant="bodyMedium" tone={valueTone} style={styles.value}>
              {value}
            </Text>
            {sub ? (
              <Text variant="bodySmall" tone="faint">
                {sub}
              </Text>
            ) : null}
          </View>
        ) : onPress ? (
          <Icon name="chevron" size={18} color={ink.faint} />
        ) : null)}
    </View>
  );
  if (!onPress) return inner;
  return (
    <Pressable
      onPress={onPress}
      onPressIn={tap}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? `${title}${subtitle ? `, ${subtitle}` : ''}${value ? `, ${value}` : ''}`}
      style={({ pressed }) => [pressed && { opacity: 0.7 }]}
    >
      {inner}
    </Pressable>
  );
}

/** a small rounded pill: account pill, status chip */
export function Pill({
  label,
  tone = 'plain',
  icon,
  onDark = false,
  onPress,
  style,
  mono = false,
}: {
  label: string;
  tone?: Tone;
  icon?: IconName;
  /** machine text (an address): mono, never upper-cased */
  mono?: boolean;
  /** on the orange card: dark translucent plate, cream text */
  onDark?: boolean;
  onPress?: () => void;
  style?: StyleProp<ViewStyle>;
}) {
  const c = tones[tone];
  const body = (
    <View
      style={[
        styles.pill,
        onDark
          ? { backgroundColor: 'rgba(26,14,6,0.16)', borderColor: 'rgba(26,14,6,0.18)' }
          : { backgroundColor: `${c}1F`, borderColor: `${c}40` },
        style,
      ]}
    >
      {icon && <Icon name={icon} size={13} color={onDark ? palette.primaryForeground : c === tones.plain ? palette.foreground : c} strokeWidth={2.2} />}
      <Text
        variant={mono ? 'monoSmall' : 'label'}
        style={{ color: onDark ? palette.primaryForeground : c === tones.plain ? palette.foreground : c, letterSpacing: mono ? 0 : 0.6 }}
        numberOfLines={1}
      >
        {label}
      </Text>
    </View>
  );
  if (!onPress) return body;
  return (
    <Pressable onPress={onPress} onPressIn={tap} accessibilityRole="button" accessibilityLabel={label} hitSlop={8}>
      {body}
    </Pressable>
  );
}

/** a callout: an icon, a title and text, in a tone */
export function Note({
  tone = 'info',
  title,
  children,
  icon,
  style,
}: {
  tone?: Tone;
  title?: string;
  children?: ReactNode;
  icon?: IconName;
  style?: StyleProp<ViewStyle>;
}) {
  const c = tones[tone];
  const ic: IconName = icon ?? (tone === 'bad' || tone === 'warn' ? 'alert' : tone === 'good' ? 'check' : 'shield');
  return (
    <View style={[styles.note, { borderColor: `${c}55`, backgroundColor: `${c}12` }, style]} accessibilityRole="summary">
      <View style={{ paddingTop: 1 }}>
        <Icon name={ic} size={18} color={c} strokeWidth={2} />
      </View>
      <View style={{ flex: 1, gap: 2 }}>
        {title ? (
          <Text variant="bodyMedium" style={{ color: c }}>
            {title}
          </Text>
        ) : null}
        {typeof children === 'string' ? (
          <Text variant="bodySmall" tone="soft">
            {children}
          </Text>
        ) : (
          children
        )}
      </View>
    </View>
  );
}

/** label / value rows (a spec sheet) */
export function Spec({ rows, style }: { rows: (false | null | undefined | { k: string; v: ReactNode })[]; style?: StyleProp<ViewStyle> }) {
  const list = rows.filter(Boolean) as { k: string; v: ReactNode }[];
  return (
    <View style={[{ gap: space.md }, style]}>
      {list.map((r) => (
        <View key={r.k} style={{ gap: 3 }}>
          <Label>{r.k}</Label>
          {typeof r.v === 'string' ? <Text variant="bodySmall">{r.v}</Text> : r.v}
        </View>
      ))}
    </View>
  );
}

/** numbered steps (device instructions) with the current one lit */
export function Steps({ steps, current, done }: { steps: string[]; current?: number; done?: number }) {
  return (
    <View style={{ gap: space.md }}>
      {steps.map((s, i) => {
        const isDone = done !== undefined && i < done;
        const isNow = current === i;
        return (
          <View key={s} style={styles.step}>
            <View
              style={[
                styles.stepN,
                isDone && { backgroundColor: palette.success, borderColor: palette.success },
                isNow && { backgroundColor: palette.primary, borderColor: palette.primary },
              ]}
            >
              {isDone ? (
                <Icon name="check" size={14} color={palette.background} strokeWidth={2.6} />
              ) : (
                <Text variant="label" style={{ color: isNow ? palette.primaryForeground : ink.soft, letterSpacing: 0 }}>
                  {i + 1}
                </Text>
              )}
            </View>
            <Text variant="bodySmall" tone={isNow ? 'default' : isDone ? 'soft' : 'faint'} style={{ flex: 1 }}>
              {s}
            </Text>
          </View>
        );
      })}
    </View>
  );
}

const styles = StyleSheet.create({
  row: { flexDirection: 'row', alignItems: 'center', gap: space.md, paddingVertical: space.md },
  mid: { flex: 1, gap: 1 },
  right: { alignItems: 'flex-end', gap: 1 },
  value: { fontVariant: ['tabular-nums'] },
  pill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: radius.pill,
    borderWidth: 1,
    alignSelf: 'flex-start',
  },
  note: { flexDirection: 'row', gap: space.md, padding: space.md, borderRadius: radius.lg, borderWidth: 1 },
  step: { flexDirection: 'row', alignItems: 'center', gap: space.md },
  stepN: {
    width: 26,
    height: 26,
    borderRadius: 13,
    borderWidth: 1,
    borderColor: ink.hairlineStrong,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
