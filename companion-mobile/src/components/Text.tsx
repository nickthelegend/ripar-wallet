import { Text as RNText, type StyleProp, type TextProps, type TextStyle } from 'react-native';
import { type TypeVariant, ink, palette, type } from '../theme';

export type TextTone =
  | 'default'
  | 'soft'
  | 'label'
  | 'faint'
  | 'signal'
  | 'steel'
  | 'danger'
  | 'success'
  | 'warn'
  /** dark ink on the orange card */
  | 'onSignal'
  /** dark ink on the steel card */
  | 'onSteel';

const tones: Record<TextTone, string> = {
  default: palette.foreground,
  soft: ink.soft,
  label: ink.label,
  faint: ink.faint,
  signal: palette.primary,
  steel: palette.steel,
  danger: palette.danger,
  success: palette.success,
  warn: palette.warn,
  onSignal: palette.primaryForeground,
  onSteel: palette.steelInk,
};

type Props = TextProps & { variant?: TypeVariant; tone?: TextTone; style?: StyleProp<TextStyle> };

export function Text({ variant = 'body', tone = 'default', style, ...rest }: Props) {
  return <RNText style={[type[variant], { color: tones[tone] }, style]} maxFontSizeMultiplier={1.6} {...rest} />;
}

/** the quiet uppercase label that names a figure: above it, never beside */
export function Label({ tone = 'label', style, ...rest }: Omit<Props, 'variant'>) {
  return <Text variant="label" tone={tone} style={style} {...rest} />;
}

/** machine output: addresses, hashes, URs */
export function Mono({ tone = 'soft', style, small = false, ...rest }: Omit<Props, 'variant'> & { small?: boolean }) {
  return <Text variant={small ? 'monoSmall' : 'mono'} tone={tone} style={style} selectable {...rest} />;
}
