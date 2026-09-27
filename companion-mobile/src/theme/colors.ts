/**
 * "Signal orange on graphite".
 *
 * A near-black graphite ground, raised graphite planes, and one warm signal orange (the colour of a camera's record
 * light) for the balance card and the primary action. Soft cream text rather than white: next to a warm accent a
 * blue-white reads cold. Steel blue is the cool counterweight for secondary cards, and red is kept for PANIC and
 * refusals only, pushed towards crimson so it never reads as "more orange".
 *
 * Contrast (WCAG 2.x, against `background` unless noted; computed, not eyeballed):
 *   foreground 16.4:1 · ink.soft 7.5:1 · ink.label 6.7:1 · ink.faint 4.7:1 (4.6:1 on card) · primary 6.8:1
 *   steel 9.0:1 · danger 6.0:1 · success 10.6:1 · primaryForeground on primary 6.6:1 · steelInk on steel 8.5:1
 */

export const palette = {
  /** graphite, a hair warm so the orange sits in it rather than on it */
  background: '#0D0E10',
  /** soft cream */
  foreground: '#F2ECE1',
  /** a raised plane */
  card: '#16181B',
  /** a plane on a plane (sheets, keypad keys) */
  cardHigh: '#1E2125',
  /** signal orange: the one loud colour */
  primary: '#FF6B1A',
  /** what the light around orange is made of */
  glow: '#FF7A2E',
  /** dark ink on orange */
  primaryForeground: '#1A0E06',
  /** the deeper surface of a secondary control */
  secondary: '#22252A',
  mutedForeground: '#A7A29A',
  /** steel blue: the cool counterweight */
  steel: '#93B4D6',
  steelInk: '#0B1520',
  steelDeep: '#1A2430',
  border: '#2A2D32',
  /** refusals, PANIC, destructive actions */
  danger: '#FF4F5E',
  success: '#6BD49A',
  /** RADIO ON and other "you changed the security posture" notes */
  warn: '#F5D547',
  /** the QR plate: black on white, what a camera wants */
  qrPaper: '#FFFFFF',
  qrInk: '#000000',
} as const;

const hexAlpha = (hex: string, alpha: number) => {
  const a = Math.round(Math.max(0, Math.min(1, alpha)) * 255)
    .toString(16)
    .padStart(2, '0')
    .toUpperCase();
  return `${hex}${a}`;
};

export const withAlpha = hexAlpha;

/** cream at fixed strengths, so a screen cannot invent a fourteenth shade of nearly-white */
export const ink = {
  soft: hexAlpha(palette.foreground, 0.66),
  /** the quiet label above a figure; not lower than 60 % (small uppercase needs 4.5:1) */
  label: hexAlpha(palette.foreground, 0.62),
  faint: hexAlpha(palette.foreground, 0.5),
  hairline: hexAlpha(palette.foreground, 0.08),
  hairlineStrong: hexAlpha(palette.foreground, 0.16),
  highlight: hexAlpha(palette.foreground, 0.08),
  wash: hexAlpha(palette.foreground, 0.04),
} as const;

export const signal = {
  edge: hexAlpha(palette.primary, 0.45),
  wash: hexAlpha(palette.primary, 0.1),
  rim: hexAlpha(palette.primary, 0.26),
  glow: hexAlpha(palette.glow, 0.32),
  glowSoft: hexAlpha(palette.glow, 0.12),
} as const;

/** semantic tones, named for what they mean */
export const tone = {
  good: palette.success,
  bad: palette.danger,
  warn: palette.warn,
  info: palette.steel,
  signal: palette.primary,
  plain: palette.mutedForeground,
} as const;

export type Tone = keyof typeof tone;
