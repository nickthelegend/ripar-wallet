import { Platform, TextStyle } from 'react-native';

/**
 * Geist for everything a person reads: a precise, neutral grotesk drawn for interfaces, with true tabular figures
 * for money. Geist Mono for what a machine produced (addresses, URs, hashes).
 */
export const font = {
  display: 'Geist_600SemiBold',
  displayBold: 'Geist_700Bold',
  body: 'Geist_400Regular',
  bodyMedium: 'Geist_500Medium',
  mono: 'GeistMono_400Regular',
  monoMedium: 'GeistMono_500Medium',
} as const;

/**
 * Tabular figures. Money is read down a column of digits; proportional numerals make a changing value shove its
 * neighbours, and a balance that jitters reads as broken.
 */
export const tabular: TextStyle = {
  fontVariant: ['tabular-nums'],
  ...Platform.select({ android: { fontFeatureSettings: "'tnum' 1" } as TextStyle, default: {} }),
};

export const type = {
  /** the big balance: one per screen */
  hero: { fontFamily: font.display, fontSize: 44, lineHeight: 48, letterSpacing: -1.6, ...tabular } as TextStyle,
  /** the amount on the send keypad */
  amount: { fontFamily: font.display, fontSize: 56, lineHeight: 62, letterSpacing: -2, ...tabular } as TextStyle,
  display: { fontFamily: font.displayBold, fontSize: 34, lineHeight: 38, letterSpacing: -1.2 } as TextStyle,
  title: { fontFamily: font.display, fontSize: 28, lineHeight: 32, letterSpacing: -0.9 } as TextStyle,
  heading: { fontFamily: font.display, fontSize: 19, lineHeight: 24, letterSpacing: -0.4 } as TextStyle,
  stat: { fontFamily: font.display, fontSize: 22, lineHeight: 26, letterSpacing: -0.6, ...tabular } as TextStyle,
  body: { fontFamily: font.body, fontSize: 15, lineHeight: 22, letterSpacing: -0.1 } as TextStyle,
  bodyMedium: { fontFamily: font.bodyMedium, fontSize: 15, lineHeight: 22, letterSpacing: -0.1 } as TextStyle,
  bodySmall: { fontFamily: font.body, fontSize: 13, lineHeight: 19, letterSpacing: -0.05 } as TextStyle,
  label: {
    fontFamily: font.bodyMedium,
    fontSize: 11,
    lineHeight: 14,
    letterSpacing: 0.9,
    textTransform: 'uppercase',
  } as TextStyle,
  mono: { fontFamily: font.mono, fontSize: 12, lineHeight: 17, letterSpacing: -0.2 } as TextStyle,
  monoSmall: { fontFamily: font.mono, fontSize: 11, lineHeight: 15, letterSpacing: -0.2 } as TextStyle,
  action: { fontFamily: font.displayBold, fontSize: 15, lineHeight: 18, letterSpacing: 0.1 } as TextStyle,
} as const;

export type TypeVariant = keyof typeof type;
