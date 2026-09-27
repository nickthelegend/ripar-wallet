import { Platform, ViewStyle } from 'react-native';

/** a 4 px base */
export const space = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  '2xl': 24,
  '3xl': 32,
  '4xl': 44,
  '5xl': 64,
} as const;

export const radius = {
  sm: 8,
  md: 12,
  lg: 16,
  xl: 22,
  '2xl': 28,
  pill: 999,
} as const;

/**
 * Elevation. React Native has no inset shadow, so the top highlight that makes a plane read as raised is drawn by
 * `Surface` as a one-pixel line. The offsets carry a y-component, so a plane sits above the ground instead of glowing.
 */
export const elevation = {
  flat: {} as ViewStyle,
  raised: {
    ...Platform.select({ android: { elevation: 6 }, default: {} }),
    boxShadow: '0px 8px 16px rgba(0, 0, 0, 0.5)',
  } as ViewStyle,
  lifted: {
    ...Platform.select({ android: { elevation: 14 }, default: {} }),
    boxShadow: '0px 16px 28px rgba(0, 0, 0, 0.6)',
  } as ViewStyle,
  /** what the orange casts; the loudest thing available: the primary action and the balance card only */
  signalGlow: {
    ...Platform.select({ android: { elevation: 10 }, default: {} }),
    boxShadow: '0px 10px 26px rgba(255, 107, 26, 0.35)',
  } as ViewStyle,
} as const;

/**
 * Motion: one settling curve for almost everything (fast start, soft landing), springs for anything under a finger.
 * Nothing moves for its own sake; an entrance never decides whether content is visible (components/motion.ts).
 */
export const motion = {
  ease: [0.16, 1, 0.3, 1] as const,
  duration: { instant: 120, quick: 180, base: 240, slow: 420, figure: 900 },
  stagger: 55,
  spring: {
    press: { damping: 18, stiffness: 320, mass: 0.6 },
    settle: { damping: 20, stiffness: 180, mass: 0.9 },
    bounce: { damping: 12, stiffness: 220, mass: 0.8 },
  },
} as const;
