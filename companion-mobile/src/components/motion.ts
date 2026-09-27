import { Platform } from 'react-native';
import { FadeIn, FadeInDown, ReduceMotion, SlideInDown } from 'react-native-reanimated';
import { motion } from '../theme';

/**
 * Entrances, guarded (the Polaris rule): an entrance must never be load-bearing for whether content is visible. Every
 * one animates from opacity 0 or off-screen, and Reanimated's layout animations compile to CSS on web without the
 * keyframes (the element keeps its from-state), so the web preview gets none. Motion is also a preference:
 * ReduceMotion.System hands the decision to the OS setting.
 */
const supported = Platform.OS !== 'web';

export const enterUp = (index = 0) =>
  supported ? FadeInDown.delay(index * motion.stagger).duration(motion.duration.slow).reduceMotion(ReduceMotion.System) : undefined;

export const enterUpAfter = (delayMs: number) =>
  supported ? FadeInDown.delay(delayMs).duration(motion.duration.slow).reduceMotion(ReduceMotion.System) : undefined;

export const enterFade = (delayMs = 0) =>
  supported ? FadeIn.delay(delayMs).duration(motion.duration.base).reduceMotion(ReduceMotion.System) : undefined;

/** a sheet arriving from the bottom edge */
export const enterSheet = () => (supported ? SlideInDown.springify().damping(20).stiffness(180).reduceMotion(ReduceMotion.System) : undefined);
