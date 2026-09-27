import * as Haptics from 'expo-haptics';

// Haptics on the press-in, not the press: feedback that waits for the gesture to finish arrives after the user knows.
export const tap = () => void Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light).catch(() => {});
export const press = () => void Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium).catch(() => {});
export const selected = () => void Haptics.selectionAsync().catch(() => {});
export const succeeded = () => void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
export const failed = () => void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error).catch(() => {});
