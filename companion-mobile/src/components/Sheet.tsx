import { useRouter } from 'expo-router';
import type { ReactNode } from 'react';
import { KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, View } from 'react-native';
import Animated from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { ink, palette, radius, space } from '../theme';
import { Icon } from './Icon';
import { enterSheet } from './motion';
import { Text } from './Text';

/**
 * A bottom sheet (Send, Receive, Confirm): a dimmed backdrop that closes it, a raised plate with a grabber and a
 * title row. Routes that use it are presented as transparent modals, so the screen they came from stays visible
 * behind the dim.
 */
export function Sheet({
  title,
  children,
  onClose,
  scroll = true,
  footer,
}: {
  title: string;
  children: ReactNode;
  onClose?: () => void;
  scroll?: boolean;
  /** pinned under the content (the primary action) */
  footer?: ReactNode;
}) {
  const insets = useSafeAreaInsets();
  const router = useRouter();
  const close = onClose ?? (() => (router.canGoBack() ? router.back() : router.replace('/')));
  return (
    <View style={styles.root}>
      <Pressable style={styles.backdrop} onPress={close} accessibilityRole="button" accessibilityLabel="Close" />
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <Animated.View entering={enterSheet()} style={[styles.sheet, { paddingBottom: insets.bottom + space.lg }]}>
          <View style={styles.grabber} />
          <View style={styles.head}>
            <Text variant="heading" accessibilityRole="header">
              {title}
            </Text>
            <Pressable onPress={close} hitSlop={12} accessibilityRole="button" accessibilityLabel="Close" style={styles.close}>
              <Icon name="close" size={18} color={palette.foreground} />
            </Pressable>
          </View>
          {scroll ? (
            <ScrollView style={styles.scroll} contentContainerStyle={{ paddingBottom: space.lg }} keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
              {children}
            </ScrollView>
          ) : (
            <View>{children}</View>
          )}
          {footer ? <View style={{ paddingTop: space.md }}>{footer}</View> : null}
        </Animated.View>
      </KeyboardAvoidingView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, justifyContent: 'flex-end' },
  backdrop: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(5,5,6,0.62)' },
  sheet: {
    backgroundColor: palette.card,
    borderTopLeftRadius: radius['2xl'],
    borderTopRightRadius: radius['2xl'],
    borderWidth: 1,
    borderColor: ink.hairlineStrong,
    paddingHorizontal: space.xl,
    paddingTop: space.sm,
    maxHeight: '94%',
    boxShadow: '0px -12px 32px rgba(0,0,0,0.55)',
  },
  grabber: { alignSelf: 'center', width: 40, height: 4, borderRadius: 2, backgroundColor: ink.hairlineStrong, marginBottom: space.md },
  head: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: space.lg },
  close: {
    width: 34,
    height: 34,
    borderRadius: 17,
    backgroundColor: palette.cardHigh,
    alignItems: 'center',
    justifyContent: 'center',
  },
  scroll: { flexGrow: 0 },
});
