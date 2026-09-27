import { useRouter } from 'expo-router';
import { type ReactNode, useCallback, useState } from 'react';
import { Pressable, RefreshControl, ScrollView, type StyleProp, StyleSheet, View, type ViewStyle } from 'react-native';
import Animated from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { tap } from '../lib/haptics';
import { ink, palette, space } from '../theme';
import { AmbientBackground } from './AmbientBackground';
import { Icon } from './Icon';
import { enterFade, enterUpAfter } from './motion';
import { Label, Text } from './Text';

/**
 * The shell every route shares: one gutter, one opening rhythm (eyebrow, title, a line of prose), the ground drawn per
 * screen (it is what makes the scene opaque), pull-to-refresh where the screen is a view of chain state, and room at
 * the bottom for the floating tab bar.
 */
export function Screen({
  eyebrow,
  title,
  lede,
  action,
  back = false,
  children,
  scroll = true,
  tabs = true,
  contentStyle,
  onRefresh,
}: {
  eyebrow?: string;
  title?: string;
  lede?: string;
  action?: ReactNode;
  /** a back chevron (for stack screens) */
  back?: boolean;
  children: ReactNode;
  scroll?: boolean;
  /** leave room for the floating tab bar */
  tabs?: boolean;
  contentStyle?: StyleProp<ViewStyle>;
  onRefresh?: () => Promise<void>;
}) {
  const insets = useSafeAreaInsets();
  const router = useRouter();
  const [refreshing, setRefreshing] = useState(false);
  const pull = useCallback(async () => {
    if (!onRefresh || refreshing) return;
    setRefreshing(true);
    tap();
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  }, [onRefresh, refreshing]);

  const head =
    title || eyebrow || back ? (
      <Animated.View entering={enterUpAfter(0)} style={styles.head}>
        {back && (
          <Pressable
            onPress={() => (router.canGoBack() ? router.back() : router.replace('/'))}
            accessibilityRole="button"
            accessibilityLabel="Back"
            hitSlop={12}
            style={styles.back}
          >
            <Icon name="back" size={22} color={palette.foreground} />
          </Pressable>
        )}
        {eyebrow ? <Label>{eyebrow}</Label> : null}
        <View style={styles.titleRow}>
          {title ? (
            <Text variant="title" style={styles.title} accessibilityRole="header">
              {title}
            </Text>
          ) : null}
          {action}
        </View>
        {lede ? (
          <Text variant="body" tone="soft" style={styles.lede}>
            {lede}
          </Text>
        ) : null}
      </Animated.View>
    ) : null;

  const body = (
    <Animated.View entering={enterFade(60)} style={contentStyle}>
      {children}
    </Animated.View>
  );
  const bottom = insets.bottom + (tabs ? 110 : space['3xl']);

  return (
    <View style={styles.ground}>
      <AmbientBackground />
      {scroll ? (
        <ScrollView
          style={styles.scroll}
          contentContainerStyle={[styles.shell, { paddingTop: insets.top + space.sm, paddingBottom: bottom }]}
          showsVerticalScrollIndicator={false}
          keyboardShouldPersistTaps="handled"
          refreshControl={
            onRefresh ? (
              <RefreshControl
                refreshing={refreshing}
                onRefresh={pull}
                tintColor={palette.primary}
                colors={[palette.primary]}
                progressBackgroundColor={palette.card}
              />
            ) : undefined
          }
        >
          {head}
          {body}
        </ScrollView>
      ) : (
        <View style={[styles.shell, { flex: 1, paddingTop: insets.top + space.sm, paddingBottom: bottom }]}>
          {head}
          {body}
        </View>
      )}
    </View>
  );
}

/** a section heading inside a screen: a label and an optional action on the right */
export function SectionHead({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <View style={styles.section}>
      <Text variant="heading">{title}</Text>
      {action}
    </View>
  );
}

const styles = StyleSheet.create({
  ground: { flex: 1, backgroundColor: palette.background },
  scroll: { flex: 1 },
  shell: { paddingHorizontal: space.xl, width: '100%', maxWidth: 640, alignSelf: 'center' },
  head: { gap: space.sm, paddingTop: space.lg, paddingBottom: space.xl },
  back: {
    width: 40,
    height: 40,
    borderRadius: 20,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: palette.card,
    borderWidth: 1,
    borderColor: ink.hairline,
    marginBottom: space.sm,
  },
  titleRow: { flexDirection: 'row', alignItems: 'flex-end', justifyContent: 'space-between', gap: space.lg },
  title: { flex: 1 },
  lede: { maxWidth: 480 },
  section: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginTop: space['2xl'], marginBottom: space.md },
});
