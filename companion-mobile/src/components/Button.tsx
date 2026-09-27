import { LinearGradient } from 'expo-linear-gradient';
import type { ReactNode } from 'react';
import { ActivityIndicator, Pressable, type StyleProp, StyleSheet, View, type ViewStyle } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withSpring } from 'react-native-reanimated';
import { press, tap } from '../lib/haptics';
import { elevation, ink, motion, palette, radius, space, type } from '../theme';
import { Text } from './Text';

const AnimatedPressable = Animated.createAnimatedComponent(Pressable);

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'light' | 'steel';
type Size = 'sm' | 'md' | 'lg';

const heights: Record<Size, number> = { sm: 40, md: 50, lg: 58 };

const colors: Record<Variant, { bg: string; fg: string }> = {
  primary: { bg: palette.primary, fg: palette.primaryForeground },
  secondary: { bg: palette.secondary, fg: palette.foreground },
  ghost: { bg: 'transparent', fg: palette.foreground },
  danger: { bg: palette.danger, fg: '#1A0306' },
  /** the white "Get Started" pill of the onboarding */
  light: { bg: palette.foreground, fg: palette.background },
  steel: { bg: palette.steel, fg: palette.steelInk },
};

/**
 * A pill. Presses scale rather than change colour: on an orange button a colour change either disappears or shouts,
 * a scale reads at any brightness. Haptics fire on press-in.
 */
export function Button({
  label,
  onPress,
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  full = false,
  icon,
  style,
  accessibilityHint,
}: {
  label: string;
  onPress?: () => void;
  variant?: Variant;
  size?: Size;
  disabled?: boolean;
  loading?: boolean;
  full?: boolean;
  icon?: ReactNode;
  style?: StyleProp<ViewStyle>;
  accessibilityHint?: string;
}) {
  const pressed = useSharedValue(0);
  const inert = disabled || loading;
  const animated = useAnimatedStyle(() => ({ transform: [{ scale: 1 - pressed.value * 0.03 }] }));
  const c = colors[variant];

  return (
    <Animated.View style={[{ borderRadius: radius.pill }, full && styles.full, variant === 'primary' && !inert ? elevation.signalGlow : undefined, animated, style]}>
      <AnimatedPressable
        disabled={inert}
        accessibilityRole="button"
        accessibilityLabel={label}
        accessibilityHint={accessibilityHint}
        accessibilityState={{ disabled: inert, busy: loading }}
        onPressIn={() => {
          pressed.value = withSpring(1, motion.spring.press);
          if (variant === 'primary' || variant === 'danger') press();
          else tap();
        }}
        onPressOut={() => {
          pressed.value = withSpring(0, motion.spring.press);
        }}
        onPress={onPress}
        style={[
          styles.base,
          {
            height: heights[size],
            backgroundColor: c.bg,
            borderColor: variant === 'ghost' ? ink.hairlineStrong : 'transparent',
            borderWidth: variant === 'ghost' ? 1 : 0,
            opacity: inert && !loading ? 0.45 : 1,
            paddingHorizontal: size === 'sm' ? space.lg : space['2xl'],
          },
          full && styles.full,
        ]}
      >
        {variant !== 'ghost' && (
          <LinearGradient
            colors={[variant === 'secondary' ? ink.highlight : 'rgba(255,255,255,0.26)', 'transparent']}
            locations={[0, 0.55]}
            style={[StyleSheet.absoluteFill, { pointerEvents: 'none' }]}
          />
        )}
        {loading ? (
          <ActivityIndicator size="small" color={c.fg} />
        ) : (
          <View style={styles.row}>
            {icon}
            <Text style={[type.action, { color: c.fg }, size === 'sm' && { fontSize: 13 }]} numberOfLines={1}>
              {label}
            </Text>
          </View>
        )}
      </AnimatedPressable>
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  base: { borderRadius: radius.pill, alignItems: 'center', justifyContent: 'center', overflow: 'hidden' },
  row: { flexDirection: 'row', alignItems: 'center', gap: space.sm },
  full: { alignSelf: 'stretch', width: '100%' },
});
