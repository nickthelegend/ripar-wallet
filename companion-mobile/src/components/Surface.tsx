import { LinearGradient } from 'expo-linear-gradient';
import { Pressable, type StyleProp, StyleSheet, View, type ViewProps, type ViewStyle } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withSpring } from 'react-native-reanimated';
import { tap } from '../lib/haptics';
import { elevation, ink, motion, palette, radius, signal } from '../theme';

const AnimatedPressable = Animated.createAnimatedComponent(Pressable);

export type SurfaceVariant = 'raised' | 'selected' | 'plate' | 'signal' | 'steel' | 'danger';

type Props = ViewProps & {
  variant?: SurfaceVariant;
  onPress?: () => void;
  padded?: boolean | number;
  radiusSize?: number;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
};

const fill: Record<SurfaceVariant, string> = {
  raised: palette.card,
  selected: palette.card,
  plate: 'transparent',
  signal: palette.primary,
  steel: palette.steel,
  danger: '#2A1216',
};

/**
 * A raised plane: a downward wash, a hairline border and a one-pixel edge light along the top (React Native has no
 * inset shadow, so the highlight is drawn). Without the edge light a border reads as an outline drawn on glass rather
 * than an object above the ground. The signal and steel variants are the bright cards (balance, secondary): same
 * construction, filled, with a stronger sheen.
 *
 * Shadow and clipping live on different views: `overflow: hidden` on the view that carries an Android elevation clips
 * the shadow away.
 */
export function Surface({ variant = 'raised', onPress, padded = false, radiusSize, style, children, ...rest }: Props) {
  const pressed = useSharedValue(0);
  const animated = useAnimatedStyle(() => ({ transform: [{ scale: 1 - pressed.value * 0.012 }] }));
  const r = radiusSize ?? radius.xl;
  const bright = variant === 'signal' || variant === 'steel';
  const padding = padded === true ? 18 : typeof padded === 'number' ? padded : undefined;
  const border =
    variant === 'selected' ? signal.edge : variant === 'danger' ? palette.danger + '66' : bright ? 'rgba(255,255,255,0.18)' : ink.hairline;

  const body = (
    <View style={[styles.clip, { borderRadius: r, borderColor: border, backgroundColor: fill[variant] }]}>
      {variant !== 'plate' && (
        <LinearGradient
          colors={bright ? ['rgba(255,255,255,0.22)', 'rgba(255,255,255,0)'] : variant === 'selected' ? [signal.wash, 'transparent'] : [ink.wash, 'transparent']}
          locations={[0, bright ? 0.6 : 0.45]}
          style={[StyleSheet.absoluteFill, { pointerEvents: 'none' }]}
        />
      )}
      {variant !== 'plate' && (
        <View
          style={[
            styles.edge,
            { backgroundColor: bright ? 'rgba(255,255,255,0.45)' : variant === 'selected' ? signal.rim : ink.highlight, pointerEvents: 'none' },
          ]}
        />
      )}
      <View style={padding !== undefined ? { padding } : undefined}>{children}</View>
    </View>
  );

  const shell: StyleProp<ViewStyle> = [
    { borderRadius: r },
    variant === 'plate' ? elevation.flat : variant === 'signal' ? elevation.signalGlow : elevation.raised,
    style,
  ];

  if (!onPress) {
    return (
      <View style={shell} {...rest}>
        {body}
      </View>
    );
  }
  return (
    <AnimatedPressable
      style={[shell, animated]}
      accessibilityRole="button"
      onPressIn={() => {
        pressed.value = withSpring(1, motion.spring.press);
        tap();
      }}
      onPressOut={() => {
        pressed.value = withSpring(0, motion.spring.press);
      }}
      onPress={onPress}
      {...rest}
    >
      {body}
    </AnimatedPressable>
  );
}

export function Rule({ style }: { style?: StyleProp<ViewStyle> }) {
  return <View style={[{ height: 1, backgroundColor: ink.hairline }, style]} />;
}

const styles = StyleSheet.create({
  clip: { borderWidth: 1, overflow: 'hidden' },
  edge: { position: 'absolute', top: 0, left: 0, right: 0, height: 1 },
});
