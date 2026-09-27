import { Tabs } from 'expo-router';
import { useEffect, useState } from 'react';
import { type LayoutChangeEvent, Pressable, StyleSheet, View } from 'react-native';
import Animated, { interpolateColor, useAnimatedStyle, useDerivedValue, useSharedValue, withSpring, type SharedValue } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Icon, type IconName } from '../../src/components';
import { tap } from '../../src/lib/haptics';
import { font, ink, palette, space } from '../../src/theme';

const TABS: { name: string; label: string; icon: IconName }[] = [
  { name: 'index', label: 'Home', icon: 'home' },
  { name: 'activity', label: 'Activity', icon: 'activity' },
  { name: 'device', label: 'Device', icon: 'device' },
  { name: 'agents', label: 'Agents', icon: 'agents' },
  { name: 'settings', label: 'Settings', icon: 'settings' },
];

const SPRING = { damping: 20, stiffness: 190, mass: 0.8 };

/**
 * One tab. Its colour is a function of the indicator's animated position rather than of a focused boolean: as the
 * orange pill travels, each glyph it passes warms and cools, so it reads as one object moving, not five switching.
 */
function TabButton({
  index,
  pos,
  focused,
  label,
  icon,
  onPress,
}: {
  index: number;
  pos: SharedValue<number>;
  focused: boolean;
  label: string;
  icon: IconName;
  onPress: () => void;
}) {
  const near = useDerivedValue(() => Math.max(0, 1 - Math.abs(pos.value - index)));
  const labelStyle = useAnimatedStyle(() => ({ color: interpolateColor(near.value, [0, 1], [ink.soft, palette.primaryForeground]) }));
  return (
    <Pressable
      style={styles.tab}
      accessibilityRole="tab"
      accessibilityLabel={label}
      accessibilityState={{ selected: focused }}
      onPressIn={tap}
      onPress={onPress}
      hitSlop={4}
    >
      <Icon name={icon} size={21} color={focused ? palette.primaryForeground : ink.soft} strokeWidth={focused ? 2.1 : 1.7} />
      <Animated.Text style={[styles.label, labelStyle]} numberOfLines={1}>
        {label}
      </Animated.Text>
    </Pressable>
  );
}

function RiparTabBar({ state, navigation }: { state: { index: number; routes: { key: string; name: string }[] }; navigation: any }) {
  const insets = useSafeAreaInsets();
  const [w, setW] = useState(0);
  const pos = useSharedValue(state.index);
  const slot = w / TABS.length;

  useEffect(() => {
    pos.value = withSpring(state.index, SPRING);
  }, [state.index, pos]);

  const pill = useAnimatedStyle(() => ({ transform: [{ translateX: pos.value * slot }] }));

  return (
    <View style={[styles.wrap, { paddingBottom: Math.max(insets.bottom, space.md) }]} pointerEvents="box-none">
      <View style={styles.bar} onLayout={(e: LayoutChangeEvent) => setW(e.nativeEvent.layout.width - 12)}>
        {w > 0 && <Animated.View style={[styles.pill, { width: slot }, pill]} />}
        {state.routes.map((route, i) => {
          const tab = TABS.find((t) => t.name === route.name);
          if (!tab) return null;
          return (
            <TabButton
              key={route.key}
              index={i}
              pos={pos}
              focused={state.index === i}
              label={tab.label}
              icon={tab.icon}
              onPress={() => {
                const ev = navigation.emit({ type: 'tabPress', target: route.key, canPreventDefault: true });
                if (!ev.defaultPrevented) navigation.navigate(route.name);
              }}
            />
          );
        })}
      </View>
    </View>
  );
}

export default function TabsLayout() {
  return (
    <Tabs
      detachInactiveScreens
      screenOptions={{ headerShown: false, sceneStyle: { backgroundColor: palette.background }, lazy: true, freezeOnBlur: true }}
      tabBar={(props) => <RiparTabBar {...(props as any)} />}
    >
      {TABS.map((t) => (
        <Tabs.Screen key={t.name} name={t.name} options={{ title: t.label }} />
      ))}
    </Tabs>
  );
}

const styles = StyleSheet.create({
  wrap: { position: 'absolute', left: 0, right: 0, bottom: 0, paddingHorizontal: space.lg, alignItems: 'center' },
  bar: {
    flexDirection: 'row',
    width: '100%',
    maxWidth: 520,
    padding: 6,
    borderRadius: 34,
    backgroundColor: '#15171AF2',
    borderWidth: 1,
    borderColor: ink.hairlineStrong,
    boxShadow: '0px 14px 30px rgba(0,0,0,0.6)',
    elevation: 18,
  },
  pill: {
    position: 'absolute',
    top: 6,
    bottom: 6,
    left: 6,
    borderRadius: 28,
    backgroundColor: palette.primary,
    boxShadow: '0px 6px 16px rgba(255,107,26,0.35)',
  },
  tab: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingVertical: 9, gap: 3 },
  label: { fontFamily: font.bodyMedium, fontSize: 10, lineHeight: 12, letterSpacing: 0.3 },
});
