import { Tabs } from 'expo-router';
import { useEffect, useState } from 'react';
import { type LayoutChangeEvent, Pressable, StyleSheet, View } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withSpring, type SharedValue } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { LinearGradient } from 'expo-linear-gradient';
import { Icon, type IconName } from '../../src/components';
import { tap } from '../../src/lib/haptics';
import { ink, palette, space } from '../../src/theme';

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
      <Icon name={icon} size={23} color={focused ? palette.primaryForeground : ink.soft} strokeWidth={focused ? 2.2 : 1.8} />
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
      {/* content fades out under the bar instead of showing through it */}
      <LinearGradient
        pointerEvents="none"
        colors={['rgba(11,12,14,0)', 'rgba(11,12,14,0.92)', palette.background]}
        locations={[0, 0.45, 1]}
        style={styles.scrim}
      />
      <View style={styles.bar}>
        <View style={styles.row} onLayout={(e: LayoutChangeEvent) => setW(e.nativeEvent.layout.width)}>
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

const BAR_H = 62;
const INSET = 6;

const styles = StyleSheet.create({
  wrap: { position: 'absolute', left: 0, right: 0, bottom: 0, paddingHorizontal: space.lg, alignItems: 'center' },
  scrim: { position: 'absolute', left: 0, right: 0, bottom: 0, height: 150 },
  bar: {
    width: '100%',
    maxWidth: 520,
    height: BAR_H,
    padding: INSET,
    borderRadius: BAR_H / 2,
    backgroundColor: '#16181C',
    borderWidth: 1,
    borderColor: ink.hairlineStrong,
    overflow: 'hidden',
    boxShadow: '0px 12px 28px rgba(0,0,0,0.55)',
    elevation: 18,
  },
  // the tabs and the pill share this box, so the pill is exactly one slot tall and wide
  row: { flex: 1, flexDirection: 'row' },
  pill: {
    position: 'absolute',
    top: 0,
    bottom: 0,
    left: 0,
    borderRadius: (BAR_H - 2 * INSET) / 2,
    backgroundColor: palette.primary,
  },
  tab: { flex: 1, alignItems: 'center', justifyContent: 'center' },
});
