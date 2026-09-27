import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect } from 'react';
import { Linking, StyleSheet, View } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withDelay, withSpring, withTiming } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Address, AmbientBackground, Button, Icon, Label, Spec, Surface, Text } from '../src/components';
import { amountText, utcText } from '../src/lib/format';
import { succeeded } from '../src/lib/haptics';
import { NETWORKS, explorerTxUrl } from '../src/lib/networks';
import { useStore } from '../src/lib/store';
import { palette, space, type } from '../src/theme';

/** "Done." A check that lands (a spring that overshoots a little: something arriving), then the receipt. */
export default function Done() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const p = useStore((s) => s.payments.find((x) => x.id === id) ?? null);
  const network = useStore((s) => s.settings.network);
  const scale = useSharedValue(0.4);
  const fade = useSharedValue(0);

  useEffect(() => {
    succeeded();
    scale.value = withSpring(1, { damping: 11, stiffness: 200, mass: 0.8 });
    fade.value = withDelay(180, withTiming(1, { duration: 360 }));
  }, [scale, fade]);

  const check = useAnimatedStyle(() => ({ transform: [{ scale: scale.value }] }));
  const rest = useAnimatedStyle(() => ({ opacity: fade.value }));
  const url = p?.tx ? explorerTxUrl(NETWORKS[network]?.explorer ?? null, p.tx) : null;

  return (
    <View style={[styles.root, { paddingTop: insets.top + space['3xl'], paddingBottom: insets.bottom + space.xl }]}>
      <AmbientBackground />
      <View style={{ alignItems: 'center', gap: space.lg }}>
        <Animated.View style={[styles.check, check]}>
          <Icon name="check" size={56} color={palette.primaryForeground} strokeWidth={3} />
        </Animated.View>
        <Text style={[type.display, { color: palette.foreground, fontSize: 44, lineHeight: 48 }]} accessibilityRole="header">
          Done.
        </Text>
        {p && (
          <Text variant="body" tone="soft" style={{ textAlign: 'center' }}>
            {amountText(BigInt(p.amount), p.decimals, p.symbol)} left your vault, co-signed on your Ripar
            {p.bpm ? ` with a ${p.bpm} bpm pulse` : ''}.
          </Text>
        )}
      </View>
      <Animated.View style={[{ marginTop: space['2xl'], gap: space.lg }, rest]}>
        {p && (
          <Surface padded={18}>
            <Label style={{ marginBottom: space.md }}>Receipt</Label>
            <Spec
              rows={[
                { k: 'Amount', v: amountText(BigInt(p.amount), p.decimals, p.symbol) },
                { k: 'To', v: <Address value={p.to} label="Payee" /> },
                p.tx ? { k: 'Transaction', v: <Address value={p.tx} label="Transaction" tone="soft" /> } : null,
                { k: 'When', v: utcText(Math.floor((p.doneAt ?? p.createdAt) / 1000)) },
                { k: 'Co-sign nonce', v: p.nonce },
                p.note ? { k: 'Note', v: p.note } : null,
              ]}
            />
          </Surface>
        )}
        <View style={{ gap: space.md }}>
          {url && <Button label="View on the explorer" variant="secondary" full onPress={() => void Linking.openURL(url)} />}
          <Button label="Back to Home" variant="light" size="lg" full onPress={() => router.replace('/(tabs)')} />
        </View>
      </Animated.View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: palette.background, paddingHorizontal: space.xl },
  check: {
    width: 112,
    height: 112,
    borderRadius: 56,
    backgroundColor: palette.primary,
    alignItems: 'center',
    justifyContent: 'center',
    boxShadow: '0px 12px 40px rgba(255,107,26,0.45)',
  },
});
