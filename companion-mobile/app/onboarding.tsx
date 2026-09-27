import { useRouter } from 'expo-router';
import { useRef, useState } from 'react';
import { type NativeScrollEvent, type NativeSyntheticEvent, Pressable, ScrollView, StyleSheet, useWindowDimensions, View } from 'react-native';
import Animated from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { AmbientBackground, Button, HeroArt, type HeroScene, Icon, IconCircle, Label, Surface, Text, enterUpAfter } from '../src/components';
import { selected } from '../src/lib/haptics';
import { type LinkChoice, store } from '../src/lib/store';
import { ink, palette, radius, space } from '../src/theme';

const SLIDES: { scene: HeroScene; eyebrow: string; title: string; body: string }[] = [
  {
    scene: 'airgap',
    eyebrow: 'Air-gapped hardware wallet',
    title: 'Keys that never touch the internet.',
    body: 'Your Ripar makes its keys on the device, keeps them there, and has no radio by default. It talks to this phone through QR codes you can see.',
  },
  {
    scene: 'shows',
    eyebrow: 'Clear signing',
    title: 'It signs only what it shows.',
    body: 'Every amount, payee and contract is on the Ripar screen, decoded by the device itself. This phone is an untrusted courier: it can ask, never decide.',
  },
  {
    scene: 'pulse',
    eyebrow: 'Proof of presence',
    title: 'A real heartbeat, then SIGN.',
    body: 'Nothing is signed without a live pulse on the thumb sensor and a press of SIGN. No stolen PIN, no remote click, no malware can fake your thumb.',
  },
];

const LINKS: { id: LinkChoice; title: string; body: string; icon: 'qr' | 'bluetooth' | 'device' }[] = [
  { id: 'qr', title: 'QR codes (recommended)', body: 'Fully air-gapped: the phone shows a QR, the Ripar shows one back.', icon: 'qr' },
  { id: 'ble', title: 'Bluetooth fallback', body: "Turns the device's radio on. Only if its camera cannot read.", icon: 'bluetooth' },
  { id: 'emulator', title: 'No device yet: emulator', body: 'The real firmware, emulated on this phone. Demo keys only.', icon: 'device' },
];

export default function Onboarding() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { width, height } = useWindowDimensions();
  const [page, setPage] = useState(0);
  const [pairing, setPairing] = useState(false);
  const [link, setLink] = useState<LinkChoice>('qr');
  const scroller = useRef<ScrollView>(null);
  const art = Math.min(width * 0.8, height * 0.4, 360);

  const onScroll = (e: NativeSyntheticEvent<NativeScrollEvent>) => {
    const p = Math.round(e.nativeEvent.contentOffset.x / width);
    if (p !== page) {
      setPage(p);
      selected();
    }
  };

  const finish = (pair: boolean) => {
    store.set({ onboarded: true });
    store.setSettings({ link });
    router.replace('/(tabs)');
    if (pair) setTimeout(() => router.push('/pair'), 50);
  };

  if (pairing) {
    return (
      <View style={[styles.root, { paddingTop: insets.top + space.xl, paddingBottom: insets.bottom + space.xl }]}>
        <AmbientBackground />
        <Animated.View entering={enterUpAfter(0)} style={{ gap: space.md, paddingHorizontal: space.xl }}>
          <IconCircle name="link" tone="signal" size={56} />
          <Text variant="display">Pair your Ripar</Text>
          <Text tone="soft">
            Two quick rounds: the Ripar shows its public keys, then confirms the contracts and its vault with your pulse. No seed
            words, no account, nothing to type.
          </Text>
        </Animated.View>
        <View style={{ gap: space.md, paddingHorizontal: space.xl, marginTop: space['2xl'] }}>
          <Label>How this phone reaches the device</Label>
          {LINKS.map((l) => (
            <Surface key={l.id} variant={link === l.id ? 'selected' : 'raised'} onPress={() => setLink(l.id)} padded={16} accessibilityLabel={`${l.title}. ${l.body}`}>
              <View style={{ flexDirection: 'row', gap: space.md, alignItems: 'center' }}>
                <IconCircle name={l.icon} tone={l.id === 'ble' ? 'warn' : l.id === 'qr' ? 'signal' : 'info'} />
                <View style={{ flex: 1 }}>
                  <Text variant="bodyMedium">{l.title}</Text>
                  <Text variant="bodySmall" tone="soft">
                    {l.body}
                  </Text>
                </View>
                <View style={[styles.radio, link === l.id && { borderColor: palette.primary }]}>
                  {link === l.id && <View style={styles.radioDot} />}
                </View>
              </View>
            </Surface>
          ))}
        </View>
        <View style={{ flex: 1 }} />
        <View style={{ gap: space.md, paddingHorizontal: space.xl }}>
          <Button label="Pair my Ripar" size="lg" full onPress={() => finish(true)} />
          <Button label="Look around first" variant="ghost" full onPress={() => finish(false)} />
        </View>
      </View>
    );
  }

  return (
    <View style={[styles.root, { paddingTop: insets.top, paddingBottom: insets.bottom + space.xl }]}>
      <AmbientBackground />
      <View style={styles.top}>
        <View style={styles.brand}>
          <View style={styles.recLight} />
          <Text variant="heading">Ripar</Text>
        </View>
        <Text variant="bodySmall" tone="soft" onPress={() => setPairing(true)} accessibilityRole="button" suppressHighlighting>
          Skip
        </Text>
      </View>
      <ScrollView
        ref={scroller}
        horizontal
        pagingEnabled
        showsHorizontalScrollIndicator={false}
        onMomentumScrollEnd={onScroll}
        style={{ flexGrow: 0 }}
      >
        {SLIDES.map((s) => (
          <View key={s.scene} style={{ width, paddingHorizontal: space.xl, alignItems: 'center' }}>
            <View style={{ height: art * 1.12, justifyContent: 'center' }}>
              <HeroArt scene={s.scene} size={art} />
            </View>
            <View style={{ alignSelf: 'stretch', gap: space.md, marginTop: space.lg }}>
              <Label tone="signal">{s.eyebrow}</Label>
              <Text variant="display" accessibilityRole="header">
                {s.title}
              </Text>
              <Text tone="soft">{s.body}</Text>
            </View>
          </View>
        ))}
      </ScrollView>
      <View style={{ flex: 1 }} />
      <View style={styles.bottom}>
        <View style={styles.dots} accessibilityLabel={`Page ${page + 1} of ${SLIDES.length}`}>
          {SLIDES.map((s, i) => (
            <View key={s.scene} style={[styles.dot, i === page && styles.dotOn]} />
          ))}
        </View>
        <View style={{ flexDirection: 'row', gap: space.md, alignItems: 'center' }}>
          <Button label="Get Started" variant="light" size="lg" style={{ flex: 1 }} onPress={() => setPairing(true)} />
          {page < SLIDES.length - 1 && (
            <Pressable
              style={({ pressed }) => [styles.next, pressed && { transform: [{ scale: 0.95 }] }]}
              onPress={() => scroller.current?.scrollTo({ x: (page + 1) * width, animated: true })}
              accessibilityRole="button"
              accessibilityLabel="Next slide"
            >
              <Icon name="chevron" size={22} color={palette.foreground} />
            </Pressable>
          )}
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: palette.background },
  top: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: space.xl, paddingVertical: space.md },
  brand: { flexDirection: 'row', alignItems: 'center', gap: space.sm },
  recLight: { width: 10, height: 10, borderRadius: 5, backgroundColor: palette.primary, boxShadow: '0px 0px 10px rgba(255,107,26,0.9)' },
  bottom: { paddingHorizontal: space.xl, gap: space.xl },
  dots: { flexDirection: 'row', gap: 6 },
  dot: { width: 8, height: 8, borderRadius: 4, backgroundColor: ink.hairlineStrong },
  dotOn: { width: 24, backgroundColor: palette.primary },
  next: {
    width: 58,
    height: 58,
    borderRadius: radius.pill,
    backgroundColor: palette.card,
    borderWidth: 1,
    borderColor: ink.hairlineStrong,
    alignItems: 'center',
    justifyContent: 'center',
  },
  radio: { width: 22, height: 22, borderRadius: 11, borderWidth: 2, borderColor: ink.hairlineStrong, alignItems: 'center', justifyContent: 'center' },
  radioDot: { width: 10, height: 10, borderRadius: 5, backgroundColor: palette.primary },
});
