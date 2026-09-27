// Side-effect import, and it has to be first: the protocol library computes a constant with TextEncoder at load, and
// viem / noble need crypto.getRandomValues before anything draws a nonce or a key.
import '../src/polyfills';

// the five faces the app uses, by subpath: the packages' index would bundle every weight (about 1.5 MB of fonts)
import { Geist_400Regular } from '@expo-google-fonts/geist/400Regular';
import { Geist_500Medium } from '@expo-google-fonts/geist/500Medium';
import { Geist_600SemiBold } from '@expo-google-fonts/geist/600SemiBold';
import { Geist_700Bold } from '@expo-google-fonts/geist/700Bold';
import { GeistMono_400Regular } from '@expo-google-fonts/geist-mono/400Regular';
import { GeistMono_500Medium } from '@expo-google-fonts/geist-mono/500Medium';
import { useFonts } from 'expo-font';
import { DarkTheme, Stack, ThemeProvider, type Theme } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { DeviceLinkProvider } from '../src/device/DeviceLinkProvider';
import { EmulatorHost } from '../src/device/emulator/EmulatorHost';
import { store, useStore } from '../src/lib/store';
import { ink, palette } from '../src/theme';

/**
 * The navigator paints its own background, light by default: without this every screen gets a grey plate over the
 * ground. background / card are transparent because each Screen draws the ground itself.
 */
const riparTheme: Theme = {
  ...DarkTheme,
  dark: true,
  colors: {
    ...DarkTheme.colors,
    primary: palette.primary,
    background: palette.background,
    card: 'transparent',
    text: palette.foreground,
    border: ink.hairline,
    notification: palette.primary,
  },
  fonts: DarkTheme.fonts,
};

/** fonts may improve the app, never decide whether it renders (Polaris learned this on a Galaxy S24 Ultra) */
const FONT_GRACE_MS = 2500;

SplashScreen.preventAutoHideAsync().catch(() => {});

function Emulator() {
  const link = useStore((s) => s.settings.link);
  return link === 'emulator' ? <EmulatorHost /> : null;
}

export default function RootLayout() {
  const [loaded, error] = useFonts({
    Geist_400Regular,
    Geist_500Medium,
    Geist_600SemiBold,
    Geist_700Bold,
    GeistMono_400Regular,
    GeistMono_500Medium,
  });
  const [grace, setGrace] = useState(false);
  const [hydrated, setHydrated] = useState(store.loaded);

  useEffect(() => {
    if (!store.loaded) void store.load().then(() => setHydrated(true));
  }, []);
  useEffect(() => {
    if (loaded || error) return;
    const t = setTimeout(() => setGrace(true), FONT_GRACE_MS);
    return () => clearTimeout(t);
  }, [loaded, error]);
  const ready = hydrated && (loaded || !!error || grace);
  useEffect(() => {
    if (ready) SplashScreen.hideAsync().catch(() => {});
  }, [ready]);

  if (!ready) return null;

  return (
    <GestureHandlerRootView style={styles.root}>
      <SafeAreaProvider>
        <ThemeProvider value={riparTheme}>
          <DeviceLinkProvider>
            <View style={styles.root}>
              <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: palette.background }, animation: 'fade' }}>
                <Stack.Screen name="index" />
                <Stack.Screen name="onboarding" options={{ animation: 'fade' }} />
                <Stack.Screen name="(tabs)" />
                <Stack.Screen name="send" options={{ presentation: 'transparentModal', animation: 'fade', contentStyle: { backgroundColor: 'transparent' } }} />
                <Stack.Screen name="receive" options={{ presentation: 'transparentModal', animation: 'fade', contentStyle: { backgroundColor: 'transparent' } }} />
                <Stack.Screen name="pay" options={{ animation: 'slide_from_bottom' }} />
                <Stack.Screen name="done" options={{ animation: 'fade', gestureEnabled: false }} />
                <Stack.Screen name="pair" options={{ animation: 'slide_from_right' }} />
                <Stack.Screen name="personal" options={{ animation: 'slide_from_right' }} />
                <Stack.Screen name="link" options={{ animation: 'slide_from_right' }} />
                <Stack.Screen name="scan" options={{ animation: 'slide_from_bottom' }} />
                <Stack.Screen name="network" options={{ animation: 'slide_from_right' }} />
                <Stack.Screen name="mandate" options={{ animation: 'slide_from_right' }} />
                <Stack.Screen name="escalation/[id]" options={{ animation: 'slide_from_right' }} />
                <Stack.Screen name="activity/[id]" options={{ animation: 'slide_from_right' }} />
              </Stack>
              <Emulator />
            </View>
          </DeviceLinkProvider>
        </ThemeProvider>
        <StatusBar style="light" />
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: palette.background },
});
