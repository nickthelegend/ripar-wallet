// Hosts the firmware emulator in a hidden WebView while the Emulator link is selected, and registers its EmulatorLink
// with the DeviceLinkProvider. The emulated device's NVS (seed + pinned context) is persisted in AsyncStorage under
// its own key, always as DEMO KEYS: a real Ripar never exports its seed; this one is a demo by design.
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useEffect, useMemo, useRef, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { WebView, type WebViewMessageEvent } from 'react-native-webview';
import { useStore } from '../../lib/store';
import { useDeviceLink } from '../DeviceLinkProvider';
import { type EmuFromPage, type EmuToPage, EmulatorLink } from '../emulator-link';
import { ValueSubject } from '../link';
import { EMU_HTML } from './emu-html.generated';

const NVS_KEY = 'ripar.emulator.nvs.v1';

export interface EmuNvsRecord {
  emulator: true;
  warning: 'EMULATOR - DEMO KEYS - never put real funds behind this device';
  mode: 'demo-seed' | 'random';
  seed: string | null;
  context: string | null;
  savedAt: number;
}

export type EmuHostState = { phase: 'loading' } | { phase: 'ready'; mode: 'demo-seed' | 'random' } | { phase: 'error'; message: string };

/** app-wide: the emulator host's state and a way to reset the emulated device */
export const emulatorHostState = new ValueSubject<EmuHostState>({ phase: 'loading' });
let resetHook: ((fresh: 'demo-seed' | 'random') => void) | null = null;

export async function resetEmulator(fresh: 'demo-seed' | 'random'): Promise<void> {
  await AsyncStorage.removeItem(NVS_KEY);
  resetHook?.(fresh);
}

export function EmulatorHost() {
  const { setEmulator } = useDeviceLink();
  const settings = useStore((s) => s.settings);
  const web = useRef<WebView>(null);
  const [key, setKey] = useState(0);

  const link = useMemo(() => {
    const post = (m: EmuToPage) => web.current?.injectJavaScript(`window.riparReceive && window.riparReceive(${JSON.stringify(JSON.stringify(m))});true;`);
    return new EmulatorLink(post, settings.frameMs, settings.fragLen);
    // the link lives as long as the host; settings changes are applied below
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useEffect(() => link.configure({ frameMs: settings.frameMs, fragLen: settings.fragLen }), [link, settings.frameMs, settings.fragLen]);

  const pendingFresh = useRef<'demo-seed' | 'random' | null>(null);
  useEffect(() => {
    resetHook = (fresh) => {
      pendingFresh.current = fresh;
      emulatorHostState.set({ phase: 'loading' });
      setKey((k) => k + 1);
    };
    return () => {
      resetHook = null;
    };
  }, []);

  useEffect(() => {
    setEmulator(link);
    return () => {
      link.close();
      setEmulator(null);
    };
  }, [link, setEmulator]);

  const onMessage = async (ev: WebViewMessageEvent) => {
    let m: EmuFromPage;
    try {
      m = JSON.parse(ev.nativeEvent.data) as EmuFromPage;
    } catch {
      return;
    }
    switch (m.t) {
      case 'ready': {
        const fresh = pendingFresh.current;
        pendingFresh.current = null;
        let nvs: EmuNvsRecord | null = null;
        try {
          const raw = await AsyncStorage.getItem(NVS_KEY);
          nvs = raw ? (JSON.parse(raw) as EmuNvsRecord) : null;
        } catch {
          nvs = null;
        }
        const saved = nvs && nvs.emulator === true && nvs.seed ? { seed: nvs.seed, context: nvs.context, mode: nvs.mode } : null;
        link.post({ t: 'boot', nvs: fresh ? null : saved, ...(fresh ? { fresh } : {}) });
        break;
      }
      case 'booted':
        emulatorHostState.set({ phase: 'ready', mode: m.mode });
        break;
      case 'nvs': {
        const rec: EmuNvsRecord = {
          emulator: true,
          warning: 'EMULATOR - DEMO KEYS - never put real funds behind this device',
          mode: m.mode,
          seed: m.nvs.seed,
          context: m.nvs.context,
          savedAt: Date.now(),
        };
        void AsyncStorage.setItem(NVS_KEY, JSON.stringify(rec)).catch(() => {});
        break;
      }
      case 'error':
        emulatorHostState.set({ phase: 'error', message: m.message });
        break;
      default:
        link.receive(m);
    }
  };

  return (
    <View style={styles.hidden} pointerEvents="none" accessibilityElementsHidden importantForAccessibility="no-hide-descendants">
      <WebView
        key={key}
        ref={web}
        source={{ html: EMU_HTML, baseUrl: 'https://ripar-emulator.local/' }}
        originWhitelist={['*']}
        javaScriptEnabled
        onMessage={onMessage}
        // the page never navigates anywhere: block any attempt
        onShouldStartLoadWithRequest={(r) => r.url.startsWith('https://ripar-emulator.local') || r.url === 'about:blank'}
        setSupportMultipleWindows={false}
        allowFileAccess={false}
        style={styles.web}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  hidden: { position: 'absolute', width: 2, height: 2, left: 0, top: 0, opacity: 0.01 },
  web: { width: 2, height: 2, backgroundColor: 'transparent' },
});
