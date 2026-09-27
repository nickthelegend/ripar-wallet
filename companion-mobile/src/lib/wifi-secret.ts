// The Wi-Fi link's 8-digit code (TEMPORARY, testing): a session secret the device shows each time its Wi-Fi turns on.
// Kept in memory and in expo-secure-store (Android Keystore-backed, this device only), never in AsyncStorage, so a
// reconnect after an app restart does not need it typed again while the device's Wi-Fi session lasts. Forgotten when
// the Wi-Fi link is disconnected or refused.
import * as SecureStore from 'expo-secure-store';

const KEY = 'ripar.wifi.code.v1';
const OPTS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

let mem: string | null = null;

export async function saveWifiCode(code: string): Promise<void> {
  mem = code;
  try {
    await SecureStore.setItemAsync(KEY, code, OPTS);
  } catch {
    /* no secure store (web preview): memory only */
  }
}

export async function loadWifiCode(): Promise<string | null> {
  if (mem) return mem;
  try {
    const v = await SecureStore.getItemAsync(KEY, OPTS);
    if (v && /^\d{8}$/.test(v)) mem = v;
  } catch {
    /* no secure store */
  }
  return mem;
}

export async function clearWifiCode(): Promise<void> {
  mem = null;
  try {
    await SecureStore.deleteItemAsync(KEY, OPTS);
  } catch {
    /* no secure store */
  }
}
