// localStorage access that never throws (private windows, blocked storage, quota) and never holds secrets:
// the companion stores settings, public device identity and records only. The one exception is the EMULATOR's
// demo NVS (a demo device's seed), kept under its own key and always labelled as such.
const PREFIX = 'ripar.companion.';

export function loadJson<T>(key: string, fallback: T): T {
  try {
    const raw = globalThis.localStorage?.getItem(PREFIX + key);
    if (raw == null) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function saveJson(key: string, value: unknown): boolean {
  try {
    globalThis.localStorage?.setItem(PREFIX + key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function removeKey(key: string): void {
  try {
    globalThis.localStorage?.removeItem(PREFIX + key);
  } catch {
    /* storage unavailable */
  }
}
