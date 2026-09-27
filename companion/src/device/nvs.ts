// Where the EMULATOR keeps its NVS (seed + pinned context) between page loads: this browser's localStorage, under its
// own key, always marked as a demo device. A real Ripar device never exports its seed; this one is a demo by design.
import { loadJson, removeKey, saveJson } from '../lib/storage';
import type { EmulatorNvsRecord, NvsStore } from './emulator';

const NVS_KEY = 'emulator.nvs.v1';

export const nvsStore: NvsStore = {
  load: () => loadJson<EmulatorNvsRecord | null>(NVS_KEY, null),
  save: (r) => void saveJson(NVS_KEY, r),
  clear: () => removeKey(NVS_KEY),
};
