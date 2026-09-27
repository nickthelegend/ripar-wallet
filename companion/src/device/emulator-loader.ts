// Browser loader of the WASM emulator (Vite aliases 'ripar-emu' / 'ripar-emu-wasm' to firmware/emu/dist). Loaded
// lazily: the ~480 KB firmware image is only fetched when the user picks the EMULATOR.
import wasmUrl from 'ripar-emu-wasm?url';
import type { EmuModule } from './emulator';

export async function loadEmulatorModule(): Promise<{ mod: EmuModule; moduleArg: Record<string, unknown> }> {
  const mod = (await import('ripar-emu')) as EmuModule;
  return { mod, moduleArg: { locateFile: (p: string) => (p.endsWith('.wasm') ? wasmUrl : p) } };
}
