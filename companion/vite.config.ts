// Vite config of the Ripar companion. @ripar/protocol is consumed from source (its "ripar-source" export condition),
// so the companion never depends on a stale protocol build. The WASM emulator is served from firmware/emu/dist
// (inside the workspace root, so Vite's fs.allow covers it). Dev server binds 127.0.0.1 only.
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const EMU_DIST = fileURLToPath(new URL('../firmware/emu/dist/', import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    conditions: ['ripar-source', 'module', 'browser', 'development|production'],
    alias: [
      // the WASM device emulator (read-only; built by firmware/emu/build.sh)
      { find: /^ripar-emu$/, replacement: `${EMU_DIST}ripar-emu.mjs` },
      { find: /^ripar-emu-wasm(\?.*)?$/, replacement: `${EMU_DIST}ripar-emu-core.wasm$1` },
    ],
  },
  server: { host: '127.0.0.1', port: 5173, strictPort: false },
  preview: { host: '127.0.0.1', port: 4173 },
  build: {
    target: 'es2022',
    sourcemap: true,
    chunkSizeWarningLimit: 1600,
  },
  optimizeDeps: {
    exclude: ['@ripar/protocol'],
  },
  worker: { format: 'es' },
});
