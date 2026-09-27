// Unit tests of the pure logic (device link helpers, BLE framing, the personal-mandate payment flow), run in Node with
// vitest (no Jest, no React Native). The firmware emulator (firmware/emu/dist, the device's own C++ as WASM) plays the
// device in the end-to-end tests. @ripar/protocol is used from source, as the app bundles it.
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { '@ripar/protocol': resolve(__dirname, '../packages/protocol/src/index.ts') },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 120_000,
    hookTimeout: 120_000,
    pool: 'forks',
  },
});
