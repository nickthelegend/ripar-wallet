// Unit tests of the companion's pure logic (request assembly, response handling, vault derivation vs
// smart-accounts-kit, the DeviceTransport with the WASM emulator in Node). No browser, no network.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: { conditions: ['ripar-source', 'module', 'node', 'default'] },
  ssr: { resolve: { conditions: ['ripar-source', 'module', 'node', 'default'] } },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 120_000,
    hookTimeout: 120_000,
    pool: 'forks',
  },
});
