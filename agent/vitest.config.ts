import { defineConfig } from 'vitest/config';

// '@ripar/protocol' is resolved to its TypeScript sources (package.json "ripar-source" condition), so the tests never
// depend on a stale packages/protocol/dist build.
export default defineConfig({
  resolve: { conditions: ['ripar-source', 'import', 'module', 'node', 'default'] },
  ssr: { resolve: { conditions: ['ripar-source', 'import', 'module', 'node', 'default'] } },
  test: {
    include: ['test/**/*.test.ts'],
    setupFiles: ['test/helpers/setup.ts'],
    environment: 'node',
    // the integration test starts anvil, runs forge and drives the WASM emulator
    testTimeout: 180_000,
    hookTimeout: 600_000,
    pool: 'forks',
  },
});
