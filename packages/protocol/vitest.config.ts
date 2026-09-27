import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // the emulator round trips and the Python differential tests spawn processes / load WASM
    testTimeout: 120_000,
    hookTimeout: 120_000,
    pool: 'forks',
  },
});
