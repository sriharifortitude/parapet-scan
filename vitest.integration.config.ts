import { defineConfig } from 'vitest/config';

/**
 * Integration tests drive the real engine over real HTTP against the lab in
 * lab/. They are a separate project so `npm test` stays runnable without Docker.
 */
export default defineConfig({
  test: {
    name: 'integration',
    include: ['tests/integration/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 120_000,
    fileParallelism: false,
  },
});
