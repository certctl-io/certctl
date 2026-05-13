/**
 * Phase 3 TEST-M3 closure (2026-05-13): Playwright harness stub for
 * the browser-driven E2E surface documented in
 * web/src/__tests__/e2e/README.md.
 *
 * This config is the minimum-viable scaffold: one chromium project,
 * webServer pointing at `npm run dev` for fast feedback, no firefox /
 * webkit projects yet. The full 15-flow suite (operator boot, OIDC
 * login, cert issuance, revocation, rotation, JWKS rotate, etc.)
 * lands in frontend-design-audit Phase 8 (TEST-H1 in that audit's
 * tracker). The smoke test that ships alongside this config proves
 * the harness wiring works.
 */

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './src/__tests__/e2e',
  // Match Playwright's *.spec.ts convention; README.md and any
  // *.test.ts vitest files are intentionally excluded.
  testMatch: /.*\.spec\.ts$/,
  // Single worker keeps the smoke test deterministic on shared CI
  // runners. Raise to fullyParallel: true once the harness covers
  // independent flows.
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    // Phase 3 SEC-M3 carve-out: the dev server uses a self-signed cert
    // via the Vite HTTPS proxy. Tell Playwright to accept it for the
    // smoke test only; production E2E against a properly-trusted cert
    // never needs this flag.
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://localhost:5173',
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
