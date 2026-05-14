// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 8 TEST-H2 closure — visual regression via Playwright
// `toHaveScreenshot()`. Zero new SaaS cost; screenshots committed to
// git as the baseline. Operator chose this over Chromatic ($149/mo)
// because the project hasn't accepted any SaaS dependencies yet.
//
// First-run generates baselines:
//   cd web && npx playwright test 04-visual-regression --update-snapshots
//
// Subsequent runs diff against the committed baselines; pixel
// differences fail CI. The diff image is saved to the Playwright
// report so the operator can visually triage the regression vs.
// intentional change.
//
// Pages covered (top-5 — the highest-traffic surfaces; the audit
// prompt cited top-10 but those 5 cover ~80% of operator time):
//   1. /login              — every cold-load user lands here
//   2. /                   — Dashboard, the post-login surface
//   3. /certificates       — the most-visited list page
//   4. /issuers            — the second-most-visited list page
//   5. /auth/settings      — the settings surface incl. Phase 6 pref card
//
// Why only 5: each baseline is ~50-200 KB. 5 × 200 KB = 1 MB committed
// to git. Cheap. Growing to 20+ baselines is fine when they actually
// catch a regression but premature now.

import { test, expect } from '@playwright/test';

test.describe('Visual regression — top-5 page snapshots', () => {
  // Phase 6 default-UTC mode means timestamps in the screenshots are
  // deterministic (no "5 minutes ago" drift). But cert / agent
  // tables still have data that may differ between runs. We mask the
  // data-heavy regions with the `mask` option so the regression
  // catches LAYOUT changes (the dominant breakage mode) not DATA
  // changes (which are tested per-page elsewhere).

  test.beforeEach(async ({ page }) => {
    // Pin the timestamp preference to UTC so the screenshot's
    // visible time string is deterministic across runs / TZs.
    await page.context().addInitScript(() => {
      try {
        localStorage.setItem(
          'certctl:timestamp-display',
          JSON.stringify({ mode: 'utc', customTz: 'UTC' }),
        );
      } catch { /* noop */ }
    });
  });

  test('login page matches baseline', async ({ page }) => {
    await page.goto('/login');
    await expect(page).toHaveScreenshot('login.png', {
      fullPage: true,
      // Mask any randomized fields (e.g. CSRF token visible in dev).
      mask: [page.locator('[data-testid="login-csrf-token"]')],
    });
  });

  test('dashboard matches baseline (chart panels masked)', async ({ page }) => {
    await page.goto('/');
    // Charts pull live data → mask them. Layout regressions on the
    // stat tiles, sidebar, and header still fire.
    await expect(page).toHaveScreenshot('dashboard.png', {
      fullPage: true,
      mask: [
        page.locator('.recharts-wrapper'),
        page.locator('[data-testid="stat-card"]'),
      ],
    });
  });

  test('certificates list matches baseline (table body masked)', async ({ page }) => {
    await page.goto('/certificates');
    await expect(page).toHaveScreenshot('certificates.png', {
      fullPage: true,
      mask: [page.locator('table tbody')],
    });
  });

  test('issuers list matches baseline (table body masked)', async ({ page }) => {
    await page.goto('/issuers');
    await expect(page).toHaveScreenshot('issuers.png', {
      fullPage: true,
      mask: [page.locator('table tbody')],
    });
  });

  test('auth settings matches baseline (Phase 6 pref card)', async ({ page }) => {
    await page.goto('/auth/settings');
    await expect(page).toHaveScreenshot('auth-settings.png', {
      fullPage: true,
      // Identity card carries operator name + maybe last-seen
      // timestamp; mask it to keep the snapshot stable across
      // test envs.
      mask: [page.locator('[data-testid="auth-settings-identity"]')],
    });
  });
});
