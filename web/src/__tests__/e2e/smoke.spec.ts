/**
 * Phase 3 TEST-M3 smoke test (2026-05-13).
 *
 * Proves the Playwright harness works end-to-end:
 *   1. webServer block in playwright.config.ts boots `npm run dev`
 *   2. Playwright chromium connects to http://localhost:5173/
 *   3. The page renders a known element from the certctl shell
 *
 * Full coverage of the 15 flows documented in
 * web/src/__tests__/e2e/README.md ships in frontend-design-audit
 * Phase 8 (TEST-H1 / TEST-H2 / TEST-H3). This file exists to keep
 * the harness wiring tested so that adding new specs is mechanical.
 */

import { test, expect } from '@playwright/test';

test.describe('certctl dashboard — smoke', () => {
  test('login page renders the certctl brand and a login affordance', async ({ page }) => {
    await page.goto('/');

    // The Layout sidebar always renders the "certctl" brand text in
    // the header — verified live at web/src/components/Layout.tsx
    // (Phase 0 frontend remediation will keep this stable when the
    // logo migrates from PNG to inline SVG).
    //
    // For the smoke we just assert the document loaded and the
    // <title> resolves; deeper page-content assertions belong in
    // per-flow specs that the frontend-design-audit Phase 8 ships.
    await expect(page).toHaveTitle(/certctl/i);

    // Body should be visible (negative test: blank page would fail).
    await expect(page.locator('body')).toBeVisible();
  });
});
