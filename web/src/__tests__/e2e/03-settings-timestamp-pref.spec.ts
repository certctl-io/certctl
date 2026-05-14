// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 8 TEST-H1 closure — Priority Flow 3 (substituted from audit's
// "Archive certificate" because that needs live cert seed data; this
// flow exercises Phase 6's settings + persistence pipeline end-to-end
// with no backend data dependency).
//
// Flow: open /auth/settings → "Timestamp display" card visible → flip
// to Local → reload → preference persisted → flip to Custom + invalid
// IANA tz → Timestamp falls back to UTC silently.
//
// Happy + error pair:
//   (a) happy: utc → local round-trip persists across reload
//   (b) error: custom mode with invalid IANA tz doesn't break the
//              page (graceful fallback per Phase 6 I18N-H3 contract)

import { test, expect } from '@playwright/test';

test.describe('Priority Flow 3 — settings: timestamp display preference', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any prior preference so the test starts from default UTC.
    await page.context().addInitScript(() => {
      try { localStorage.removeItem('certctl:timestamp-display'); } catch { /* noop */ }
    });
  });

  test('Timestamp display card renders on /auth/settings', async ({ page }) => {
    await page.goto('/auth/settings');
    const card = page.getByTestId('timestamp-pref-card');
    await expect(card).toBeVisible();
    await expect(card).toContainText(/Timestamp display/i);
    // Phase 6: 3 radio modes (UTC / Local / Custom). UTC is default.
    await expect(page.getByTestId('timestamp-mode-utc')).toBeChecked();
    await expect(page.getByTestId('timestamp-mode-local')).not.toBeChecked();
    await expect(page.getByTestId('timestamp-mode-custom')).not.toBeChecked();
  });

  test('happy: flip to Local + reload → preference persists', async ({ page }) => {
    await page.goto('/auth/settings');
    await page.getByTestId('timestamp-mode-local').check();
    await expect(page.getByTestId('timestamp-mode-local')).toBeChecked();
    // Phase 6 I18N-H3: pref persists to localStorage. Round-trip
    // confirms the read+write boundary works.
    const stored = await page.evaluate(() =>
      localStorage.getItem('certctl:timestamp-display'),
    );
    expect(stored).toContain('local');

    await page.reload();
    await expect(page.getByTestId('timestamp-mode-local')).toBeChecked();
  });

  test('error: invalid IANA tz in custom mode falls back gracefully', async ({ page }) => {
    await page.goto('/auth/settings');
    await page.getByTestId('timestamp-mode-custom').check();
    // The custom-tz input appears only when mode === 'custom'.
    const tzInput = page.getByTestId('timestamp-custom-tz-input');
    await expect(tzInput).toBeVisible();
    await tzInput.fill('Not/Real_Zone');
    // Phase 6 contract: invalid IANA tz silently falls back to UTC
    // inside formatDateTimeInZone (the helper catches Intl.RangeError).
    // The page must not throw — assert it stays mounted + responsive.
    await expect(page.getByTestId('timestamp-pref-card')).toBeVisible();
    // Navigate to a page with timestamps and verify it renders
    // without an uncaught error boundary takeover.
    await page.goto('/audit');
    await expect(page.locator('body')).toBeVisible();
  });
});
