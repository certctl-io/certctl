// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// DesktopOnlyBanner — Phase 9 closure for FE-M2 (operator decision
// 2026-05-14: certctl is desktop-only). Renders a top-of-viewport
// notice when the viewport is narrower than the `lg` Tailwind
// breakpoint (1024px) telling operators they're outside the
// supported viewport.
//
// Visibility is gated by CSS media query (.desktop-only-banner in
// src/index.css). Component dismissal persists to localStorage so an
// operator who needs occasional narrow-viewport access doesn't see
// the banner forever.
//
// Pairs with the operator's FE-M2 decision: rather than rip out the
// 29 partial sm:/md:/lg: responsive classes (zero benefit at
// desktop widths) OR ship full mobile (1+ sprint of QA + ongoing
// maintenance), the project ships an HONEST signal — "we don't
// promise mobile" — that doesn't claim support that isn't there.

import { useEffect, useState } from 'react';

const STORAGE_KEY = 'certctl:desktop-only-banner-dismissed';

export default function DesktopOnlyBanner() {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    if (typeof localStorage === 'undefined') return false;
    try {
      return localStorage.getItem(STORAGE_KEY) === 'true';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    if (dismissed && typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(STORAGE_KEY, 'true');
      } catch { /* noop */ }
    }
  }, [dismissed]);

  if (dismissed) return null;

  return (
    <div
      className="desktop-only-banner fixed top-0 left-0 right-0 z-50 items-center justify-between gap-3 bg-amber-50 border-b border-amber-200 px-4 py-2 text-xs text-amber-900"
      role="status"
      aria-live="polite"
      data-testid="desktop-only-banner"
    >
      <span>
        <strong>Desktop-only:</strong> certctl is designed for viewports ≥ 1024px. Some UI may render cramped at this width.
      </span>
      <button
        type="button"
        onClick={() => setDismissed(true)}
        className="px-2 py-0.5 rounded text-amber-900 hover:bg-amber-100 transition-colors shrink-0"
        aria-label="Dismiss desktop-only notice"
        data-testid="desktop-only-banner-dismiss"
      >
        Dismiss
      </button>
    </div>
  );
}
