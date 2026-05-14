// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Operator timestamp-display preference — Phase 6 closure for I18N-H3.
//
// Default: 'utc' (frontend display ≡ server audit log byte-for-byte).
// Operators who prefer their local time explicitly opt in; operators
// running across timezones (e.g. an EU admin watching a US-East server)
// can pick a Custom IANA timezone.
//
// Storage: localStorage. No backend round-trip — the preference is
// purely cosmetic + per-browser. If the operator clears storage they
// reset to the safe default.

const STORAGE_KEY = 'certctl:timestamp-display';

export type TimestampMode = 'utc' | 'local' | 'custom';

export interface TimestampPref {
  mode: TimestampMode;
  /** Only meaningful when mode === 'custom'. IANA TZ name, e.g. 'America/New_York'. */
  customTz: string;
}

const DEFAULT: TimestampPref = { mode: 'utc', customTz: 'UTC' };

/** Read the current preference. Always returns a valid value (defaults on parse/missing). */
export function getTimestampPref(): TimestampPref {
  if (typeof localStorage === 'undefined') return DEFAULT;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT;
    const parsed = JSON.parse(raw) as Partial<TimestampPref>;
    if (parsed.mode !== 'utc' && parsed.mode !== 'local' && parsed.mode !== 'custom') {
      return DEFAULT;
    }
    return {
      mode: parsed.mode,
      customTz: typeof parsed.customTz === 'string' && parsed.customTz.length > 0
        ? parsed.customTz
        : DEFAULT.customTz,
    };
  } catch {
    return DEFAULT;
  }
}

/** Write the preference. Silently no-ops if storage unavailable (e.g. private mode). */
export function setTimestampPref(pref: TimestampPref): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(pref));
    // Fire a custom event so live <Timestamp> components can re-render
    // without a page reload. Vanilla CustomEvent — works in every
    // browser certctl supports.
    window.dispatchEvent(new CustomEvent('certctl:timestamp-pref-changed', { detail: pref }));
  } catch { /* noop */ }
}
