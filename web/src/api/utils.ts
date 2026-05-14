// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Date / time / display helpers — the i18n-ready boundary the rest of
// the frontend consumes. Phase 6 closure for I18N-H1 + I18N-H2 + I18N-H3.
//
// Locale handling:
//   • Pre-Phase-6 these helpers hardcoded `'en-US'`, so a German /
//     French / Japanese operator saw English month names regardless
//     of their browser locale.
//   • Post-Phase-6 we pass `undefined` for the locale arg, which makes
//     the runtime use the browser default (navigator.language). The
//     options object stays — `month: 'short'` etc. — so the SHAPE of
//     the output is stable across locales while the language follows
//     the user.
//   • When a hard i18n framework lands (Phase 10), this file is the
//     single migration target. Display code never reaches for
//     Date.prototype.toLocaleString directly any more — Phase 6's CI
//     guard at scripts/ci-guards/no-raw-toLocaleString.sh prevents
//     regression.
//
// Timezone handling (I18N-H3):
//   • formatDate / formatDateTime use the runtime's local timezone —
//     keeps the existing operator-friendly default.
//   • formatDateUTC / formatDateTimeUTC are explicit-UTC siblings.
//     The audit-log table on the server emits UTC, so these helpers
//     give the frontend a way to render the same byte-for-byte
//     timestamp the operator sees in `journalctl -u certctl` or in a
//     `psql` query.
//   • <Timestamp iso={...} /> (web/src/components/Timestamp.tsx) wraps
//     a UTC render in a Phase 1 Tooltip showing the operator-local
//     equivalent. Default display is UTC (so screen ≡ logs); operators
//     opt into local via the AuthSettingsPage "Timestamp display"
//     preference.

const DATE_OPTS: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
};

const DATETIME_OPTS: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
};

/** Format an ISO timestamp as a date in the browser's local timezone. */
export function formatDate(iso: string | undefined | null): string {
  if (!iso) return '—';
  // `undefined` for the locale arg = use the browser default
  // (navigator.language). DO NOT hardcode 'en-US' here — that was
  // the I18N-H1 bug Phase 6 closes.
  return new Date(iso).toLocaleDateString(undefined, DATE_OPTS);
}

/** Format an ISO timestamp as a date+time in the browser's local timezone. */
export function formatDateTime(iso: string | undefined | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, DATETIME_OPTS);
}

/** Format an ISO timestamp as a date forced to UTC. */
export function formatDateUTC(iso: string | undefined | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { ...DATE_OPTS, timeZone: 'UTC' });
}

/**
 * Format an ISO timestamp as a date+time forced to UTC.
 * Matches the format certctl-server emits to journalctl + audit_events.
 * Operator can cross-reference frontend display ≡ server log byte-for-byte.
 */
export function formatDateTimeUTC(iso: string | undefined | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { ...DATETIME_OPTS, timeZone: 'UTC' });
}

/**
 * Format an ISO timestamp in an operator-specified timezone (IANA TZ name).
 * Used by <Timestamp /> when the operator picks "Custom TZ" in settings.
 * Falls back to UTC if the timezone name is invalid (Intl throws RangeError).
 */
export function formatDateTimeInZone(iso: string | undefined | null, timeZone: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, { ...DATETIME_OPTS, timeZone });
  } catch {
    return new Date(iso).toLocaleString(undefined, { ...DATETIME_OPTS, timeZone: 'UTC' });
  }
}

// D-2 (master): widened to accept undefined/null since several Go-side
// timestamp fields are emitted as `omitempty` (e.g. Agent.last_heartbeat_at
// for never-heartbeated agents). Pre-D-2 the TS interfaces declared
// these as required strings, masking the case; post-D-2 the optionality
// is propagated end-to-end and the helper handles it explicitly.
export function timeAgo(iso: string | undefined | null): string {
  if (!iso) return '—';
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(iso);
}

export function daysUntil(iso: string): number {
  if (!iso) return 0;
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}

export function expiryColor(days: number): string {
  if (days <= 0) return 'text-red-400';
  if (days <= 7) return 'text-red-400';
  if (days <= 14) return 'text-amber-400';
  if (days <= 30) return 'text-amber-300';
  return 'text-emerald-400';
}
