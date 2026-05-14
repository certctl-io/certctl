// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Timestamp — Phase 6 closure for I18N-H3 (zero timezone handling
// today; server UTC audit logs can't be cross-referenced with frontend
// display without operator math).
//
// Default behavior: render the timestamp in UTC (so what the operator
// sees on-screen is byte-for-byte equivalent to what they'll grep out
// of `audit_events.created_at` or `journalctl -u certctl`), wrap it in
// the Phase 1 Tooltip primitive that surfaces the operator-local
// equivalent on hover / focus.
//
// Operator preference (`certctl:timestamp-display` in localStorage,
// see api/timestampPref.ts) flips the default. Available modes:
//   • utc       — render UTC, hover shows local. The safe default.
//   • local     — render browser-local, hover shows UTC.
//   • custom    — render in a configured IANA timezone, hover shows UTC.
//
// Why this lives as a primitive: pre-Phase-6, ~8 raw new Date(x)
// .toLocaleString() sites across 6 pages each made their own choice.
// Phase 6 routes them all through this one component + the CI guard
// at scripts/ci-guards/no-raw-toLocaleString.sh prevents new raw sites.

import { useEffect, useState } from 'react';
import Tooltip from './Tooltip';
import { formatDateTime, formatDateTimeUTC, formatDateTimeInZone } from '../api/utils';
import { getTimestampPref, type TimestampPref } from '../api/timestampPref';

interface TimestampProps {
  /** ISO-8601 timestamp from the API. Falsy renders an em-dash. */
  iso: string | undefined | null;
  /**
   * Override the operator preference for this one site — usually
   * unset. Set to 'utc' when the visible label MUST be UTC (e.g.
   * inside an audit-log column where the column header says "UTC").
   */
  forceMode?: 'utc' | 'local';
  /** Optional class for the visible span. */
  className?: string;
}

function render(iso: string | undefined | null, pref: TimestampPref, forceMode?: 'utc' | 'local'): {
  visible: string;
  hover: string;
} {
  if (!iso) return { visible: '—', hover: '—' };
  const mode = forceMode ?? pref.mode;
  if (mode === 'utc') {
    return { visible: formatDateTimeUTC(iso) + ' UTC', hover: formatDateTime(iso) + ' (local)' };
  }
  if (mode === 'local') {
    return { visible: formatDateTime(iso), hover: formatDateTimeUTC(iso) + ' UTC' };
  }
  // mode === 'custom'
  return {
    visible: formatDateTimeInZone(iso, pref.customTz) + ' (' + pref.customTz + ')',
    hover: formatDateTimeUTC(iso) + ' UTC',
  };
}

export default function Timestamp({ iso, forceMode, className }: TimestampProps) {
  // Initialize from localStorage at mount time so SSR-style empty
  // renders don't flash the wrong format on first paint.
  const [pref, setPref] = useState<TimestampPref>(() => getTimestampPref());

  // Live-update when the operator changes the preference on the
  // Settings page. timestampPref.ts dispatches a CustomEvent we
  // subscribe to here.
  useEffect(() => {
    function onChange(e: Event) {
      const detail = (e as CustomEvent<TimestampPref>).detail;
      if (detail) setPref(detail);
    }
    window.addEventListener('certctl:timestamp-pref-changed', onChange);
    return () => window.removeEventListener('certctl:timestamp-pref-changed', onChange);
  }, []);

  const { visible, hover } = render(iso, pref, forceMode);

  if (!iso) {
    return <span className={className}>{visible}</span>;
  }

  return (
    <Tooltip content={hover}>
      <span className={className}>{visible}</span>
    </Tooltip>
  );
}
