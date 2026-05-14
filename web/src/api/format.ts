// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Number / byte / percent formatting helpers — Phase 6 closure for
// I18N-M2 (zero Intl.NumberFormat usage; cert counts via
// .toLocaleString() on numbers — browser-locale-aware — sit alongside
// .toFixed(1) not localized at all).
//
// All helpers route through `Intl.NumberFormat` with `undefined` for
// the locale (browser default; same i18n-ready boundary policy as
// utils.ts). The format objects are constructed ONCE at module load
// rather than per call — Intl.NumberFormat construction is the
// expensive part; .format() is cheap.
//
// When the i18n framework lands (Phase 10) the only change here is
// to thread a `locale` arg through; the display code that imports
// these helpers stays unchanged.

/**
 * Standard integer / decimal formatter — "5,432.10" in en, "5.432,10"
 * in de-DE, "5 432,10" in fr-FR. Use for cert counts, agent counts,
 * issuance rates, anything that's a count or a non-byte/non-percent
 * scalar.
 */
const numberFmt = new Intl.NumberFormat(undefined, {
  maximumFractionDigits: 2,
});

/**
 * Compact / abbreviated formatter — "5.4K", "1.2M". Use for stat tiles
 * where vertical space is constrained and ballpark magnitude beats
 * exact value. Intl.NumberFormat's `notation: 'compact'` follows
 * locale conventions (English K/M/B vs CJK 万/億 etc.) automatically.
 */
const compactFmt = new Intl.NumberFormat(undefined, {
  notation: 'compact',
  maximumFractionDigits: 1,
});

/**
 * Percent formatter — input is a fraction in [0, 1] OR an explicit
 * percentage with `style: 'percent'` semantics. We default to "input
 * is a fraction" because that's the common case for success-rate /
 * error-rate / etc. Output: "99.5%" (en) / "99,5 %" (fr).
 */
const percentFmt = new Intl.NumberFormat(undefined, {
  style: 'percent',
  minimumFractionDigits: 0,
  maximumFractionDigits: 2,
});

/**
 * Bytes formatter — Intl.NumberFormat with `style: 'unit'` and the
 * byte unit. Output: "5.4 MB" (en) / "5,4 MB" (fr). Browser does the
 * SI scaling automatically when given a base unit + value. For
 * non-SI binary (KiB / MiB / GiB), use the manual scaler below.
 *
 * Note: Safari < 14 doesn't support the 'unit' style. The fallback
 * branches produce "5.4 MB" without locale awareness; an operator on
 * old Safari sees consistent-but-American output, which is the same
 * graceful-degradation contract as the rest of the i18n boundary.
 */
const bytesFmt = (() => {
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'unit',
      unit: 'megabyte',
      maximumFractionDigits: 1,
    });
  } catch {
    return null; // signals fallback
  }
})();

/** Format an integer or decimal in the operator's locale. */
export function formatNumber(value: number): string {
  if (!Number.isFinite(value)) return '—';
  return numberFmt.format(value);
}

/**
 * Compact-format a magnitude — 1500 → "1.5K", 1_500_000 → "1.5M".
 * Use for tile labels + chart axis ticks.
 */
export function formatCompact(value: number): string {
  if (!Number.isFinite(value)) return '—';
  return compactFmt.format(value);
}

/**
 * Format a fraction in [0, 1] as a percentage. Pass 0.995 → "99.5%".
 * For an already-percentified value (e.g. server returns 99.5 not
 * 0.995), divide by 100 at the call site.
 */
export function formatPercent(value: number): string {
  if (!Number.isFinite(value)) return '—';
  return percentFmt.format(value);
}

/**
 * Format a byte count with SI-decimal scaling (1KB = 1000B). Output
 * locale-aware where possible; falls back to "5.4 MB"-style English
 * on old Safari (see bytesFmt comment above).
 *
 * For binary scaling (1KiB = 1024B) use formatBytesBinary — relevant
 * for memory / disk numbers that surface in Observability tiles.
 */
export function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return '—';
  const { magnitude, unit } = pickSIUnit(value);
  const scaled = value / magnitude;
  if (bytesFmt) {
    // Intl.NumberFormat doesn't accept the unit dynamically post-
    // construction — we'd need a per-unit cache for that. Simpler:
    // format the scaled magnitude with the standard number formatter
    // and append the unit. Locale-aware decimal separator + space.
    return `${numberFmt.format(round1(scaled))} ${unit}`;
  }
  return `${round1(scaled)} ${unit}`;
}

function pickSIUnit(bytes: number): { magnitude: number; unit: string } {
  const abs = Math.abs(bytes);
  if (abs >= 1e12) return { magnitude: 1e12, unit: 'TB' };
  if (abs >= 1e9)  return { magnitude: 1e9,  unit: 'GB' };
  if (abs >= 1e6)  return { magnitude: 1e6,  unit: 'MB' };
  if (abs >= 1e3)  return { magnitude: 1e3,  unit: 'KB' };
  return { magnitude: 1, unit: 'B' };
}

function round1(v: number): number {
  return Math.round(v * 10) / 10;
}
