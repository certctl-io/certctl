// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Skeleton — Phase 4 closure for UX-M1 (206 isLoading sites render as
// "Loading…" text in PageHeader subtitle → layout shift on every fetch).
//
// Four variants, each shaped to match the page region it stands in for
// so the eventual content lands without CLS:
//
//   • page   — full-page Suspense fallback used by main.tsx route
//              lazy-load boundaries. Includes a PageHeader-shaped
//              skeleton + a body grid of card / table skeletons.
//   • table  — list-page body. 6 rows × 5 cells, header row dimmed.
//              Drop into DataTable's isLoading branch (or page-local
//              tables that don't go through DataTable yet).
//   • card   — single content card. One title-row + 3 prose rows.
//              Composable inside dashboards / detail pages.
//   • stat   — KPI tile. One label-row + one large number-row.
//              Sized to match DashboardPage's stat panels.
//
// Every variant uses Tailwind's `animate-pulse` on layout-shaped divs
// so the eye reads "content loading here" instead of a flash of empty
// container followed by re-flow when the real content paints.
//
// Accessibility: each variant carries role="status" + aria-busy="true"
// + aria-label so screen-reader users hear "Loading <region>" instead
// of an empty announcement.

interface SkeletonProps {
  variant: 'page' | 'table' | 'card' | 'stat';
  /** Override default aria-label. Default: "Loading content". */
  ariaLabel?: string;
  /** Number of rows for the `table` variant. Default 6. */
  rows?: number;
  /** Number of columns for the `table` variant. Default 5. */
  columns?: number;
}

export default function Skeleton({
  variant,
  ariaLabel = 'Loading content',
  rows = 6,
  columns = 5,
}: SkeletonProps) {
  if (variant === 'page') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={ariaLabel}
        className="animate-pulse"
      >
        {/* PageHeader-shaped band */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-surface-border bg-surface">
          <div>
            <div className="h-3 w-32 bg-surface-border rounded mb-2" />
            <div className="h-5 w-48 bg-surface-border rounded" />
          </div>
          <div className="h-9 w-28 bg-surface-border rounded" />
        </div>
        {/* Body grid: 4 stat tiles + 1 card */}
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="bg-surface border border-surface-border rounded-lg p-4"
              >
                <div className="h-3 w-20 bg-surface-border rounded mb-3" />
                <div className="h-7 w-16 bg-surface-border rounded" />
              </div>
            ))}
          </div>
          <Card />
        </div>
      </div>
    );
  }

  if (variant === 'table') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={ariaLabel}
        className="animate-pulse"
      >
        <table className="w-full">
          <thead>
            <tr className="border-b border-surface-border">
              {Array.from({ length: columns }).map((_, i) => (
                <th key={i} className="text-left px-4 py-3">
                  <div className="h-3 w-20 bg-surface-border rounded" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }).map((_, r) => (
              <tr key={r} className="border-b border-surface-border">
                {Array.from({ length: columns }).map((_, c) => (
                  <td key={c} className="px-4 py-3">
                    <div
                      className={
                        'h-3 bg-surface-border rounded ' +
                        (c === 0 ? 'w-40' : c === columns - 1 ? 'w-16' : 'w-24')
                      }
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (variant === 'card') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={ariaLabel}
        className="animate-pulse"
      >
        <Card />
      </div>
    );
  }

  // variant === 'stat'
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label={ariaLabel}
      className="animate-pulse bg-surface border border-surface-border rounded-lg p-4"
    >
      <div className="h-3 w-20 bg-surface-border rounded mb-3" />
      <div className="h-7 w-16 bg-surface-border rounded" />
    </div>
  );
}

/** Card sub-shape, shared between `page` and `card` variants. */
function Card() {
  return (
    <div className="bg-surface border border-surface-border rounded-lg p-6">
      <div className="h-4 w-40 bg-surface-border rounded mb-4" />
      <div className="space-y-2">
        <div className="h-3 w-full bg-surface-border rounded" />
        <div className="h-3 w-11/12 bg-surface-border rounded" />
        <div className="h-3 w-2/3 bg-surface-border rounded" />
      </div>
    </div>
  );
}
