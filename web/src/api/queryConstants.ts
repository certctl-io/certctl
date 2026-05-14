// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// queryConstants — the TanStack Query staleTime / gcTime tier model.
// Phase 2 closure for TQ-M2 (twelve inconsistent staleTime override
// values 15s–5min with no governing principle) + TQ-M1 (zero gcTime
// overrides; 5-min default holds stale data across 87 pages of nav).
//
// Tier model
// ==========
// staleTime answers: "how long can the cached value be served as-is
// without firing a background refetch?". Three tiers:
//
//   REAL_TIME    15s   — data that needs to look live for an operator
//                        watching a workflow finish: in-flight jobs,
//                        running agent heartbeats, scan progress,
//                        certs-by-status. Refetch on window focus.
//   REFERENCE     5min  — list endpoints + reference data: issuers,
//                        profiles, owners, teams, agent groups,
//                        certificate listings, audit log. The dominant
//                        case in the codebase. No window-focus refetch.
//   CONSTANT     1hr   — server-side metadata that's effectively
//                        immutable in a normal session: OpenAPI spec,
//                        version metadata, permission catalogue,
//                        RBAC role list.
//
// gcTime answers: "how long should the cached value linger after
// every observer unmounts before garbage-collection?". Three tiers:
//
//   HEAVY         1min — large payloads that pile up memory if held
//                        long after the consumer page closed
//                        (certificate listings, audit-log pages,
//                        chart-data series).
//   STANDARD      5min — the default for normal pages — held long
//                        enough that revisits within a typical
//                        workflow get an instant cache hit, but not
//                        so long that the user's tab balloons.
//   REFERENCE   30min — small, reusable data fetched on most pages
//                        (RBAC catalogue, issuer/profile dropdown
//                        options). Holding 30 min means the operator
//                        navigating between Certificates / Targets /
//                        Profiles / Issuers gets the same dropdown
//                        cache without re-fetching.
//
// Migration policy: every new useQuery should pick ONE staleTime tier
// + ONE gcTime tier. Bare numeric values are forbidden; the rg-based
// CI guard will flag any new `staleTime:` not followed by
// `STALE_TIME.` and `gcTime:` not followed by `GC_TIME.`.

// staleTime — how long the cached value is "fresh" (no background refetch).
export const STALE_TIME = {
  /** 15s — live tile data (in-flight jobs, agent heartbeats, scan progress). */
  REAL_TIME:   15_000,
  /** 5min — list endpoints + reference data. The dominant case. */
  REFERENCE:   5 * 60_000,
  /** 1hr — effectively immutable in a normal session (catalogues, metadata). */
  CONSTANT:    60 * 60_000,
} as const;

// gcTime — how long the cached value lingers after every observer unmounts.
export const GC_TIME = {
  /** 1min — large payloads (cert listings, audit pages, chart series). */
  HEAVY:       60_000,
  /** 5min — the normal-page default. */
  STANDARD:    5 * 60_000,
  /** 30min — small reusable dropdown / catalogue data. */
  REFERENCE:   30 * 60_000,
} as const;

// Convenience exports for the explicit tier names — useful when the
// caller wants to log the tier alongside the actual ms value (TanStack
// Devtools prints the millisecond integer; this lets you cross-ref
// the symbolic name).
export type StaleTimeTier = keyof typeof STALE_TIME;
export type GcTimeTier = keyof typeof GC_TIME;
