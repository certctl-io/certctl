// Bundle-8 / Audit M-010:
//
// Single hook for filter / sort / pagination state on every list page.
// Pre-Bundle-8, list pages stored these in local `useState` (see
// CertificatesPage:417 `const [page, setPage] = useState(1)`), which
// broke deep-linking and browser-back consistency. The DashboardPage
// already used `useSearchParams` directly; this hook canonicalises that
// pattern so the rest of the list pages can migrate mechanically.
//
// URL contract:
//
//   ?page=2&page_size=25&sort=-created_at&filter[status]=active&filter[team_id]=t-platform
//
// Defaults are applied client-side — they do NOT appear in the URL when
// the user hasn't customised them, keeping shareable URLs short.
//
// Bundle-8 ships the hook + 1 demonstration migration (CertificatesPage)
// per the bundle prompt. The remaining list pages (IssuersPage,
// TargetsPage, AgentsPage, PoliciesPage, ProfilesPage, OwnersPage,
// TeamsPage, AgentGroupsPage, AuditEventsPage, NotificationsPage,
// JobsPage, RenewalPoliciesPage, DiscoveryPage) are deferred to a
// follow-up bundle — tracked as new ID `M-029`.

import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';

export interface ListParams {
  /** Current page (1-indexed). Default: 1. */
  page: number;
  /** Page size. Default: 25. */
  pageSize: number;
  /** Sort key (e.g., `created_at`, `-name` for descending). Default: `''` (no sort). */
  sort: string;
  /** Filter map keyed by filter name (e.g. `{status: 'active', team_id: 't-platform'}`). */
  filters: Record<string, string>;
}

export interface ListParamsControls {
  params: ListParams;
  setPage: (page: number) => void;
  setPageSize: (pageSize: number) => void;
  setSort: (sort: string) => void;
  setFilter: (key: string, value: string | null) => void;
  resetParams: () => void;
}

const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 25;

/**
 * Read filter/sort/pagination state from URL search params, with helpers to
 * update the URL via `setSearchParams({ replace: true })` (preserves
 * browser-back history without flooding it with intermediate states).
 *
 * @param defaults - per-page overrides for the global defaults above
 */
export function useListParams(defaults?: Partial<ListParams>): ListParamsControls {
  const [searchParams, setSearchParams] = useSearchParams();

  const params = useMemo<ListParams>(() => {
    const page = parsePositiveInt(searchParams.get('page'), defaults?.page ?? DEFAULT_PAGE);
    const pageSize = parsePositiveInt(
      searchParams.get('page_size'),
      defaults?.pageSize ?? DEFAULT_PAGE_SIZE,
    );
    const sort = searchParams.get('sort') ?? defaults?.sort ?? '';
    const filters: Record<string, string> = { ...(defaults?.filters ?? {}) };
    searchParams.forEach((value, key) => {
      const m = /^filter\[(.+)\]$/.exec(key);
      if (m && value) {
        filters[m[1]] = value;
      }
    });
    return { page, pageSize, sort, filters };
  }, [searchParams, defaults]);

  const updateParam = useCallback(
    (key: string, value: string | null) => {
      const next = new URLSearchParams(searchParams);
      if (value === null || value === '') {
        next.delete(key);
      } else {
        next.set(key, value);
      }
      // Bundle-8: filter / sort changes reset page to 1 (the existing
      // CertificatesPage behaviour we're preserving). Only the page
      // setter is allowed to set page > 1 directly.
      if (key !== 'page') {
        next.delete('page');
      }
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  return {
    params,
    setPage: (page) => updateParam('page', page > 1 ? String(page) : null),
    setPageSize: (size) => updateParam('page_size', size !== DEFAULT_PAGE_SIZE ? String(size) : null),
    setSort: (sort) => updateParam('sort', sort || null),
    setFilter: (key, value) => updateParam(`filter[${key}]`, value),
    resetParams: () => setSearchParams(new URLSearchParams(), { replace: true }),
  };
}

function parsePositiveInt(raw: string | null, fallback: number): number {
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}
