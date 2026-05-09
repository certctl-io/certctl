import { useQuery } from '@tanstack/react-query';
import { authMe, type AuthMeResponse } from '../api/client';

// =============================================================================
// Bundle 1 Phase 10 — `useAuthMe` is the GUI's single source of truth for
// "what can the current actor do?" Every Phase-10 auth page (Roles,
// Keys, Auth Settings, Audit category filter) consumes this hook on
// mount + caches via TanStack Query, so toggling between pages doesn't
// re-fetch the permission set every navigation.
//
// The hook returns three things:
//
//   - data:        the raw AuthMeResponse from /v1/auth/me (or undefined while
//                  loading / on error).
//   - hasPerm(p):  predicate the caller uses to gate buttons / links.
//                  Reads the cached effective_permissions slice.
//   - isLoading + error: standard TanStack Query surface.
//
// The permission check is intentionally a string-equality match against
// the canonical permission names. Scope semantics (global / profile /
// issuer) are NOT applied client-side — the server is the load-bearing
// gate. The client uses hasPerm purely for "show or hide the button"
// UX; the server returns 403 if a missing perm gets through anyway.
// =============================================================================

const STALE_TIME_MS = 60_000;

export function useAuthMe() {
  const query = useQuery<AuthMeResponse, Error>({
    queryKey: ['auth', 'me'],
    queryFn: authMe,
    staleTime: STALE_TIME_MS,
    retry: 0,
  });

  const hasPerm = (perm: string): boolean => {
    if (!query.data) return false;
    return query.data.effective_permissions.some(p => p.permission === perm);
  };

  const hasAnyPerm = (perms: string[]): boolean => {
    if (!query.data) return false;
    return perms.some(p => hasPerm(p));
  };

  const isAdmin = (): boolean => {
    return Boolean(query.data?.roles?.includes('r-admin') || query.data?.admin);
  };

  return {
    data: query.data,
    isLoading: query.isLoading,
    error: query.error,
    hasPerm,
    hasAnyPerm,
    isAdmin,
  };
}
