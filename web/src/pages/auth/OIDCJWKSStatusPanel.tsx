import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  authOIDCJWKSStatus,
  refreshOIDCProvider,
  type JWKSStatusSnapshot,
} from '../../api/client';

// =============================================================================
// Audit 2026-05-11 Fix 10 — JWKS health panel (MED-7 GUI half).
//
// MED-7 backend (`GET /api/v1/auth/oidc/providers/{id}/jwks-status`,
// commit d85114f) shipped the per-provider verifier counters
// (last_refresh_at, refresh_count, last_error, rejected_jws_count,
// iss_param_supported, current_kids) on dev/auth-bundle-2 but the
// GUI never called the endpoint. `authOIDCJWKSStatus` in the API
// client was dead code; operators debugging "why is login failing
// for this IdP?" had to drop to curl. The whole point of MED-7 was
// to surface this for in-GUI observability — that gap is what this
// panel closes.
//
// What each row means at a glance (for the operator):
//   - Last refresh: when did the server last fetch the JWKS doc?
//     A long-ago timestamp + high rejected_jws_count = the IdP
//     rotated keys and the cache hasn't caught up.
//   - Refresh count: cumulative since process boot. A non-zero
//     count post-boot proves the auto-refresh path (MED-6) fired
//     at least once.
//   - Rejected JWS count: number of ID tokens whose signature
//     failed verification. Step-change spikes correlate to IdP
//     key rotations.
//   - Last error: the most recent JWKS-refresh failure message
//     (sanitized — no token content). Empty means the cache is
//     healthy.
//   - RFC 9207 iss param: whether the IdP advertises the
//     authorization_response_iss_parameter_supported field at
//     discovery time. Informational only — the operator-side
//     verifier still demands it by default; this surfaces whether
//     the IdP plays ball.
//   - Current KIDs: the key fingerprints currently in the cache.
//     Backend may decline to expose these (privacy / opacity);
//     the panel renders a clear "(not exposed)" sentinel when
//     the list is empty so the operator knows the absence is by
//     design, not by failure.
//
// "Refresh now" button calls POST .../refresh (RefreshKeys path)
// which re-fetches discovery + JWKS AND re-runs the IdP downgrade-
// attack defense. After refresh the panel's TanStack Query is
// invalidated so the freshly-updated counters render in the UI
// without a manual page reload.
//
// The panel is permission-gated server-side; when a non-admin
// caller (e.g. a viewer role with only auth.oidc.list) loads the
// detail page, the status endpoint returns 403 and the panel
// quietly hides. That keeps the surface unobtrusive for read-only
// users while still giving admins one-click observability.
// =============================================================================

interface Props {
  providerID: string;
  /** Optional. When false, the Refresh-now button is hidden
   * (callers without auth.oidc.edit see the read-only panel). */
  canRefresh?: boolean;
}

export default function OIDCJWKSStatusPanel({ providerID, canRefresh = true }: Props) {
  const qc = useQueryClient();
  const statusQuery = useQuery<JWKSStatusSnapshot, Error>({
    queryKey: ['auth', 'oidc', 'jwks-status', providerID],
    queryFn: () => authOIDCJWKSStatus(providerID),
    // 30s freshness — operators rarely poll faster than this.
    staleTime: 30_000,
    // 403 / 404 / 500 — don't drown the page in retries. The panel
    // hides itself on error (see below).
    retry: 0,
  });
  const [refreshing, setRefreshing] = useState(false);
  const [refreshErr, setRefreshErr] = useState<string | null>(null);

  if (statusQuery.error) {
    // The most likely error is HTTP 403 for callers without
    // auth.oidc.list, in which case we hide the panel silently.
    // 404 (unknown provider id) is also possible if the detail
    // page is loaded with a stale URL after a provider was deleted
    // in another tab — hiding is acceptable there too. We do NOT
    // log to console because this isn't an error worth flagging
    // to the user; the page itself surfaces the 403 / 404 via its
    // own permission / not-found path.
    return null;
  }

  async function doRefresh() {
    setRefreshing(true);
    setRefreshErr(null);
    try {
      await refreshOIDCProvider(providerID);
      // Invalidate the status query so the freshly-updated
      // counters (refresh_count++, last_refresh_at=now, possibly
      // last_error="") render on the next render pass. We don't
      // mutate the cache optimistically because the backend's
      // refresh path can fail in interesting ways (discovery
      // unreachable, alg-downgrade rejection) and we want the
      // real post-refresh state to surface.
      await qc.invalidateQueries({
        queryKey: ['auth', 'oidc', 'jwks-status', providerID],
      });
    } catch (e) {
      setRefreshErr(e instanceof Error ? e.message : String(e));
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <section
      className="bg-surface border border-surface-border rounded mt-4"
      data-testid="oidc-jwks-status-panel"
    >
      <header className="px-4 py-3 border-b border-surface-border flex items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-ink">JWKS health</div>
          <div className="text-xs text-ink-muted">
            Per-provider verifier counters. Updates live after Refresh now.
          </div>
        </div>
        {canRefresh && (
          <button
            type="button"
            onClick={doRefresh}
            disabled={refreshing}
            className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink disabled:opacity-50 whitespace-nowrap"
            data-testid="oidc-jwks-refresh-now"
            title="Force a JWKS + discovery re-fetch; re-runs the IdP alg-downgrade defense"
          >
            {refreshing ? 'Refreshing…' : 'Refresh now'}
          </button>
        )}
      </header>
      <div className="px-4 py-3 text-sm">
        {refreshErr && (
          <div
            className="text-red-700 text-xs mb-2"
            data-testid="oidc-jwks-refresh-error"
          >
            Refresh failed: {refreshErr}
          </div>
        )}
        {statusQuery.isLoading && (
          <div className="text-ink-muted text-xs" data-testid="oidc-jwks-status-loading">
            Loading…
          </div>
        )}
        {statusQuery.data && (
          <dl
            className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs"
            data-testid="oidc-jwks-status-fields"
          >
            <dt className="text-ink-muted">Last refresh</dt>
            <dd
              className="font-mono text-ink"
              data-testid="oidc-jwks-status-last-refresh"
            >
              {statusQuery.data.last_refresh_at ? (
                statusQuery.data.last_refresh_at
              ) : (
                <span className="text-ink-muted">(never — cold cache)</span>
              )}
            </dd>

            <dt className="text-ink-muted">Refresh count</dt>
            <dd
              className="font-mono text-ink"
              data-testid="oidc-jwks-status-refresh-count"
            >
              {statusQuery.data.refresh_count}
            </dd>

            <dt className="text-ink-muted">Rejected JWS count</dt>
            <dd
              className="font-mono text-ink"
              data-testid="oidc-jwks-status-rejected-jws-count"
            >
              {statusQuery.data.rejected_jws_count}
            </dd>

            <dt className="text-ink-muted">Last error</dt>
            <dd
              className="font-mono text-ink"
              data-testid="oidc-jwks-status-last-error"
            >
              {statusQuery.data.last_error ? (
                <span className="text-red-700">{statusQuery.data.last_error}</span>
              ) : (
                <span className="text-ink-muted">(none)</span>
              )}
            </dd>

            <dt className="text-ink-muted">RFC 9207 iss param</dt>
            <dd
              className="font-mono text-ink"
              data-testid="oidc-jwks-status-iss-param"
            >
              {statusQuery.data.iss_param_supported
                ? 'supported by IdP'
                : 'not advertised'}
            </dd>

            <dt className="text-ink-muted">Current KIDs</dt>
            <dd
              className="font-mono text-ink break-all"
              data-testid="oidc-jwks-status-current-kids"
            >
              {(statusQuery.data.current_kids ?? []).length === 0 ? (
                <span className="text-ink-muted">
                  (not exposed — query jwks_uri directly to inspect)
                </span>
              ) : (
                statusQuery.data.current_kids.join(', ')
              )}
            </dd>
          </dl>
        )}
      </div>
    </section>
  );
}
