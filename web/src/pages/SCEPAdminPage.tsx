import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getAdminSCEPIntuneStats, reloadAdminSCEPIntuneTrust, getAuditEvents } from '../api/client';
import PageHeader from '../components/PageHeader';
import ErrorState from '../components/ErrorState';
import { useAuth } from '../components/AuthProvider';
import { formatDateTime } from '../api/utils';
import type { IntuneStatsSnapshot, IntuneTrustAnchorInfo, AuditEvent } from '../api/types';

// SCEP RFC 8894 + Intune master bundle Phase 9.4: per-profile Intune
// Monitoring tab.
//
// Surfaces:
//   - Status banner per profile (trust anchor expiry countdown, rotates
//     when < 30 days; the soonest-to-expire anchor wins).
//   - Live counters table per profile (success / signature_invalid /
//     claim_mismatch / expired / wrong_audience / replay / rate_limited /
//     malformed / compliance_failed / not_yet_valid / unknown_version).
//     Polled every 30s via TanStack Query.
//   - Recent failures table (last 50) populated from the audit log
//     filtered to action=scep_pkcsreq_intune (and the renewal sibling).
//   - Trust anchor reload button (per-profile) with confirmation modal;
//     calls POST /api/v1/admin/scep/intune/reload-trust under the hood
//     (the SIGHUP-equivalent path).
//
// Admin-gated: the page itself renders an "Admin access required" banner
// for non-admin callers and never issues the underlying admin requests.
// Server-side enforcement is the M-008 admin gate; this is a UX hint.

const COUNTER_LABEL_ORDER = [
  'success',
  'signature_invalid',
  'expired',
  'not_yet_valid',
  'wrong_audience',
  'replay',
  'rate_limited',
  'claim_mismatch',
  'compliance_failed',
  'malformed',
  'unknown_version',
] as const;

const COUNTER_PRESENTATION: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' }> = {
  success: { label: 'Success', tone: 'good' },
  signature_invalid: { label: 'Signature invalid', tone: 'bad' },
  expired: { label: 'Expired', tone: 'warn' },
  not_yet_valid: { label: 'Not yet valid', tone: 'warn' },
  wrong_audience: { label: 'Wrong audience', tone: 'bad' },
  replay: { label: 'Replay', tone: 'bad' },
  rate_limited: { label: 'Rate-limited', tone: 'warn' },
  claim_mismatch: { label: 'Claim mismatch', tone: 'bad' },
  compliance_failed: { label: 'Compliance failed', tone: 'warn' },
  malformed: { label: 'Malformed', tone: 'bad' },
  unknown_version: { label: 'Unknown version', tone: 'warn' },
};

const TONE_CLASS: Record<'good' | 'warn' | 'bad', string> = {
  good: 'text-emerald-600',
  warn: 'text-amber-600',
  bad: 'text-red-600',
};

// soonestExpiryDays returns the smallest days_to_expiry across the
// profile's trust anchor pool. Returns null when the pool is empty (the
// per-profile preflight should have refused this state at boot, but
// defensive in case the holder is reloaded mid-flight to an empty file).
function soonestExpiryDays(anchors?: IntuneTrustAnchorInfo[]): number | null {
  if (!anchors || anchors.length === 0) return null;
  let min = Number.POSITIVE_INFINITY;
  for (const a of anchors) {
    if (a.expired) return -1; // any expired wins
    if (a.days_to_expiry < min) min = a.days_to_expiry;
  }
  return min === Number.POSITIVE_INFINITY ? null : min;
}

function expiryBadge(days: number | null): { text: string; tone: 'good' | 'warn' | 'bad' } {
  if (days === null) return { text: 'No trust anchors', tone: 'warn' };
  if (days < 0) return { text: 'EXPIRED', tone: 'bad' };
  if (days < 7) return { text: `${days}d remaining`, tone: 'bad' };
  if (days < 30) return { text: `${days}d remaining (rotate soon)`, tone: 'warn' };
  return { text: `${days}d remaining`, tone: 'good' };
}

interface ConfirmReloadModalProps {
  profile: IntuneStatsSnapshot;
  onCancel: () => void;
  onConfirm: () => void;
  pending: boolean;
  errorMessage?: string;
}

function ConfirmReloadModal({ profile, onCancel, onConfirm, pending, errorMessage }: ConfirmReloadModalProps) {
  const pathLabel = profile.path_id || '(legacy /scep root)';
  return (
    <div
      role="dialog"
      aria-labelledby="reload-trust-title"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
    >
      <div className="bg-surface w-full max-w-md rounded-lg shadow-xl border border-surface-border p-6">
        <h3 id="reload-trust-title" className="text-base font-semibold text-ink mb-2">
          Reload Intune trust anchor
        </h3>
        <p className="text-sm text-ink-muted mb-4">
          This re-reads <code className="text-xs">{profile.trust_anchor_path}</code> from disk and atomically
          swaps the trust pool for SCEP profile <strong>{pathLabel}</strong>. Equivalent to sending
          <code className="text-xs"> SIGHUP </code> to the server. If the new file fails to parse, the
          previous trust pool stays in place — enrollments keep working off the old trust anchor while you
          fix the file.
        </p>
        {errorMessage && (
          <div className="mb-3 rounded border border-red-300 bg-red-50 p-3 text-xs text-red-800">
            {errorMessage}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={pending}
            className="px-3 py-1.5 text-sm rounded border border-surface-border bg-surface hover:bg-surface-alt"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            className="px-3 py-1.5 text-sm rounded bg-brand-500 text-white hover:bg-brand-600 disabled:opacity-50"
          >
            {pending ? 'Reloading…' : 'Reload trust anchor'}
          </button>
        </div>
      </div>
    </div>
  );
}

interface ProfileCardProps {
  profile: IntuneStatsSnapshot;
  onRequestReload: (profile: IntuneStatsSnapshot) => void;
}

function ProfileCard({ profile, onRequestReload }: ProfileCardProps) {
  const pathLabel = profile.path_id || '(legacy /scep root)';
  if (!profile.enabled) {
    return (
      <section className="bg-surface border border-surface-border rounded-lg p-5 mb-4" data-testid={`profile-card-${profile.path_id}`}>
        <header className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-base font-semibold text-ink">{pathLabel}</h3>
            <p className="text-xs text-ink-muted">Issuer: {profile.issuer_id}</p>
          </div>
          <span className="text-xs px-2 py-0.5 rounded-full bg-surface-alt text-ink-muted">
            Intune disabled
          </span>
        </header>
        <p className="text-sm text-ink-muted">
          This profile honors only the static challenge password. To enable Intune dispatch, set
          <code className="mx-1">CERTCTL_SCEP_PROFILE_{(profile.path_id || 'DEFAULT').toUpperCase()}_INTUNE_ENABLED=true</code>
          plus the matching trust-anchor path env var, then restart the server.
        </p>
      </section>
    );
  }

  const days = soonestExpiryDays(profile.trust_anchors);
  const badge = expiryBadge(days);

  return (
    <section className="bg-surface border border-surface-border rounded-lg p-5 mb-4" data-testid={`profile-card-${profile.path_id}`}>
      <header className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-base font-semibold text-ink">{pathLabel}</h3>
          <p className="text-xs text-ink-muted">
            Issuer: {profile.issuer_id}
            {profile.audience && <> · Audience: <code>{profile.audience}</code></>}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`text-xs px-2 py-0.5 rounded-full font-medium ${
              badge.tone === 'good'
                ? 'bg-emerald-100 text-emerald-800'
                : badge.tone === 'warn'
                  ? 'bg-amber-100 text-amber-800'
                  : 'bg-red-100 text-red-800'
            }`}
            data-testid={`expiry-badge-${profile.path_id}`}
          >
            Trust anchor: {badge.text}
          </span>
          <button
            type="button"
            onClick={() => onRequestReload(profile)}
            className="text-xs px-2 py-1 rounded border border-surface-border bg-surface hover:bg-surface-alt"
            data-testid={`reload-button-${profile.path_id}`}
          >
            Reload trust
          </button>
        </div>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        {COUNTER_LABEL_ORDER.map(label => {
          const value = profile.counters?.[label] ?? 0;
          const presentation = COUNTER_PRESENTATION[label];
          return (
            <div key={label} className="border border-surface-border rounded p-2">
              <div className={`text-lg font-semibold ${TONE_CLASS[presentation.tone]}`} data-testid={`counter-${profile.path_id}-${label}`}>
                {value}
              </div>
              <div className="text-[11px] text-ink-muted uppercase tracking-wide">{presentation.label}</div>
            </div>
          );
        })}
      </div>

      <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs text-ink-muted">
        <div>
          <dt className="font-semibold text-ink">Replay cache size</dt>
          <dd>{profile.replay_cache_size}</dd>
        </div>
        <div>
          <dt className="font-semibold text-ink">Per-device rate limit</dt>
          <dd>{profile.rate_limit_disabled ? 'Disabled' : 'Active'}</dd>
        </div>
        <div>
          <dt className="font-semibold text-ink">Trust anchors</dt>
          <dd>{profile.trust_anchors?.length ?? 0}</dd>
        </div>
      </dl>

      {profile.trust_anchors && profile.trust_anchors.length > 0 && (
        <details className="mt-3 text-xs text-ink-muted">
          <summary className="cursor-pointer font-semibold text-ink">Trust anchor details</summary>
          <table className="mt-2 w-full text-left">
            <thead>
              <tr className="text-[11px] text-ink-muted uppercase">
                <th className="py-1 pr-2">Subject</th>
                <th className="py-1 pr-2">Not after</th>
                <th className="py-1">Days to expiry</th>
              </tr>
            </thead>
            <tbody>
              {profile.trust_anchors.map(a => (
                <tr key={`${profile.path_id}-${a.subject}-${a.not_after}`} className="border-t border-surface-border">
                  <td className="py-1 pr-2 font-mono">{a.subject || '(empty CN)'}</td>
                  <td className="py-1 pr-2">{formatDateTime(a.not_after)}</td>
                  <td className={`py-1 ${a.expired ? 'text-red-600 font-semibold' : ''}`}>
                    {a.expired ? 'EXPIRED' : a.days_to_expiry}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </section>
  );
}

function RecentFailuresTable({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return (
      <p className="text-sm text-ink-muted px-4 py-6">
        No recent Intune-dispatched enrollment events. Counters stay at zero until the first device hits a SCEP profile with Intune enabled.
      </p>
    );
  }
  return (
    <table className="w-full text-sm" data-testid="recent-failures-table">
      <thead className="text-xs text-ink-muted uppercase tracking-wide">
        <tr>
          <th className="py-2 pl-4 pr-2 text-left">Timestamp</th>
          <th className="py-2 pr-2 text-left">Action</th>
          <th className="py-2 pr-2 text-left">Resource</th>
          <th className="py-2 pr-4 text-left">Details</th>
        </tr>
      </thead>
      <tbody>
        {events.map(e => (
          <tr key={e.id} className="border-t border-surface-border">
            <td className="py-2 pl-4 pr-2 font-mono text-xs">{formatDateTime(e.timestamp)}</td>
            <td className="py-2 pr-2">{e.action}</td>
            <td className="py-2 pr-2">{e.resource_type} · <code className="text-xs">{e.resource_id}</code></td>
            <td className="py-2 pr-4 text-xs text-ink-muted">
              {e.details ? Object.entries(e.details).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`).join(' · ') : '-'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function SCEPAdminPage() {
  const auth = useAuth();
  const queryClient = useQueryClient();
  const [reloadTarget, setReloadTarget] = useState<IntuneStatsSnapshot | null>(null);
  const [reloadError, setReloadError] = useState<string | undefined>(undefined);

  const statsQuery = useQuery({
    queryKey: ['admin', 'scep', 'intune', 'stats'],
    queryFn: getAdminSCEPIntuneStats,
    enabled: !auth.authRequired || auth.admin, // skip the request entirely when non-admin
    refetchInterval: 30_000,
  });

  // Audit-log filter: every Intune-dispatched enrollment (success + failure)
  // emits action=scep_pkcsreq_intune (initial) or scep_renewalreq_intune
  // (renewal). The audit endpoint accepts a single action filter; we fetch
  // both server-side via two queries and merge client-side rather than
  // adding a comma-separated filter that would require backend changes.
  const auditPKCSQuery = useQuery({
    queryKey: ['audit', { action: 'scep_pkcsreq_intune' }],
    queryFn: () => getAuditEvents({ action: 'scep_pkcsreq_intune' }),
    enabled: !auth.authRequired || auth.admin,
    refetchInterval: 60_000,
  });
  const auditRenewalQuery = useQuery({
    queryKey: ['audit', { action: 'scep_renewalreq_intune' }],
    queryFn: () => getAuditEvents({ action: 'scep_renewalreq_intune' }),
    enabled: !auth.authRequired || auth.admin,
    refetchInterval: 60_000,
  });

  const reloadMutation = useMutation({
    mutationFn: (pathID: string) => reloadAdminSCEPIntuneTrust(pathID),
    onSuccess: () => {
      setReloadTarget(null);
      setReloadError(undefined);
      void queryClient.invalidateQueries({ queryKey: ['admin', 'scep', 'intune', 'stats'] });
    },
    onError: (err: Error) => {
      setReloadError(err.message);
    },
  });

  if (auth.authRequired && !auth.admin) {
    return (
      <>
        <PageHeader title="SCEP Intune Monitoring" subtitle="Admin-only observability surface" />
        <div className="p-6">
          <ErrorState
            error={new Error('Admin access required: this page exposes per-profile trust anchor expiries and an admin-only reload action. Sign in with an admin-tagged API key to view it.')}
          />
        </div>
      </>
    );
  }

  if (statsQuery.isLoading) {
    return (
      <>
        <PageHeader title="SCEP Intune Monitoring" subtitle="Per-profile dispatcher state" />
        <div className="p-6 text-sm text-ink-muted">Loading per-profile stats…</div>
      </>
    );
  }

  if (statsQuery.error) {
    return (
      <>
        <PageHeader title="SCEP Intune Monitoring" subtitle="Per-profile dispatcher state" />
        <div className="p-6">
          <ErrorState error={statsQuery.error as Error} onRetry={() => statsQuery.refetch()} />
        </div>
      </>
    );
  }

  const profiles = statsQuery.data?.profiles ?? [];
  const events: AuditEvent[] = [
    ...(auditPKCSQuery.data?.data ?? []),
    ...(auditRenewalQuery.data?.data ?? []),
  ]
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, 50);

  return (
    <>
      <PageHeader
        title="SCEP Intune Monitoring"
        subtitle={`${profiles.length} SCEP profile${profiles.length === 1 ? '' : 's'} configured · counters auto-refresh every 30s`}
        action={
          <button
            type="button"
            onClick={() => statsQuery.refetch()}
            className="text-xs px-3 py-1.5 rounded border border-surface-border bg-surface hover:bg-surface-alt"
            data-testid="refresh-stats-button"
          >
            Refresh now
          </button>
        }
      />
      <div className="p-6 overflow-y-auto">
        {profiles.length === 0 && (
          <div className="rounded border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 mb-4">
            No SCEP profiles are configured. Set <code>CERTCTL_SCEP_ENABLED=true</code> and either the
            legacy single-profile env vars or <code>CERTCTL_SCEP_PROFILES=...</code> with the indexed
            per-profile family to register at least one endpoint.
          </div>
        )}
        {profiles.map(p => (
          <ProfileCard
            key={p.path_id || '(root)'}
            profile={p}
            onRequestReload={profile => {
              setReloadError(undefined);
              setReloadTarget(profile);
            }}
          />
        ))}

        <section className="bg-surface border border-surface-border rounded-lg mt-6">
          <div className="px-4 py-3 border-b border-surface-border">
            <h3 className="text-sm font-semibold text-ink">
              Recent Intune-dispatched enrollments (last 50)
            </h3>
            <p className="text-xs text-ink-muted">
              Filtered to <code>action=scep_pkcsreq_intune</code> + <code>action=scep_renewalreq_intune</code>.
              Refreshes every 60s.
            </p>
          </div>
          {auditPKCSQuery.isLoading || auditRenewalQuery.isLoading ? (
            <p className="text-sm text-ink-muted px-4 py-6">Loading audit log…</p>
          ) : (
            <RecentFailuresTable events={events} />
          )}
        </section>
      </div>

      {reloadTarget && (
        <ConfirmReloadModal
          profile={reloadTarget}
          onCancel={() => {
            setReloadTarget(null);
            setReloadError(undefined);
          }}
          onConfirm={() => reloadMutation.mutate(reloadTarget.path_id)}
          pending={reloadMutation.isPending}
          errorMessage={reloadError}
        />
      )}
    </>
  );
}
