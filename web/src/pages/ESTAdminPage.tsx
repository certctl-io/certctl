import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useLocation, useSearchParams } from 'react-router-dom';
import {
  getAdminESTProfiles,
  reloadAdminESTTrust,
  getAuditEvents,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import ErrorState from '../components/ErrorState';
import { useAuth } from '../components/AuthProvider';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { formatDateTime } from '../api/utils';
import type {
  ESTStatsSnapshot,
  ESTTrustAnchorInfo,
  AuditEvent,
} from '../api/types';

// EST RFC 7030 hardening master bundle Phase 8 — operator-facing EST
// administration page with three tabs.
//
//   Profiles (default)  — every configured EST profile, lean card per
//                         profile with always-present fields (auth-mode
//                         badges, mTLS trust-anchor expiry countdown,
//                         counter grid). Per-card "Reload trust" action
//                         (admin-gated; opens ConfirmReloadModal). Polled
//                         every 30s via TanStack Query.
//   Recent Activity     — full EST audit log filter covering the four
//                         action codes the service emits
//                         (est_simple_enroll / est_simple_reenroll /
//                         est_server_keygen / est_auth_failed). Merged +
//                         sorted descending. Filter chips for All /
//                         Enrollment / Re-enrollment / ServerKeygen /
//                         AuthFailure. Polled every 60s.
//   Trust Bundle        — for mTLS profiles: per-profile trust bundle
//                         viewer (cert subjects + expiry). The
//                         upload-new-bundle action is intentionally
//                         omitted at GA — operators rotate the file on
//                         disk + use the Reload action on the Profiles
//                         tab. A future phase ships the upload endpoint.
//
// Admin-gated: the page renders an "Admin access required" banner for
// non-admin callers and never issues the underlying admin requests.
// Server-side enforcement is the M-008 admin gate; this is a UX hint.
//
// The 12 counter labels match service/est_counters.go's estCounter*
// constants; new labels added there MUST also be added to
// COUNTER_LABEL_ORDER + COUNTER_PRESENTATION below.

const COUNTER_LABEL_ORDER = [
  'success_simpleenroll',
  'success_simplereenroll',
  'success_serverkeygen',
  'auth_failed_basic',
  'auth_failed_mtls',
  'auth_failed_channel_binding',
  'csr_invalid',
  'csr_policy_violation',
  'csr_signature_mismatch',
  'rate_limited',
  'issuer_error',
  'internal_error',
] as const;

const COUNTER_PRESENTATION: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' }> = {
  success_simpleenroll: { label: 'Enrollments', tone: 'good' },
  success_simplereenroll: { label: 'Re-enrollments', tone: 'good' },
  success_serverkeygen: { label: 'Server-keygen', tone: 'good' },
  auth_failed_basic: { label: 'Auth failed (Basic)', tone: 'warn' },
  auth_failed_mtls: { label: 'Auth failed (mTLS)', tone: 'warn' },
  auth_failed_channel_binding: { label: 'Channel-binding mismatch', tone: 'bad' },
  csr_invalid: { label: 'CSR invalid', tone: 'warn' },
  csr_policy_violation: { label: 'CSR policy violation', tone: 'warn' },
  csr_signature_mismatch: { label: 'CSR signature mismatch', tone: 'bad' },
  rate_limited: { label: 'Rate-limited', tone: 'warn' },
  issuer_error: { label: 'Issuer error', tone: 'bad' },
  internal_error: { label: 'Internal error', tone: 'bad' },
};

const TONE_CLASS: Record<'good' | 'warn' | 'bad', string> = {
  good: 'text-emerald-600',
  warn: 'text-amber-600',
  bad: 'text-red-600',
};

type TabId = 'profiles' | 'activity' | 'trust';
type ActivityFilter = 'all' | 'enroll' | 'reenroll' | 'serverkeygen' | 'authfail';

const TAB_LABELS: Record<TabId, string> = {
  profiles: 'Profiles',
  activity: 'Recent Activity',
  trust: 'Trust Bundle',
};

const EST_AUDIT_ACTIONS = [
  'est_simple_enroll',
  'est_simple_reenroll',
  'est_server_keygen',
  'est_auth_failed',
] as const;

// =============================================================================
// Tone + badge helpers (shared across tabs).
// =============================================================================

function expiryBadge(days: number | null, expired: boolean): { text: string; tone: 'good' | 'warn' | 'bad' } {
  if (expired) return { text: 'EXPIRED', tone: 'bad' };
  if (days === null) return { text: 'Not loaded', tone: 'warn' };
  if (days < 7) return { text: `${days}d remaining`, tone: 'bad' };
  if (days < 30) return { text: `${days}d remaining (rotate soon)`, tone: 'warn' };
  return { text: `${days}d remaining`, tone: 'good' };
}

function badgeClass(tone: 'good' | 'warn' | 'bad'): string {
  if (tone === 'good') return 'bg-emerald-100 text-emerald-800';
  if (tone === 'warn') return 'bg-amber-100 text-amber-800';
  return 'bg-red-100 text-red-800';
}

function pillClass(active: boolean): string {
  return active
    ? 'bg-brand-100 text-brand-800 border-brand-300'
    : 'bg-surface-alt text-ink-muted border-surface-border';
}

// soonestExpiryDays returns the smallest days_to_expiry across the
// profile's mTLS trust anchor pool. Returns null when the pool is
// empty (the per-profile preflight should have refused this state at
// boot, but defensive in case the holder is reloaded mid-flight to an
// empty file).
function soonestExpiryDays(anchors?: ESTTrustAnchorInfo[]): number | null {
  if (!anchors || anchors.length === 0) return null;
  let min = Number.POSITIVE_INFINITY;
  for (const a of anchors) {
    if (a.expired) return -1;
    if (a.days_to_expiry < min) min = a.days_to_expiry;
  }
  return min === Number.POSITIVE_INFINITY ? null : min;
}

// =============================================================================
// Profiles tab.
// =============================================================================

interface ProfilesTabProps {
  profiles: ESTStatsSnapshot[];
  isLoading: boolean;
  onRequestReload: (profile: ESTStatsSnapshot) => void;
}

function ProfilesTab({ profiles, isLoading, onRequestReload }: ProfilesTabProps) {
  if (isLoading) {
    return <p className="text-sm text-ink-muted px-1 py-6">Loading profiles…</p>;
  }
  if (profiles.length === 0) {
    return (
      <div className="rounded border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">
        No EST profiles are configured. Set <code>CERTCTL_EST_ENABLED=true</code> and either the
        legacy single-profile env vars or <code>CERTCTL_EST_PROFILES=...</code> with the indexed
        per-profile family to register at least one endpoint.
      </div>
    );
  }
  return (
    <>
      {profiles.map(p => (
        <ProfileSummaryCard
          key={p.path_id || '(root)'}
          profile={p}
          onRequestReload={onRequestReload}
        />
      ))}
    </>
  );
}

interface ProfileSummaryCardProps {
  profile: ESTStatsSnapshot;
  onRequestReload: (profile: ESTStatsSnapshot) => void;
}

function ProfileSummaryCard({ profile, onRequestReload }: ProfileSummaryCardProps) {
  const pathLabel = profile.path_id || '(legacy /.well-known/est root)';
  const trustDays = soonestExpiryDays(profile.trust_anchors);
  const trustExpired = (profile.trust_anchors ?? []).some(a => a.expired);
  const trustBadge = profile.mtls_enabled
    ? expiryBadge(trustDays, trustExpired)
    : null;

  return (
    <section
      className="bg-surface border border-surface-border rounded-lg p-5 mb-4"
      data-testid={`est-profile-summary-${profile.path_id}`}
    >
      <header className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-base font-semibold text-ink">{pathLabel}</h3>
          <p className="text-xs text-ink-muted">
            Issuer: {profile.issuer_id}
            {profile.profile_id && (
              <>
                {' '}· Profile: <code className="font-mono">{profile.profile_id}</code>
              </>
            )}
          </p>
        </div>
        {trustBadge && (
          <span
            className={`text-xs px-2 py-0.5 rounded-full font-medium ${badgeClass(trustBadge.tone)}`}
            data-testid={`est-trust-expiry-badge-${profile.path_id}`}
          >
            mTLS trust: {trustBadge.text}
          </span>
        )}
      </header>

      <div className="flex flex-wrap gap-2 mb-3" data-testid={`est-profile-badges-${profile.path_id}`}>
        <span className={`text-[11px] uppercase tracking-wide px-2 py-0.5 rounded border ${pillClass(profile.mtls_enabled)}`}>
          mTLS {profile.mtls_enabled ? 'enabled' : 'disabled'}
        </span>
        <span className={`text-[11px] uppercase tracking-wide px-2 py-0.5 rounded border ${pillClass(profile.basic_auth_configured)}`}>
          HTTP Basic {profile.basic_auth_configured ? 'configured' : 'not set'}
        </span>
        <span className={`text-[11px] uppercase tracking-wide px-2 py-0.5 rounded border ${pillClass(profile.server_keygen_enabled)}`}>
          Server-keygen {profile.server_keygen_enabled ? 'enabled' : 'disabled'}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3" data-testid={`est-profile-counters-${profile.path_id}`}>
        {COUNTER_LABEL_ORDER.map(label => {
          const presentation = COUNTER_PRESENTATION[label];
          const value = profile.counters?.[label] ?? 0;
          return (
            <div key={label} className="bg-surface-alt rounded px-3 py-2" data-testid={`est-counter-${profile.path_id}-${label}`}>
              <div className="text-[10px] uppercase tracking-wide text-ink-muted">{presentation.label}</div>
              <div className={`text-base font-semibold ${TONE_CLASS[presentation.tone]}`}>{value}</div>
            </div>
          );
        })}
      </div>

      {profile.mtls_enabled && profile.trust_anchor_path && (
        <p className="text-[11px] text-ink-muted font-mono mb-2">
          Trust bundle: {profile.trust_anchor_path}
        </p>
      )}

      {profile.mtls_enabled && (
        <div className="mt-2 pt-3 border-t border-surface-border flex justify-end">
          <button
            type="button"
            onClick={() => onRequestReload(profile)}
            className="text-xs px-3 py-1.5 rounded border border-surface-border bg-surface hover:bg-surface-alt"
            data-testid={`est-reload-trust-${profile.path_id}`}
          >
            Reload trust anchor
          </button>
        </div>
      )}
    </section>
  );
}

// =============================================================================
// Confirm-reload modal.
// =============================================================================

interface ConfirmReloadModalProps {
  profile: ESTStatsSnapshot;
  onCancel: () => void;
  onConfirm: () => void;
  pending: boolean;
  errorMessage?: string;
}

function ConfirmReloadModal({ profile, onCancel, onConfirm, pending, errorMessage }: ConfirmReloadModalProps) {
  const pathLabel = profile.path_id || '(legacy /.well-known/est root)';
  return (
    <div
      role="dialog"
      aria-labelledby="est-reload-trust-title"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
    >
      <div className="bg-surface w-full max-w-md rounded-lg shadow-xl border border-surface-border p-6">
        <h3 id="est-reload-trust-title" className="text-base font-semibold text-ink mb-2">
          Reload EST mTLS trust anchor
        </h3>
        <p className="text-sm text-ink-muted mb-4">
          This re-reads <code className="text-xs">{profile.trust_anchor_path}</code> from disk and atomically
          swaps the trust pool for EST profile <strong>{pathLabel}</strong>. Equivalent to sending
          <code className="text-xs"> SIGHUP </code> to the server. If the new file fails to parse, the
          previous trust pool stays in place — enrollments keep working off the old trust anchor while you
          fix the file.
        </p>
        {errorMessage && (
          <div className="mb-3 rounded border border-red-300 bg-red-50 p-3 text-xs text-red-800" data-testid="est-reload-error">
            {errorMessage}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={pending}
            data-testid="est-reload-cancel"
            className="px-3 py-1.5 text-sm rounded border border-surface-border bg-surface hover:bg-surface-alt"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            data-testid="est-reload-confirm"
            className="px-3 py-1.5 text-sm rounded bg-brand-500 text-white hover:bg-brand-600 disabled:opacity-50"
          >
            {pending ? 'Reloading…' : 'Reload trust anchor'}
          </button>
        </div>
      </div>
    </div>
  );
}

// =============================================================================
// Recent Activity tab.
// =============================================================================

interface ActivityTabProps {
  events: AuditEvent[];
  isLoading: boolean;
  filter: ActivityFilter;
  setFilter: (f: ActivityFilter) => void;
}

function activityMatches(filter: ActivityFilter, e: AuditEvent): boolean {
  if (filter === 'all') return true;
  if (filter === 'enroll') return e.action === 'est_simple_enroll';
  if (filter === 'reenroll') return e.action === 'est_simple_reenroll';
  if (filter === 'serverkeygen') return e.action === 'est_server_keygen';
  if (filter === 'authfail') return e.action === 'est_auth_failed';
  return false;
}

const ACTIVITY_FILTERS: { id: ActivityFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'enroll', label: 'Enrollment' },
  { id: 'reenroll', label: 'Re-enrollment' },
  { id: 'serverkeygen', label: 'Server-keygen' },
  { id: 'authfail', label: 'Auth failure' },
];

function ActivityTab({ events, isLoading, filter, setFilter }: ActivityTabProps) {
  const filtered = useMemo(() => events.filter(e => activityMatches(filter, e)), [events, filter]);
  return (
    <>
      <div className="flex flex-wrap gap-2 mb-4" data-testid="est-activity-filters">
        {ACTIVITY_FILTERS.map(f => (
          <button
            key={f.id}
            type="button"
            onClick={() => setFilter(f.id)}
            data-testid={`est-activity-filter-${f.id}`}
            aria-pressed={filter === f.id}
            className={`text-xs px-3 py-1 rounded-full border ${pillClass(filter === f.id)}`}
          >
            {f.label}
          </button>
        ))}
      </div>
      {isLoading && <p className="text-sm text-ink-muted">Loading audit events…</p>}
      {!isLoading && filtered.length === 0 && (
        <p className="text-sm text-ink-muted">No events match the selected filter.</p>
      )}
      {!isLoading && filtered.length > 0 && (
        <div className="bg-surface border border-surface-border rounded-lg overflow-hidden">
          <table className="w-full text-sm" data-testid="est-activity-table">
            <thead className="bg-surface-alt text-ink-muted text-xs uppercase tracking-wide">
              <tr>
                <th className="text-left px-3 py-2">Timestamp</th>
                <th className="text-left px-3 py-2">Action</th>
                <th className="text-left px-3 py-2">Subject</th>
                <th className="text-left px-3 py-2">Resource</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 100).map((e, i) => (
                <tr key={`${e.timestamp}-${i}`} className="border-t border-surface-border">
                  <td className="px-3 py-2 text-xs text-ink-muted">{formatDateTime(e.timestamp)}</td>
                  <td className="px-3 py-2 text-xs font-mono">{e.action}</td>
                  <td className="px-3 py-2 text-xs">{e.actor || '—'}</td>
                  <td className="px-3 py-2 text-xs">{e.resource_id || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

// =============================================================================
// Trust Bundle tab.
// =============================================================================

interface TrustBundleTabProps {
  profiles: ESTStatsSnapshot[];
}

function TrustBundleTab({ profiles }: TrustBundleTabProps) {
  const mtlsProfiles = profiles.filter(p => p.mtls_enabled && p.trust_anchors && p.trust_anchors.length > 0);
  if (mtlsProfiles.length === 0) {
    return (
      <div className="rounded border border-surface-border bg-surface-alt p-4 text-sm text-ink-muted">
        No EST profiles have mTLS enabled. The Trust Bundle tab is only relevant when at least one
        profile carries an <code>MTLS_CLIENT_CA_TRUST_BUNDLE_PATH</code>.
      </div>
    );
  }
  return (
    <>
      {mtlsProfiles.map(p => (
        <section
          key={p.path_id || '(root)'}
          className="bg-surface border border-surface-border rounded-lg p-5 mb-4"
          data-testid={`est-trust-card-${p.path_id}`}
        >
          <header className="flex items-center justify-between mb-2">
            <h3 className="text-base font-semibold text-ink">{p.path_id || '(legacy root)'}</h3>
            <span className="text-xs font-mono text-ink-muted">{p.trust_anchor_path}</span>
          </header>
          <table className="w-full text-sm">
            <thead className="bg-surface-alt text-ink-muted text-xs uppercase tracking-wide">
              <tr>
                <th className="text-left px-3 py-2">Subject</th>
                <th className="text-left px-3 py-2">Not before</th>
                <th className="text-left px-3 py-2">Not after</th>
                <th className="text-left px-3 py-2">Days remaining</th>
              </tr>
            </thead>
            <tbody>
              {(p.trust_anchors ?? []).map(a => (
                <tr key={`${p.path_id}-${a.subject}-${a.not_after}`} className="border-t border-surface-border">
                  <td className="px-3 py-2 text-xs font-mono">{a.subject}</td>
                  <td className="px-3 py-2 text-xs">{formatDateTime(a.not_before)}</td>
                  <td className="px-3 py-2 text-xs">{formatDateTime(a.not_after)}</td>
                  <td className={`px-3 py-2 text-xs font-semibold ${a.expired ? 'text-red-600' : a.days_to_expiry < 30 ? 'text-amber-600' : 'text-emerald-600'}`}>
                    {a.expired ? 'EXPIRED' : `${a.days_to_expiry}d`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </>
  );
}

// =============================================================================
// Top-level page.
// =============================================================================

function pickInitialTab(searchParams: URLSearchParams): TabId {
  const fromQuery = searchParams.get('tab');
  if (fromQuery === 'activity' || fromQuery === 'trust') return fromQuery;
  return 'profiles';
}

export default function ESTAdminPage() {
  const auth = useAuth();
  const adminAccess = !auth.authRequired || auth.admin;
  const [searchParams, setSearchParams] = useSearchParams();
  const _location = useLocation();
  void _location; // reserved for future deep-link cases (mirrors SCEPAdminPage)

  const [activeTab, setActiveTab] = useState<TabId>(() => pickInitialTab(searchParams));
  const [reloadTarget, setReloadTarget] = useState<ESTStatsSnapshot | null>(null);
  const [reloadError, setReloadError] = useState<string | undefined>(undefined);
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>('all');

  // Keep URL in sync with tab so deep links survive page reloads.
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (activeTab === 'profiles') {
      next.delete('tab');
    } else {
      next.set('tab', activeTab);
    }
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [activeTab, searchParams, setSearchParams]);

  // Per-profile snapshot. Polled every 30s on the profiles tab.
  const profilesQuery = useQuery({
    queryKey: ['admin', 'est', 'profiles'],
    queryFn: getAdminESTProfiles,
    enabled: adminAccess,
    refetchInterval: 30_000,
  });

  // EST audit-log queries — four parallel queries (one per action) so
  // the activity tab can present a merged + filterable feed without a
  // dedicated server endpoint.
  const auditQueries = EST_AUDIT_ACTIONS.map(action =>
    // eslint-disable-next-line react-hooks/rules-of-hooks
    useQuery({
      queryKey: ['audit', { action }],
      queryFn: () => getAuditEvents({ action }),
      enabled: adminAccess && activeTab === 'activity',
      refetchInterval: 60_000,
    }),
  );
  const allAuditEvents: AuditEvent[] = useMemo(() => {
    const merged: AuditEvent[] = [];
    for (const q of auditQueries) {
      if (q.data?.data) merged.push(...q.data.data);
    }
    return merged.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auditQueries.map(q => q.dataUpdatedAt).join('|')]);
  const auditLoading = auditQueries.some(q => q.isLoading);

  // M-009 useTrackedMutation guard: every mutation in this page MUST
  // route through useTrackedMutation so the audit / progress hooks fire.
  const reloadMutation = useTrackedMutation<
    Awaited<ReturnType<typeof reloadAdminESTTrust>>,
    Error,
    string
  >({
    mutationFn: (pathID: string) => reloadAdminESTTrust(pathID),
    invalidates: [['admin', 'est', 'profiles']],
    onSuccess: () => {
      setReloadTarget(null);
      setReloadError(undefined);
    },
    onError: (err: Error) => {
      setReloadError(err.message);
    },
  });

  if (auth.authRequired && !auth.admin) {
    return (
      <>
        <PageHeader title="EST Administration" subtitle="Admin-only observability surface" />
        <div className="p-6">
          <ErrorState
            error={
              new Error(
                'Admin access required: this page exposes per-profile mTLS trust-anchor expiries, auth-mode posture, per-status enrollment counters, and an admin-only reload action. Sign in with an admin-tagged API key to view it.',
              )
            }
          />
        </div>
      </>
    );
  }

  const profiles = profilesQuery.data?.profiles ?? [];

  return (
    <>
      <PageHeader
        title="EST Administration"
        subtitle={`${profiles.length} EST profile${profiles.length === 1 ? '' : 's'} configured · per-profile observability + recent activity + trust-bundle viewer`}
        action={
          <button
            type="button"
            onClick={() => {
              void profilesQuery.refetch();
            }}
            className="text-xs px-3 py-1.5 rounded border border-surface-border bg-surface hover:bg-surface-alt"
            data-testid="est-refresh-stats-button"
          >
            Refresh now
          </button>
        }
      />
      <div className="border-b border-surface-border bg-surface px-6">
        <nav className="flex gap-1 -mb-px" data-testid="est-admin-tabs">
          {(['profiles', 'activity', 'trust'] as TabId[]).map(t => (
            <button
              key={t}
              type="button"
              onClick={() => setActiveTab(t)}
              className={`px-4 py-2.5 text-sm border-b-2 transition-colors ${
                activeTab === t
                  ? 'border-brand-500 text-brand-700 font-semibold'
                  : 'border-transparent text-ink-muted hover:text-ink hover:border-surface-border'
              }`}
              data-testid={`est-tab-${t}`}
              aria-pressed={activeTab === t}
            >
              {TAB_LABELS[t]}
            </button>
          ))}
        </nav>
      </div>

      <div className="p-6 overflow-y-auto">
        {profilesQuery.error && activeTab === 'profiles' && (
          <ErrorState error={profilesQuery.error as Error} onRetry={() => profilesQuery.refetch()} />
        )}

        {activeTab === 'profiles' && !profilesQuery.error && (
          <ProfilesTab
            profiles={profiles}
            isLoading={profilesQuery.isLoading}
            onRequestReload={profile => {
              setReloadError(undefined);
              setReloadTarget(profile);
            }}
          />
        )}

        {activeTab === 'activity' && (
          <ActivityTab
            events={allAuditEvents}
            isLoading={auditLoading}
            filter={activityFilter}
            setFilter={setActivityFilter}
          />
        )}

        {activeTab === 'trust' && <TrustBundleTab profiles={profiles} />}
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
