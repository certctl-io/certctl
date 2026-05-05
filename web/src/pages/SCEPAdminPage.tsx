import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useLocation, useSearchParams } from 'react-router-dom';
import {
  getAdminSCEPIntuneStats,
  getAdminSCEPProfiles,
  reloadAdminSCEPIntuneTrust,
  getAuditEvents,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import ErrorState from '../components/ErrorState';
import { useAuth } from '../components/AuthProvider';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { formatDateTime } from '../api/utils';
import type {
  IntuneStatsSnapshot,
  IntuneTrustAnchorInfo,
  AuditEvent,
  SCEPProfileStatsSnapshot,
} from '../api/types';

// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up
// (the project's SCEP GUI restructure spec): per-profile SCEP
// administration page with three tabs.
//
//   Profiles (default)  — every configured SCEP profile, lean card per
//                         profile with always-present fields (RA cert
//                         expiry, mTLS sibling-route status,
//                         challenge-password-set indicator). Cards on
//                         Intune-enabled profiles get a "View Intune
//                         details →" link that deep-links to the
//                         Intune tab filtered to that profile.
//   Intune Monitoring   — the existing Phase 9.4 deep-dive. Per-profile
//                         counters (success / signature_invalid /
//                         claim_mismatch / expired / wrong_audience /
//                         replay / rate_limited / malformed /
//                         compliance_failed / not_yet_valid /
//                         unknown_version), trust anchor expiry
//                         countdown, recent failures table, reload-
//                         trust button + confirmation modal. Polled
//                         every 30s via TanStack Query.
//   Recent Activity     — full SCEP audit log filter covering all four
//                         action codes (scep_pkcsreq, scep_renewalreq,
//                         scep_pkcsreq_intune, scep_renewalreq_intune).
//                         Merged + sorted descending by timestamp.
//                         Filter chips for All / Initial / Renewal /
//                         Intune / Static. Polled every 60s.
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

type TabId = 'profiles' | 'intune' | 'activity';
type ActivityFilter = 'all' | 'initial' | 'renewal' | 'intune' | 'static';

const TAB_LABELS: Record<TabId, string> = {
  profiles: 'Profiles',
  intune: 'Intune Monitoring',
  activity: 'Recent Activity',
};

const SCEP_AUDIT_ACTIONS = [
  'scep_pkcsreq',
  'scep_renewalreq',
  'scep_pkcsreq_intune',
  'scep_renewalreq_intune',
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
// profile's Intune trust anchor pool. Returns null when the pool is
// empty (the per-profile preflight should have refused this state at
// boot, but defensive in case the holder is reloaded mid-flight to an
// empty file).
function soonestExpiryDays(anchors?: IntuneTrustAnchorInfo[]): number | null {
  if (!anchors || anchors.length === 0) return null;
  let min = Number.POSITIVE_INFINITY;
  for (const a of anchors) {
    if (a.expired) return -1;
    if (a.days_to_expiry < min) min = a.days_to_expiry;
  }
  return min === Number.POSITIVE_INFINITY ? null : min;
}

// =============================================================================
// Profiles tab — per-profile lean card with always-present fields.
// =============================================================================

interface ProfilesTabProps {
  profiles: SCEPProfileStatsSnapshot[];
  isLoading: boolean;
  onViewIntuneDetails: (pathID: string) => void;
}

function ProfilesTab({ profiles, isLoading, onViewIntuneDetails }: ProfilesTabProps) {
  if (isLoading) {
    return <p className="text-sm text-ink-muted px-1 py-6">Loading profiles…</p>;
  }
  if (profiles.length === 0) {
    return (
      <div className="rounded border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">
        No SCEP profiles are configured. Set <code>CERTCTL_SCEP_ENABLED=true</code> and either the
        legacy single-profile env vars or <code>CERTCTL_SCEP_PROFILES=...</code> with the indexed
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
          onViewIntuneDetails={onViewIntuneDetails}
        />
      ))}
    </>
  );
}

interface ProfileSummaryCardProps {
  profile: SCEPProfileStatsSnapshot;
  onViewIntuneDetails: (pathID: string) => void;
}

function ProfileSummaryCard({ profile, onViewIntuneDetails }: ProfileSummaryCardProps) {
  const pathLabel = profile.path_id || '(legacy /scep root)';
  const intuneEnabled = !!profile.intune;
  const raBadge = expiryBadge(
    profile.ra_cert_subject ? profile.ra_cert_days_to_expiry : null,
    profile.ra_cert_expired,
  );

  return (
    <section
      className="bg-surface border border-surface-border rounded-lg p-5 mb-4"
      data-testid={`profile-summary-${profile.path_id}`}
    >
      <header className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-base font-semibold text-ink">{pathLabel}</h3>
          <p className="text-xs text-ink-muted">Issuer: {profile.issuer_id}</p>
        </div>
        <span
          className={`text-xs px-2 py-0.5 rounded-full font-medium ${badgeClass(raBadge.tone)}`}
          data-testid={`ra-expiry-badge-${profile.path_id}`}
        >
          RA cert: {raBadge.text}
        </span>
      </header>

      <div className="flex flex-wrap gap-2 mb-3" data-testid={`profile-badges-${profile.path_id}`}>
        <span className={`text-[11px] uppercase tracking-wide px-2 py-0.5 rounded border ${pillClass(profile.challenge_password_set)}`}>
          Challenge password{profile.challenge_password_set ? ' set' : ' MISSING'}
        </span>
        <span className={`text-[11px] uppercase tracking-wide px-2 py-0.5 rounded border ${pillClass(profile.mtls_enabled)}`}>
          mTLS {profile.mtls_enabled ? 'enabled' : 'disabled'}
        </span>
        <span className={`text-[11px] uppercase tracking-wide px-2 py-0.5 rounded border ${pillClass(intuneEnabled)}`}>
          Intune {intuneEnabled ? 'enabled' : 'disabled'}
        </span>
      </div>

      <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs text-ink-muted">
        <div>
          <dt className="font-semibold text-ink">RA cert subject</dt>
          <dd className="font-mono text-[11px]">{profile.ra_cert_subject || '(not loaded)'}</dd>
        </div>
        {profile.ra_cert_not_after && (
          <div>
            <dt className="font-semibold text-ink">RA cert expires</dt>
            <dd>{formatDateTime(profile.ra_cert_not_after)}</dd>
          </div>
        )}
        {profile.mtls_enabled && profile.mtls_trust_bundle_path && (
          <div>
            <dt className="font-semibold text-ink">mTLS trust bundle</dt>
            <dd className="font-mono text-[11px]">{profile.mtls_trust_bundle_path}</dd>
          </div>
        )}
      </dl>

      {intuneEnabled && (
        <div className="mt-4 pt-3 border-t border-surface-border flex justify-end">
          <button
            type="button"
            onClick={() => onViewIntuneDetails(profile.path_id)}
            className="text-xs text-brand-600 hover:text-brand-800 font-medium"
            data-testid={`view-intune-details-${profile.path_id}`}
          >
            View Intune details →
          </button>
        </div>
      )}
    </section>
  );
}

// =============================================================================
// Intune Monitoring tab — the existing Phase 9.4 deep-dive surface.
// =============================================================================

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

interface IntuneTabProps {
  profiles: IntuneStatsSnapshot[];
  isLoading: boolean;
  onRequestReload: (profile: IntuneStatsSnapshot) => void;
  highlightPathID: string | null;
  events: AuditEvent[];
  eventsLoading: boolean;
}

function IntuneTab({ profiles, isLoading, onRequestReload, highlightPathID, events, eventsLoading }: IntuneTabProps) {
  if (isLoading) {
    return <p className="text-sm text-ink-muted px-1 py-6">Loading Intune monitoring data…</p>;
  }
  const intuneProfiles = profiles.filter(p => p.enabled);
  return (
    <>
      {intuneProfiles.length === 0 && (
        <div className="rounded border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 mb-4">
          No SCEP profile has Intune enabled. Set
          <code className="mx-1">CERTCTL_SCEP_PROFILE_&lt;NAME&gt;_INTUNE_ENABLED=true</code>
          plus the matching trust-anchor path env var, then restart the server.
        </div>
      )}
      {intuneProfiles.map(p => (
        <IntuneProfileCard
          key={p.path_id || '(root)'}
          profile={p}
          onRequestReload={onRequestReload}
          highlighted={highlightPathID === p.path_id}
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
        {eventsLoading ? (
          <p className="text-sm text-ink-muted px-4 py-6">Loading audit log…</p>
        ) : (
          <RecentEventsTable events={events.slice(0, 50)} testID="intune-failures-table" emptyMessage="No recent Intune-dispatched enrollment events. Counters stay at zero until the first device hits a SCEP profile with Intune enabled." />
        )}
      </section>
    </>
  );
}

interface IntuneProfileCardProps {
  profile: IntuneStatsSnapshot;
  onRequestReload: (profile: IntuneStatsSnapshot) => void;
  highlighted: boolean;
}

function IntuneProfileCard({ profile, onRequestReload, highlighted }: IntuneProfileCardProps) {
  const pathLabel = profile.path_id || '(legacy /scep root)';
  const days = soonestExpiryDays(profile.trust_anchors);
  const badge = expiryBadge(days, days !== null && days < 0);
  const cardClass = highlighted
    ? 'bg-surface border-2 border-brand-400 rounded-lg p-5 mb-4 shadow-sm'
    : 'bg-surface border border-surface-border rounded-lg p-5 mb-4';

  return (
    <section className={cardClass} data-testid={`profile-card-${profile.path_id}`}>
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
            className={`text-xs px-2 py-0.5 rounded-full font-medium ${badgeClass(badge.tone)}`}
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

// =============================================================================
// Recent Activity tab — full SCEP audit log filter.
// =============================================================================

interface ActivityTabProps {
  events: AuditEvent[];
  isLoading: boolean;
  filter: ActivityFilter;
  setFilter: (f: ActivityFilter) => void;
}

function activityFilterMatches(filter: ActivityFilter, action: string): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'initial':
      return action === 'scep_pkcsreq' || action === 'scep_pkcsreq_intune';
    case 'renewal':
      return action === 'scep_renewalreq' || action === 'scep_renewalreq_intune';
    case 'intune':
      return action === 'scep_pkcsreq_intune' || action === 'scep_renewalreq_intune';
    case 'static':
      return action === 'scep_pkcsreq' || action === 'scep_renewalreq';
  }
}

function ActivityTab({ events, isLoading, filter, setFilter }: ActivityTabProps) {
  const filtered = events.filter(e => activityFilterMatches(filter, e.action));
  return (
    <section className="bg-surface border border-surface-border rounded-lg" data-testid="activity-tab">
      <div className="px-4 py-3 border-b border-surface-border">
        <h3 className="text-sm font-semibold text-ink">SCEP enrollment audit log (last 100)</h3>
        <p className="text-xs text-ink-muted mb-3">
          Merged across <code>scep_pkcsreq</code> + <code>scep_renewalreq</code> +
          <code> scep_pkcsreq_intune</code> + <code>scep_renewalreq_intune</code>. Refreshes every 60s.
        </p>
        <div className="flex flex-wrap gap-2" data-testid="activity-filter-chips">
          {(['all', 'initial', 'renewal', 'intune', 'static'] as const).map(f => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={`text-xs px-2 py-1 rounded border ${
                filter === f
                  ? 'bg-brand-100 text-brand-800 border-brand-300'
                  : 'bg-surface text-ink-muted border-surface-border hover:bg-surface-alt'
              }`}
              data-testid={`activity-filter-${f}`}
            >
              {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>
      {isLoading ? (
        <p className="text-sm text-ink-muted px-4 py-6">Loading audit log…</p>
      ) : (
        <RecentEventsTable
          events={filtered.slice(0, 100)}
          testID="activity-events-table"
          emptyMessage={
            events.length === 0
              ? 'No SCEP enrollment events recorded yet.'
              : 'No events match the current filter — try a different chip.'
          }
        />
      )}
    </section>
  );
}

// =============================================================================
// Shared events table.
// =============================================================================

interface RecentEventsTableProps {
  events: AuditEvent[];
  testID: string;
  emptyMessage: string;
}

function RecentEventsTable({ events, testID, emptyMessage }: RecentEventsTableProps) {
  if (events.length === 0) {
    return <p className="text-sm text-ink-muted px-4 py-6">{emptyMessage}</p>;
  }
  return (
    <table className="w-full text-sm" data-testid={testID}>
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

// =============================================================================
// Top-level page.
// =============================================================================

// pickInitialTab honors three signals (precedence high → low):
//   1. ?tab=intune|activity in the query string (deep link)
//   2. Pathname ending in /scep/intune (legacy route alias from
//      Phase 9.4; preserved so external bookmarks land on Intune)
//   3. Default to 'profiles'
function pickInitialTab(searchParams: URLSearchParams, pathname: string): TabId {
  const fromQuery = searchParams.get('tab');
  if (fromQuery === 'intune' || fromQuery === 'activity') return fromQuery;
  if (pathname.endsWith('/scep/intune')) return 'intune';
  return 'profiles';
}

export default function SCEPAdminPage() {
  const auth = useAuth();
  const adminAccess = !auth.authRequired || auth.admin;
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();

  const [activeTab, setActiveTab] = useState<TabId>(() => pickInitialTab(searchParams, location.pathname));
  const [highlightPathID, setHighlightPathID] = useState<string | null>(searchParams.get('profile'));
  const [reloadTarget, setReloadTarget] = useState<IntuneStatsSnapshot | null>(null);
  const [reloadError, setReloadError] = useState<string | undefined>(undefined);
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>('all');

  // Keep URL in sync with tab + highlighted profile so deep links survive
  // page reloads + browser back/forward.
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (activeTab === 'profiles') {
      next.delete('tab');
    } else {
      next.set('tab', activeTab);
    }
    if (highlightPathID && activeTab === 'intune') {
      next.set('profile', highlightPathID);
    } else {
      next.delete('profile');
    }
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [activeTab, highlightPathID, searchParams, setSearchParams]);

  // Always-present per-profile data (Profiles tab).
  const profilesQuery = useQuery({
    queryKey: ['admin', 'scep', 'profiles'],
    queryFn: getAdminSCEPProfiles,
    enabled: adminAccess,
    refetchInterval: 30_000,
  });

  // Intune deep-dive data (Intune tab).
  const intuneStatsQuery = useQuery({
    queryKey: ['admin', 'scep', 'intune', 'stats'],
    queryFn: getAdminSCEPIntuneStats,
    enabled: adminAccess && activeTab === 'intune',
    refetchInterval: 30_000,
  });

  // Audit log queries — four parallel queries (one per SCEP action) so
  // both the Intune tab's recent-failures table and the Activity tab's
  // full SCEP audit feed can pull from the same React Query cache.
  const auditQueries = SCEP_AUDIT_ACTIONS.map(action =>
    // eslint-disable-next-line react-hooks/rules-of-hooks
    useQuery({
      queryKey: ['audit', { action }],
      queryFn: () => getAuditEvents({ action }),
      enabled: adminAccess && (activeTab === 'intune' || activeTab === 'activity'),
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
  const intuneOnlyEvents = useMemo(
    () =>
      allAuditEvents.filter(
        e => e.action === 'scep_pkcsreq_intune' || e.action === 'scep_renewalreq_intune',
      ),
    [allAuditEvents],
  );

  const reloadMutation = useTrackedMutation<
    Awaited<ReturnType<typeof reloadAdminSCEPIntuneTrust>>,
    Error,
    string
  >({
    mutationFn: (pathID: string) => reloadAdminSCEPIntuneTrust(pathID),
    invalidates: [
      ['admin', 'scep', 'intune', 'stats'],
      ['admin', 'scep', 'profiles'],
    ],
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
        <PageHeader title="SCEP Administration" subtitle="Admin-only observability surface" />
        <div className="p-6">
          <ErrorState
            error={new Error('Admin access required: this page exposes per-profile RA cert expiries, mTLS bundle paths, Intune trust anchor expiries, and an admin-only reload action. Sign in with an admin-tagged API key to view it.')}
          />
        </div>
      </>
    );
  }

  const profiles = profilesQuery.data?.profiles ?? [];
  const intuneProfiles = intuneStatsQuery.data?.profiles ?? [];

  const handleViewIntuneDetails = (pathID: string) => {
    setHighlightPathID(pathID);
    setActiveTab('intune');
  };

  return (
    <>
      <PageHeader
        title="SCEP Administration"
        subtitle={`${profiles.length} SCEP profile${profiles.length === 1 ? '' : 's'} configured · per-profile observability + Intune monitoring + recent activity`}
        action={
          <button
            type="button"
            onClick={() => {
              void profilesQuery.refetch();
              if (activeTab === 'intune') void intuneStatsQuery.refetch();
            }}
            className="text-xs px-3 py-1.5 rounded border border-surface-border bg-surface hover:bg-surface-alt"
            data-testid="refresh-stats-button"
          >
            Refresh now
          </button>
        }
      />
      <div className="border-b border-surface-border bg-surface px-6">
        <nav className="flex gap-1 -mb-px" data-testid="scep-admin-tabs">
          {(['profiles', 'intune', 'activity'] as TabId[]).map(t => (
            <button
              key={t}
              type="button"
              onClick={() => setActiveTab(t)}
              className={`px-4 py-2.5 text-sm border-b-2 transition-colors ${
                activeTab === t
                  ? 'border-brand-500 text-brand-700 font-semibold'
                  : 'border-transparent text-ink-muted hover:text-ink hover:border-surface-border'
              }`}
              data-testid={`tab-${t}`}
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
        {intuneStatsQuery.error && activeTab === 'intune' && (
          <ErrorState error={intuneStatsQuery.error as Error} onRetry={() => intuneStatsQuery.refetch()} />
        )}

        {activeTab === 'profiles' && !profilesQuery.error && (
          <ProfilesTab
            profiles={profiles}
            isLoading={profilesQuery.isLoading}
            onViewIntuneDetails={handleViewIntuneDetails}
          />
        )}

        {activeTab === 'intune' && !intuneStatsQuery.error && (
          <IntuneTab
            profiles={intuneProfiles}
            isLoading={intuneStatsQuery.isLoading}
            onRequestReload={profile => {
              setReloadError(undefined);
              setReloadTarget(profile);
            }}
            highlightPathID={highlightPathID}
            events={intuneOnlyEvents}
            eventsLoading={auditLoading}
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
