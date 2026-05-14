import { Suspense, lazy, useEffect, useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { STALE_TIME } from '../api/queryConstants';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  getCertificates, getJobs, getHealth,
  getDashboardSummary, getCertificatesByStatus, getExpirationTimeline,
  getJobTrends, getIssuanceRate, previewDigest, sendDigest, getIssuers,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import Skeleton from '../components/Skeleton';
import { daysUntil, expiryColor, formatDate } from '../api/utils';
// Phase 4 closure (PERF-M1 + P-H3): memo-wrapped chart panels so a query
// refetch in one tile doesn't force every Recharts subtree to reconcile.
// See pages/dashboard/charts.tsx for the equality model.
import {
  CertsByStatusPieChart,
  ExpirationTimelineBarChart,
  JobTrendsLineChart,
  IssuanceRateBarChart,
  type PieDatum,
  type WeeklyExpirationDatum,
} from './dashboard/charts';
// Phase 4 closure (FE-M5): OnboardingWizard is 1043 LOC + only renders
// on first-run dashboards (one-time dismiss persisted to localStorage).
// Lazy-loading the wizard keeps its step-form code off the hot path for
// every dashboard load after the operator dismisses it once.
const OnboardingWizard = lazy(() => import('./OnboardingWizard'));

// formatStatus moved to pages/dashboard/charts.tsx in Phase 4 alongside
// the memoized chart panels that use it; deleted from here in Hotfix #8
// to close CodeQL js/unused-local-variable alert #35.

const STATUS_COLORS: Record<string, string> = {
  Active: '#10b981',
  Expiring: '#f59e0b',
  Expired: '#ef4444',
  Revoked: '#8b5cf6',
  Pending: '#6366f1',
  RenewalInProgress: '#2ea88f',
  Failed: '#f43f5e',
  Archived: '#64748b',
};

function StatCard({ label, value, icon, color }: { label: string; value: string | number; icon: string; color: string }) {
  const colorMap: Record<string, { bg: string; border: string; text: string }> = {
    success: { bg: 'bg-emerald-50', border: 'border-t-emerald-500', text: 'text-emerald-700' },
    warning: { bg: 'bg-amber-50', border: 'border-t-amber-500', text: 'text-amber-700' },
    danger:  { bg: 'bg-red-50', border: 'border-t-red-500', text: 'text-red-700' },
    info:    { bg: 'bg-blue-50', border: 'border-t-brand-400', text: 'text-brand-500' },
  };
  const config = colorMap[color] || colorMap.info;
  return (
    <div className={`bg-surface border border-surface-border border-t-4 ${config.border} rounded p-5 flex items-start gap-4 hover:bg-surface-muted transition-colors shadow-sm`}>
      <div className={`w-10 h-10 rounded flex items-center justify-center shrink-0 ${config.bg} ${config.text}`}>
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
        </svg>
      </div>
      <div>
        <p className="text-xs font-semibold text-ink-muted uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold mt-1 text-ink">{value}</p>
      </div>
    </div>
  );
}

// ChartCard + CustomTooltip + formatShortDate moved to
// pages/dashboard/charts.tsx (Phase 4 PERF-M1 closure) where they live
// alongside the memo-wrapped chart panels that consume them.

function DigestCard() {
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);

  const previewMutation = useTrackedMutation({
    mutationFn: previewDigest,
    invalidates: 'noop',
    noopReason: 'previewDigest is read-only — server renders HTML; no cached query touched',
    onSuccess: (html) => {
      setPreviewHtml(html);
      setShowPreview(true);
    },
  });

  const sendMutation = useTrackedMutation({
    mutationFn: sendDigest,
    invalidates: 'noop',
    noopReason: 'sendDigest dispatches an email server-side; no cached client query reflects digest-send state',
  });

  return (
    <>
      <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-ink-muted">Certificate Digest</h3>
            <p className="text-xs text-ink-faint mt-0.5">Send an email summary of certificate status to configured recipients</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => previewMutation.mutate()}
              disabled={previewMutation.isPending}
              className="btn btn-secondary text-xs"
            >
              {previewMutation.isPending ? 'Loading...' : 'Preview'}
            </button>
            <button
              onClick={() => sendMutation.mutate()}
              disabled={sendMutation.isPending}
              className="btn btn-primary text-xs"
            >
              {sendMutation.isPending ? 'Sending...' : 'Send Now'}
            </button>
          </div>
        </div>
        {sendMutation.isSuccess && (
          <div className="mt-3 text-xs text-emerald-600 bg-emerald-50 border border-emerald-200 rounded px-3 py-2">
            Digest sent successfully.
          </div>
        )}
        {sendMutation.isError && (
          <div className="mt-3 text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">
            Failed to send digest. Check SMTP configuration.
          </div>
        )}
        {previewMutation.isError && (
          <div className="mt-3 text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">
            Digest not configured. Set CERTCTL_DIGEST_ENABLED=true and configure SMTP.
          </div>
        )}
      </div>

      {/* Preview Modal */}
      {showPreview && previewHtml && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowPreview(false)}>
          <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200">
              <h3 className="text-sm font-semibold text-gray-700">Digest Email Preview</h3>
              <button onClick={() => setShowPreview(false)} className="text-gray-400 hover:text-gray-600">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="overflow-y-auto max-h-[calc(80vh-52px)]">
              <iframe
                srcDoc={previewHtml}
                title="Digest Preview"
                className="w-full h-[600px] border-0"
                sandbox=""
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Onboarding wizard state: once shown, stays shown until explicitly dismissed.
  // Uses a ref to "latch" the first-run detection so query refetches don't yank the wizard away.
  const [onboardingDismissed, setOnboardingDismissed] = useState(() => {
    try { return localStorage.getItem('certctl:onboarding-dismissed') === 'true'; } catch { return false; }
  });
  const [showWizard, setShowWizard] = useState(false);

  // Re-entry signal: sidebar "Setup guide" button navigates to /?onboarding=1 to reopen the wizard
  // even after dismissal. Takes precedence over localStorage dismissal; stripped on close.
  const forceOnboarding = searchParams.get('onboarding') === '1';

  // Phase 2 PERF-H1 closure: visibility-aware polling.
  // Pre-Phase-2: Dashboard fired 9 useQuery on mount with 8 polling
  // (1× 10s + 5× 30s + 2× 60s = ~18 background calls/min). When the
  // browser tab is hidden (operator working in a different tab) the
  // polling still fires — wasted backend cycles + battery.
  //
  // Fix: track document.visibilityState; when hidden, the
  // refetchInterval gate below returns false (paused). Also bump the
  // `jobs` poll from 10s → 30s — the live-tile reason (operator
  // watching a job finish) doesn't need 10s granularity when 30s is
  // already inside the human-attention window. The CertificateDetail
  // page is where 10s polling makes sense (the operator is staring
  // at the specific job they just kicked off).
  //
  // Backend-aggregation gap: ['dashboard-summary'] + ['certs-by-status']
  // + ['certificates', {}] could collapse into a single endpoint
  // (3 round-trips → 1) — tracked as a separate Phase-3 backend item.
  const queryClient = useQueryClient();
  const [tabVisible, setTabVisible] = useState(
    typeof document !== 'undefined' ? document.visibilityState === 'visible' : true,
  );
  useEffect(() => {
    if (typeof document === 'undefined') return;
    const handler = () => {
      const visible = document.visibilityState === 'visible';
      setTabVisible(visible);
      // When the tab becomes visible after being hidden, immediately
      // invalidate the dashboard live-tile queries so the operator
      // sees fresh data instead of waiting for the next poll tick.
      if (visible) {
        queryClient.invalidateQueries({ queryKey: ['health'] });
        queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
        queryClient.invalidateQueries({ queryKey: ['jobs', {}] });
        queryClient.invalidateQueries({ queryKey: ['certs-by-status'] });
      }
    };
    document.addEventListener('visibilitychange', handler);
    return () => document.removeEventListener('visibilitychange', handler);
  }, [queryClient]);

  // refetchInterval returns false (paused) when the tab is hidden;
  // otherwise the per-query base interval applies.
  const liveTileGate = (baseMs: number) => (tabVisible ? baseMs : false);

  // All hooks must be called unconditionally (React rules of hooks — no hooks after early returns)
  const { data: health } = useQuery({
    queryKey: ['health'], queryFn: getHealth,
    refetchInterval: liveTileGate(30_000),
    refetchOnWindowFocus: true, staleTime: STALE_TIME.REAL_TIME,
  });
  const { data: summary } = useQuery({
    queryKey: ['dashboard-summary'], queryFn: getDashboardSummary,
    refetchInterval: liveTileGate(30_000),
    refetchOnWindowFocus: true, staleTime: STALE_TIME.REAL_TIME,
  });
  const { data: issuersData } = useQuery({ queryKey: ['issuers'], queryFn: () => getIssuers() });
  const { data: statusCounts } = useQuery({
    queryKey: ['certs-by-status'], queryFn: getCertificatesByStatus,
    refetchInterval: liveTileGate(30_000),
    refetchOnWindowFocus: true, staleTime: STALE_TIME.REAL_TIME,
  });
  const { data: expirationTimeline } = useQuery({
    queryKey: ['expiration-timeline'], queryFn: () => getExpirationTimeline(90),
    refetchInterval: liveTileGate(60_000),
  });
  const { data: jobTrends } = useQuery({
    queryKey: ['job-trends'], queryFn: () => getJobTrends(30),
    refetchInterval: liveTileGate(30_000),
  });
  const { data: issuanceRate } = useQuery({
    queryKey: ['issuance-rate'], queryFn: () => getIssuanceRate(30),
    refetchInterval: liveTileGate(60_000),
  });
  const { data: certs } = useQuery({
    queryKey: ['certificates', {}], queryFn: () => getCertificates(),
    refetchInterval: liveTileGate(30_000),
  });
  const { data: jobs } = useQuery({
    queryKey: ['jobs', {}], queryFn: () => getJobs(),
    refetchInterval: liveTileGate(30_000),     // PERF-H1: 10s → 30s
    refetchOnWindowFocus: true, staleTime: STALE_TIME.REAL_TIME,
  });

  // Prepare pie chart data — memoized so the reference is stable across
  // re-renders that didn't change statusCounts. Without this useMemo the
  // chart's React.memo prop-equality check fails on every dashboard
  // re-render (fresh array every time) and the perf win evaporates.
  //
  // Hooks must be called unconditionally on every render path (Rules of
  // Hooks), so these live BEFORE the wizard early-return below — never
  // after it.
  const pieData = useMemo<PieDatum[]>(() => (
    (statusCounts || []).filter(s => s.count > 0).map(s => ({
      name: s.status,
      value: s.count,
      fill: STATUS_COLORS[s.status] || '#64748b',
    }))
  ), [statusCounts]);

  // Format expiration heatmap for display — aggregate weekly for 90 days.
  // Same useMemo reasoning as pieData above.
  const weeklyExpiration = useMemo<WeeklyExpirationDatum[]>(() => (
    (expirationTimeline || []).reduce<WeeklyExpirationDatum[]>((acc, bucket, i) => {
      const weekIdx = Math.floor(i / 7);
      if (!acc[weekIdx]) {
        acc[weekIdx] = { week: bucket.date, count: 0 };
      }
      acc[weekIdx].count += bucket.count;
      return acc;
    }, [])
  ), [expirationTimeline]);

  // Detect first-run ONCE: no user-configured issuers AND no certificates.
  // Auto-seeded env var issuers (source="env") don't count — they exist on every fresh boot.
  // Once showWizard latches true, it stays true until the user dismisses.
  const userConfiguredIssuers = (issuersData?.data ?? []).filter((i: { source?: string }) => i.source !== 'env');
  const isFirstRun = !onboardingDismissed &&
    summary !== undefined && issuersData !== undefined &&
    summary.total_certificates === 0 &&
    userConfiguredIssuers.length === 0;

  if ((isFirstRun || forceOnboarding) && !showWizard) {
    // Can't call setState during render — use a microtask
    setTimeout(() => setShowWizard(true), 0);
  }

  if ((showWizard && !onboardingDismissed) || forceOnboarding) {
    return (
      <Suspense fallback={<Skeleton variant="page" ariaLabel="Loading onboarding wizard" />}>
        <OnboardingWizard onDismiss={() => {
          try { localStorage.setItem('certctl:onboarding-dismissed', 'true'); } catch { /* noop */ }
          setOnboardingDismissed(true);
          setShowWizard(false);
          // Strip ?onboarding=1 so page refresh doesn't relaunch the wizard
          if (searchParams.has('onboarding')) {
            const next = new URLSearchParams(searchParams);
            next.delete('onboarding');
            setSearchParams(next, { replace: true });
          }
        }} />
      </Suspense>
    );
  }

  const totalCerts = summary?.total_certificates || 0;
  const expiringSoon = summary?.expiring_certificates || 0;
  const expired = summary?.expired_certificates || 0;
  const activeAgents = summary?.active_agents || 0;
  const pendingJobs = summary?.pending_jobs || 0;

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={health?.status === 'healthy' ? 'System healthy' : 'Checking system status...'}
      />
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <StatCard label="Total Certificates" value={totalCerts} color="info"
            icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          <StatCard label="Expiring Soon" value={expiringSoon} color={expiringSoon > 0 ? 'warning' : 'success'}
            icon="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          <StatCard label="Expired" value={expired} color={expired > 0 ? 'danger' : 'success'}
            icon="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          <StatCard label="Active Agents" value={activeAgents} color="success"
            icon="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
          <StatCard label="Pending Jobs" value={pendingJobs} color={pendingJobs > 0 ? 'warning' : 'info'}
            icon="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </div>

        {/* Charts Row 1 — memo-wrapped panels from pages/dashboard/charts.tsx
            (Phase 4 PERF-M1). Each panel re-renders only when its own data
            ref changes, so a refetch on one tile doesn't reconcile the
            other three Recharts subtrees. */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <CertsByStatusPieChart data={pieData} />
          <ExpirationTimelineBarChart data={weeklyExpiration} />
        </div>

        {/* Charts Row 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <JobTrendsLineChart data={jobTrends || []} />
          <IssuanceRateBarChart data={issuanceRate || []} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Expiring Certificates */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-ink-muted">Certificates Expiring Soon</h3>
              <button onClick={() => navigate('/certificates')} className="text-xs text-brand-400 hover:text-brand-500">View all</button>
            </div>
            {!certs?.data?.length ? (
              <p className="text-sm text-ink-faint">No certificates</p>
            ) : (
              <div className="space-y-2">
                {certs.data
                  .filter(c => c.status !== 'Archived')
                  .sort((a, b) => new Date(a.expires_at).getTime() - new Date(b.expires_at).getTime())
                  .slice(0, 5)
                  .map(c => {
                    const days = daysUntil(c.expires_at);
                    return (
                      <div
                        key={c.id}
                        onClick={() => navigate(`/certificates/${c.id}`)}
                        className="flex items-center justify-between py-2 px-3 rounded hover:bg-surface-muted cursor-pointer transition-colors"
                      >
                        <div>
                          <div className="text-sm text-ink">{c.common_name}</div>
                          <div className="text-xs text-ink-faint">{c.environment || 'no env'}</div>
                        </div>
                        <div className="text-right">
                          <div className={`text-sm ${expiryColor(days)}`}>
                            {days <= 0 ? 'Expired' : `${days} days`}
                          </div>
                          <div className="text-xs text-ink-faint">{formatDate(c.expires_at)}</div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            )}
          </div>

          {/* Recent Jobs */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-ink-muted">Recent Jobs</h3>
              <button onClick={() => navigate('/jobs')} className="text-xs text-brand-400 hover:text-brand-500">View all</button>
            </div>
            {!jobs?.data?.length ? (
              <p className="text-sm text-ink-faint">No jobs</p>
            ) : (
              <div className="space-y-2">
                {jobs.data.slice(0, 5).map(j => (
                  <div key={j.id} className="flex items-center justify-between py-2 px-3 rounded hover:bg-surface-muted transition-colors">
                    <div>
                      <div className="text-sm text-ink">{j.type}</div>
                      <div className="text-xs text-ink-faint font-mono">{j.certificate_id}</div>
                    </div>
                    <StatusBadge status={j.status} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Certificate Digest */}
        <DigestCard />

        {/* Pending Jobs Banner */}
        {pendingJobs > 0 && (
          <div className="bg-brand-50 border border-brand-200 rounded px-5 py-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-brand-600">{pendingJobs} pending job{pendingJobs > 1 ? 's' : ''}</p>
              <p className="text-xs text-brand-600/70 mt-0.5">Jobs are waiting to be processed</p>
            </div>
            <button onClick={() => navigate('/jobs')} className="btn btn-primary text-xs">View Jobs</button>
          </div>
        )}
      </div>
    </>
  );
}
