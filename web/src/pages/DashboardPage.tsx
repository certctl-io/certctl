import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import {
  getCertificates, getAgents, getJobs, getNotifications, getHealth,
  getDashboardSummary, getCertificatesByStatus, getExpirationTimeline,
  getJobTrends, getIssuanceRate, previewDigest, sendDigest, getIssuers,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import { daysUntil, expiryColor, formatDate } from '../api/utils';
import OnboardingWizard from './OnboardingWizard';

// Convert PascalCase status like "RenewalInProgress" to "Renewal In Progress"
const formatStatus = (s: string) => s.replace(/([a-z])([A-Z])/g, '$1 $2');

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

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
      <h3 className="text-sm font-semibold text-ink-muted mb-4">{title}</h3>
      <div className="h-64">
        {children}
      </div>
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-surface border border-surface-border rounded px-3 py-2 text-xs shadow-lg">
      <p className="text-ink mb-1">{label}</p>
      {payload.map((entry: any, i: number) => (
        <p key={i} style={{ color: entry.color }}>
          {entry.name}: {typeof entry.value === 'number' && entry.name?.includes('rate') ? `${entry.value.toFixed(1)}%` : entry.value}
        </p>
      ))}
    </div>
  );
};

function DigestCard() {
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);

  const previewMutation = useMutation({
    mutationFn: previewDigest,
    onSuccess: (html) => {
      setPreviewHtml(html);
      setShowPreview(true);
    },
  });

  const sendMutation = useMutation({ mutationFn: sendDigest });

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

  // All hooks must be called unconditionally (React rules of hooks — no hooks after early returns)
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 30000 });
  const { data: summary } = useQuery({ queryKey: ['dashboard-summary'], queryFn: getDashboardSummary, refetchInterval: 30000 });
  const { data: issuersData } = useQuery({ queryKey: ['issuers'], queryFn: () => getIssuers() });
  const { data: statusCounts } = useQuery({ queryKey: ['certs-by-status'], queryFn: getCertificatesByStatus, refetchInterval: 30000 });
  const { data: expirationTimeline } = useQuery({ queryKey: ['expiration-timeline'], queryFn: () => getExpirationTimeline(90), refetchInterval: 60000 });
  const { data: jobTrends } = useQuery({ queryKey: ['job-trends'], queryFn: () => getJobTrends(30), refetchInterval: 30000 });
  const { data: issuanceRate } = useQuery({ queryKey: ['issuance-rate'], queryFn: () => getIssuanceRate(30), refetchInterval: 60000 });
  const { data: certs } = useQuery({ queryKey: ['certificates', {}], queryFn: () => getCertificates(), refetchInterval: 30000 });
  const { data: jobs } = useQuery({ queryKey: ['jobs', {}], queryFn: () => getJobs(), refetchInterval: 10000 });

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
    );
  }

  const totalCerts = summary?.total_certificates || 0;
  const expiringSoon = summary?.expiring_certificates || 0;
  const expired = summary?.expired_certificates || 0;
  const activeAgents = summary?.active_agents || 0;
  const pendingJobs = summary?.pending_jobs || 0;

  // Prepare pie chart data
  const pieData = (statusCounts || []).filter(s => s.count > 0).map(s => ({
    name: s.status,
    value: s.count,
    fill: STATUS_COLORS[s.status] || '#64748b',
  }));

  // Format expiration heatmap for display — aggregate weekly for 90 days
  const weeklyExpiration = (expirationTimeline || []).reduce<{ week: string; count: number }[]>((acc, bucket, i) => {
    const weekIdx = Math.floor(i / 7);
    if (!acc[weekIdx]) {
      acc[weekIdx] = { week: bucket.date, count: 0 };
    }
    acc[weekIdx].count += bucket.count;
    return acc;
  }, []);

  // Format dates for x-axis labels
  const formatShortDate = (dateStr: string) => {
    const d = new Date(dateStr + 'T00:00:00');
    return `${d.getMonth() + 1}/${d.getDate()}`;
  };

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

        {/* Charts Row 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Certificates by Status (Pie) */}
          <ChartCard title="Certificates by Status">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, value }) => `${formatStatus(name || '')}: ${value}`}
                    labelLine={false}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={index} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    formatter={(value: string) => <span className="text-xs text-ink-muted">{formatStatus(value)}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-ink-faint">No certificate data</div>
            )}
          </ChartCard>

          {/* Expiration Heatmap (Bar chart by week) */}
          <ChartCard title="Expiration Timeline (Next 90 Days)">
            {weeklyExpiration.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={weeklyExpiration}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="week" tick={{ fill: '#64748b', fontSize: 11 }} tickFormatter={formatShortDate} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="count" name="Expiring certs" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-ink-faint">No expiration data</div>
            )}
          </ChartCard>
        </div>

        {/* Charts Row 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Job Trends (Line chart) */}
          <ChartCard title="Job Success/Failure Trends (30 Days)">
            {(jobTrends || []).length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={jobTrends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} tickFormatter={formatShortDate} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend formatter={(value: string) => <span className="text-xs text-ink-muted">{value}</span>} />
                  <Line type="monotone" dataKey="completed_count" name="Completed" stroke="#10b981" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="failed_count" name="Failed" stroke="#ef4444" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-ink-faint">No job trend data</div>
            )}
          </ChartCard>

          {/* Issuance Rate (Bar chart) */}
          <ChartCard title="Certificate Issuance Rate (30 Days)">
            {(issuanceRate || []).length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={issuanceRate}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} tickFormatter={formatShortDate} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="issued_count" name="Issued" fill="#2ea88f" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-ink-faint">No issuance data</div>
            )}
          </ChartCard>
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
