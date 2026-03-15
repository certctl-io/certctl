import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getCertificates, getAgents, getJobs, getNotifications, getHealth } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import { daysUntil, expiryColor, formatDate } from '../api/utils';

function StatCard({ label, value, icon, color }: { label: string; value: string | number; icon: string; color: string }) {
  const colorMap: Record<string, string> = {
    success: 'bg-emerald-500/10 text-emerald-400',
    warning: 'bg-amber-500/10 text-amber-400',
    danger:  'bg-red-500/10 text-red-400',
    info:    'bg-blue-500/10 text-blue-400',
  };
  return (
    <div className="card p-5 flex items-start gap-4 hover:border-blue-500/30 transition-colors">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${colorMap[color] || colorMap.info}`}>
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
        </svg>
      </div>
      <div>
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold mt-1">{value}</p>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();

  const { data: health } = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 30000 });
  const { data: certs } = useQuery({ queryKey: ['certificates', {}], queryFn: () => getCertificates(), refetchInterval: 30000 });
  const { data: agents } = useQuery({ queryKey: ['agents'], queryFn: () => getAgents(), refetchInterval: 15000 });
  const { data: jobs } = useQuery({ queryKey: ['jobs', {}], queryFn: () => getJobs(), refetchInterval: 10000 });
  const { data: notifs } = useQuery({ queryKey: ['notifications'], queryFn: () => getNotifications() });

  const totalCerts = certs?.total || 0;
  const expiringSoon = certs?.data?.filter(c => {
    const d = daysUntil(c.expires_at);
    return d > 0 && d <= 30;
  }).length || 0;
  const expired = certs?.data?.filter(c => c.status === 'Expired' || daysUntil(c.expires_at) <= 0).length || 0;
  const activeAgents = agents?.data?.filter(a => a.status === 'Online').length || agents?.total || 0;
  const pendingJobs = jobs?.data?.filter(j => j.status === 'Pending' || j.status === 'Running').length || 0;

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={health?.status === 'healthy' ? 'System healthy' : 'Checking system status...'}
      />
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total Certificates" value={totalCerts} color="info"
            icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          <StatCard label="Expiring Soon" value={expiringSoon} color={expiringSoon > 0 ? 'warning' : 'success'}
            icon="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          <StatCard label="Expired" value={expired} color={expired > 0 ? 'danger' : 'success'}
            icon="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          <StatCard label="Active Agents" value={activeAgents} color="success"
            icon="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Expiring Certificates */}
          <div className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-slate-300">Certificates Expiring Soon</h3>
              <button onClick={() => navigate('/certificates')} className="text-xs text-blue-400 hover:text-blue-300">View all</button>
            </div>
            {!certs?.data?.length ? (
              <p className="text-sm text-slate-500">No certificates</p>
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
                        className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-slate-700/50 cursor-pointer transition-colors"
                      >
                        <div>
                          <div className="text-sm text-slate-200">{c.common_name}</div>
                          <div className="text-xs text-slate-500">{c.environment || 'no env'}</div>
                        </div>
                        <div className="text-right">
                          <div className={`text-sm ${expiryColor(days)}`}>
                            {days <= 0 ? 'Expired' : `${days} days`}
                          </div>
                          <div className="text-xs text-slate-500">{formatDate(c.expires_at)}</div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            )}
          </div>

          {/* Recent Jobs */}
          <div className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-slate-300">Recent Jobs</h3>
              <button onClick={() => navigate('/jobs')} className="text-xs text-blue-400 hover:text-blue-300">View all</button>
            </div>
            {!jobs?.data?.length ? (
              <p className="text-sm text-slate-500">No jobs</p>
            ) : (
              <div className="space-y-2">
                {jobs.data.slice(0, 5).map(j => (
                  <div key={j.id} className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-slate-700/50 transition-colors">
                    <div>
                      <div className="text-sm text-slate-200">{j.type}</div>
                      <div className="text-xs text-slate-500 font-mono">{j.certificate_id}</div>
                    </div>
                    <StatusBadge status={j.status} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Pending Jobs Banner */}
        {pendingJobs > 0 && (
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg px-5 py-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-blue-400">{pendingJobs} pending job{pendingJobs > 1 ? 's' : ''}</p>
              <p className="text-xs text-slate-400 mt-0.5">Jobs are waiting to be processed</p>
            </div>
            <button onClick={() => navigate('/jobs')} className="btn btn-primary text-xs">View Jobs</button>
          </div>
        )}
      </div>
    </>
  );
}
