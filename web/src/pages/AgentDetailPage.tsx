import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getAgent, getJobs } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime, timeAgo } from '../api/utils';

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-2 border-b border-surface-border/50">
      <span className="text-sm text-ink-muted">{label}</span>
      <span className="text-sm text-ink">{value}</span>
    </div>
  );
}

function heartbeatStatus(lastHeartbeat: string): string {
  if (!lastHeartbeat) return 'Offline';
  const ago = Date.now() - new Date(lastHeartbeat).getTime();
  if (ago < 5 * 60 * 1000) return 'Online';
  if (ago < 15 * 60 * 1000) return 'Stale';
  return 'Offline';
}

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: agent, isLoading, error, refetch } = useQuery({
    queryKey: ['agent', id],
    queryFn: () => getAgent(id!),
    enabled: !!id,
    refetchInterval: 10000,
  });

  const { data: jobs } = useQuery({
    queryKey: ['agent-jobs', id],
    queryFn: () => getJobs({ per_page: '10' }),
    enabled: !!id,
  });

  // Filter jobs related to this agent (deployment jobs)
  const agentJobs = jobs?.data?.slice(0, 10) || [];

  if (isLoading) {
    return (
      <>
        <PageHeader title="Agent" />
        <div className="flex items-center justify-center flex-1 text-ink-muted">Loading...</div>
      </>
    );
  }

  if (error || !agent) {
    return (
      <>
        <PageHeader title="Agent" />
        <ErrorState error={error as Error || new Error('Not found')} onRetry={() => refetch()} />
      </>
    );
  }

  const health = agent.status || heartbeatStatus(agent.last_heartbeat_at);

  return (
    <>
      <PageHeader
        title={agent.name}
        subtitle={agent.id}
        action={
          <button onClick={() => navigate('/agents')} className="btn btn-ghost text-xs">Back</button>
        }
      />
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Agent Info */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Agent Details</h3>
            <InfoRow label="Health" value={<StatusBadge status={health} />} />
            <InfoRow label="Hostname" value={<span className="font-mono text-xs">{agent.hostname || '—'}</span>} />
            <InfoRow label="IP Address" value={<span className="font-mono text-xs">{agent.ip_address || '—'}</span>} />
            <InfoRow label="Version" value={agent.version || '—'} />
            <InfoRow label="Last Heartbeat" value={
              agent.last_heartbeat_at ? (
                <span>
                  {timeAgo(agent.last_heartbeat_at)}
                  <span className="text-ink-faint ml-2 text-xs">{formatDateTime(agent.last_heartbeat_at)}</span>
                </span>
              ) : '—'
            } />
            <InfoRow label="Registered" value={formatDateTime(agent.created_at)} />
            <InfoRow label="Updated" value={formatDateTime(agent.updated_at)} />
          </div>

          {/* System Info */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">System Information</h3>
            <InfoRow label="Operating System" value={agent.os || '—'} />
            <InfoRow label="Architecture" value={agent.architecture || '—'} />
            <InfoRow label="IP Address" value={<span className="font-mono text-xs">{agent.ip_address || '—'}</span>} />
            <InfoRow label="Agent Version" value={agent.version || '—'} />
            {agent.capabilities?.length ? (
              <div className="mt-4">
                <p className="text-xs text-ink-muted mb-2">Capabilities</p>
                <div className="flex flex-wrap gap-2">
                  {agent.capabilities.map((c) => (
                    <span key={c} className="badge badge-info">{c}</span>
                  ))}
                </div>
              </div>
            ) : null}
            {agent.tags && Object.keys(agent.tags).length > 0 ? (
              <div className="mt-4">
                <p className="text-xs text-ink-muted mb-2">Tags</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(agent.tags).map(([k, v]) => (
                    <span key={k} className="badge badge-neutral">{k}: {v}</span>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </div>

        {/* Recent Jobs */}
        <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-ink-muted mb-4">Recent Jobs</h3>
          {!agentJobs.length ? (
            <p className="text-sm text-ink-faint">No recent jobs</p>
          ) : (
            <div className="space-y-2">
              {agentJobs.map(j => (
                <div key={j.id} className="flex items-center justify-between py-2 px-3 rounded hover:bg-surface-muted transition-colors">
                  <div>
                    <div className="text-sm text-ink">{j.type}</div>
                    <div className="text-xs text-ink-faint font-mono">{j.id}</div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-ink-muted font-mono">{j.certificate_id}</span>
                    <StatusBadge status={j.status} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Heartbeat Timeline */}
        <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-ink-muted mb-4">Heartbeat Status</h3>
          <div className="flex items-center gap-4">
            <div className={`w-3 h-3 rounded-full ${
              health === 'Online' ? 'bg-emerald-500 animate-pulse' :
              health === 'Stale' ? 'bg-amber-500' : 'bg-red-500'
            }`} />
            <div>
              <p className="text-sm text-ink">{health}</p>
              <p className="text-xs text-ink-muted">
                {health === 'Online' && 'Agent is responding to heartbeat checks'}
                {health === 'Stale' && 'Agent has not sent a heartbeat recently'}
                {health === 'Offline' && 'Agent is not responding'}
              </p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
