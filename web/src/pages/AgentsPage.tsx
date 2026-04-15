import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getAgents } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { timeAgo } from '../api/utils';
import type { Agent } from '../api/types';

function heartbeatStatus(lastHeartbeat: string): string {
  if (!lastHeartbeat) return 'Offline';
  const ago = Date.now() - new Date(lastHeartbeat).getTime();
  if (ago < 5 * 60 * 1000) return 'Online';
  if (ago < 15 * 60 * 1000) return 'Stale';
  return 'Offline';
}

export default function AgentsPage() {
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['agents'],
    queryFn: () => getAgents(),
    refetchInterval: 15000,
  });

  const columns: Column<Agent>[] = [
    {
      key: 'name',
      label: 'Agent',
      render: (a) => (
        <div>
          <div className="font-medium text-ink">{a.name}</div>
          <div className="text-xs text-ink-faint">{a.id}</div>
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Health',
      render: (a) => <StatusBadge status={a.status || heartbeatStatus(a.last_heartbeat_at)} />,
    },
    { key: 'hostname', label: 'Hostname', render: (a) => <span className="text-ink-muted font-mono text-xs">{a.hostname || '—'}</span> },
    { key: 'os', label: 'OS / Arch', render: (a) => <span className="text-ink-muted text-xs">{a.os && a.architecture ? `${a.os}/${a.architecture}` : a.os || '—'}</span> },
    { key: 'ip', label: 'IP Address', render: (a) => <span className="text-ink-muted font-mono text-xs">{a.ip_address || '—'}</span> },
    { key: 'version', label: 'Version', render: (a) => <span className="text-ink-muted text-xs">{a.version || '—'}</span> },
    {
      key: 'heartbeat',
      label: 'Last Heartbeat',
      render: (a) => <span className="text-ink-muted text-xs">{timeAgo(a.last_heartbeat_at)}</span>,
    },
  ];

  return (
    <>
      <PageHeader title="Agents" subtitle={data ? `${data.total} agents` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No agents registered" onRowClick={(a) => navigate(`/agents/${a.id}`)} />
        )}
      </div>
    </>
  );
}
