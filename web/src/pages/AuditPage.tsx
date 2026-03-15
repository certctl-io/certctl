import { useQuery } from '@tanstack/react-query';
import { getAuditEvents } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { AuditEvent } from '../api/types';

const actionColors: Record<string, string> = {
  certificate_created: 'text-emerald-400',
  renewal_triggered: 'text-blue-400',
  renewal_job_created: 'text-blue-400',
  renewal_completed: 'text-emerald-400',
  deployment_completed: 'text-emerald-400',
  deployment_failed: 'text-red-400',
  expiration_alert_sent: 'text-amber-400',
  agent_registered: 'text-blue-400',
  policy_violated: 'text-red-400',
};

export default function AuditPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['audit'],
    queryFn: () => getAuditEvents(),
    refetchInterval: 30000,
  });

  const columns: Column<AuditEvent>[] = [
    {
      key: 'action',
      label: 'Action',
      render: (e) => (
        <span className={`text-sm font-medium ${actionColors[e.action] || 'text-slate-300'}`}>
          {e.action.replace(/_/g, ' ')}
        </span>
      ),
    },
    {
      key: 'actor',
      label: 'Actor',
      render: (e) => (
        <div>
          <div className="text-sm text-slate-200">{e.actor}</div>
          <div className="text-xs text-slate-500">{e.actor_type}</div>
        </div>
      ),
    },
    {
      key: 'resource',
      label: 'Resource',
      render: (e) => (
        <div>
          <div className="text-sm text-slate-300">{e.resource_type}</div>
          <div className="text-xs text-slate-500 font-mono">{e.resource_id}</div>
        </div>
      ),
    },
    {
      key: 'details',
      label: 'Details',
      render: (e) => {
        if (!e.details || Object.keys(e.details).length === 0) return <span className="text-slate-500">—</span>;
        return (
          <span className="text-xs text-slate-400 font-mono truncate max-w-xs block">
            {JSON.stringify(e.details).slice(0, 60)}
          </span>
        );
      },
    },
    { key: 'time', label: 'Time', render: (e) => <span className="text-xs text-slate-400">{formatDateTime(e.timestamp)}</span> },
  ];

  return (
    <>
      <PageHeader title="Audit Trail" subtitle={data ? `${data.total} events` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No audit events" />
        )}
      </div>
    </>
  );
}
