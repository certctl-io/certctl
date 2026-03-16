import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getTargets, deleteTarget } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Target } from '../api/types';

const typeLabels: Record<string, string> = {
  nginx: 'NGINX',
  f5_bigip: 'F5 BIG-IP',
  iis: 'IIS',
  apache: 'Apache',
  haproxy: 'HAProxy',
};

export default function TargetsPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['targets'],
    queryFn: () => getTargets(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteTarget,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['targets'] }),
  });

  const columns: Column<Target>[] = [
    {
      key: 'name',
      label: 'Target',
      render: (t) => (
        <div>
          <div className="font-medium text-slate-200">{t.name}</div>
          <div className="text-xs text-slate-500 font-mono">{t.id}</div>
        </div>
      ),
    },
    {
      key: 'type',
      label: 'Type',
      render: (t) => (
        <span className="badge badge-neutral">{typeLabels[t.type] || t.type}</span>
      ),
    },
    {
      key: 'hostname',
      label: 'Hostname',
      render: (t) => <span className="text-slate-300 font-mono text-xs">{t.hostname || '\u2014'}</span>,
    },
    {
      key: 'agent',
      label: 'Agent',
      render: (t) => <span className="text-xs text-slate-400 font-mono">{t.agent_id || '\u2014'}</span>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (t) => <StatusBadge status={t.status} />,
    },
    {
      key: 'created',
      label: 'Created',
      render: (t) => <span className="text-xs text-slate-400">{formatDateTime(t.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (t) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete target ${t.name}?`)) deleteMutation.mutate(t.id); }}
          className="text-xs text-red-400 hover:text-red-300 transition-colors"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Deployment Targets" subtitle={data ? `${data.total} targets` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No deployment targets" />
        )}
      </div>
    </>
  );
}
