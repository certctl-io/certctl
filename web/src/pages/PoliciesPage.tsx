import { useQuery } from '@tanstack/react-query';
import { getPolicies } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { PolicyRule } from '../api/types';

const severityStyles: Record<string, string> = {
  low: 'badge-info',
  medium: 'badge-warning',
  high: 'badge-danger',
  critical: 'badge-danger',
};

export default function PoliciesPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['policies'],
    queryFn: () => getPolicies(),
  });

  const columns: Column<PolicyRule>[] = [
    {
      key: 'name',
      label: 'Rule',
      render: (p) => (
        <div>
          <div className="font-medium text-slate-200">{p.name}</div>
          <div className="text-xs text-slate-500">{p.id}</div>
        </div>
      ),
    },
    { key: 'type', label: 'Type', render: (p) => <span className="text-sm text-slate-300">{p.type.replace(/_/g, ' ')}</span> },
    {
      key: 'severity',
      label: 'Severity',
      render: (p) => <span className={`badge ${severityStyles[p.severity] || 'badge-neutral'}`}>{p.severity}</span>,
    },
    {
      key: 'enabled',
      label: 'Enabled',
      render: (p) => (
        <span className={p.enabled ? 'text-emerald-400' : 'text-slate-500'}>
          {p.enabled ? 'Yes' : 'No'}
        </span>
      ),
    },
    { key: 'created', label: 'Created', render: (p) => <span className="text-xs text-slate-400">{formatDateTime(p.created_at)}</span> },
  ];

  return (
    <>
      <PageHeader title="Policies" subtitle={data ? `${data.total} rules` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No policy rules" />
        )}
      </div>
    </>
  );
}
