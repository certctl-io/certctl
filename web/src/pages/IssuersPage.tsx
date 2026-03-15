import { useQuery } from '@tanstack/react-query';
import { getIssuers } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Issuer } from '../api/types';

const typeLabels: Record<string, string> = {
  local_ca: 'Local CA',
  acme: 'ACME',
  vault: 'Vault PKI',
  manual: 'Manual',
};

export default function IssuersPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['issuers'],
    queryFn: () => getIssuers(),
  });

  const columns: Column<Issuer>[] = [
    {
      key: 'name',
      label: 'Issuer',
      render: (i) => (
        <div>
          <div className="font-medium text-slate-200">{i.name}</div>
          <div className="text-xs text-slate-500 font-mono">{i.id}</div>
        </div>
      ),
    },
    {
      key: 'type',
      label: 'Type',
      render: (i) => (
        <span className="badge badge-neutral">{typeLabels[i.type] || i.type}</span>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (i) => <StatusBadge status={i.status} />,
    },
    {
      key: 'config',
      label: 'Config',
      render: (i) => {
        if (!i.config || Object.keys(i.config).length === 0) return <span className="text-slate-500">&mdash;</span>;
        return (
          <span className="text-xs text-slate-400 font-mono truncate max-w-xs block">
            {JSON.stringify(i.config).slice(0, 60)}
          </span>
        );
      },
    },
    {
      key: 'created',
      label: 'Created',
      render: (i) => <span className="text-xs text-slate-400">{formatDateTime(i.created_at)}</span>,
    },
  ];

  return (
    <>
      <PageHeader title="Issuers" subtitle={data ? `${data.total} issuers` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No issuers configured" />
        )}
      </div>
    </>
  );
}
