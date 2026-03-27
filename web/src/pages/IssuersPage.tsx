import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getIssuers, testIssuerConnection, deleteIssuer } from '../api/client';
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
  const queryClient = useQueryClient();
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['issuers'],
    queryFn: () => getIssuers(),
  });

  const testMutation = useMutation({
    mutationFn: testIssuerConnection,
    onSuccess: (_data, id) => setTestResult({ id, ok: true, msg: 'Connection successful' }),
    onError: (err: Error, id) => setTestResult({ id, ok: false, msg: err.message }),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteIssuer,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['issuers'] }),
  });

  const columns: Column<Issuer>[] = [
    {
      key: 'name',
      label: 'Issuer',
      render: (i) => (
        <div>
          <div className="font-medium text-ink">{i.name}</div>
          <div className="text-xs text-ink-faint font-mono">{i.id}</div>
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
        if (!i.config || Object.keys(i.config).length === 0) return <span className="text-ink-faint">&mdash;</span>;
        return (
          <span className="text-xs text-ink-muted font-mono truncate max-w-xs block">
            {JSON.stringify(i.config).slice(0, 60)}
          </span>
        );
      },
    },
    {
      key: 'created',
      label: 'Created',
      render: (i) => <span className="text-xs text-ink-muted">{formatDateTime(i.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (i) => (
        <div className="flex gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); testMutation.mutate(i.id); }}
            disabled={testMutation.isPending}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            Test
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); if (confirm(`Delete issuer ${i.name}?`)) deleteMutation.mutate(i.id); }}
            className="text-xs text-red-600 hover:text-red-700 transition-colors"
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Issuers" subtitle={data ? `${data.total} issuers` : undefined} />
      {testResult && (
        <div className={`mx-6 mt-3 rounded px-4 py-3 text-sm ${testResult.ok ? 'bg-emerald-100 border border-emerald-200 text-emerald-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
          {testResult.id}: {testResult.msg}
          <button onClick={() => setTestResult(null)} className="ml-3 text-xs opacity-60 hover:opacity-100">dismiss</button>
        </div>
      )}
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
