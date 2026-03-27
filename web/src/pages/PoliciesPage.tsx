import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getPolicies, updatePolicy, deletePolicy } from '../api/client';
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

const severityDots: Record<string, string> = {
  low: 'bg-emerald-500',
  medium: 'bg-amber-500',
  high: 'bg-orange-500',
  critical: 'bg-red-500',
};

export default function PoliciesPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['policies'],
    queryFn: () => getPolicies(),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => updatePolicy(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });

  const policies = data?.data || [];
  const enabledCount = policies.filter(p => p.enabled).length;
  const bySeverity = policies.reduce<Record<string, number>>((acc, p) => {
    acc[p.severity] = (acc[p.severity] || 0) + 1;
    return acc;
  }, {});

  const columns: Column<PolicyRule>[] = [
    {
      key: 'name',
      label: 'Rule',
      render: (p) => (
        <div>
          <div className="font-medium text-ink">{p.name}</div>
          <div className="text-xs text-ink-faint">{p.id}</div>
        </div>
      ),
    },
    { key: 'type', label: 'Type', render: (p) => <span className="text-sm text-ink">{p.type.replace(/_/g, ' ')}</span> },
    {
      key: 'severity',
      label: 'Severity',
      render: (p) => <span className={`badge ${severityStyles[p.severity] || 'badge-neutral'}`}>{p.severity}</span>,
    },
    {
      key: 'config',
      label: 'Config',
      render: (p) => {
        if (!p.config || Object.keys(p.config).length === 0) return <span className="text-ink-faint">&mdash;</span>;
        return (
          <span className="text-xs text-ink-muted font-mono truncate max-w-xs block">
            {JSON.stringify(p.config).slice(0, 50)}
          </span>
        );
      },
    },
    {
      key: 'enabled',
      label: 'Enabled',
      render: (p) => (
        <button
          onClick={(e) => { e.stopPropagation(); toggleMutation.mutate({ id: p.id, enabled: !p.enabled }); }}
          className={`text-xs font-medium transition-colors ${p.enabled ? 'text-emerald-600 hover:text-emerald-700' : 'text-ink-faint hover:text-ink-muted'}`}
        >
          {p.enabled ? 'Enabled' : 'Disabled'}
        </button>
      ),
    },
    { key: 'created', label: 'Created', render: (p) => <span className="text-xs text-ink-muted">{formatDateTime(p.created_at)}</span> },
    {
      key: 'actions',
      label: '',
      render: (p) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete policy ${p.name}?`)) deleteMutation.mutate(p.id); }}
          className="text-xs text-red-600 hover:text-red-700 transition-colors"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Policies" subtitle={data ? `${data.total} rules` : undefined} />
      {policies.length > 0 && (
        <div className="px-4 py-3 flex flex-wrap gap-4 border-b border-surface-border/50">
          <div className="flex items-center gap-2">
            <span className="text-xs text-ink-muted">Enabled:</span>
            <span className="text-xs font-medium text-emerald-600">{enabledCount}</span>
            <span className="text-xs text-ink-faint">/</span>
            <span className="text-xs text-ink-muted">{policies.length}</span>
          </div>
          {Object.entries(bySeverity).map(([sev, count]) => (
            <div key={sev} className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${severityDots[sev] || 'bg-slate-400'}`} />
              <span className="text-xs text-ink capitalize">{sev}</span>
              <span className="text-xs text-ink-faint">{count}</span>
            </div>
          ))}
        </div>
      )}
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={policies} isLoading={isLoading} emptyMessage="No policy rules" />
        )}
      </div>
    </>
  );
}
