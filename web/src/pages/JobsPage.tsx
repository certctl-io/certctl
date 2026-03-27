import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getJobs, cancelJob } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Job } from '../api/types';

export default function JobsPage() {
  const [statusFilter, setStatusFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const queryClient = useQueryClient();

  const params: Record<string, string> = {};
  if (statusFilter) params.status = statusFilter;
  if (typeFilter) params.type = typeFilter;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['jobs', params],
    queryFn: () => getJobs(params),
    refetchInterval: 10000,
  });

  const cancelMutation = useMutation({
    mutationFn: cancelJob,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['jobs'] }),
  });

  const columns: Column<Job>[] = [
    {
      key: 'id',
      label: 'Job',
      render: (j) => (
        <div>
          <div className="font-mono text-xs text-ink">{j.id}</div>
          <div className="text-xs text-ink-faint">{j.type}</div>
        </div>
      ),
    },
    { key: 'status', label: 'Status', render: (j) => <StatusBadge status={j.status} /> },
    { key: 'cert', label: 'Certificate', render: (j) => <span className="text-xs text-ink-muted font-mono">{j.certificate_id}</span> },
    {
      key: 'attempts',
      label: 'Attempts',
      render: (j) => <span className="text-ink-muted">{j.attempts}/{j.max_attempts}</span>,
    },
    { key: 'scheduled', label: 'Scheduled', render: (j) => <span className="text-xs text-ink-muted">{formatDateTime(j.scheduled_at)}</span> },
    { key: 'completed', label: 'Completed', render: (j) => <span className="text-xs text-ink-muted">{formatDateTime(j.completed_at)}</span> },
    {
      key: 'actions',
      label: '',
      render: (j) => (
        j.status === 'Pending' || j.status === 'Running' ? (
          <button
            onClick={(e) => { e.stopPropagation(); cancelMutation.mutate(j.id); }}
            className="text-xs text-red-400 hover:text-red-300"
          >
            Cancel
          </button>
        ) : null
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Jobs" subtitle={data ? `${data.total} jobs` : undefined} />
      <div className="px-6 py-3 flex gap-3 border-b border-surface-border/50">
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All statuses</option>
          <option value="Pending">Pending</option>
          <option value="Running">Running</option>
          <option value="Completed">Completed</option>
          <option value="Failed">Failed</option>
          <option value="Cancelled">Cancelled</option>
        </select>
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All types</option>
          <option value="Renewal">Renewal</option>
          <option value="Issuance">Issuance</option>
          <option value="Deployment">Deployment</option>
          <option value="Validation">Validation</option>
        </select>
      </div>
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No jobs found" />
        )}
      </div>
    </>
  );
}
