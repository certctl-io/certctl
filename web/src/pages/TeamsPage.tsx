import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getTeams, deleteTeam } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Team } from '../api/types';

export default function TeamsPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['teams'],
    queryFn: () => getTeams(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteTeam,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['teams'] }),
    onError: (err: Error) => alert(`Delete failed: ${err.message}`),
  });

  const columns: Column<Team>[] = [
    {
      key: 'name',
      label: 'Team',
      render: (t) => (
        <div>
          <div className="font-medium text-slate-200">{t.name}</div>
          <div className="text-xs text-slate-500 font-mono">{t.id}</div>
        </div>
      ),
    },
    {
      key: 'description',
      label: 'Description',
      render: (t) => (
        <span className="text-slate-300 text-sm max-w-sm truncate block">{t.description || '\u2014'}</span>
      ),
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
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete team ${t.name}?`)) deleteMutation.mutate(t.id); }}
          className="text-xs text-red-400 hover:text-red-300 transition-colors"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Teams" subtitle={data ? `${data.total} teams` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No teams configured" />
        )}
      </div>
    </>
  );
}
