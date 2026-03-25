import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getOwners, getTeams, deleteOwner } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Owner, Team } from '../api/types';

export default function OwnersPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['owners'],
    queryFn: () => getOwners(),
  });

  const { data: teamsData } = useQuery({
    queryKey: ['teams'],
    queryFn: () => getTeams(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteOwner,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['owners'] }),
    onError: (err: Error) => alert(`Delete failed: ${err.message}`),
  });

  const teamMap = new Map<string, Team>();
  (teamsData?.data || []).forEach((t) => teamMap.set(t.id, t));

  const columns: Column<Owner>[] = [
    {
      key: 'name',
      label: 'Owner',
      render: (o) => (
        <div>
          <div className="font-medium text-slate-200">{o.name}</div>
          <div className="text-xs text-slate-500 font-mono">{o.id}</div>
        </div>
      ),
    },
    {
      key: 'email',
      label: 'Email',
      render: (o) => <span className="text-slate-300">{o.email || '\u2014'}</span>,
    },
    {
      key: 'team',
      label: 'Team',
      render: (o) => {
        const team = teamMap.get(o.team_id);
        return team
          ? <span className="text-blue-400">{team.name}</span>
          : <span className="text-slate-500 font-mono text-xs">{o.team_id || '\u2014'}</span>;
      },
    },
    {
      key: 'created',
      label: 'Created',
      render: (o) => <span className="text-xs text-slate-400">{formatDateTime(o.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (o) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete owner ${o.name}?`)) deleteMutation.mutate(o.id); }}
          className="text-xs text-red-400 hover:text-red-300 transition-colors"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Owners" subtitle={data ? `${data.total} owners` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No owners configured" />
        )}
      </div>
    </>
  );
}
