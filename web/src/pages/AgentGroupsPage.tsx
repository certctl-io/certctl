import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getAgentGroups, deleteAgentGroup } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { AgentGroup } from '../api/types';

export default function AgentGroupsPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['agent-groups'],
    queryFn: () => getAgentGroups(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteAgentGroup,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['agent-groups'] }),
  });

  const columns: Column<AgentGroup>[] = [
    {
      key: 'name',
      label: 'Group',
      render: (g) => (
        <div>
          <div className="font-medium text-ink">{g.name}</div>
          <div className="text-xs text-ink-faint font-mono">{g.id}</div>
          {g.description && (
            <div className="text-xs text-ink-muted mt-0.5 max-w-xs truncate">{g.description}</div>
          )}
        </div>
      ),
    },
    {
      key: 'criteria',
      label: 'Match Criteria',
      render: (g) => {
        const criteria: string[] = [];
        if (g.match_os) criteria.push(`OS: ${g.match_os}`);
        if (g.match_architecture) criteria.push(`Arch: ${g.match_architecture}`);
        if (g.match_ip_cidr) criteria.push(`IP: ${g.match_ip_cidr}`);
        if (g.match_version) criteria.push(`Ver: ${g.match_version}`);
        return criteria.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {criteria.map((c, i) => (
              <span key={i} className="badge badge-neutral text-xs">{c}</span>
            ))}
          </div>
        ) : (
          <span className="text-ink-faint text-xs">Manual only</span>
        );
      },
    },
    {
      key: 'enabled',
      label: 'Status',
      render: (g) => <StatusBadge status={g.enabled ? 'active' : 'disabled'} />,
    },
    {
      key: 'created',
      label: 'Created',
      render: (g) => <span className="text-xs text-ink-muted">{formatDateTime(g.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (g) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete group ${g.name}?`)) deleteMutation.mutate(g.id); }}
          className="text-xs text-red-600 hover:text-red-700 transition-colors"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Agent Groups" subtitle={data ? `${data.total} groups` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No agent groups configured" />
        )}
      </div>
    </>
  );
}
