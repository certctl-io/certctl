import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getProfiles, deleteProfile } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { CertificateProfile } from '../api/types';

function formatTTL(seconds: number): string {
  if (seconds === 0) return 'No limit';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export default function ProfilesPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['profiles'],
    queryFn: () => getProfiles(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['profiles'] }),
  });

  const columns: Column<CertificateProfile>[] = [
    {
      key: 'name',
      label: 'Profile',
      render: (p) => (
        <div>
          <div className="font-medium text-ink">{p.name}</div>
          <div className="text-xs text-ink-faint font-mono">{p.id}</div>
          {p.description && (
            <div className="text-xs text-ink-muted mt-0.5 max-w-xs truncate">{p.description}</div>
          )}
        </div>
      ),
    },
    {
      key: 'algorithms',
      label: 'Key Algorithms',
      render: (p) => (
        <div className="flex flex-wrap gap-1">
          {(p.allowed_key_algorithms || []).map((alg, i) => (
            <span key={i} className="badge badge-neutral text-xs">
              {alg.algorithm} {alg.min_size}+
            </span>
          ))}
        </div>
      ),
    },
    {
      key: 'ttl',
      label: 'Max TTL',
      render: (p) => (
        <div>
          <span className="text-ink">{formatTTL(p.max_ttl_seconds)}</span>
          {p.allow_short_lived && (
            <span className="ml-2 text-xs text-amber-700 bg-amber-100 px-1.5 py-0.5 rounded">
              short-lived
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'ekus',
      label: 'EKUs',
      render: (p) => (
        <div className="flex flex-wrap gap-1">
          {(p.allowed_ekus || []).map((eku, i) => (
            <span key={i} className="text-xs text-ink-muted">{eku}</span>
          ))}
        </div>
      ),
    },
    {
      key: 'spiffe',
      label: 'SPIFFE',
      render: (p) => (
        p.spiffe_uri_pattern
          ? <span className="text-xs text-brand-400 font-mono">{p.spiffe_uri_pattern}</span>
          : <span className="text-ink-faint">&mdash;</span>
      ),
    },
    {
      key: 'enabled',
      label: 'Status',
      render: (p) => <StatusBadge status={p.enabled ? 'active' : 'disabled'} />,
    },
    {
      key: 'created',
      label: 'Created',
      render: (p) => <span className="text-xs text-ink-muted">{formatDateTime(p.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (p) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete profile ${p.name}?`)) deleteMutation.mutate(p.id); }}
          className="text-xs text-red-600 hover:text-red-700 transition-colors"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Certificate Profiles" subtitle={data ? `${data.total} profiles` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No profiles configured" />
        )}
      </div>
    </>
  );
}
