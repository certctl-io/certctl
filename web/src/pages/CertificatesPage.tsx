import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getCertificates } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDate, daysUntil, expiryColor } from '../api/utils';
import type { Certificate } from '../api/types';

export default function CertificatesPage() {
  const navigate = useNavigate();
  const [statusFilter, setStatusFilter] = useState('');
  const [envFilter, setEnvFilter] = useState('');

  const params: Record<string, string> = {};
  if (statusFilter) params.status = statusFilter;
  if (envFilter) params.environment = envFilter;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['certificates', params],
    queryFn: () => getCertificates(params),
    refetchInterval: 30000,
  });

  const columns: Column<Certificate>[] = [
    {
      key: 'name',
      label: 'Certificate',
      render: (c) => (
        <div>
          <div className="font-medium text-slate-200">{c.common_name}</div>
          <div className="text-xs text-slate-500 mt-0.5">{c.id}</div>
        </div>
      ),
    },
    { key: 'status', label: 'Status', render: (c) => <StatusBadge status={c.status} /> },
    {
      key: 'expires',
      label: 'Expires',
      render: (c) => {
        const days = daysUntil(c.expires_at);
        return (
          <div>
            <div className={expiryColor(days)}>{formatDate(c.expires_at)}</div>
            <div className="text-xs text-slate-500">{days <= 0 ? 'Expired' : `${days} days`}</div>
          </div>
        );
      },
    },
    { key: 'env', label: 'Environment', render: (c) => <span className="text-slate-300">{c.environment || '—'}</span> },
    { key: 'issuer', label: 'Issuer', render: (c) => <span className="text-slate-400 text-xs">{c.issuer_id}</span> },
    { key: 'owner', label: 'Owner', render: (c) => <span className="text-slate-400 text-xs">{c.owner_id}</span> },
  ];

  return (
    <>
      <PageHeader
        title="Certificates"
        subtitle={data ? `${data.total} certificates` : undefined}
      />
      <div className="px-6 py-3 flex gap-3 border-b border-slate-700/50">
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-300"
        >
          <option value="">All statuses</option>
          <option value="Active">Active</option>
          <option value="Expiring">Expiring</option>
          <option value="Expired">Expired</option>
          <option value="RenewalInProgress">Renewal In Progress</option>
          <option value="Archived">Archived</option>
        </select>
        <select
          value={envFilter}
          onChange={e => setEnvFilter(e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-300"
        >
          <option value="">All environments</option>
          <option value="production">Production</option>
          <option value="staging">Staging</option>
          <option value="development">Development</option>
        </select>
      </div>
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data || []}
            isLoading={isLoading}
            onRowClick={(c) => navigate(`/certificates/${c.id}`)}
            emptyMessage="No certificates found"
          />
        )}
      </div>
    </>
  );
}
