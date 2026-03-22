import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getCertificates, createCertificate } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDate, daysUntil, expiryColor } from '../api/utils';
import type { Certificate } from '../api/types';

function CreateCertificateModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [form, setForm] = useState({
    id: '',
    common_name: '',
    environment: 'production',
    issuer_id: '',
    owner_id: '',
    team_id: '',
    renewal_policy_id: '',
  });
  const [error, setError] = useState('');

  const mutation = useMutation({
    mutationFn: () => createCertificate(form),
    onSuccess: () => onSuccess(),
    onError: (err: Error) => setError(err.message),
  });

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-slate-800 border border-slate-600 rounded-xl p-6 w-full max-w-lg shadow-2xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-slate-200 mb-4">New Certificate</h2>
        {error && <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-3 py-2 text-sm mb-4">{error}</div>}
        <div className="space-y-3">
          <div>
            <label className="text-xs text-slate-400 block mb-1">ID (optional)</label>
            <input value={form.id} onChange={e => setForm(f => ({ ...f, id: e.target.value }))}
              className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
              placeholder="mc-api-prod (auto-generated if empty)" />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Common Name *</label>
            <input value={form.common_name} onChange={e => setForm(f => ({ ...f, common_name: e.target.value }))}
              className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
              placeholder="api.example.com" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-slate-400 block mb-1">Environment</label>
              <select value={form.environment} onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200">
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Issuer ID *</label>
              <input value={form.issuer_id} onChange={e => setForm(f => ({ ...f, issuer_id: e.target.value }))}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                placeholder="iss-local" />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-slate-400 block mb-1">Owner ID</label>
              <input value={form.owner_id} onChange={e => setForm(f => ({ ...f, owner_id: e.target.value }))}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                placeholder="o-alice" />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Team ID</label>
              <input value={form.team_id} onChange={e => setForm(f => ({ ...f, team_id: e.target.value }))}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                placeholder="t-platform" />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Policy ID</label>
              <input value={form.renewal_policy_id} onChange={e => setForm(f => ({ ...f, renewal_policy_id: e.target.value }))}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                placeholder="rp-standard" />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="btn btn-ghost text-sm">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={!form.common_name || !form.issuer_id || mutation.isPending}
            className="btn btn-primary text-sm disabled:opacity-50"
          >
            {mutation.isPending ? 'Creating...' : 'Create Certificate'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CertificatesPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState('');
  const [envFilter, setEnvFilter] = useState('');
  const [showCreate, setShowCreate] = useState(false);

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
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary text-xs">
            + New Certificate
          </button>
        }
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
          <option value="Revoked">Revoked</option>
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
      {showCreate && (
        <CreateCertificateModal
          onClose={() => setShowCreate(false)}
          onSuccess={() => {
            setShowCreate(false);
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
        />
      )}
    </>
  );
}
