import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getCertificates, createCertificate, triggerRenewal, revokeCertificate, updateCertificate, getOwners } from '../api/client';
import { REVOCATION_REASONS } from '../api/types';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDate, daysUntil, expiryColor } from '../api/utils';
import type { Certificate } from '../api/types';

function CreateCertificateModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [form, setForm] = useState({
    name: '',
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
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-lg shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">New Certificate</h2>
        {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-4">{error}</div>}
        <div className="space-y-3">
          <div>
            <label className="text-xs text-ink-muted block mb-1">Name *</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
              placeholder="API Production Cert" />
          </div>
          <div>
            <label className="text-xs text-ink-muted block mb-1">ID (optional)</label>
            <input value={form.id} onChange={e => setForm(f => ({ ...f, id: e.target.value }))}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
              placeholder="mc-api-prod (auto-generated if empty)" />
          </div>
          <div>
            <label className="text-xs text-ink-muted block mb-1">Common Name *</label>
            <input value={form.common_name} onChange={e => setForm(f => ({ ...f, common_name: e.target.value }))}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
              placeholder="api.example.com" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-ink-muted block mb-1">Environment</label>
              <select value={form.environment} onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink">
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-ink-muted block mb-1">Issuer ID *</label>
              <input value={form.issuer_id} onChange={e => setForm(f => ({ ...f, issuer_id: e.target.value }))}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
                placeholder="iss-local" />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-ink-muted block mb-1">Owner ID</label>
              <input value={form.owner_id} onChange={e => setForm(f => ({ ...f, owner_id: e.target.value }))}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
                placeholder="o-alice" />
            </div>
            <div>
              <label className="text-xs text-ink-muted block mb-1">Team ID</label>
              <input value={form.team_id} onChange={e => setForm(f => ({ ...f, team_id: e.target.value }))}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
                placeholder="t-platform" />
            </div>
            <div>
              <label className="text-xs text-ink-muted block mb-1">Policy ID</label>
              <input value={form.renewal_policy_id} onChange={e => setForm(f => ({ ...f, renewal_policy_id: e.target.value }))}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
                placeholder="rp-standard" />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="btn btn-ghost text-sm">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={!form.name || !form.common_name || !form.issuer_id || mutation.isPending}
            className="btn btn-primary text-sm disabled:opacity-50"
          >
            {mutation.isPending ? 'Creating...' : 'Create Certificate'}
          </button>
        </div>
      </div>
    </div>
  );
}

function BulkRevokeModal({ ids, onClose, onSuccess }: { ids: string[]; onClose: () => void; onSuccess: () => void }) {
  const [reason, setReason] = useState('unspecified');
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);

  const handleRevoke = async () => {
    setRunning(true);
    setError('');
    let succeeded = 0;
    for (const id of ids) {
      try {
        await revokeCertificate(id, reason);
        succeeded++;
        setProgress(succeeded);
      } catch (err) {
        setError(`Failed on ${id}: ${err instanceof Error ? err.message : 'Unknown error'}`);
        break;
      }
    }
    if (!error) onSuccess();
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-red-700 mb-2">Bulk Revoke</h2>
        <p className="text-sm text-ink-muted mb-4">
          Revoke {ids.length} certificate{ids.length > 1 ? 's' : ''}. This cannot be undone.
        </p>
        {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-3">{error}</div>}
        {running && (
          <div className="mb-3">
            <div className="flex justify-between text-xs text-ink-muted mb-1">
              <span>Progress</span>
              <span>{progress}/{ids.length}</span>
            </div>
            <div className="w-full bg-surface-border rounded-full h-2">
              <div className="bg-red-500 h-2 rounded-full transition-all" style={{ width: `${(progress / ids.length) * 100}%` }} />
            </div>
          </div>
        )}
        <label className="text-xs text-ink-muted block mb-2">Revocation Reason (RFC 5280)</label>
        <select value={reason} onChange={e => setReason(e.target.value)}
          className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink mb-4"
          disabled={running}
        >
          {REVOCATION_REASONS.map(r => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="btn btn-ghost text-sm" disabled={running}>Cancel</button>
          <button onClick={handleRevoke} disabled={running}
            className="btn text-sm bg-red-600 hover:bg-red-500 text-white disabled:opacity-50">
            {running ? `Revoking (${progress}/${ids.length})...` : `Revoke ${ids.length} Certificates`}
          </button>
        </div>
      </div>
    </div>
  );
}

function BulkReassignModal({ ids, onClose, onSuccess }: { ids: string[]; onClose: () => void; onSuccess: () => void }) {
  const [ownerId, setOwnerId] = useState('');
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);

  const { data: owners } = useQuery({
    queryKey: ['owners'],
    queryFn: () => getOwners(),
  });

  const handleReassign = async () => {
    if (!ownerId) return;
    setRunning(true);
    setError('');
    let succeeded = 0;
    for (const id of ids) {
      try {
        await updateCertificate(id, { owner_id: ownerId } as Partial<Certificate>);
        succeeded++;
        setProgress(succeeded);
      } catch (err) {
        setError(`Failed on ${id}: ${err instanceof Error ? err.message : 'Unknown error'}`);
        break;
      }
    }
    if (!error) onSuccess();
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-2">Reassign Owner</h2>
        <p className="text-sm text-ink-muted mb-4">
          Reassign {ids.length} certificate{ids.length > 1 ? 's' : ''} to a new owner.
        </p>
        {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-3">{error}</div>}
        {running && (
          <div className="mb-3">
            <div className="flex justify-between text-xs text-ink-muted mb-1">
              <span>Progress</span>
              <span>{progress}/{ids.length}</span>
            </div>
            <div className="w-full bg-surface-border rounded-full h-2">
              <div className="bg-brand-400 h-2 rounded-full transition-all" style={{ width: `${(progress / ids.length) * 100}%` }} />
            </div>
          </div>
        )}
        <label className="text-xs text-ink-muted block mb-2">New Owner</label>
        <select value={ownerId} onChange={e => setOwnerId(e.target.value)}
          className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink mb-4"
          disabled={running}
        >
          <option value="">Select owner...</option>
          {owners?.data?.map(o => (
            <option key={o.id} value={o.id}>{o.name} ({o.email})</option>
          ))}
        </select>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="btn btn-ghost text-sm" disabled={running}>Cancel</button>
          <button onClick={handleReassign} disabled={running || !ownerId}
            className="btn btn-primary text-sm disabled:opacity-50">
            {running ? `Reassigning (${progress}/${ids.length})...` : `Reassign ${ids.length} Certificates`}
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
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showBulkRevoke, setShowBulkRevoke] = useState(false);
  const [showBulkReassign, setShowBulkReassign] = useState(false);
  const [bulkRenewProgress, setBulkRenewProgress] = useState<{ done: number; total: number; running: boolean } | null>(null);

  const params: Record<string, string> = {};
  if (statusFilter) params.status = statusFilter;
  if (envFilter) params.environment = envFilter;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['certificates', params],
    queryFn: () => getCertificates(params),
    refetchInterval: 30000,
  });

  const handleBulkRenewal = async () => {
    const ids = Array.from(selectedIds);
    setBulkRenewProgress({ done: 0, total: ids.length, running: true });
    for (let i = 0; i < ids.length; i++) {
      try {
        await triggerRenewal(ids[i]);
      } catch {
        // continue on individual failures
      }
      setBulkRenewProgress({ done: i + 1, total: ids.length, running: i + 1 < ids.length });
    }
    queryClient.invalidateQueries({ queryKey: ['certificates'] });
    setSelectedIds(new Set());
    setTimeout(() => setBulkRenewProgress(null), 3000);
  };

  const columns: Column<Certificate>[] = [
    {
      key: 'name',
      label: 'Certificate',
      render: (c) => (
        <div>
          <div className="font-medium text-ink">{c.common_name}</div>
          <div className="text-xs text-ink-faint mt-0.5">{c.id}</div>
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
            <div className="text-xs text-ink-faint">{days <= 0 ? 'Expired' : `${days} days`}</div>
          </div>
        );
      },
    },
    { key: 'env', label: 'Environment', render: (c) => <span className="text-ink-muted">{c.environment || '—'}</span> },
    { key: 'issuer', label: 'Issuer', render: (c) => <span className="text-ink-muted text-xs">{c.issuer_id}</span> },
    { key: 'owner', label: 'Owner', render: (c) => <span className="text-ink-muted text-xs">{c.owner_id}</span> },
  ];

  const selectedArray = Array.from(selectedIds);
  const hasSelection = selectedArray.length > 0;

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

      {/* Bulk Action Bar */}
      {hasSelection && (
        <div className="px-6 py-3 bg-brand-50 border-b border-brand-200 flex items-center justify-between">
          <span className="text-sm text-brand-600 font-medium">{selectedArray.length} selected</span>
          <div className="flex gap-2">
            <button onClick={handleBulkRenewal} disabled={bulkRenewProgress?.running}
              className="btn btn-primary text-xs disabled:opacity-50">
              {bulkRenewProgress?.running
                ? `Renewing (${bulkRenewProgress.done}/${bulkRenewProgress.total})...`
                : 'Trigger Renewal'}
            </button>
            <button onClick={() => setShowBulkRevoke(true)}
              className="btn btn-ghost text-xs text-amber-400 hover:text-amber-300 border border-amber-600/50">
              Revoke
            </button>
            <button onClick={() => setShowBulkReassign(true)}
              className="btn btn-ghost text-xs text-brand-400 hover:text-brand-300 border border-brand-600/50">
              Reassign Owner
            </button>
            <button onClick={() => setSelectedIds(new Set())}
              className="btn btn-ghost text-xs text-ink-muted">
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Bulk Renewal Success */}
      {bulkRenewProgress && !bulkRenewProgress.running && (
        <div className="px-6 py-2 bg-emerald-50 border-b border-emerald-200">
          <span className="text-sm text-emerald-700">
            Triggered renewal for {bulkRenewProgress.done} certificate{bulkRenewProgress.done > 1 ? 's' : ''}.
          </span>
        </div>
      )}

      <div className="px-6 py-3 flex gap-3 border-b border-surface-border/50">
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
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
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
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
            selectable
            selectedKeys={selectedIds}
            onSelectionChange={setSelectedIds}
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
      {showBulkRevoke && (
        <BulkRevokeModal
          ids={selectedArray}
          onClose={() => setShowBulkRevoke(false)}
          onSuccess={() => {
            setShowBulkRevoke(false);
            setSelectedIds(new Set());
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
        />
      )}
      {showBulkReassign && (
        <BulkReassignModal
          ids={selectedArray}
          onClose={() => setShowBulkReassign(false)}
          onSuccess={() => {
            setShowBulkReassign(false);
            setSelectedIds(new Set());
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
        />
      )}
    </>
  );
}
