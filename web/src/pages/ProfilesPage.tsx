import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getProfiles, deleteProfile, createProfile } from '../api/client';
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

interface CreateProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
}

function CreateProfileModal({ isOpen, onClose, onSuccess, isLoading, error }: CreateProfileModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [ttl, setTtl] = useState('86400');
  const [shortLived, setShortLived] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      await createProfile({
        name: name.trim(),
        description: description.trim(),
        max_ttl_seconds: parseInt(ttl) || 86400,
        allow_short_lived: shortLived,
        enabled: true,
      });
      setName('');
      setDescription('');
      setTtl('86400');
      setShortLived(false);
      onSuccess();
    } catch (err) {
      console.error('Create profile error:', err);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Profile</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="e.g., Web Server Certs"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="Optional description"
              rows={2}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Max TTL (seconds)</label>
            <input
              type="number"
              value={ttl}
              onChange={e => setTtl(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="86400"
            />
            <p className="text-xs text-ink-muted mt-1">e.g. 86400 = 1 day, 2592000 = 30 days</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="shortLived"
              checked={shortLived}
              onChange={e => setShortLived(e.target.checked)}
              className="w-4 h-4"
            />
            <label htmlFor="shortLived" className="text-sm text-ink">Allow short-lived certs</label>
          </div>
          <div className="flex gap-2 pt-4">
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Creating...' : 'Create Profile'}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="flex-1 btn btn-ghost"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ProfilesPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['profiles'],
    queryFn: () => getProfiles(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['profiles'] }),
  });

  const createMutation = useMutation({
    mutationFn: createProfile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profiles'] });
      setShowCreate(false);
    },
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
      <PageHeader
        title="Certificate Profiles"
        subtitle={data ? `${data.total} profiles` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary">
            + New Profile
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No profiles configured" />
        )}
      </div>
      <CreateProfileModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => {}}
        isLoading={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
      />
    </>
  );
}
