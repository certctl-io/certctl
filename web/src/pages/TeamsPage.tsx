import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getTeams, deleteTeam, createTeam } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Team } from '../api/types';

interface CreateTeamModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
}

function CreateTeamModal({ isOpen, onClose, onSuccess, isLoading, error }: CreateTeamModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      await createTeam({
        name: name.trim(),
        description: description.trim(),
      });
      setName('');
      setDescription('');
      onSuccess();
    } catch (err) {
      console.error('Create team error:', err);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Team</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="e.g., Platform Team"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="Optional team description"
              rows={2}
            />
          </div>
          <div className="flex gap-2 pt-4">
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Creating...' : 'Create Team'}
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

export default function TeamsPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['teams'],
    queryFn: () => getTeams(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteTeam,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['teams'] }),
    onError: (err: Error) => alert(`Delete failed: ${err.message}`),
  });

  const createMutation = useMutation({
    mutationFn: createTeam,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['teams'] });
      setShowCreate(false);
    },
  });

  const columns: Column<Team>[] = [
    {
      key: 'name',
      label: 'Team',
      render: (t) => (
        <div>
          <div className="font-medium text-ink">{t.name}</div>
          <div className="text-xs text-ink-faint font-mono">{t.id}</div>
        </div>
      ),
    },
    {
      key: 'description',
      label: 'Description',
      render: (t) => (
        <span className="text-ink text-sm max-w-sm truncate block">{t.description || '\u2014'}</span>
      ),
    },
    {
      key: 'created',
      label: 'Created',
      render: (t) => <span className="text-xs text-ink-muted">{formatDateTime(t.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (t) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete team ${t.name}?`)) deleteMutation.mutate(t.id); }}
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
        title="Teams"
        subtitle={data ? `${data.total} teams` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary">
            + New Team
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No teams configured" />
        )}
      </div>
      <CreateTeamModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => {}}
        isLoading={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
      />
    </>
  );
}
