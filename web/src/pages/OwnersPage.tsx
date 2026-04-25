import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getOwners, getTeams, deleteOwner, createOwner, updateOwner } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Owner, Team } from '../api/types';

interface CreateOwnerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
  teamsData?: { data: Team[] };
}

function CreateOwnerModal({ isOpen, onClose, onSuccess, isLoading, error, teamsData }: CreateOwnerModalProps) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [teamId, setTeamId] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !email.trim()) return;
    await createOwner({
      name: name.trim(),
      email: email.trim(),
      team_id: teamId || undefined,
    });
    setName('');
    setEmail('');
    setTeamId('');
    onSuccess();
  };

  if (!isOpen) return null;

  const teams = teamsData?.data || [];

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Owner</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="e.g., Alice Smith"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Email *</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="alice@example.com"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Team</label>
            <select
              value={teamId}
              onChange={e => setTeamId(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
            >
              <option value="">Unassigned</option>
              {teams.map(team => (
                <option key={team.id} value={team.id}>{team.name}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2 pt-4">
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Creating...' : 'Create Owner'}
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

// EditOwnerModal — B-1 master closure (cat-b-31ceb6aaa9f1). Pre-B-1 the
// only way to rename an owner was delete-and-recreate, which destroyed
// audit history and broke every cert that referenced the old owner_id.
// Mirrors CreateOwnerModal shape; pre-populates from the editing owner;
// calls updateOwner(id, fields) instead of createOwner.
interface EditOwnerModalProps {
  owner: Owner | null;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
  teamsData?: { data: Team[] };
}

function EditOwnerModal({ owner, onClose, onSuccess, isLoading, error, teamsData }: EditOwnerModalProps) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [teamId, setTeamId] = useState('');

  // Reset form fields whenever the editing target changes (modal opens).
  useEffect(() => {
    if (owner) {
      setName(owner.name);
      setEmail(owner.email);
      setTeamId(owner.team_id || '');
    }
  }, [owner]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!owner || !name.trim() || !email.trim()) return;
    await updateOwner(owner.id, {
      name: name.trim(),
      email: email.trim(),
      team_id: teamId || undefined,
    });
    onSuccess();
  };

  if (!owner) return null;
  const teams = teamsData?.data || [];

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Edit Owner</h2>
        <p className="text-xs text-ink-muted mb-4 font-mono">{owner.id}</p>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Email *</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Team</label>
            <select
              value={teamId}
              onChange={e => setTeamId(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
            >
              <option value="">Unassigned</option>
              {teams.map(team => (
                <option key={team.id} value={team.id}>{team.name}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2 pt-4">
            <button type="submit" disabled={isLoading} className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed">
              {isLoading ? 'Saving...' : 'Save Changes'}
            </button>
            <button type="button" onClick={onClose} className="flex-1 btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function OwnersPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editingOwner, setEditingOwner] = useState<Owner | null>(null);

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

  const createMutation = useMutation({
    mutationFn: createOwner,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['owners'] });
      setShowCreate(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Owner> }) => updateOwner(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['owners'] });
      setEditingOwner(null);
    },
  });

  const teamMap = new Map<string, Team>();
  (teamsData?.data || []).forEach((t) => teamMap.set(t.id, t));

  const columns: Column<Owner>[] = [
    {
      key: 'name',
      label: 'Owner',
      render: (o) => (
        <div>
          <div className="font-medium text-ink">{o.name}</div>
          <div className="text-xs text-ink-faint font-mono">{o.id}</div>
        </div>
      ),
    },
    {
      key: 'email',
      label: 'Email',
      render: (o) => <span className="text-ink">{o.email || '\u2014'}</span>,
    },
    {
      key: 'team',
      label: 'Team',
      render: (o) => {
        const team = teamMap.get(o.team_id);
        return team
          ? <span className="text-brand-400">{team.name}</span>
          : <span className="text-ink-faint font-mono text-xs">{o.team_id || '\u2014'}</span>;
      },
    },
    {
      key: 'created',
      label: 'Created',
      render: (o) => <span className="text-xs text-ink-muted">{formatDateTime(o.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (o) => (
        <div className="flex gap-3 justify-end">
          <button
            onClick={(e) => { e.stopPropagation(); setEditingOwner(o); }}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            Edit
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); if (confirm(`Delete owner ${o.name}?`)) deleteMutation.mutate(o.id); }}
            className="text-xs text-red-600 hover:text-red-700 transition-colors"
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Owners"
        subtitle={data ? `${data.total} owners` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary">
            + New Owner
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No owners configured" />
        )}
      </div>
      <CreateOwnerModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['owners'] });
          setShowCreate(false);
        }}
        isLoading={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
        teamsData={teamsData}
      />
      <EditOwnerModal
        owner={editingOwner}
        onClose={() => setEditingOwner(null)}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['owners'] });
          setEditingOwner(null);
        }}
        isLoading={updateMutation.isPending}
        error={updateMutation.error ? (updateMutation.error as Error).message : null}
        teamsData={teamsData}
      />
    </>
  );
}
