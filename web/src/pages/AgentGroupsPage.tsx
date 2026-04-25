import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getAgentGroups, deleteAgentGroup, createAgentGroup, updateAgentGroup } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { AgentGroup } from '../api/types';

interface CreateAgentGroupModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
}

function CreateAgentGroupModal({ isOpen, onClose, onSuccess, isLoading, error }: CreateAgentGroupModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [matchOs, setMatchOs] = useState('');
  const [matchArch, setMatchArch] = useState('');
  const [matchIpCidr, setMatchIpCidr] = useState('');
  const [matchVersion, setMatchVersion] = useState('');
  const [enabled, setEnabled] = useState(true);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    await createAgentGroup({
        name: name.trim(),
        description: description.trim(),
        match_os: matchOs.trim() || undefined,
        match_architecture: matchArch.trim() || undefined,
        match_ip_cidr: matchIpCidr.trim() || undefined,
        match_version: matchVersion.trim() || undefined,
        enabled,
      });
      setName('');
      setDescription('');
      setMatchOs('');
      setMatchArch('');
      setMatchIpCidr('');
      setMatchVersion('');
    setEnabled(true);
    onSuccess();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Agent Group</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="e.g., Production Linux Servers"
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
            <label className="block text-sm font-medium text-ink mb-1">Match OS</label>
            <input
              value={matchOs}
              onChange={e => setMatchOs(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="linux"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Match Architecture</label>
            <input
              value={matchArch}
              onChange={e => setMatchArch(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="amd64"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Match IP CIDR</label>
            <input
              value={matchIpCidr}
              onChange={e => setMatchIpCidr(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="10.0.0.0/8"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Match Version</label>
            <input
              value={matchVersion}
              onChange={e => setMatchVersion(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="2.0.*"
            />
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="enabled"
              checked={enabled}
              onChange={e => setEnabled(e.target.checked)}
              className="w-4 h-4"
            />
            <label htmlFor="enabled" className="text-sm text-ink">Enabled</label>
          </div>
          <div className="flex gap-2 pt-4">
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Creating...' : 'Create Group'}
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

// EditAgentGroupModal — B-1 master closure (cat-b-31ceb6aaa9f1).
// Mirrors CreateAgentGroupModal; pre-populates from the editing group;
// calls updateAgentGroup(id, fields) to close the destructive-rename
// hazard. Membership-rule fields (match_os, match_architecture,
// match_ip_cidr, match_version) are editable like the rest — operators
// frequently want to widen/narrow group membership without recreating.
interface EditAgentGroupModalProps {
  group: AgentGroup | null;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
}

function EditAgentGroupModal({ group, onClose, onSuccess, isLoading, error }: EditAgentGroupModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [matchOs, setMatchOs] = useState('');
  const [matchArch, setMatchArch] = useState('');
  const [matchIpCidr, setMatchIpCidr] = useState('');
  const [matchVersion, setMatchVersion] = useState('');
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    if (group) {
      setName(group.name);
      setDescription(group.description || '');
      setMatchOs(group.match_os || '');
      setMatchArch(group.match_architecture || '');
      setMatchIpCidr(group.match_ip_cidr || '');
      setMatchVersion(group.match_version || '');
      setEnabled(group.enabled);
    }
  }, [group]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!group || !name.trim()) return;
    await updateAgentGroup(group.id, {
      name: name.trim(),
      description: description.trim(),
      match_os: matchOs.trim(),
      match_architecture: matchArch.trim(),
      match_ip_cidr: matchIpCidr.trim(),
      match_version: matchVersion.trim(),
      enabled,
    });
    onSuccess();
  };

  if (!group) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Edit Agent Group</h2>
        <p className="text-xs text-ink-muted mb-4 font-mono">{group.id}</p>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input value={name} onChange={e => setName(e.target.value)} required
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Match OS</label>
            <input value={matchOs} onChange={e => setMatchOs(e.target.value)} placeholder="linux"
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Match Architecture</label>
            <input value={matchArch} onChange={e => setMatchArch(e.target.value)} placeholder="amd64"
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Match IP CIDR</label>
            <input value={matchIpCidr} onChange={e => setMatchIpCidr(e.target.value)} placeholder="10.0.0.0/24"
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Match Version</label>
            <input value={matchVersion} onChange={e => setMatchVersion(e.target.value)} placeholder="v2.0.x"
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <label className="flex items-center gap-2 text-sm text-ink">
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
            Enabled
          </label>
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

export default function AgentGroupsPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editingGroup, setEditingGroup] = useState<AgentGroup | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['agent-groups'],
    queryFn: () => getAgentGroups(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteAgentGroup,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['agent-groups'] }),
  });

  const createMutation = useMutation({
    mutationFn: createAgentGroup,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-groups'] });
      setShowCreate(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<AgentGroup> }) => updateAgentGroup(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-groups'] });
      setEditingGroup(null);
    },
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
        <div className="flex gap-3 justify-end">
          <button
            onClick={(e) => { e.stopPropagation(); setEditingGroup(g); }}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            Edit
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); if (confirm(`Delete group ${g.name}?`)) deleteMutation.mutate(g.id); }}
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
        title="Agent Groups"
        subtitle={data ? `${data.total} groups` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary">
            + New Group
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No agent groups configured" />
        )}
      </div>
      <CreateAgentGroupModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['agent-groups'] });
          setShowCreate(false);
        }}
        isLoading={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
      />
      <EditAgentGroupModal
        group={editingGroup}
        onClose={() => setEditingGroup(null)}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['agent-groups'] });
          setEditingGroup(null);
        }}
        isLoading={updateMutation.isPending}
        error={updateMutation.error ? (updateMutation.error as Error).message : null}
      />
    </>
  );
}
