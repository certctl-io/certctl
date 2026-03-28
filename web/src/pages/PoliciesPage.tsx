import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getPolicies, updatePolicy, deletePolicy, createPolicy } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { PolicyRule } from '../api/types';

const severityStyles: Record<string, string> = {
  low: 'badge-info',
  medium: 'badge-warning',
  high: 'badge-danger',
  critical: 'badge-danger',
};

const severityDots: Record<string, string> = {
  low: 'bg-emerald-500',
  medium: 'bg-amber-500',
  high: 'bg-orange-500',
  critical: 'bg-red-500',
};

interface CreatePolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
}

function CreatePolicyModal({ isOpen, onClose, onSuccess, isLoading, error }: CreatePolicyModalProps) {
  const [name, setName] = useState('');
  const [type, setType] = useState('key_algorithm');
  const [severity, setSeverity] = useState('medium');
  const [configStr, setConfigStr] = useState('{}');
  const [enabled, setEnabled] = useState(true);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      const config = JSON.parse(configStr);
      await createPolicy({ name: name.trim(), type, severity, config, enabled });
      setName('');
      setType('key_algorithm');
      setSeverity('medium');
      setConfigStr('{}');
      setEnabled(true);
      onSuccess();
    } catch (err) {
      console.error('Create policy error:', err);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Policy</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="e.g., Key Length Enforcement"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Type *</label>
            <select
              value={type}
              onChange={e => setType(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
            >
              <option value="key_algorithm">Key Algorithm</option>
              <option value="cert_lifetime">Certificate Lifetime</option>
              <option value="san_pattern">SAN Pattern</option>
              <option value="key_usage">Key Usage</option>
              <option value="revocation_check">Revocation Check</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Severity *</label>
            <select
              value={severity}
              onChange={e => setSeverity(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Config (JSON)</label>
            <textarea
              value={configStr}
              onChange={e => setConfigStr(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink font-mono focus:outline-none focus:border-brand-400"
              placeholder='{"key": "value"}'
              rows={3}
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
              {isLoading ? 'Creating...' : 'Create Policy'}
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

export default function PoliciesPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['policies'],
    queryFn: () => getPolicies(),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => updatePolicy(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });

  const createMutation = useMutation({
    mutationFn: createPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      setShowCreate(false);
    },
  });

  const policies = data?.data || [];
  const enabledCount = policies.filter(p => p.enabled).length;
  const bySeverity = policies.reduce<Record<string, number>>((acc, p) => {
    acc[p.severity] = (acc[p.severity] || 0) + 1;
    return acc;
  }, {});

  const columns: Column<PolicyRule>[] = [
    {
      key: 'name',
      label: 'Rule',
      render: (p) => (
        <div>
          <div className="font-medium text-ink">{p.name}</div>
          <div className="text-xs text-ink-faint">{p.id}</div>
        </div>
      ),
    },
    { key: 'type', label: 'Type', render: (p) => <span className="text-sm text-ink">{p.type.replace(/_/g, ' ')}</span> },
    {
      key: 'severity',
      label: 'Severity',
      render: (p) => <span className={`badge ${severityStyles[p.severity] || 'badge-neutral'}`}>{p.severity}</span>,
    },
    {
      key: 'config',
      label: 'Config',
      render: (p) => {
        if (!p.config || Object.keys(p.config).length === 0) return <span className="text-ink-faint">&mdash;</span>;
        return (
          <span className="text-xs text-ink-muted font-mono truncate max-w-xs block">
            {JSON.stringify(p.config).slice(0, 50)}
          </span>
        );
      },
    },
    {
      key: 'enabled',
      label: 'Enabled',
      render: (p) => (
        <button
          onClick={(e) => { e.stopPropagation(); toggleMutation.mutate({ id: p.id, enabled: !p.enabled }); }}
          className={`text-xs font-medium transition-colors ${p.enabled ? 'text-emerald-600 hover:text-emerald-700' : 'text-ink-faint hover:text-ink-muted'}`}
        >
          {p.enabled ? 'Enabled' : 'Disabled'}
        </button>
      ),
    },
    { key: 'created', label: 'Created', render: (p) => <span className="text-xs text-ink-muted">{formatDateTime(p.created_at)}</span> },
    {
      key: 'actions',
      label: '',
      render: (p) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete policy ${p.name}?`)) deleteMutation.mutate(p.id); }}
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
        title="Policies"
        subtitle={data ? `${data.total} rules` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary">
            + New Policy
          </button>
        }
      />
      {policies.length > 0 && (
        <div className="px-4 py-3 flex flex-wrap gap-4 border-b border-surface-border/50">
          <div className="flex items-center gap-2">
            <span className="text-xs text-ink-muted">Enabled:</span>
            <span className="text-xs font-medium text-emerald-600">{enabledCount}</span>
            <span className="text-xs text-ink-faint">/</span>
            <span className="text-xs text-ink-muted">{policies.length}</span>
          </div>
          {Object.entries(bySeverity).map(([sev, count]) => (
            <div key={sev} className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${severityDots[sev] || 'bg-slate-400'}`} />
              <span className="text-xs text-ink capitalize">{sev}</span>
              <span className="text-xs text-ink-faint">{count}</span>
            </div>
          ))}
        </div>
      )}
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={policies} isLoading={isLoading} emptyMessage="No policy rules" />
        )}
      </div>
      <CreatePolicyModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => {}}
        isLoading={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
      />
    </>
  );
}
