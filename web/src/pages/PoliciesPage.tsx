import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { getPolicies, updatePolicy, deletePolicy, createPolicy } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import {
  POLICY_TYPES,
  POLICY_SEVERITIES,
  type PolicyRule,
  type PolicyType,
  type PolicySeverity,
} from '../api/types';

/**
 * Severity → badge style. Keyed on the backend's TitleCase PolicySeverity
 * enum values (D-006). The pre-fix map keyed on `low`/`medium`/`high`/`critical`
 * which never matched the backend's `Warning`/`Error`/`Critical`, so every
 * existing rule fell through to the `badge-neutral` default.
 */
const severityStyles: Record<PolicySeverity, string> = {
  Warning: 'badge-warning',
  Error: 'badge-danger',
  Critical: 'badge-danger',
};

const severityDots: Record<PolicySeverity, string> = {
  Warning: 'bg-amber-500',
  Error: 'bg-orange-500',
  Critical: 'bg-red-500',
};

/**
 * Convert TitleCase enum value to a human-readable label for display.
 * "AllowedIssuers" → "Allowed Issuers"
 */
function humanize(s: string): string {
  return s.replace(/([A-Z])/g, ' $1').trim();
}

interface CreatePolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
}

function CreatePolicyModal({ isOpen, onClose, onSuccess, isLoading, error }: CreatePolicyModalProps) {
  const [name, setName] = useState('');
  const [type, setType] = useState<PolicyType>(POLICY_TYPES[0]);
  const [severity, setSeverity] = useState<PolicySeverity>('Warning');
  const [configStr, setConfigStr] = useState('{}');
  const [enabled, setEnabled] = useState(true);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    const config = JSON.parse(configStr);
    await createPolicy({ name: name.trim(), type, severity, config, enabled });
    setName('');
    setType(POLICY_TYPES[0]);
    setSeverity('Warning');
    setConfigStr('{}');
    setEnabled(true);
    onSuccess();
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
              onChange={e => setType(e.target.value as PolicyType)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
            >
              {POLICY_TYPES.map(t => (
                <option key={t} value={t}>{humanize(t)}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Severity *</label>
            <select
              value={severity}
              onChange={e => setSeverity(e.target.value as PolicySeverity)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
            >
              {POLICY_SEVERITIES.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
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

  const toggleMutation = useTrackedMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => updatePolicy(id, { enabled }),
    invalidates: [['policies']],
  });

  const deleteMutation = useTrackedMutation({
    mutationFn: deletePolicy,
    invalidates: [['policies']],
  });

  const createMutation = useTrackedMutation({
    mutationFn: createPolicy,
    invalidates: [['policies']],
    onSuccess: () => {
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
    { key: 'type', label: 'Type', render: (p) => <span className="text-sm text-ink">{humanize(p.type)}</span> },
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
              <div className={`w-2 h-2 rounded-full ${severityDots[sev as PolicySeverity] || 'bg-slate-400'}`} />
              <span className="text-xs text-ink">{sev}</span>
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
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['policies'] });
          setShowCreate(false);
        }}
        isLoading={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
      />
    </>
  );
}
