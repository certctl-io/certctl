import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getRenewalPolicies,
  createRenewalPolicy,
  updateRenewalPolicy,
  deleteRenewalPolicy,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { RenewalPolicy } from '../api/types';

// RenewalPoliciesPage — B-1 master closure (cat-b-4631ca092bee).
// Pre-B-1 the backend had full CRUD at /api/v1/renewal-policies but
// there was no GUI page. Operators wanting to edit the seeded
// `rp-default` policy or create custom `rp-*` policies for short-lived
// certs had to go through `psql` directly. This page exposes the table
// + Create + Edit + Delete affordances. Renewal policies are referenced
// by managed certificates via `renewal_policy_id`; the backend's
// repository.ErrRenewalPolicyInUse sentinel surfaces a 409 on Delete
// when a policy still has cert references — surfaced as an alert here.
//
// Field set per `internal/domain/certificate.go::RenewalPolicy`:
//   - renewal_window_days: int (when to start renewal — usually 30)
//   - auto_renew: bool (whether the scheduler renews automatically)
//   - max_retries: int
//   - retry_interval_seconds: int (post-U-3 column rename;
//     cat-o-retry_interval_unit_mismatch closed)
//   - alert_thresholds_days: int[] (notification days before expiry)

interface PolicyFormFields {
  name: string;
  renewal_window_days: number;
  auto_renew: boolean;
  max_retries: number;
  retry_interval_seconds: number;
  alert_thresholds_days: number[];
}

function defaultFields(): PolicyFormFields {
  return {
    name: '',
    renewal_window_days: 30,
    auto_renew: true,
    max_retries: 3,
    retry_interval_seconds: 60,
    alert_thresholds_days: [30, 14, 7, 0],
  };
}

function policyToFields(p: RenewalPolicy): PolicyFormFields {
  return {
    name: p.name,
    renewal_window_days: p.renewal_window_days,
    auto_renew: p.auto_renew,
    max_retries: p.max_retries,
    retry_interval_seconds: p.retry_interval_seconds,
    alert_thresholds_days: p.alert_thresholds_days || [],
  };
}

// PolicyFormModal — shared scaffolding for Create + Edit. The only
// shape difference between the two flows is which mutationFn the
// caller supplies + the modal title; everything else mirrors.
interface PolicyFormModalProps {
  title: string;
  initial: PolicyFormFields;
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (fields: PolicyFormFields) => void;
  isSaving: boolean;
  error: string | null;
}

function PolicyFormModal({ title, initial, isOpen, onClose, onSubmit, isSaving, error }: PolicyFormModalProps) {
  const [fields, setFields] = useState<PolicyFormFields>(initial);

  useEffect(() => {
    if (isOpen) setFields(initial);
  }, [isOpen, initial]);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!fields.name.trim()) return;
    onSubmit({ ...fields, name: fields.name.trim() });
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">{title}</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={fields.name}
              onChange={e => setFields({ ...fields, name: e.target.value })}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="e.g., Standard 30-day"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Renewal Window (days)</label>
              <input
                type="number"
                value={fields.renewal_window_days}
                onChange={e => setFields({ ...fields, renewal_window_days: Number(e.target.value) })}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
                min={1}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Max Retries</label>
              <input
                type="number"
                value={fields.max_retries}
                onChange={e => setFields({ ...fields, max_retries: Number(e.target.value) })}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
                min={0}
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Retry Interval (seconds)</label>
            <input
              type="number"
              value={fields.retry_interval_seconds}
              onChange={e => setFields({ ...fields, retry_interval_seconds: Number(e.target.value) })}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              min={0}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Alert Thresholds (days, comma-separated)</label>
            <input
              value={fields.alert_thresholds_days.join(', ')}
              onChange={e => {
                const parts = e.target.value
                  .split(',')
                  .map(s => Number(s.trim()))
                  .filter(n => !isNaN(n));
                setFields({ ...fields, alert_thresholds_days: parts });
              }}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
              placeholder="30, 14, 7, 0"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={fields.auto_renew}
              onChange={e => setFields({ ...fields, auto_renew: e.target.checked })}
            />
            Auto-renew
          </label>
          <div className="flex gap-2 pt-4">
            <button type="submit" disabled={isSaving} className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed">
              {isSaving ? 'Saving...' : 'Save'}
            </button>
            <button type="button" onClick={onClose} className="flex-1 btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function RenewalPoliciesPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<RenewalPolicy | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['renewal-policies'],
    queryFn: () => getRenewalPolicies(),
  });

  const createMutation = useMutation({
    mutationFn: createRenewalPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['renewal-policies'] });
      setShowCreate(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<RenewalPolicy> }) => updateRenewalPolicy(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['renewal-policies'] });
      setEditing(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteRenewalPolicy,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['renewal-policies'] }),
    // Backend surfaces ErrRenewalPolicyInUse as a 409. We surface as an
    // alert so the operator sees "this policy is still attached to N
    // certificates" and can re-target those certs to another policy
    // before deleting.
    onError: (err: Error) => alert(`Delete failed: ${err.message}`),
  });

  const columns: Column<RenewalPolicy>[] = [
    {
      key: 'name',
      label: 'Policy',
      render: (p) => (
        <div>
          <div className="font-medium text-ink">{p.name}</div>
          <div className="text-xs text-ink-faint font-mono">{p.id}</div>
        </div>
      ),
    },
    {
      key: 'window',
      label: 'Renewal Window',
      render: (p) => <span className="text-sm text-ink">{p.renewal_window_days} days</span>,
    },
    {
      key: 'auto_renew',
      label: 'Auto',
      render: (p) => (
        <span className={p.auto_renew ? 'text-brand-400' : 'text-ink-faint'}>
          {p.auto_renew ? 'on' : 'manual'}
        </span>
      ),
    },
    {
      key: 'retries',
      label: 'Retries',
      render: (p) => <span className="text-sm text-ink-muted">{p.max_retries}× / {p.retry_interval_seconds}s</span>,
    },
    {
      key: 'alerts',
      label: 'Alert Thresholds',
      render: (p) => (
        <span className="text-xs text-ink-muted font-mono">
          {(p.alert_thresholds_days || []).join(', ') || '—'}
        </span>
      ),
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
        <div className="flex gap-3 justify-end">
          <button
            onClick={(e) => { e.stopPropagation(); setEditing(p); }}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            Edit
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (confirm(`Delete renewal policy ${p.name}?`)) deleteMutation.mutate(p.id);
            }}
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
        title="Renewal Policies"
        subtitle={data ? `${data.total} policies` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary">
            + New Policy
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data || []}
            isLoading={isLoading}
            emptyMessage="No renewal policies configured"
          />
        )}
      </div>
      <PolicyFormModal
        title="Create Renewal Policy"
        initial={defaultFields()}
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSubmit={(fields) => createMutation.mutate(fields)}
        isSaving={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
      />
      <PolicyFormModal
        title="Edit Renewal Policy"
        initial={editing ? policyToFields(editing) : defaultFields()}
        isOpen={!!editing}
        onClose={() => setEditing(null)}
        onSubmit={(fields) => {
          if (!editing) return;
          updateMutation.mutate({ id: editing.id, data: fields });
        }}
        isSaving={updateMutation.isPending}
        error={updateMutation.error ? (updateMutation.error as Error).message : null}
      />
    </>
  );
}
