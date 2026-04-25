import { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getIssuers, testIssuerConnection, deleteIssuer, createIssuer, updateIssuer } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Issuer } from '../api/types';
import { issuerTypes, typeLabels, getIssuerCatalogStatus, type IssuerTypeConfig } from '../config/issuerTypes';
import TypeSelector from '../components/issuer/TypeSelector';
import ConfigForm from '../components/issuer/ConfigForm';
import ConfigDetailModal from '../components/issuer/ConfigDetailModal';

/** Derive display status from backend enabled boolean */
function issuerStatus(issuer: Issuer): string {
  if (issuer.enabled !== undefined) {
    return issuer.enabled ? 'Enabled' : 'Disabled';
  }
  // Fallback for legacy data that may have status string
  return issuer.status || 'Unknown';
}

export default function IssuersPage() {
  const queryClient = useQueryClient();
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [preselectedType, setPreselectedType] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [configModal, setConfigModal] = useState<{ title: string; config: Record<string, unknown> } | null>(null);
  // B-1 master closure (cat-b-7a34f893a8f9): rename-only Edit affordance.
  // Pre-B-1 the only way to rename an issuer was delete-and-recreate,
  // which destroyed cert provenance and forced a re-encryption cycle
  // through internal/crypto/encryption.go for every cert under the
  // issuer. Type and credential blob are intentionally NOT editable here
  // — changing the underlying CA driver type would require
  // re-encrypting config under a different schema, and credentials are
  // stored encrypted at rest (we can't decrypt them client-side to
  // pre-populate). Operators who need to rotate credentials still
  // delete + recreate. Documented as a deferred follow-up in the L-1
  // CHANGELOG entry.
  const [editingIssuer, setEditingIssuer] = useState<Issuer | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['issuers'],
    queryFn: () => getIssuers(),
  });

  const testMutation = useMutation({
    mutationFn: testIssuerConnection,
    onSuccess: (_data, id) => setTestResult({ id, ok: true, msg: 'Connection successful' }),
    onError: (err: Error, id) => setTestResult({ id, ok: false, msg: err.message }),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteIssuer,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['issuers'] }),
  });

  const createMutation = useMutation({
    mutationFn: (data: { name: string; type: string; config: Record<string, unknown> }) =>
      createIssuer(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['issuers'] });
      setShowCreateModal(false);
      setPreselectedType(null);
    },
  });

  // B-1 master closure: updateIssuer is wired to the rename-only Edit
  // modal. Type and credential blob are NOT mutated here — see editingIssuer
  // docblock above. Sends `{ name, type, config }` to satisfy the backend
  // PUT contract (the handler decodes into a full domain.Issuer struct);
  // type + config are preserved by reading them from the editing target.
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Issuer> }) => updateIssuer(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['issuers'] });
      setEditingIssuer(null);
    },
  });

  const catalogStatus = useMemo(
    () => getIssuerCatalogStatus(data?.data || []),
    [data?.data]
  );

  // Filter issuers by type
  const filteredIssuers = useMemo(() => {
    if (!data?.data) return [];
    if (!typeFilter) return data.data;
    return data.data.filter(i => i.type === typeFilter);
  }, [data?.data, typeFilter]);

  const columns: Column<Issuer>[] = [
    {
      key: 'name',
      label: 'Issuer',
      render: (i) => (
        <div>
          <Link to={`/issuers/${i.id}`} className="font-medium text-accent hover:text-accent-bright" onClick={(e) => e.stopPropagation()}>
            {i.name}
          </Link>
          <div className="text-xs text-ink-faint font-mono">{i.id}</div>
        </div>
      ),
    },
    {
      key: 'type',
      label: 'Type',
      render: (i) => (
        <span className="badge badge-neutral">{typeLabels[i.type] || i.type}</span>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (i) => <StatusBadge status={issuerStatus(i)} />,
    },
    {
      key: 'config',
      label: 'Config',
      render: (i) => {
        if (!i.config || Object.keys(i.config).length === 0) return <span className="text-ink-faint">&mdash;</span>;
        return (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setConfigModal({ title: `${i.name} Configuration`, config: i.config });
            }}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            View Config
          </button>
        );
      },
    },
    {
      key: 'created',
      label: 'Created',
      render: (i) => <span className="text-xs text-ink-muted">{formatDateTime(i.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (i) => (
        <div className="flex gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); testMutation.mutate(i.id); }}
            disabled={testMutation.isPending}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            Test
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); setEditingIssuer(i); }}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            Edit
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); if (confirm(`Delete issuer ${i.name}?`)) deleteMutation.mutate(i.id); }}
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
        title="Issuers"
        subtitle={data ? `${data.total} configured` : undefined}
        action={
          <button
            onClick={() => {
              setPreselectedType(null);
              setShowCreateModal(true);
            }}
            className="px-4 py-2 bg-brand-600 text-white rounded font-medium hover:bg-brand-700 transition-colors text-sm"
          >
            + New Issuer
          </button>
        }
      />
      {testResult && (
        <div className={`mx-6 mt-3 rounded px-4 py-3 text-sm ${testResult.ok ? 'bg-emerald-100 border border-emerald-200 text-emerald-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
          {testResult.id}: {testResult.msg}
          <button onClick={() => setTestResult(null)} className="ml-3 text-xs opacity-60 hover:opacity-100">dismiss</button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <>
            {/* Issuer Type Catalog Cards */}
            <div className="px-6 py-4">
              <h3 className="text-sm font-semibold text-ink-muted mb-3">Issuer Types</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {catalogStatus.map(({ type, status, count }) => (
                  <CatalogCard
                    key={type.id}
                    type={type}
                    status={status}
                    count={count}
                    onConfigure={() => {
                      setPreselectedType(type.id);
                      setShowCreateModal(true);
                    }}
                    onFilter={() => {
                      // Match both the canonical id and aliases
                      const filterValue = type.id === 'local' ? 'local' : type.id;
                      setTypeFilter(prev => prev === filterValue ? '' : filterValue);
                    }}
                  />
                ))}
              </div>
            </div>

            {/* Configured Issuers Table */}
            <div className="px-6 pb-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-ink-muted">Configured Issuers</h3>
                <div className="flex items-center gap-2">
                  <select
                    value={typeFilter}
                    onChange={(e) => setTypeFilter(e.target.value)}
                    className="text-xs px-2 py-1.5 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500"
                  >
                    <option value="">All Types</option>
                    {issuerTypes.filter(t => !t.comingSoon).map(t => (
                      <option key={t.id} value={t.id}>{t.name}</option>
                    ))}
                  </select>
                </div>
              </div>
              <DataTable
                columns={columns}
                data={filteredIssuers}
                isLoading={isLoading}
                emptyMessage={typeFilter ? `No ${typeLabels[typeFilter] || typeFilter} issuers configured` : 'No issuers configured'}
              />
            </div>
          </>
        )}
      </div>

      {/* Config Detail Modal */}
      {configModal && (
        <ConfigDetailModal
          title={configModal.title}
          config={configModal.config}
          onClose={() => setConfigModal(null)}
        />
      )}

      {/* Create Issuer Modal */}
      {showCreateModal && (
        <CreateIssuerModal
          preselectedType={preselectedType}
          onSubmit={(name, type, config) => {
            createMutation.mutate({ name, type, config });
          }}
          onCancel={() => {
            setShowCreateModal(false);
            setPreselectedType(null);
          }}
          isSubmitting={createMutation.isPending}
        />
      )}

      {/* B-1 closure: EditIssuerModal — rename-only. */}
      <EditIssuerModal
        issuer={editingIssuer}
        onClose={() => setEditingIssuer(null)}
        onSave={(name) => {
          if (!editingIssuer) return;
          updateMutation.mutate({
            id: editingIssuer.id,
            data: {
              name,
              // Preserve type + config + enabled — the rename-only
              // contract. Credential blob stays encrypted at rest.
              type: editingIssuer.type,
              config: editingIssuer.config,
              enabled: editingIssuer.enabled,
            },
          });
        }}
        isSaving={updateMutation.isPending}
        error={updateMutation.error ? (updateMutation.error as Error).message : null}
      />
    </>
  );
}

// ─── EditIssuerModal — rename-only Edit modal (B-1) ─────────────
//
// Locked: type, config (credentials), enabled. Editable: name only.
// The audit's "destructive rename workflow" complaint is specifically
// about renames; B-1 closes that hazard. Credential rotation still
// requires delete-and-recreate (see CHANGELOG B-1 known follow-ups).
interface EditIssuerModalProps {
  issuer: Issuer | null;
  onClose: () => void;
  onSave: (name: string) => void;
  isSaving: boolean;
  error: string | null;
}

function EditIssuerModal({ issuer, onClose, onSave, isSaving, error }: EditIssuerModalProps) {
  const [name, setName] = useState('');
  useEffect(() => { if (issuer) setName(issuer.name); }, [issuer]);

  if (!issuer) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    onSave(name.trim());
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Edit Issuer</h2>
        <p className="text-xs text-ink-muted mb-4 font-mono">{issuer.id}</p>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input value={name} onChange={e => setName(e.target.value)} required
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink-muted mb-1">Type (locked)</label>
            <input value={issuer.type} disabled
              className="w-full bg-surface-border/50 border border-surface-border rounded px-3 py-2 text-sm text-ink-muted font-mono" />
            <p className="text-xs text-ink-faint mt-1">
              To change issuer type or rotate credentials, delete and recreate.
              See CHANGELOG B-1 known follow-ups.
            </p>
          </div>
          <div className="flex gap-2 pt-4">
            <button type="submit" disabled={isSaving} className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed">
              {isSaving ? 'Saving...' : 'Save Changes'}
            </button>
            <button type="button" onClick={onClose} className="flex-1 btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Catalog Card ───────────────────────────────────────────────

interface CatalogCardProps {
  type: IssuerTypeConfig;
  status: 'connected' | 'available' | 'coming_soon';
  count: number;
  onConfigure: () => void;
  onFilter: () => void;
}

function CatalogCard({ type, status, count, onConfigure, onFilter }: CatalogCardProps) {
  const statusConfig = {
    connected: { label: `${count} configured`, cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
    available: { label: 'Available', cls: 'bg-brand-500/10 text-brand-400 border-brand-500/30' },
    coming_soon: { label: 'Coming Soon', cls: 'bg-gray-500/10 text-gray-400 border-gray-500/30' },
  };
  const { label, cls } = statusConfig[status];

  return (
    <div className={`p-4 border rounded-lg ${status === 'coming_soon' ? 'border-surface-border/50 opacity-60' : 'border-surface-border'}`}>
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-lg">{type.icon}</span>
          <span className="font-medium text-ink text-sm">{type.name}</span>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded-full border ${cls}`}>{label}</span>
      </div>
      <p className="text-xs text-ink-muted mb-3">{type.description}</p>
      {status === 'connected' && (
        <button
          onClick={onFilter}
          className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
        >
          View issuers
        </button>
      )}
      {status === 'available' && (
        <button
          onClick={onConfigure}
          className="text-xs px-3 py-1 bg-brand-600 text-white rounded hover:bg-brand-700 transition-colors"
        >
          Configure
        </button>
      )}
    </div>
  );
}

// ─── Create Issuer Modal ────────────────────────────────────────

interface CreateIssuerModalProps {
  preselectedType: string | null;
  onSubmit: (name: string, type: string, config: Record<string, unknown>) => void;
  onCancel: () => void;
  isSubmitting: boolean;
}

function CreateIssuerModal({ preselectedType, onSubmit, onCancel, isSubmitting }: CreateIssuerModalProps) {
  const [step, setStep] = useState<'type' | 'config'>(preselectedType ? 'config' : 'type');
  const [selectedType, setSelectedType] = useState<string | null>(preselectedType);
  const [form, setForm] = useState<Record<string, unknown>>(() => {
    if (preselectedType) {
      const tc = issuerTypes.find(t => t.id === preselectedType);
      const defaults: Record<string, unknown> = {};
      tc?.configFields.forEach(f => { if (f.defaultValue) defaults[f.key] = f.defaultValue; });
      return defaults;
    }
    return {};
  });

  const selectedTypeConfig = issuerTypes.find(t => t.id === selectedType);

  function handleTypeSelect(typeId: string) {
    setSelectedType(typeId);
    const tc = issuerTypes.find(t => t.id === typeId);
    const defaults: Record<string, unknown> = {};
    tc?.configFields.forEach(f => { if (f.defaultValue) defaults[f.key] = f.defaultValue; });
    setForm(defaults);
    setStep('config');
  }

  function handleSubmit() {
    if (!selectedType || !form.name) return;
    const config = { ...form };
    const name = config.name as string;
    delete config.name;
    onSubmit(name, selectedType, config);
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <div className="bg-surface border border-surface-border rounded-lg shadow-lg max-w-2xl w-full mx-4">
        {/* Header */}
        <div className="border-b border-surface-border px-6 py-4 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-ink">
            {step === 'type' ? 'Create Issuer' : `Configure ${selectedTypeConfig?.name || 'Issuer'}`}
          </h2>
          <button onClick={onCancel} className="text-ink-muted hover:text-ink transition-colors">
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-6">
          {step === 'type' ? (
            <TypeSelector onSelect={handleTypeSelect} />
          ) : (
            <div className="space-y-5">
              {/* Name field */}
              <div>
                <label className="block text-sm font-medium text-ink mb-2">Issuer Name *</label>
                <input
                  type="text"
                  value={(form.name as string) || ''}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g., Production CA"
                  className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
                />
              </div>
              {/* Type-specific fields via ConfigForm */}
              {selectedTypeConfig && (
                <ConfigForm
                  fields={selectedTypeConfig.configFields}
                  values={form}
                  onChange={(key, value) => setForm({ ...form, [key]: value })}
                />
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-surface-border px-6 py-4 flex justify-end gap-3">
          {step === 'config' && (
            <button
              onClick={() => setStep('type')}
              className="px-4 py-2 border border-surface-border rounded text-ink hover:bg-surface-hover transition-colors text-sm font-medium"
            >
              Back
            </button>
          )}
          <button
            onClick={onCancel}
            className="px-4 py-2 border border-surface-border rounded text-ink hover:bg-surface-hover transition-colors text-sm font-medium"
          >
            Cancel
          </button>
          {step === 'config' && (
            <button
              onClick={handleSubmit}
              disabled={isSubmitting || !form.name}
              className="px-4 py-2 bg-brand-600 text-white rounded text-sm font-medium hover:bg-brand-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? 'Creating...' : 'Create Issuer'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
