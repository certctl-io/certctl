import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getIssuers, testIssuerConnection, deleteIssuer, createIssuer } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Issuer } from '../api/types';

const typeLabels: Record<string, string> = {
  local_ca: 'Local CA',
  acme: 'ACME',
  stepca: 'step-ca',
  openssl: 'OpenSSL/Custom',
  vault: 'Vault PKI',
  manual: 'Manual',
};

interface IssuerConfigField {
  key: string;
  label: string;
  placeholder?: string;
  required: boolean;
  type?: string;
  options?: string[];
  defaultValue?: string;
}

interface IssuerTypeConfig {
  id: string;
  name: string;
  description: string;
  configFields: IssuerConfigField[];
}

const issuerTypes: IssuerTypeConfig[] = [
  {
    id: 'local_ca',
    name: 'Local CA',
    description: 'Self-signed or subordinate CA for certificate issuance',
    configFields: [
      { key: 'ca_cert_path', label: 'CA Cert Path (optional)', placeholder: '/path/to/ca.crt', required: false },
      { key: 'ca_key_path', label: 'CA Key Path (optional)', placeholder: '/path/to/ca.key', required: false },
    ],
  },
  {
    id: 'acme',
    name: 'ACME',
    description: "Let's Encrypt or other ACME-compatible CA",
    configFields: [
      { key: 'directory_url', label: 'Directory URL', placeholder: 'https://acme-v02.api.letsencrypt.org/directory', required: true },
      { key: 'email', label: 'Email', placeholder: 'admin@example.com', required: true },
      { key: 'challenge_type', label: 'Challenge Type', type: 'select', options: ['http-01', 'dns-01', 'dns-persist-01'], required: false, defaultValue: 'http-01' },
    ],
  },
  {
    id: 'stepca',
    name: 'step-ca',
    description: 'Smallstep private CA',
    configFields: [
      { key: 'ca_url', label: 'CA URL', placeholder: 'https://ca.example.com', required: true },
      { key: 'provisioner_name', label: 'Provisioner Name', placeholder: 'my-provisioner', required: true },
      { key: 'provisioner_key', label: 'Provisioner Key (JWK)', placeholder: '{...}', type: 'textarea', required: true },
    ],
  },
  {
    id: 'openssl',
    name: 'OpenSSL/Custom',
    description: 'Script-based signing with your own CA',
    configFields: [
      { key: 'sign_script', label: 'Sign Script Path', placeholder: '/path/to/sign.sh', required: true },
      { key: 'revoke_script', label: 'Revoke Script Path (optional)', placeholder: '/path/to/revoke.sh', required: false },
      { key: 'crl_script', label: 'CRL Script Path (optional)', placeholder: '/path/to/crl.sh', required: false },
      { key: 'timeout_seconds', label: 'Timeout (seconds)', placeholder: '30', type: 'number', required: false },
    ],
  },
];

export default function IssuersPage() {
  const queryClient = useQueryClient();
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createStep, setCreateStep] = useState<'type' | 'config'>('type');
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState<Record<string, unknown>>({});

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
      setCreateStep('type');
      setSelectedType(null);
      setCreateForm({});
    },
  });

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
      render: (i) => <StatusBadge status={i.status} />,
    },
    {
      key: 'config',
      label: 'Config',
      render: (i) => {
        if (!i.config || Object.keys(i.config).length === 0) return <span className="text-ink-faint">&mdash;</span>;
        return (
          <span className="text-xs text-ink-muted font-mono truncate max-w-xs block">
            {JSON.stringify(i.config).slice(0, 60)}
          </span>
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
        subtitle={data ? `${data.total} issuers` : undefined}
        action={
          <button
            onClick={() => {
              setShowCreateModal(true);
              setCreateStep('type');
              setSelectedType(null);
              setCreateForm({});
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
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No issuers configured" />
        )}
      </div>

      {showCreateModal && (
        <CreateIssuerModal
          step={createStep}
          selectedType={selectedType}
          form={createForm}
          onTypeSelect={(type) => {
            setSelectedType(type);
            const typeConfig = issuerTypes.find((t) => t.id === type);
            const defaultConfig: Record<string, unknown> = {};
            if (typeConfig) {
              typeConfig.configFields.forEach((field) => {
                if (field.defaultValue) {
                  defaultConfig[field.key] = field.defaultValue;
                }
              });
            }
            setCreateForm({ ...defaultConfig });
            setCreateStep('config');
          }}
          onFormChange={(field, value) => {
            setCreateForm({ ...createForm, [field]: value });
          }}
          onBack={() => setCreateStep('type')}
          onSubmit={() => {
            if (!selectedType || !createForm.name) return;
            const config: Record<string, unknown> = { ...createForm };
            const name = config.name as string;
            delete config.name;
            createMutation.mutate({ name, type: selectedType, config });
          }}
          onCancel={() => {
            setShowCreateModal(false);
            setCreateStep('type');
            setSelectedType(null);
            setCreateForm({});
          }}
          isSubmitting={createMutation.isPending}
        />
      )}
    </>
  );
}

interface CreateIssuerModalProps {
  step: 'type' | 'config';
  selectedType: string | null;
  form: Record<string, unknown>;
  onTypeSelect: (type: string) => void;
  onFormChange: (field: string, value: unknown) => void;
  onBack: () => void;
  onSubmit: () => void;
  onCancel: () => void;
  isSubmitting: boolean;
}

function CreateIssuerModal({
  step,
  selectedType,
  form,
  onTypeSelect,
  onFormChange,
  onBack,
  onSubmit,
  onCancel,
  isSubmitting,
}: CreateIssuerModalProps) {
  const selectedTypeConfig = issuerTypes.find((t) => t.id === selectedType);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <div className="bg-surface border border-surface-border rounded-lg shadow-lg max-w-2xl w-full mx-4">
        {/* Header */}
        <div className="border-b border-surface-border px-6 py-4 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-ink">
            {step === 'type' ? 'Create Issuer' : `Configure ${selectedTypeConfig?.name || 'Issuer'}`}
          </h2>
          <button
            onClick={onCancel}
            className="text-ink-muted hover:text-ink transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-6">
          {step === 'type' ? (
            <div className="grid grid-cols-2 gap-4">
              {issuerTypes.map((type) => (
                <button
                  key={type.id}
                  onClick={() => onTypeSelect(type.id)}
                  className="p-4 border border-surface-border rounded-lg hover:border-brand-500 hover:bg-opacity-5 transition-all text-left"
                >
                  <div className="font-medium text-ink">{type.name}</div>
                  <div className="text-sm text-ink-muted mt-1">{type.description}</div>
                </button>
              ))}
            </div>
          ) : (
            <div className="space-y-5">
              {/* Name field always shown */}
              <div>
                <label className="block text-sm font-medium text-ink mb-2">Issuer Name *</label>
                <input
                  type="text"
                  value={(form.name as string) || ''}
                  onChange={(e) => onFormChange('name', e.target.value)}
                  placeholder="e.g., Production CA"
                  className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
                />
              </div>

              {/* Type-specific fields */}
              {selectedTypeConfig?.configFields.map((field) => (
                <div key={field.key}>
                  <label className="block text-sm font-medium text-ink mb-2">
                    {field.label}
                    {field.required && <span className="text-red-600 ml-1">*</span>}
                  </label>
                  {field.type === 'select' ? (
                    <select
                      value={(form[field.key] as string) || ''}
                      onChange={(e) => onFormChange(field.key, e.target.value)}
                      className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500 transition-colors"
                    >
                      <option value="">Select {field.label}</option>
                      {field.options?.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  ) : field.type === 'textarea' ? (
                    <textarea
                      value={(form[field.key] as string) || ''}
                      onChange={(e) => onFormChange(field.key, e.target.value)}
                      placeholder={field.placeholder}
                      rows={4}
                      className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors font-mono text-xs"
                    />
                  ) : field.type === 'number' ? (
                    <input
                      type="number"
                      value={(form[field.key] as number | string) || ''}
                      onChange={(e) => onFormChange(field.key, e.target.value ? parseInt(e.target.value, 10) : '')}
                      placeholder={field.placeholder}
                      className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
                    />
                  ) : (
                    <input
                      type="text"
                      value={(form[field.key] as string) || ''}
                      onChange={(e) => onFormChange(field.key, e.target.value)}
                      placeholder={field.placeholder}
                      className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
                    />
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-surface-border px-6 py-4 flex justify-end gap-3">
          {step === 'config' && (
            <button
              onClick={onBack}
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
              onClick={onSubmit}
              disabled={isSubmitting || !form.name}
              className="px-4 py-2 bg-brand-600 text-white rounded text-sm font-medium hover:bg-brand-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? 'Creating...' : 'Create Issuer'}
            </button>
          )}
          {step === 'type' && (
            <button
              onClick={() => selectedType && onTypeSelect(selectedType)}
              disabled={!selectedType}
              className="px-4 py-2 bg-brand-600 text-white rounded text-sm font-medium hover:bg-brand-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
