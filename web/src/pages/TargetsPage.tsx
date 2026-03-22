import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getTargets, createTarget, deleteTarget } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Target } from '../api/types';

const typeLabels: Record<string, string> = {
  nginx: 'NGINX',
  f5_bigip: 'F5 BIG-IP',
  iis: 'IIS',
  apache: 'Apache',
  haproxy: 'HAProxy',
};

const TARGET_TYPES = [
  { value: 'nginx', label: 'NGINX', description: 'Deploy to NGINX web server via file write + config validation + reload' },
  { value: 'apache', label: 'Apache httpd', description: 'Separate cert/chain/key files, apachectl configtest, graceful reload' },
  { value: 'haproxy', label: 'HAProxy', description: 'Combined PEM file (cert+chain+key), optional validate, reload' },
  { value: 'f5_bigip', label: 'F5 BIG-IP', description: 'iControl REST via proxy agent (V3 implementation)' },
  { value: 'iis', label: 'IIS', description: 'Windows IIS via agent-local PowerShell or proxy WinRM (V3 implementation)' },
];

const CONFIG_FIELDS: Record<string, { key: string; label: string; placeholder: string; required?: boolean }[]> = {
  nginx: [
    { key: 'cert_path', label: 'Certificate Path', placeholder: '/etc/nginx/ssl/cert.pem', required: true },
    { key: 'key_path', label: 'Key Path', placeholder: '/etc/nginx/ssl/key.pem', required: true },
    { key: 'chain_path', label: 'Chain Path', placeholder: '/etc/nginx/ssl/chain.pem' },
    { key: 'reload_cmd', label: 'Reload Command', placeholder: 'nginx -t && systemctl reload nginx' },
  ],
  apache: [
    { key: 'cert_path', label: 'Certificate Path', placeholder: '/etc/apache2/ssl/cert.pem', required: true },
    { key: 'key_path', label: 'Key Path', placeholder: '/etc/apache2/ssl/key.pem', required: true },
    { key: 'chain_path', label: 'Chain Path', placeholder: '/etc/apache2/ssl/chain.pem' },
    { key: 'reload_cmd', label: 'Reload Command', placeholder: 'apachectl configtest && apachectl graceful' },
  ],
  haproxy: [
    { key: 'pem_path', label: 'Combined PEM Path', placeholder: '/etc/haproxy/certs/combined.pem', required: true },
    { key: 'reload_cmd', label: 'Reload Command', placeholder: 'systemctl reload haproxy' },
    { key: 'validate_cmd', label: 'Validate Command (optional)', placeholder: 'haproxy -c -f /etc/haproxy/haproxy.cfg' },
  ],
  f5_bigip: [
    { key: 'management_ip', label: 'Management IP', placeholder: '192.168.1.100', required: true },
    { key: 'partition', label: 'Partition', placeholder: 'Common' },
    { key: 'proxy_agent_id', label: 'Proxy Agent ID', placeholder: 'agent-f5-proxy' },
  ],
  iis: [
    { key: 'site_name', label: 'IIS Site Name', placeholder: 'Default Web Site', required: true },
    { key: 'binding_ip', label: 'Binding IP', placeholder: '*' },
    { key: 'binding_port', label: 'Binding Port', placeholder: '443' },
    { key: 'cert_store', label: 'Certificate Store', placeholder: 'My' },
  ],
};

function CreateTargetWizard({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [step, setStep] = useState<'type' | 'config' | 'review'>('type');
  const [targetType, setTargetType] = useState('');
  const [name, setName] = useState('');
  const [hostname, setHostname] = useState('');
  const [agentId, setAgentId] = useState('');
  const [config, setConfig] = useState<Record<string, string>>({});
  const [error, setError] = useState('');

  const mutation = useMutation({
    mutationFn: () => createTarget({
      name,
      type: targetType,
      hostname,
      agent_id: agentId,
      config: Object.fromEntries(Object.entries(config).filter(([, v]) => v)),
    }),
    onSuccess: () => onSuccess(),
    onError: (err: Error) => setError(err.message),
  });

  const fields = CONFIG_FIELDS[targetType] || [];
  const canProceedToReview = name && targetType && fields.filter(f => f.required).every(f => config[f.key]);

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-slate-800 border border-slate-600 rounded-xl p-6 w-full max-w-lg shadow-2xl" onClick={e => e.stopPropagation()}>
        {/* Step indicators */}
        <div className="flex items-center gap-3 mb-6">
          {['Select Type', 'Configure', 'Review'].map((label, i) => {
            const stepNames = ['type', 'config', 'review'] as const;
            const currentIdx = stepNames.indexOf(step);
            const isActive = i === currentIdx;
            const isDone = i < currentIdx;
            return (
              <div key={label} className="flex items-center gap-2">
                <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
                  isDone ? 'bg-emerald-500 text-white' : isActive ? 'bg-blue-500 text-white' : 'bg-slate-700 text-slate-400'
                }`}>
                  {isDone ? '✓' : i + 1}
                </div>
                <span className={`text-xs ${isActive ? 'text-slate-200' : 'text-slate-500'}`}>{label}</span>
                {i < 2 && <div className="w-8 h-px bg-slate-700" />}
              </div>
            );
          })}
        </div>

        {error && <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-3 py-2 text-sm mb-4">{error}</div>}

        {/* Step 1: Select Type */}
        {step === 'type' && (
          <div>
            <h2 className="text-lg font-semibold text-slate-200 mb-4">Select Target Type</h2>
            <div className="space-y-2">
              {TARGET_TYPES.map(t => (
                <button
                  key={t.value}
                  onClick={() => { setTargetType(t.value); setConfig({}); }}
                  className={`w-full text-left px-4 py-3 rounded-lg border transition-colors ${
                    targetType === t.value
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-slate-600 hover:border-slate-500 bg-slate-900'
                  }`}
                >
                  <div className="text-sm font-medium text-slate-200">{t.label}</div>
                  <div className="text-xs text-slate-400 mt-0.5">{t.description}</div>
                </button>
              ))}
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={onClose} className="btn btn-ghost text-sm">Cancel</button>
              <button onClick={() => setStep('config')} disabled={!targetType}
                className="btn btn-primary text-sm disabled:opacity-50">Next</button>
            </div>
          </div>
        )}

        {/* Step 2: Configure */}
        {step === 'config' && (
          <div>
            <h2 className="text-lg font-semibold text-slate-200 mb-4">
              Configure {typeLabels[targetType] || targetType} Target
            </h2>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Target Name *</label>
                <input value={name} onChange={e => setName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  placeholder="web-server-1" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Hostname</label>
                  <input value={hostname} onChange={e => setHostname(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                    placeholder="web1.example.com" />
                </div>
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Agent ID</label>
                  <input value={agentId} onChange={e => setAgentId(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                    placeholder="agent-web1" />
                </div>
              </div>
              {fields.map(f => (
                <div key={f.key}>
                  <label className="text-xs text-slate-400 block mb-1">{f.label} {f.required ? '*' : ''}</label>
                  <input value={config[f.key] || ''} onChange={e => setConfig(c => ({ ...c, [f.key]: e.target.value }))}
                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                    placeholder={f.placeholder} />
                </div>
              ))}
            </div>
            <div className="flex justify-between gap-3 mt-6">
              <button onClick={() => setStep('type')} className="btn btn-ghost text-sm">Back</button>
              <div className="flex gap-3">
                <button onClick={onClose} className="btn btn-ghost text-sm">Cancel</button>
                <button onClick={() => setStep('review')} disabled={!canProceedToReview}
                  className="btn btn-primary text-sm disabled:opacity-50">Review</button>
              </div>
            </div>
          </div>
        )}

        {/* Step 3: Review */}
        {step === 'review' && (
          <div>
            <h2 className="text-lg font-semibold text-slate-200 mb-4">Review Target</h2>
            <div className="bg-slate-900 rounded-lg p-4 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Name</span>
                <span className="text-slate-200">{name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Type</span>
                <span className="text-slate-200">{typeLabels[targetType] || targetType}</span>
              </div>
              {hostname && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Hostname</span>
                  <span className="text-slate-200 font-mono text-xs">{hostname}</span>
                </div>
              )}
              {agentId && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Agent</span>
                  <span className="text-slate-200 font-mono text-xs">{agentId}</span>
                </div>
              )}
              {Object.entries(config).filter(([, v]) => v).map(([k, v]) => (
                <div key={k} className="flex justify-between">
                  <span className="text-slate-400">{k.replace(/_/g, ' ')}</span>
                  <span className="text-slate-200 font-mono text-xs truncate max-w-xs">{v}</span>
                </div>
              ))}
            </div>
            <div className="flex justify-between gap-3 mt-6">
              <button onClick={() => setStep('config')} className="btn btn-ghost text-sm">Back</button>
              <div className="flex gap-3">
                <button onClick={onClose} className="btn btn-ghost text-sm">Cancel</button>
                <button onClick={() => mutation.mutate()} disabled={mutation.isPending}
                  className="btn btn-primary text-sm disabled:opacity-50">
                  {mutation.isPending ? 'Creating...' : 'Create Target'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function TargetsPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['targets'],
    queryFn: () => getTargets(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteTarget,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['targets'] }),
  });

  const columns: Column<Target>[] = [
    {
      key: 'name',
      label: 'Target',
      render: (t) => (
        <div>
          <div className="font-medium text-slate-200">{t.name}</div>
          <div className="text-xs text-slate-500 font-mono">{t.id}</div>
        </div>
      ),
    },
    {
      key: 'type',
      label: 'Type',
      render: (t) => (
        <span className="badge badge-neutral">{typeLabels[t.type] || t.type}</span>
      ),
    },
    {
      key: 'hostname',
      label: 'Hostname',
      render: (t) => <span className="text-slate-300 font-mono text-xs">{t.hostname || '\u2014'}</span>,
    },
    {
      key: 'agent',
      label: 'Agent',
      render: (t) => <span className="text-xs text-slate-400 font-mono">{t.agent_id || '\u2014'}</span>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (t) => <StatusBadge status={t.status} />,
    },
    {
      key: 'created',
      label: 'Created',
      render: (t) => <span className="text-xs text-slate-400">{formatDateTime(t.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (t) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete target ${t.name}?`)) deleteMutation.mutate(t.id); }}
          className="text-xs text-red-400 hover:text-red-300 transition-colors"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Deployment Targets"
        subtitle={data ? `${data.total} targets` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary text-xs">
            + New Target
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No deployment targets" />
        )}
      </div>
      {showCreate && (
        <CreateTargetWizard
          onClose={() => setShowCreate(false)}
          onSuccess={() => {
            setShowCreate(false);
            queryClient.invalidateQueries({ queryKey: ['targets'] });
          }}
        />
      )}
    </>
  );
}
