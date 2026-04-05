import { useState } from 'react';
import { Link } from 'react-router-dom';
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
  NGINX: 'NGINX',
  Apache: 'Apache',
  HAProxy: 'HAProxy',
  Traefik: 'Traefik',
  Caddy: 'Caddy',
  Envoy: 'Envoy',
  Postfix: 'Postfix',
  Dovecot: 'Dovecot',
  F5: 'F5 BIG-IP',
  IIS: 'IIS',
  SSH: 'SSH',
  WinCertStore: 'Windows Cert Store',
  JavaKeystore: 'Java Keystore',
};

const TARGET_TYPES = [
  { value: 'NGINX', label: 'NGINX', description: 'Deploy to NGINX web server via file write + config validation + reload' },
  { value: 'Apache', label: 'Apache httpd', description: 'Separate cert/chain/key files, apachectl configtest, graceful reload' },
  { value: 'HAProxy', label: 'HAProxy', description: 'Combined PEM file (cert+chain+key), optional validate, reload' },
  { value: 'Traefik', label: 'Traefik', description: 'File provider deployment — writes cert/key to watched directory, auto-reload' },
  { value: 'Caddy', label: 'Caddy', description: 'Admin API hot-reload or file-based deployment with configurable mode' },
  { value: 'Envoy', label: 'Envoy', description: 'File-based deployment — writes cert/key to watched directory. Optional SDS file generation.' },
  { value: 'Postfix', label: 'Postfix', description: 'Postfix MTA — file write + postfix reload' },
  { value: 'Dovecot', label: 'Dovecot', description: 'Dovecot IMAP/POP3 — file write + doveadm reload' },
  { value: 'F5', label: 'F5 BIG-IP', description: 'iControl REST — cert upload, SSL profile update via proxy agent' },
  { value: 'IIS', label: 'IIS', description: 'Windows IIS via agent-local PowerShell or remote WinRM proxy agent' },
  { value: 'SSH', label: 'SSH', description: 'Agentless deployment via SSH/SFTP — deploy to any Linux/Unix server without installing an agent' },
  { value: 'WinCertStore', label: 'Windows Cert Store', description: 'Import certificates into Windows Certificate Store for Exchange, RDP, SQL Server, ADFS' },
  { value: 'JavaKeystore', label: 'Java Keystore', description: 'Deploy to JKS/PKCS#12 keystores for Tomcat, Jetty, Kafka, Elasticsearch, and JVM services' },
];

const CONFIG_FIELDS: Record<string, { key: string; label: string; placeholder: string; required?: boolean }[]> = {
  NGINX: [
    { key: 'cert_path', label: 'Certificate Path', placeholder: '/etc/nginx/ssl/cert.pem', required: true },
    { key: 'key_path', label: 'Key Path', placeholder: '/etc/nginx/ssl/key.pem', required: true },
    { key: 'chain_path', label: 'Chain Path', placeholder: '/etc/nginx/ssl/chain.pem' },
    { key: 'reload_cmd', label: 'Reload Command', placeholder: 'nginx -t && systemctl reload nginx' },
  ],
  Apache: [
    { key: 'cert_path', label: 'Certificate Path', placeholder: '/etc/apache2/ssl/cert.pem', required: true },
    { key: 'key_path', label: 'Key Path', placeholder: '/etc/apache2/ssl/key.pem', required: true },
    { key: 'chain_path', label: 'Chain Path', placeholder: '/etc/apache2/ssl/chain.pem' },
    { key: 'reload_cmd', label: 'Reload Command', placeholder: 'apachectl configtest && apachectl graceful' },
  ],
  HAProxy: [
    { key: 'pem_path', label: 'Combined PEM Path', placeholder: '/etc/haproxy/certs/combined.pem', required: true },
    { key: 'reload_cmd', label: 'Reload Command', placeholder: 'systemctl reload haproxy' },
    { key: 'validate_cmd', label: 'Validate Command (optional)', placeholder: 'haproxy -c -f /etc/haproxy/haproxy.cfg' },
  ],
  Traefik: [
    { key: 'cert_dir', label: 'Certificate Directory', placeholder: '/etc/traefik/certs', required: true },
    { key: 'cert_file', label: 'Certificate Filename', placeholder: 'cert.pem (default)' },
    { key: 'key_file', label: 'Key Filename', placeholder: 'key.pem (default)' },
  ],
  Caddy: [
    { key: 'mode', label: 'Deployment Mode', placeholder: 'api (default) or file', required: true },
    { key: 'admin_api', label: 'Admin API URL', placeholder: 'http://localhost:2019 (default)' },
    { key: 'cert_dir', label: 'Certificate Directory (file mode)', placeholder: '/etc/caddy/certs' },
    { key: 'cert_file', label: 'Certificate Filename', placeholder: 'cert.pem (default)' },
    { key: 'key_file', label: 'Key Filename', placeholder: 'key.pem (default)' },
  ],
  Envoy: [
    { key: 'cert_dir', label: 'Certificate Directory', placeholder: '/etc/envoy/certs', required: true },
    { key: 'cert_filename', label: 'Certificate Filename', placeholder: 'cert.pem (default)' },
    { key: 'key_filename', label: 'Key Filename', placeholder: 'key.pem (default)' },
    { key: 'chain_filename', label: 'Chain Filename (optional)', placeholder: 'chain.pem (leave empty to append to cert)' },
    { key: 'sds_config', label: 'Generate SDS Config', placeholder: 'true or false' },
  ],
  Postfix: [
    { key: 'cert_path', label: 'Certificate Path', placeholder: '/etc/postfix/certs/cert.pem' },
    { key: 'key_path', label: 'Key Path', placeholder: '/etc/postfix/certs/key.pem' },
    { key: 'chain_path', label: 'Chain Path (optional)', placeholder: '/etc/postfix/certs/chain.pem' },
    { key: 'reload_command', label: 'Reload Command', placeholder: 'postfix reload' },
    { key: 'validate_command', label: 'Validate Command', placeholder: 'postfix check' },
  ],
  Dovecot: [
    { key: 'cert_path', label: 'Certificate Path', placeholder: '/etc/dovecot/certs/cert.pem' },
    { key: 'key_path', label: 'Key Path', placeholder: '/etc/dovecot/certs/key.pem' },
    { key: 'chain_path', label: 'Chain Path (optional)', placeholder: '/etc/dovecot/certs/chain.pem' },
    { key: 'reload_command', label: 'Reload Command', placeholder: 'doveadm reload' },
    { key: 'validate_command', label: 'Validate Command', placeholder: 'doveconf -n' },
  ],
  F5: [
    { key: 'host', label: 'Management Host', placeholder: 'f5.internal.example.com', required: true },
    { key: 'port', label: 'Management Port', placeholder: '443' },
    { key: 'username', label: 'Username', placeholder: 'admin', required: true },
    { key: 'password', label: 'Password', placeholder: 'F5 admin password', required: true },
    { key: 'partition', label: 'Partition', placeholder: 'Common' },
    { key: 'ssl_profile', label: 'SSL Profile', placeholder: 'clientssl_api', required: true },
    { key: 'insecure', label: 'Skip TLS Verify', placeholder: 'true (default)' },
    { key: 'timeout', label: 'Timeout (seconds)', placeholder: '30' },
  ],
  IIS: [
    { key: 'site_name', label: 'IIS Site Name', placeholder: 'Default Web Site', required: true },
    { key: 'cert_store', label: 'Certificate Store', placeholder: 'My', required: true },
    { key: 'port', label: 'HTTPS Port', placeholder: '443' },
    { key: 'ip_address', label: 'Binding IP', placeholder: '*' },
    { key: 'binding_info', label: 'Host Header (SNI)', placeholder: 'www.example.com' },
    { key: 'sni', label: 'Enable SNI', placeholder: 'true or false' },
    { key: 'mode', label: 'Deployment Mode', placeholder: 'local (default) or winrm' },
    { key: 'winrm.winrm_host', label: 'WinRM Host (remote mode)', placeholder: 'iis-server.example.com' },
    { key: 'winrm.winrm_port', label: 'WinRM Port', placeholder: '5985 (HTTP) or 5986 (HTTPS)' },
    { key: 'winrm.winrm_username', label: 'WinRM Username', placeholder: 'Administrator' },
    { key: 'winrm.winrm_password', label: 'WinRM Password', placeholder: '(sensitive)' },
    { key: 'winrm.winrm_https', label: 'WinRM Use HTTPS', placeholder: 'true or false' },
    { key: 'winrm.winrm_insecure', label: 'WinRM Skip TLS Verify', placeholder: 'false' },
  ],
  SSH: [
    { key: 'host', label: 'SSH Host', placeholder: '192.168.1.100 or server.example.com', required: true },
    { key: 'port', label: 'SSH Port', placeholder: '22 (default)' },
    { key: 'user', label: 'SSH Username', placeholder: 'root or certctl', required: true },
    { key: 'auth_method', label: 'Auth Method', placeholder: 'key (default) or password' },
    { key: 'private_key_path', label: 'Private Key Path', placeholder: '/home/certctl/.ssh/id_ed25519' },
    { key: 'password', label: 'SSH Password', placeholder: 'Leave empty for key auth' },
    { key: 'cert_path', label: 'Remote Certificate Path', placeholder: '/etc/ssl/certs/cert.pem', required: true },
    { key: 'key_path', label: 'Remote Key Path', placeholder: '/etc/ssl/private/key.pem', required: true },
    { key: 'chain_path', label: 'Remote Chain Path (optional)', placeholder: '/etc/ssl/certs/chain.pem' },
    { key: 'reload_command', label: 'Reload Command (optional)', placeholder: 'systemctl reload nginx' },
    { key: 'timeout', label: 'Connection Timeout (seconds)', placeholder: '30 (default)' },
  ],
  WinCertStore: [
    { key: 'store_name', label: 'Certificate Store', placeholder: 'My (default)', required: true },
    { key: 'store_location', label: 'Store Location', placeholder: 'LocalMachine (default) or CurrentUser' },
    { key: 'friendly_name', label: 'Friendly Name (optional)', placeholder: 'My Production Cert' },
    { key: 'remove_expired', label: 'Remove Expired Certs', placeholder: 'false (default)' },
    { key: 'mode', label: 'Deployment Mode', placeholder: 'local (default) or winrm' },
    { key: 'winrm_host', label: 'WinRM Host (remote mode)', placeholder: 'win-server.example.com' },
    { key: 'winrm_port', label: 'WinRM Port', placeholder: '5985 (HTTP) or 5986 (HTTPS)' },
    { key: 'winrm_username', label: 'WinRM Username', placeholder: 'Administrator' },
    { key: 'winrm_password', label: 'WinRM Password', placeholder: '(sensitive)' },
  ],
  JavaKeystore: [
    { key: 'keystore_path', label: 'Keystore Path', placeholder: '/opt/app/conf/keystore.p12', required: true },
    { key: 'keystore_password', label: 'Keystore Password', placeholder: 'changeit', required: true },
    { key: 'keystore_type', label: 'Keystore Type', placeholder: 'PKCS12 (default) or JKS' },
    { key: 'alias', label: 'Key Alias', placeholder: 'server (default)' },
    { key: 'reload_command', label: 'Reload Command (optional)', placeholder: 'systemctl restart tomcat' },
    { key: 'keytool_path', label: 'Keytool Path (optional)', placeholder: 'keytool (default, from PATH)' },
  ],
};

function CreateTargetWizard({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [step, setStep] = useState<'type' | 'config' | 'review'>('type');
  const [targetType, setTargetType] = useState('');
  const [name, setName] = useState('');
  const [agentId, setAgentId] = useState('');
  const [config, setConfig] = useState<Record<string, string>>({});
  const [error, setError] = useState('');

  const mutation = useMutation({
    mutationFn: () => createTarget({
      name,
      type: targetType,
      agent_id: agentId,
      config: Object.fromEntries(Object.entries(config).filter(([, v]) => v)),
    }),
    onSuccess: () => onSuccess(),
    onError: (err: Error) => setError(err.message),
  });

  const fields = CONFIG_FIELDS[targetType] || [];
  const canProceedToReview = name && targetType && fields.filter(f => f.required).every(f => config[f.key]);

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-lg shadow-xl" onClick={e => e.stopPropagation()}>
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
                  isDone ? 'bg-emerald-600 text-white' : isActive ? 'bg-brand-400 text-white' : 'bg-surface-border text-ink-muted'
                }`}>
                  {isDone ? '✓' : i + 1}
                </div>
                <span className={`text-xs ${isActive ? 'text-ink' : 'text-ink-faint'}`}>{label}</span>
                {i < 2 && <div className="w-8 h-px bg-surface-border" />}
              </div>
            );
          })}
        </div>

        {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-4">{error}</div>}

        {/* Step 1: Select Type */}
        {step === 'type' && (
          <div>
            <h2 className="text-lg font-semibold text-ink mb-4">Select Target Type</h2>
            <div className="space-y-2">
              {TARGET_TYPES.map(t => (
                <button
                  key={t.value}
                  onClick={() => { setTargetType(t.value); setConfig({}); }}
                  className={`w-full text-left px-4 py-3 rounded border transition-colors ${
                    targetType === t.value
                      ? 'border-brand-400 bg-brand-50'
                      : 'border-surface-border hover:border-surface-border bg-white'
                  }`}
                >
                  <div className="text-sm font-medium text-ink">{t.label}</div>
                  <div className="text-xs text-ink-muted mt-0.5">{t.description}</div>
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
            <h2 className="text-lg font-semibold text-ink mb-4">
              Configure {typeLabels[targetType] || targetType} Target
            </h2>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-ink-muted block mb-1">Target Name *</label>
                <input value={name} onChange={e => setName(e.target.value)}
                  className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
                  placeholder="web-server-1" />
              </div>
              <div>
                <label className="text-xs text-ink-muted block mb-1">Agent ID</label>
                <input value={agentId} onChange={e => setAgentId(e.target.value)}
                  className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
                  placeholder="agent-web1" />
              </div>
              {fields.map(f => (
                <div key={f.key}>
                  <label className="text-xs text-ink-muted block mb-1">{f.label} {f.required ? '*' : ''}</label>
                  <input value={config[f.key] || ''} onChange={e => setConfig(c => ({ ...c, [f.key]: e.target.value }))}
                    className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400"
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
            <h2 className="text-lg font-semibold text-ink mb-4">Review Target</h2>
            <div className="bg-page rounded p-4 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-ink-muted">Name</span>
                <span className="text-ink">{name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-ink-muted">Type</span>
                <span className="text-ink">{typeLabels[targetType] || targetType}</span>
              </div>
              {agentId && (
                <div className="flex justify-between">
                  <span className="text-ink-muted">Agent</span>
                  <span className="text-ink font-mono text-xs">{agentId}</span>
                </div>
              )}
              {Object.entries(config).filter(([, v]) => v).map(([k, v]) => (
                <div key={k} className="flex justify-between">
                  <span className="text-ink-muted">{k.replace(/_/g, ' ')}</span>
                  <span className="text-ink font-mono text-xs truncate max-w-xs">{v}</span>
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
          <Link to={`/targets/${t.id}`} className="font-medium text-accent hover:text-accent-bright" onClick={(e) => e.stopPropagation()}>
            {t.name}
          </Link>
          <div className="text-xs text-ink-faint font-mono">{t.id}</div>
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
      key: 'agent',
      label: 'Agent',
      render: (t) => <span className="text-xs text-ink-muted font-mono">{t.agent_id || '\u2014'}</span>,
    },
    {
      key: 'enabled',
      label: 'Status',
      render: (t) => <StatusBadge status={t.enabled ? 'Enabled' : 'Disabled'} />,
    },
    {
      key: 'test_status',
      label: 'Connection',
      render: (t) => {
        if (!t.test_status || t.test_status === 'untested') return <span className="text-xs text-ink-faint">—</span>;
        return <StatusBadge status={t.test_status === 'success' ? 'Connected' : 'Failed'} />;
      },
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
          onClick={(e) => { e.stopPropagation(); if (confirm(`Delete target ${t.name}?`)) deleteMutation.mutate(t.id); }}
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
