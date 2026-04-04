import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, Link } from 'react-router-dom';
import {
  getIssuers, getAgents, getProfiles,
  createIssuer, testIssuerConnection,
  createCertificate, triggerRenewal,
  getApiKey,
} from '../api/client';
import { issuerTypes, type IssuerTypeConfig } from '../config/issuerTypes';
import ConfigForm from '../components/issuer/ConfigForm';
import type { Issuer, Agent } from '../api/types';

// ─── Types ───────────────────────────────────────────

type WizardStep = 'issuer' | 'agent' | 'certificate' | 'complete';

const STEPS: { key: WizardStep; label: string }[] = [
  { key: 'issuer', label: 'Connect a CA' },
  { key: 'agent', label: 'Deploy Agent' },
  { key: 'certificate', label: 'Add Certificate' },
  { key: 'complete', label: 'Done' },
];

// ─── Helpers ─────────────────────────────────────────

function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      {label && <div className="text-xs text-ink-muted mb-1 font-medium">{label}</div>}
      <pre className="bg-gray-900 text-gray-100 rounded p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
        {code}
      </pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        className="absolute top-2 right-2 px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded transition-colors"
      >
        {copied ? 'Copied!' : 'Copy'}
      </button>
    </div>
  );
}

function StepIndicator({ steps, current }: { steps: typeof STEPS; current: WizardStep }) {
  const currentIdx = steps.findIndex(s => s.key === current);
  return (
    <div className="flex items-center justify-center gap-2 mb-8">
      {steps.map((s, i) => {
        const isCompleted = i < currentIdx;
        const isCurrent = s.key === current;
        return (
          <div key={s.key} className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
              isCompleted ? 'bg-emerald-500 text-white' :
              isCurrent ? 'bg-accent text-white' :
              'bg-surface-border text-ink-muted'
            }`}>
              {isCompleted ? (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              ) : i + 1}
            </div>
            <span className={`text-xs font-medium hidden sm:inline ${isCurrent ? 'text-ink' : 'text-ink-muted'}`}>
              {s.label}
            </span>
            {i < steps.length - 1 && (
              <div className={`w-8 h-0.5 ${i < currentIdx ? 'bg-emerald-500' : 'bg-surface-border'}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

function WizardFooter({ onSkip, onNext, nextLabel, nextDisabled, showSkip = true }: {
  onSkip?: () => void;
  onNext?: () => void;
  nextLabel?: string;
  nextDisabled?: boolean;
  showSkip?: boolean;
}) {
  return (
    <div className="flex justify-between items-center pt-6 border-t border-surface-border mt-6">
      <div>
        {showSkip && onSkip && (
          <button onClick={onSkip} className="text-sm text-ink-muted hover:text-ink transition-colors">
            Skip this step
          </button>
        )}
      </div>
      {onNext && (
        <button
          onClick={onNext}
          disabled={nextDisabled}
          className="btn btn-primary disabled:opacity-50"
        >
          {nextLabel || 'Continue'}
        </button>
      )}
    </div>
  );
}

// ─── Step 1: Connect a CA ────────────────────────────

function IssuerStep({ onNext, onSkip, onIssuerCreated }: {
  onNext: () => void;
  onSkip: () => void;
  onIssuerCreated: (issuer: Issuer) => void;
}) {
  const queryClient = useQueryClient();
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, unknown>>({});
  const [issuerName, setIssuerName] = useState('');
  const [error, setError] = useState('');
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [createdIssuer, setCreatedIssuer] = useState<Issuer | null>(null);

  const typeConfig = selectedType ? issuerTypes.find(t => t.id === selectedType) : null;

  const createMutation = useMutation({
    mutationFn: () => createIssuer({
      name: issuerName || `${typeConfig?.name || selectedType} Issuer`,
      type: selectedType!,
      config: configValues as Record<string, unknown>,
    }),
    onSuccess: (issuer) => {
      setCreatedIssuer(issuer);
      onIssuerCreated(issuer);
      queryClient.invalidateQueries({ queryKey: ['issuers'] });
      setError('');
    },
    onError: (err: Error) => setError(err.message),
  });

  const testMutation = useMutation({
    mutationFn: () => testIssuerConnection(createdIssuer!.id),
    onSuccess: () => setTestResult({ ok: true, msg: 'Connection successful' }),
    onError: (err: Error) => setTestResult({ ok: false, msg: err.message }),
  });

  // After issuer is created successfully
  if (createdIssuer) {
    return (
      <div>
        <h2 className="text-lg font-semibold text-ink mb-2">CA Connected</h2>
        <div className="bg-emerald-50 border border-emerald-200 rounded p-4 mb-4">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span className="text-sm font-medium text-emerald-700">
              {createdIssuer.name} ({typeConfig?.name}) created successfully
            </span>
          </div>
        </div>

        {!testResult && (
          <button
            onClick={() => testMutation.mutate()}
            disabled={testMutation.isPending}
            className="btn btn-secondary text-sm mb-4"
          >
            {testMutation.isPending ? 'Testing...' : 'Test Connection'}
          </button>
        )}

        {testResult?.ok && (
          <div className="bg-emerald-50 border border-emerald-200 rounded p-3 mb-4 text-sm text-emerald-700">
            Connection test passed.
          </div>
        )}
        {testResult && !testResult.ok && (
          <div className="bg-red-50 border border-red-200 rounded p-3 mb-4 text-sm text-red-700">
            Connection test failed: {testResult.msg}
          </div>
        )}

        <WizardFooter onNext={onNext} nextLabel="Next: Deploy Agent" showSkip={false} />
      </div>
    );
  }

  // Type selection
  if (!selectedType) {
    return (
      <div>
        <h2 className="text-lg font-semibold text-ink mb-1">Connect a Certificate Authority</h2>
        <p className="text-sm text-ink-muted mb-6">
          Choose a CA to issue and manage certificates. You can add more later from the Issuers page.
        </p>
        <div className="grid grid-cols-2 gap-4">
          {issuerTypes.filter(t => !t.comingSoon).map((type: IssuerTypeConfig) => (
            <button
              key={type.id}
              onClick={() => setSelectedType(type.id)}
              className="p-4 border border-surface-border rounded-lg hover:border-brand-500 hover:bg-surface-muted transition-all text-left"
            >
              <div className="flex items-center gap-2">
                <span className="text-lg">{type.icon}</span>
                <span className="font-medium text-ink">{type.name}</span>
              </div>
              <div className="text-xs text-ink-muted mt-1">{type.description}</div>
            </button>
          ))}
        </div>
        <WizardFooter onSkip={onSkip} />
      </div>
    );
  }

  // Config form for selected type
  const requiredFields = typeConfig?.configFields.filter(f => f.required) || [];
  const allRequiredFilled = requiredFields.every(f => configValues[f.key]);

  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <button onClick={() => { setSelectedType(null); setConfigValues({}); setError(''); }}
          className="text-ink-muted hover:text-ink transition-colors">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
        </button>
        <h2 className="text-lg font-semibold text-ink">
          Configure {typeConfig?.name}
        </h2>
      </div>
      <p className="text-sm text-ink-muted mb-6">{typeConfig?.description}</p>

      <div className="mb-5">
        <label className="block text-sm font-medium text-ink mb-2">Display Name</label>
        <input
          type="text"
          value={issuerName}
          onChange={e => setIssuerName(e.target.value)}
          placeholder={`${typeConfig?.name || ''} Issuer`}
          className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
        />
      </div>

      <ConfigForm
        fields={typeConfig?.configFields || []}
        values={configValues}
        onChange={(key, val) => setConfigValues(prev => ({ ...prev, [key]: val }))}
      />

      {error && (
        <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>
      )}

      <WizardFooter
        onSkip={onSkip}
        onNext={() => createMutation.mutate()}
        nextLabel={createMutation.isPending ? 'Creating...' : 'Create Issuer'}
        nextDisabled={!allRequiredFilled || createMutation.isPending}
      />
    </div>
  );
}

// ─── Step 2: Deploy an Agent ─────────────────────────

function AgentStep({ onNext, onSkip }: { onNext: () => void; onSkip: () => void }) {
  const [activeTab, setActiveTab] = useState<'linux' | 'macos' | 'docker'>('linux');

  const apiKey = getApiKey() || '<your-api-key>';
  const serverUrl = typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8443` : 'http://localhost:8443';

  // Poll for agents every 5s
  const { data: agents } = useQuery({
    queryKey: ['agents'],
    queryFn: () => getAgents(),
    refetchInterval: 5000,
  });

  const agentList = agents?.data || [];
  const hasAgents = agentList.length > 0;

  const tabs = [
    { key: 'linux' as const, label: 'Linux' },
    { key: 'macos' as const, label: 'macOS' },
    { key: 'docker' as const, label: 'Docker' },
  ];

  const commands: Record<string, { code: string; label: string }> = {
    linux: {
      label: 'Install via shell script (systemd service)',
      code: `curl -sSL https://raw.githubusercontent.com/shankar0123/certctl/master/install-agent.sh | bash

# Then configure:
sudo systemctl edit certctl-agent
# Add:
# [Service]
# Environment="CERTCTL_SERVER_URL=${serverUrl}"
# Environment="CERTCTL_API_KEY=${apiKey}"

sudo systemctl restart certctl-agent`,
    },
    macos: {
      label: 'Install via shell script (launchd service)',
      code: `curl -sSL https://raw.githubusercontent.com/shankar0123/certctl/master/install-agent.sh | bash

# Then configure:
# Edit /Library/LaunchDaemons/com.certctl.agent.plist
# Set CERTCTL_SERVER_URL to ${serverUrl}
# Set CERTCTL_API_KEY to ${apiKey}

sudo launchctl unload /Library/LaunchDaemons/com.certctl.agent.plist
sudo launchctl load /Library/LaunchDaemons/com.certctl.agent.plist`,
    },
    docker: {
      label: 'Run as Docker container',
      code: `docker run -d --name certctl-agent \\
  -e CERTCTL_SERVER_URL=${serverUrl} \\
  -e CERTCTL_API_KEY=${apiKey} \\
  ghcr.io/shankar0123/certctl-agent:latest`,
    },
  };

  return (
    <div>
      <h2 className="text-lg font-semibold text-ink mb-1">Deploy a certctl Agent</h2>
      <p className="text-sm text-ink-muted mb-6">
        Agents run on your infrastructure to manage certificates, generate keys, and deploy to targets.
        Install one now or skip to do it later.
      </p>

      {/* OS Tabs */}
      <div className="flex gap-1 mb-4 bg-surface-border/30 rounded-lg p-1 w-fit">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`px-4 py-1.5 text-sm rounded-md transition-colors ${
              activeTab === t.key
                ? 'bg-surface text-ink font-medium shadow-sm'
                : 'text-ink-muted hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <CodeBlock code={commands[activeTab].code} label={commands[activeTab].label} />

      {/* Agent detection */}
      <div className="mt-6 p-4 border border-surface-border rounded-lg">
        <div className="flex items-center gap-3">
          {hasAgents ? (
            <>
              <div className="w-3 h-3 rounded-full bg-emerald-500" />
              <div>
                <div className="text-sm font-medium text-emerald-700">
                  {agentList.length} agent{agentList.length !== 1 ? 's' : ''} detected
                </div>
                <div className="text-xs text-ink-muted mt-0.5">
                  {agentList.slice(0, 3).map(a => a.name || a.id).join(', ')}
                  {agentList.length > 3 && ` and ${agentList.length - 3} more`}
                </div>
              </div>
            </>
          ) : (
            <>
              <div className="w-3 h-3 rounded-full bg-amber-400 animate-pulse" />
              <div className="text-sm text-ink-muted">
                Waiting for an agent to connect... <span className="text-xs">(polling every 5s)</span>
              </div>
            </>
          )}
        </div>
      </div>

      <WizardFooter
        onSkip={onSkip}
        onNext={onNext}
        nextLabel={hasAgents ? 'Next: Add Certificate' : 'Next: Add Certificate'}
      />
    </div>
  );
}

// ─── Step 3: Add a Certificate ───────────────────────

function CertificateStep({ onNext, onSkip, createdIssuerId }: {
  onNext: (certName?: string) => void;
  onSkip: () => void;
  createdIssuerId: string | null;
}) {
  const queryClient = useQueryClient();
  const [commonName, setCommonName] = useState('');
  const [sans, setSans] = useState('');
  const [issuerId, setIssuerId] = useState(createdIssuerId || '');
  const [profileId, setProfileId] = useState('');
  const [error, setError] = useState('');
  const [created, setCreated] = useState(false);

  const { data: issuers } = useQuery({ queryKey: ['issuers'], queryFn: () => getIssuers() });
  const { data: profiles } = useQuery({ queryKey: ['profiles'], queryFn: () => getProfiles() });
  const { data: agents } = useQuery({ queryKey: ['agents'], queryFn: () => getAgents() });

  const hasAgents = (agents?.data?.length ?? 0) > 0;

  const createMutation = useMutation({
    mutationFn: async () => {
      const sanList = sans.split(',').map(s => s.trim()).filter(Boolean);
      const cert = await createCertificate({
        common_name: commonName,
        sans: sanList,
        issuer_id: issuerId,
        certificate_profile_id: profileId || undefined,
        environment: 'production',
      });
      // Trigger issuance
      await triggerRenewal(cert.id);
      return cert;
    },
    onSuccess: (cert) => {
      setCreated(true);
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
      setTimeout(() => onNext(cert.common_name), 1500);
    },
    onError: (err: Error) => setError(err.message),
  });

  if (created) {
    return (
      <div>
        <h2 className="text-lg font-semibold text-ink mb-2">Certificate Requested</h2>
        <div className="bg-emerald-50 border border-emerald-200 rounded p-4">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span className="text-sm font-medium text-emerald-700">
              Certificate for {commonName} has been requested. Moving to summary...
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-lg font-semibold text-ink mb-1">Add a Certificate</h2>
      <p className="text-sm text-ink-muted mb-6">
        Issue your first certificate, or skip this step and explore the dashboard.
      </p>

      <div className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-ink mb-2">
            Common Name <span className="text-red-600">*</span>
          </label>
          <input
            type="text"
            value={commonName}
            onChange={e => setCommonName(e.target.value)}
            placeholder="example.com"
            className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-ink mb-2">
            Subject Alternative Names <span className="text-xs text-ink-muted font-normal">(comma-separated)</span>
          </label>
          <input
            type="text"
            value={sans}
            onChange={e => setSans(e.target.value)}
            placeholder="www.example.com, api.example.com"
            className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-2">
              Issuer <span className="text-red-600">*</span>
            </label>
            <select
              value={issuerId}
              onChange={e => setIssuerId(e.target.value)}
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500 transition-colors"
            >
              <option value="">Select issuer...</option>
              {issuers?.data?.map(iss => (
                <option key={iss.id} value={iss.id}>{iss.name} ({iss.type})</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-ink mb-2">
              Profile <span className="text-xs text-ink-muted font-normal">(optional)</span>
            </label>
            <select
              value={profileId}
              onChange={e => setProfileId(e.target.value)}
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500 transition-colors"
            >
              <option value="">Default</option>
              {profiles?.data?.map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Discovery hint */}
      {hasAgents && (
        <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded text-sm text-blue-700">
          <span className="font-medium">Already have certificates on disk?</span>{' '}
          Visit the <Link to="/discovery" className="underline hover:text-blue-900">Discovery page</Link> to
          import and manage existing certificates found by your agents.
        </div>
      )}
      {!hasAgents && (
        <div className="mt-6 p-4 bg-gray-50 border border-gray-200 rounded text-sm text-ink-muted">
          <span className="font-medium">Tip:</span> Deploy an agent with{' '}
          <code className="bg-gray-200 px-1 rounded text-xs">CERTCTL_DISCOVERY_DIRS=/etc/ssl/certs</code>{' '}
          to automatically discover existing certificates on your infrastructure.
        </div>
      )}

      {error && (
        <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>
      )}

      <WizardFooter
        onSkip={onSkip}
        onNext={() => createMutation.mutate()}
        nextLabel={createMutation.isPending ? 'Creating...' : 'Issue Certificate'}
        nextDisabled={!commonName || !issuerId || createMutation.isPending}
      />
    </div>
  );
}

// ─── Step 4: Complete ────────────────────────────────

function CompleteStep({ onFinish, issuerName, certName }: {
  onFinish: () => void;
  issuerName: string | null;
  certName: string | null;
}) {
  const { data: issuers } = useQuery({ queryKey: ['issuers'], queryFn: () => getIssuers() });
  const { data: agents } = useQuery({ queryKey: ['agents'], queryFn: () => getAgents() });

  const issuerCount = issuers?.data?.length ?? 0;
  const agentCount = agents?.data?.length ?? 0;

  return (
    <div className="text-center py-8">
      <div className="w-16 h-16 mx-auto mb-6 bg-emerald-100 rounded-full flex items-center justify-center">
        <svg className="w-8 h-8 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>

      <h2 className="text-xl font-semibold text-ink mb-2">You're all set!</h2>
      <p className="text-sm text-ink-muted mb-8 max-w-md mx-auto">
        certctl is ready to manage your certificate lifecycle. Here's what's configured:
      </p>

      {/* Summary */}
      <div className="max-w-sm mx-auto mb-8 space-y-3 text-left">
        <div className="flex items-center gap-3 p-3 bg-surface border border-surface-border rounded">
          <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs ${issuerCount > 0 ? 'bg-emerald-100 text-emerald-600' : 'bg-gray-100 text-gray-400'}`}>
            {issuerCount > 0 ? (
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
            ) : '—'}
          </div>
          <div className="text-sm">
            <span className="font-medium text-ink">
              {issuerCount > 0 ? `${issuerCount} issuer${issuerCount !== 1 ? 's' : ''} configured` : 'No issuers configured'}
            </span>
            {issuerName && <span className="text-ink-muted ml-1">({issuerName})</span>}
          </div>
        </div>

        <div className="flex items-center gap-3 p-3 bg-surface border border-surface-border rounded">
          <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs ${agentCount > 0 ? 'bg-emerald-100 text-emerald-600' : 'bg-gray-100 text-gray-400'}`}>
            {agentCount > 0 ? (
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
            ) : '—'}
          </div>
          <span className="text-sm font-medium text-ink">
            {agentCount > 0 ? `${agentCount} agent${agentCount !== 1 ? 's' : ''} connected` : 'No agents deployed yet'}
          </span>
        </div>

        <div className="flex items-center gap-3 p-3 bg-surface border border-surface-border rounded">
          <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs ${certName ? 'bg-emerald-100 text-emerald-600' : 'bg-gray-100 text-gray-400'}`}>
            {certName ? (
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
            ) : '—'}
          </div>
          <span className="text-sm font-medium text-ink">
            {certName ? `Certificate requested: ${certName}` : 'No certificates added yet'}
          </span>
        </div>
      </div>

      <button onClick={onFinish} className="btn btn-primary text-sm px-8 mb-6">
        Go to Dashboard
      </button>

      <div className="flex justify-center gap-6 text-xs">
        <a href="https://github.com/shankar0123/certctl/blob/master/docs/quickstart.md" target="_blank" rel="noopener noreferrer" className="text-accent hover:text-accent-bright">Quickstart Guide</a>
        <a href="https://github.com/shankar0123/certctl/blob/master/docs/architecture.md" target="_blank" rel="noopener noreferrer" className="text-accent hover:text-accent-bright">Architecture</a>
        <a href="https://github.com/shankar0123/certctl/blob/master/docs/connectors.md" target="_blank" rel="noopener noreferrer" className="text-accent hover:text-accent-bright">Connectors</a>
      </div>
    </div>
  );
}

// ─── Main Wizard ─────────────────────────────────────

export default function OnboardingWizard({ onDismiss }: { onDismiss: () => void }) {
  const [step, setStep] = useState<WizardStep>('issuer');
  const [createdIssuerId, setCreatedIssuerId] = useState<string | null>(null);
  const [issuerName, setIssuerName] = useState<string | null>(null);
  const [certName, setCertName] = useState<string | null>(null);
  const navigate = useNavigate();

  const goTo = (s: WizardStep) => setStep(s);

  return (
    <>
      <div className="flex items-center justify-between px-6 pt-5 pb-0">
        <div>
          <h1 className="text-xl font-bold text-ink">Welcome to certctl</h1>
          <p className="text-sm text-ink-muted mt-0.5">Let's set up your certificate lifecycle management</p>
        </div>
        <button
          onClick={onDismiss}
          className="text-xs text-ink-muted hover:text-ink transition-colors"
        >
          Skip setup
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="max-w-2xl mx-auto">
          <StepIndicator steps={STEPS} current={step} />

          <div className="bg-surface border border-surface-border rounded-lg p-6 shadow-sm">
            {step === 'issuer' && (
              <IssuerStep
                onNext={() => goTo('agent')}
                onSkip={() => goTo('agent')}
                onIssuerCreated={(iss) => { setCreatedIssuerId(iss.id); setIssuerName(iss.name); }}
              />
            )}

            {step === 'agent' && (
              <AgentStep
                onNext={() => goTo('certificate')}
                onSkip={() => goTo('certificate')}
              />
            )}

            {step === 'certificate' && (
              <CertificateStep
                onNext={(name) => { if (name) setCertName(name); goTo('complete'); }}
                onSkip={() => goTo('complete')}
                createdIssuerId={createdIssuerId}
              />
            )}

            {step === 'complete' && (
              <CompleteStep
                onFinish={() => { onDismiss(); navigate('/'); }}
                issuerName={issuerName}
                certName={certName}
              />
            )}
          </div>
        </div>
      </div>
    </>
  );
}
