// Phase 4 closure (FE-M3): OnboardingWizard mega-page split — Step 1.
// Connect a Certificate Authority. Behavior preserved byte-equivalent
// from the pre-split src/pages/OnboardingWizard.tsx lines 112-278.

import { useState } from 'react';
import { useTrackedMutation } from '../../hooks/useTrackedMutation';
import { createIssuer, testIssuerConnection } from '../../api/client';
import { issuerTypes, type IssuerTypeConfig } from '../../config/issuerTypes';
import ConfigForm from '../../components/issuer/ConfigForm';
import type { Issuer } from '../../api/types';
import { WizardFooter } from './StepShell';

export default function IssuerStep({ onNext, onSkip, onIssuerCreated }: {
  onNext: () => void;
  onSkip: () => void;
  onIssuerCreated: (issuer: Issuer) => void;
}) {
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, unknown>>({});
  const [issuerName, setIssuerName] = useState('');

  // Pre-populate default values when a type is selected (matches IssuersPage behavior)
  function handleTypeSelect(typeId: string) {
    setSelectedType(typeId);
    const tc = issuerTypes.find(t => t.id === typeId);
    const defaults: Record<string, unknown> = {};
    tc?.configFields.forEach(f => { if (f.defaultValue !== undefined) defaults[f.key] = f.defaultValue; });
    setConfigValues(defaults);
  }
  const [error, setError] = useState('');
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [createdIssuer, setCreatedIssuer] = useState<Issuer | null>(null);

  const typeConfig = selectedType ? issuerTypes.find(t => t.id === selectedType) : null;

  const createMutation = useTrackedMutation({
    mutationFn: () => createIssuer({
      name: issuerName || `${typeConfig?.name || selectedType} Issuer`,
      type: selectedType!,
      config: configValues as Record<string, unknown>,
    }),
    invalidates: [['issuers']],
    onSuccess: (issuer) => {
      setCreatedIssuer(issuer);
      onIssuerCreated(issuer);
      setError('');
    },
    onError: (err: Error) => setError(err.message),
  });

  // testIssuerConnection updates last_tested_at server-side; refresh the
  // issuers list so the timestamp + status columns reflect the new probe.
  // The local setTestResult banner still surfaces the immediate pass/fail.
  const testMutation = useTrackedMutation({
    mutationFn: () => testIssuerConnection(createdIssuer!.id),
    invalidates: [['issuers']],
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
              onClick={() => handleTypeSelect(type.id)}
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
        <button onClick={() => { setSelectedType(null); setConfigValues({}); setIssuerName(''); setError(''); }}
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
