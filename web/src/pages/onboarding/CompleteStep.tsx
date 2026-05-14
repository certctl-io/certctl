// Phase 4 closure (FE-M3): OnboardingWizard mega-page split — Step 4.
// Summary + "You're all set!" review screen. Behavior preserved
// byte-equivalent from the pre-split OnboardingWizard.tsx lines 901-975.

import { useQuery } from '@tanstack/react-query';
import { getIssuers, getAgents } from '../../api/client';

export default function CompleteStep({ onFinish, issuerName, certName }: {
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

      {/* Doc links updated 2026-05-14 to match the post-2026-05-04
          audience-organized doc tree (getting-started/ + reference/).
          Pre-fix the three links pointed at docs/quickstart.md,
          docs/architecture.md, docs/connectors.md — none of those paths
          exist any more; they were 404s the operator hit on every
          successful onboarding completion. Verified against `ls docs/`
          before writing. */}
      <div className="flex justify-center gap-6 text-xs">
        <a href="https://github.com/certctl-io/certctl/blob/master/docs/getting-started/quickstart.md" target="_blank" rel="noopener noreferrer" className="text-accent hover:text-accent-bright">Quickstart Guide</a>
        <a href="https://github.com/certctl-io/certctl/blob/master/docs/reference/architecture.md" target="_blank" rel="noopener noreferrer" className="text-accent hover:text-accent-bright">Architecture</a>
        <a href="https://github.com/certctl-io/certctl/blob/master/docs/reference/connectors/index.md" target="_blank" rel="noopener noreferrer" className="text-accent hover:text-accent-bright">Connectors</a>
      </div>
    </div>
  );
}
