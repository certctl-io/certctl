// Phase 4 closure (FE-M3): OnboardingWizard mega-page split.
//
// Pre-Phase-4 this file was 1043 LOC containing:
//   • 4 step component definitions (Issuer / Agent / Certificate / Complete)
//   • 2 inline modal helpers (CreateTeamModalInline, CreateOwnerModalInline)
//   • 3 layout helpers (CodeBlock, StepIndicator, WizardFooter)
//   • The shell + state + step transitions
// — all in a single file that took ~30s to navigate end-to-end in the
// editor and hit the eslint per-file-LOC ceiling.
//
// Post-Phase-4 this file is just the shell + state + step transitions
// (~67 LOC). Each step now lives in src/pages/onboarding/ as its own
// file, importable in isolation:
//
//   • types.ts          — WizardStep type + STEPS list
//   • StepShell.tsx     — shared CodeBlock + StepIndicator + WizardFooter
//   • IssuerStep.tsx    — Step 1
//   • AgentStep.tsx     — Step 2
//   • CertificateStep.tsx — Step 3 (owns its inline team/owner modals)
//   • CompleteStep.tsx  — Step 4
//
// Behavior preserved byte-equivalent — no logic change, just a
// directory reshape. DashboardPage's lazy(() => import('./OnboardingWizard'))
// import path is unchanged because this file still exists at the same
// location and still has a default export with the same prop shape.

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { STEPS, type WizardStep } from './onboarding/types';
import { StepIndicator } from './onboarding/StepShell';
import IssuerStep from './onboarding/IssuerStep';
import AgentStep from './onboarding/AgentStep';
import CertificateStep from './onboarding/CertificateStep';
import CompleteStep from './onboarding/CompleteStep';

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
