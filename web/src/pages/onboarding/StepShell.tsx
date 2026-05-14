// Phase 4 closure (FE-M3): OnboardingWizard mega-page split.
// Shared shell helpers used by every step:
//   • StepIndicator — the top progress strip ("Connect a CA → Deploy Agent → …")
//   • WizardFooter  — the bottom Skip / Continue bar
//   • CodeBlock     — copyable install-command box (AgentStep, also reusable)
//
// Behavior copied byte-equivalent from the pre-split OnboardingWizard.tsx
// so the existing E2E vitest + the operator's muscle memory don't drift.

import { useState } from 'react';
import { STEPS, type WizardStep } from './types';

export function CodeBlock({ code, label }: { code: string; label?: string }) {
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

export function StepIndicator({ steps, current }: { steps: typeof STEPS; current: WizardStep }) {
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

export function WizardFooter({ onSkip, onNext, nextLabel, nextDisabled, showSkip = true }: {
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
