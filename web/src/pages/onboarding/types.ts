// Phase 4 closure (FE-M3): OnboardingWizard mega-page split.
// Shared types + the canonical step ordering, factored out so each
// step component imports the type without taking a dependency on the
// shell.

export type WizardStep = 'issuer' | 'agent' | 'certificate' | 'complete';

export const STEPS: { key: WizardStep; label: string }[] = [
  { key: 'issuer',      label: 'Connect a CA' },
  { key: 'agent',       label: 'Deploy Agent' },
  { key: 'certificate', label: 'Add Certificate' },
  { key: 'complete',    label: 'Done' },
];
