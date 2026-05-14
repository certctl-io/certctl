// Phase 4 closure (FE-M3): OnboardingWizard mega-page split — Step 3.
// Add a Certificate. Behavior preserved byte-equivalent from the
// pre-split src/pages/OnboardingWizard.tsx lines 414-897 (CertificateStep
// + the two inline modals it owns — CreateTeamModalInline and
// CreateOwnerModalInline). The inline modals live in this file because
// they are tightly coupled to the certificate form (they're invoked
// from inline "+ New team / + New owner" affordances), so splitting
// them into their own file would just add an import edge for zero
// reuse outside this step.

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useTrackedMutation } from '../../hooks/useTrackedMutation';
import {
  getIssuers, getAgents, getProfiles, getOwners, getTeams, getRenewalPolicies,
  createCertificate, triggerRenewal, createTeam, createOwner,
} from '../../api/client';
import { WizardFooter } from './StepShell';

// Inline CreateTeamModal — mirrors TeamsPage.tsx CreateTeamModal pattern.
// Used inside CertificateStep so users can create a team without leaving the wizard.
function CreateTeamModalInline({ isOpen, onClose, onCreated }: {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (teamId: string) => void;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');

  const mutation = useTrackedMutation({
    mutationFn: () => createTeam({ name: name.trim(), description: description.trim() }),
    invalidates: [['teams']],
    onSuccess: (team) => {
      setName('');
      setDescription('');
      setError('');
      onCreated(team.id);
      onClose();
    },
    onError: (err: Error) => setError(err.message),
  });

  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Team</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={(e) => { e.preventDefault(); if (!name.trim()) return; mutation.mutate(); }} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-2">
              Name <span className="text-red-600">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Platform Engineering"
              autoFocus
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-2">
              Description <span className="text-xs text-ink-muted font-normal">(optional)</span>
            </label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
            />
          </div>
          <div className="flex gap-2 pt-2">
            <button
              type="submit"
              disabled={mutation.isPending || !name.trim()}
              className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {mutation.isPending ? 'Creating...' : 'Create Team'}
            </button>
            <button type="button" onClick={onClose} className="flex-1 btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Inline CreateOwnerModal — mirrors OwnersPage.tsx CreateOwnerModal pattern.
// Used inside CertificateStep so users can create an owner without leaving the wizard.
function CreateOwnerModalInline({ isOpen, onClose, onCreated, teams }: {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (ownerId: string) => void;
  teams: { id: string; name: string }[];
}) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [teamId, setTeamId] = useState('');
  const [error, setError] = useState('');

  const mutation = useTrackedMutation({
    mutationFn: () => createOwner({
      name: name.trim(),
      email: email.trim(),
      team_id: teamId || undefined,
    }),
    invalidates: [['owners']],
    onSuccess: (owner) => {
      setName('');
      setEmail('');
      setTeamId('');
      setError('');
      onCreated(owner.id);
      onClose();
    },
    onError: (err: Error) => setError(err.message),
  });

  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Owner</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!name.trim() || !email.trim()) return;
            mutation.mutate();
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-ink mb-2">
              Name <span className="text-red-600">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Alice Chen"
              autoFocus
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-2">
              Email <span className="text-red-600">*</span>
            </label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="alice@example.com"
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-2">
              Team <span className="text-xs text-ink-muted font-normal">(optional)</span>
            </label>
            <select
              value={teamId}
              onChange={e => setTeamId(e.target.value)}
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500 transition-colors"
            >
              <option value="">Unassigned</option>
              {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </div>
          <div className="flex gap-2 pt-2">
            <button
              type="submit"
              disabled={mutation.isPending || !name.trim() || !email.trim()}
              className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {mutation.isPending ? 'Creating...' : 'Create Owner'}
            </button>
            <button type="button" onClick={onClose} className="flex-1 btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function CertificateStep({ onNext, onSkip, createdIssuerId }: {
  onNext: (certName?: string) => void;
  onSkip: () => void;
  createdIssuerId: string | null;
}) {
  const [name, setName] = useState('');
  const [commonName, setCommonName] = useState('');
  const [sans, setSans] = useState('');
  const [issuerId, setIssuerId] = useState(createdIssuerId || '');
  const [profileId, setProfileId] = useState('');
  const [ownerId, setOwnerId] = useState('');
  const [teamId, setTeamId] = useState('');
  const [renewalPolicyId, setRenewalPolicyId] = useState('');
  const [error, setError] = useState('');
  const [created, setCreated] = useState(false);

  // Inline-create modals so users never have to leave the wizard (UX-001).
  const [teamModalOpen, setTeamModalOpen] = useState(false);
  const [ownerModalOpen, setOwnerModalOpen] = useState(false);

  // C-001: the server requires name, common_name, issuer_id, owner_id,
  // team_id, and renewal_policy_id (handler in
  // internal/api/handler/certificates.go + ManagedCertificate.required in
  // api/openapi.yaml). The wizard must collect the same six fields so that
  // "Issue Certificate" doesn't 400 at the API boundary.
  const { data: issuers } = useQuery({ queryKey: ['issuers'], queryFn: () => getIssuers() });
  const { data: profiles } = useQuery({ queryKey: ['profiles'], queryFn: () => getProfiles() });
  const { data: agents } = useQuery({ queryKey: ['agents'], queryFn: () => getAgents() });
  const { data: owners } = useQuery({ queryKey: ['owners'], queryFn: () => getOwners({ per_page: '500' }) });
  const { data: teams } = useQuery({ queryKey: ['teams'], queryFn: () => getTeams({ per_page: '500' }) });
  // G-1: bind renewal_policy_id dropdown to /api/v1/renewal-policies (rp-* IDs
  // from the renewal_policies table). Previously populated from getPolicies()
  // which returned compliance rules (pol-* IDs) and violated the FK
  // managed_certificates.renewal_policy_id → renewal_policies(id) on submit.
  const { data: policies } = useQuery({ queryKey: ['renewal-policies'], queryFn: () => getRenewalPolicies(1, 500) });

  const hasAgents = (agents?.data?.length ?? 0) > 0;

  const createMutation = useTrackedMutation({
    mutationFn: async () => {
      const sanList = sans.split(',').map(s => s.trim()).filter(Boolean);
      const cert = await createCertificate({
        name,
        common_name: commonName,
        sans: sanList,
        issuer_id: issuerId,
        certificate_profile_id: profileId || undefined,
        owner_id: ownerId,
        team_id: teamId,
        renewal_policy_id: renewalPolicyId,
        environment: 'production',
      });
      // Trigger issuance
      await triggerRenewal(cert.id);
      return cert;
    },
    invalidates: [['certificates'], ['dashboard-summary']],
    onSuccess: (cert) => {
      setCreated(true);
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
            Name <span className="text-red-600">*</span>
          </label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="API Production Cert"
            className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors"
          />
        </div>

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

        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-ink">
                Owner <span className="text-red-600">*</span>
              </label>
              <button
                type="button"
                onClick={() => setOwnerModalOpen(true)}
                className="text-xs text-brand-600 hover:text-brand-700 hover:underline"
              >
                + New owner
              </button>
            </div>
            <select
              value={ownerId}
              onChange={e => setOwnerId(e.target.value)}
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500 transition-colors"
            >
              <option value="">Select owner...</option>
              {owners?.data?.map(o => (
                <option key={o.id} value={o.id}>
                  {o.name}{o.email ? ` (${o.email})` : ''}
                </option>
              ))}
            </select>
            {(owners?.data?.length ?? 0) === 0 && (
              <p className="mt-1 text-xs text-ink-muted">
                No owners yet —{' '}
                <button
                  type="button"
                  onClick={() => setOwnerModalOpen(true)}
                  className="underline hover:text-ink"
                >
                  create one now
                </button>
                .
              </p>
            )}
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-ink">
                Team <span className="text-red-600">*</span>
              </label>
              <button
                type="button"
                onClick={() => setTeamModalOpen(true)}
                className="text-xs text-brand-600 hover:text-brand-700 hover:underline"
              >
                + New team
              </button>
            </div>
            <select
              value={teamId}
              onChange={e => setTeamId(e.target.value)}
              className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500 transition-colors"
            >
              <option value="">Select team...</option>
              {teams?.data?.map(t => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            {(teams?.data?.length ?? 0) === 0 && (
              <p className="mt-1 text-xs text-ink-muted">
                No teams yet —{' '}
                <button
                  type="button"
                  onClick={() => setTeamModalOpen(true)}
                  className="underline hover:text-ink"
                >
                  create one now
                </button>
                .
              </p>
            )}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-ink mb-2">
            Renewal Policy <span className="text-red-600">*</span>
          </label>
          <select
            value={renewalPolicyId}
            onChange={e => setRenewalPolicyId(e.target.value)}
            className="w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink focus:outline-none focus:border-brand-500 transition-colors"
          >
            <option value="">Select renewal policy...</option>
            {policies?.data?.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          {(policies?.data?.length ?? 0) === 0 && (
            <p className="mt-1 text-xs text-ink-muted">
              No renewal policies yet — create one from the <Link to="/policies" className="underline hover:text-ink">Policies page</Link> first, then return here.
            </p>
          )}
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
        nextDisabled={
          !name ||
          !commonName ||
          !issuerId ||
          !ownerId ||
          !teamId ||
          !renewalPolicyId ||
          createMutation.isPending
        }
      />

      <CreateTeamModalInline
        isOpen={teamModalOpen}
        onClose={() => setTeamModalOpen(false)}
        onCreated={(id) => setTeamId(id)}
      />
      <CreateOwnerModalInline
        isOpen={ownerModalOpen}
        onClose={() => setOwnerModalOpen(false)}
        onCreated={(id) => setOwnerId(id)}
        teams={(teams?.data ?? []).map(t => ({ id: t.id, name: t.name }))}
      />
    </div>
  );
}
