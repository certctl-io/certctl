import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { getCertificate, getCertificateVersions, triggerRenewal, triggerDeployment, archiveCertificate, revokeCertificate, updateCertificate, getTargets, getJobs, getRenewalPolicies, getProfiles, getProfile, downloadCertificatePEM, exportCertificatePKCS12, getOCSPStatus, fetchCRL, getAdminCRLCache } from '../api/client';
import { REVOCATION_REASONS } from '../api/types';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { useAuth } from '../components/AuthProvider';
import { formatDate, formatDateTime, daysUntil, expiryColor, timeAgo } from '../api/utils';
import type { Job, CRLCacheRow } from '../api/types';

function InfoRow({ label, value, editable, onEdit }: { label: string; value: React.ReactNode; editable?: boolean; onEdit?: () => void }) {
  return (
    <div className="flex justify-between py-2 border-b border-surface-border/50 group">
      <span className="text-sm text-ink-muted">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-sm text-ink">{value}</span>
        {editable && onEdit && (
          <button onClick={onEdit} className="opacity-0 group-hover:opacity-100 transition-opacity text-xs text-brand-400 hover:text-brand-500">
            Edit
          </button>
        )}
      </div>
    </div>
  );
}

// Timeline step component for deployment status
function TimelineStep({ label, status, time, isLast }: { label: string; status: 'completed' | 'active' | 'pending' | 'failed'; time?: string; isLast?: boolean }) {
  const dotStyles = {
    completed: 'bg-emerald-500 ring-emerald-200',
    active: 'bg-brand-400 ring-brand-200 animate-pulse',
    pending: 'bg-surface-muted ring-surface-border',
    failed: 'bg-red-500 ring-red-200',
  };
  const lineStyles = {
    completed: 'bg-emerald-300',
    active: 'bg-brand-200',
    pending: 'bg-surface-border',
    failed: 'bg-red-300',
  };
  const textStyles = {
    completed: 'text-emerald-600',
    active: 'text-brand-400',
    pending: 'text-ink-faint',
    failed: 'text-red-600',
  };

  return (
    <div className="flex items-start gap-3 relative">
      <div className="flex flex-col items-center">
        <div className={`w-3 h-3 rounded-full ring-4 ${dotStyles[status]} flex-shrink-0 mt-0.5`} />
        {!isLast && <div className={`w-0.5 h-8 ${lineStyles[status]}`} />}
      </div>
      <div className="pb-6">
        <div className={`text-sm font-medium ${textStyles[status]}`}>{label}</div>
        {time && <div className="text-xs text-ink-faint mt-0.5">{time}</div>}
      </div>
    </div>
  );
}

function DeploymentTimeline({ certId, certStatus, createdAt, issuedAt }: { certId: string; certStatus: string; createdAt: string; issuedAt?: string }) {
  const { data: jobsData } = useQuery({
    queryKey: ['jobs', { certificate_id: certId }],
    queryFn: () => getJobs({ certificate_id: certId }),
  });

  const jobs = jobsData?.data || [];
  const issuanceJobs = jobs.filter((j: Job) => j.type === 'Issuance' || j.type === 'Renewal');
  const deployJobs = jobs.filter((j: Job) => j.type === 'Deployment');
  const latestIssuance = issuanceJobs[0];
  const latestDeploy = deployJobs[0];

  // Determine step statuses
  const getRequestedStatus = () => 'completed' as const;
  const getRequestedTime = () => formatDateTime(createdAt);

  const getIssuedStatus = () => {
    if (issuedAt) return 'completed' as const;
    if (latestIssuance?.status === 'Running' || latestIssuance?.status === 'AwaitingCSR' || latestIssuance?.status === 'AwaitingApproval') return 'active' as const;
    if (latestIssuance?.status === 'Failed') return 'failed' as const;
    return 'pending' as const;
  };
  const getIssuedTime = () => {
    if (issuedAt) return formatDateTime(issuedAt);
    if (latestIssuance) return `${latestIssuance.status} — ${timeAgo(latestIssuance.created_at)}`;
    return undefined;
  };

  const getDeployStatus = () => {
    if (!issuedAt) return 'pending' as const;
    if (latestDeploy?.status === 'Completed') return 'completed' as const;
    if (latestDeploy?.status === 'Running') return 'active' as const;
    if (latestDeploy?.status === 'Failed') return 'failed' as const;
    if (latestDeploy?.status === 'Pending') return 'active' as const;
    return 'pending' as const;
  };
  const getDeployTime = () => {
    if (latestDeploy?.status === 'Completed') return formatDateTime(latestDeploy.completed_at);
    if (latestDeploy) return `${latestDeploy.status} — ${timeAgo(latestDeploy.created_at)}`;
    return undefined;
  };

  // Verification step (M25: post-deployment TLS verification)
  const getVerifiedStatus = () => {
    if (!latestDeploy || latestDeploy.status !== 'Completed') return 'pending' as const;
    if (latestDeploy.verification_status === 'success') return 'completed' as const;
    if (latestDeploy.verification_status === 'failed') return 'failed' as const;
    if (latestDeploy.verification_status === 'skipped') return 'completed' as const;
    if (latestDeploy.verification_status === 'pending') return 'active' as const;
    return 'pending' as const;
  };
  const getVerifiedTime = () => {
    if (!latestDeploy || latestDeploy.status !== 'Completed') return undefined;
    if (latestDeploy.verification_status === 'success' && latestDeploy.verified_at) {
      return `Verified ${formatDateTime(latestDeploy.verified_at)}`;
    }
    if (latestDeploy.verification_status === 'failed') {
      return latestDeploy.verification_error || 'Verification failed';
    }
    if (latestDeploy.verification_status === 'skipped') return 'Skipped (best-effort)';
    if (latestDeploy.verification_status === 'pending') return 'Awaiting verification';
    return undefined;
  };

  const getActiveStatus = () => {
    if (certStatus === 'Active') return 'completed' as const;
    if (certStatus === 'Revoked') return 'failed' as const;
    if (certStatus === 'Expired') return 'failed' as const;
    if (latestDeploy?.status === 'Completed') return 'completed' as const;
    return 'pending' as const;
  };
  const getActiveTime = () => {
    if (certStatus === 'Revoked') return 'Revoked';
    if (certStatus === 'Expired') return 'Expired';
    if (certStatus === 'Active') return 'Currently active';
    return undefined;
  };

  // Only show verification step if deployment has completed and verification data exists
  const showVerificationStep = latestDeploy?.status === 'Completed' && latestDeploy?.verification_status;

  return (
    <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
      <h3 className="text-sm font-semibold text-ink-muted mb-4">Lifecycle Timeline</h3>
      <div className="pl-1">
        <TimelineStep label="Requested" status={getRequestedStatus()} time={getRequestedTime()} />
        <TimelineStep label="Issued" status={getIssuedStatus()} time={getIssuedTime()} />
        <TimelineStep label="Deploying" status={getDeployStatus()} time={getDeployTime()} />
        {showVerificationStep && (
          <TimelineStep label="Verified" status={getVerifiedStatus()} time={getVerifiedTime()} />
        )}
        <TimelineStep label={certStatus === 'Revoked' ? 'Revoked' : certStatus === 'Expired' ? 'Expired' : 'Active'}
          status={getActiveStatus()} time={getActiveTime()} isLast />
      </div>
    </div>
  );
}

// CRL/OCSP-Responder Phase 5: Revocation Endpoints panel.
//
// Surfaces the standards-compliant revocation URLs (CRL distribution point
// per RFC 5280 §4.2.1.13, OCSP responder per RFC 6960 §A.1) for relying
// parties that don't already know certctl's well-known scheme. Both endpoints
// live under /.well-known/pki/ and run unauthenticated — relying-party clients
// should never need a Bearer key to check revocation status.
//
// The "Test CRL fetch" / "Check OCSP status" buttons exercise the same
// network path the CRL/OCSP responders advertise via the AIA + CDP
// extensions on issued leaves, so an operator confirming "did Phase 4
// actually wire end-to-end?" can do it without curl. Failures bubble up
// as inline error text rather than throwing a global error boundary.
//
// The cache-age badge is admin-only (gated client-side AND server-side; the
// server returns 403 for non-admin even if the GUI bug-clicks the fetch).
// Stale rows render in amber per the IsStale flag (next_update < now). Rows
// missing entirely (issuer never had a CRL pre-generated) render the neutral
// "Not yet generated" pill.
function RevocationEndpointsCard({ issuerId, serialNumber }: { issuerId: string; serialNumber?: string }) {
  const { admin } = useAuth();
  const [crlState, setCrlState] = useState<{ status: 'idle' | 'loading' | 'ok' | 'err'; msg?: string }>({ status: 'idle' });
  const [ocspState, setOcspState] = useState<{ status: 'idle' | 'loading' | 'ok' | 'err'; msg?: string }>({ status: 'idle' });

  // Build the absolute URLs from window.location so operators can copy-paste
  // them straight into curl / openssl. Using window.location keeps the URLs
  // honest under reverse-proxy deployments where the perceived host differs
  // from what the dev sees in their browser bar — the location object is the
  // ground truth for "what URL does the relying party hit?".
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const crlURL = `${origin}/.well-known/pki/crl/${issuerId}`;
  // OCSP per RFC 6960 §A.1.1 supports both POST (preferred for CSR-style
  // requests) and the GET form with base64-url(DER) in the path. The GUI's
  // "Check OCSP status" button uses the simpler /{issuer}/{serial_hex}
  // helper certctl exposes alongside the standards endpoint — that's what
  // getOCSPStatus() in client.ts hits.
  const ocspURL = `${origin}/.well-known/pki/ocsp/${issuerId}`;

  // Admin-only: pull the cache row for this issuer so we can show
  // "generated 2m ago / next update 58m" with a stale-warning chip.
  const { data: cacheData } = useQuery({
    queryKey: ['admin-crl-cache'],
    queryFn: () => getAdminCRLCache(),
    enabled: admin,
    // Refresh a touch faster than the default scheduler interval (1h) so
    // the badge feels live during ops investigation. Falls back gracefully
    // if the user navigates away before the next tick.
    refetchInterval: 60_000,
    retry: false,
  });

  const issuerRow: CRLCacheRow | undefined = cacheData?.cache_rows?.find(r => r.issuer_id === issuerId);

  const handleTestCRL = async () => {
    setCrlState({ status: 'loading' });
    try {
      const r = await fetchCRL(issuerId);
      setCrlState({ status: 'ok', msg: `OK — ${r.byteLength.toLocaleString()} bytes (${r.contentType || 'no content-type'})` });
    } catch (e) {
      setCrlState({ status: 'err', msg: e instanceof Error ? e.message : 'Fetch failed' });
    }
  };

  const handleCheckOCSP = async () => {
    if (!serialNumber) {
      setOcspState({ status: 'err', msg: 'Serial number unavailable — cert has not been issued yet.' });
      return;
    }
    setOcspState({ status: 'loading' });
    try {
      const buf = await getOCSPStatus(issuerId, serialNumber);
      setOcspState({ status: 'ok', msg: `OCSP response received — ${buf.byteLength.toLocaleString()} bytes (DER)` });
    } catch (e) {
      setOcspState({ status: 'err', msg: e instanceof Error ? e.message : 'OCSP request failed' });
    }
  };

  return (
    <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-ink-muted">Revocation Endpoints</h3>
        {admin && (
          issuerRow ? (
            issuerRow.cache_present ? (
              <span
                className={`text-xs px-2 py-0.5 rounded font-medium ${
                  issuerRow.is_stale ? 'bg-amber-50 text-amber-700' : 'bg-emerald-50 text-emerald-700'
                }`}
                title={`CRL #${issuerRow.crl_number ?? '—'} — generated ${
                  issuerRow.generated_at ? formatDateTime(issuerRow.generated_at) : '—'
                }, next update ${issuerRow.next_update ? formatDateTime(issuerRow.next_update) : '—'}`}
              >
                {issuerRow.is_stale ? 'Cache stale' : 'Cache fresh'}
                {issuerRow.generated_at ? ` · ${timeAgo(issuerRow.generated_at)}` : ''}
              </span>
            ) : (
              <span className="text-xs px-2 py-0.5 rounded font-medium bg-surface-muted text-ink-faint">
                Not yet generated
              </span>
            )
          ) : null
        )}
      </div>

      <div className="space-y-3">
        <div>
          <div className="text-xs text-ink-muted mb-1">CRL Distribution Point (RFC 5280 §4.2.1.13)</div>
          <div className="flex items-center gap-2">
            <code className="font-mono text-xs bg-surface-muted px-2 py-1 rounded text-ink flex-1 break-all">{crlURL}</code>
            <button
              onClick={handleTestCRL}
              disabled={crlState.status === 'loading'}
              className="text-xs px-3 py-1 rounded border border-surface-border text-brand-400 hover:text-brand-500 hover:border-brand-300 disabled:opacity-50 transition-colors"
            >
              {crlState.status === 'loading' ? 'Fetching…' : 'Test CRL fetch'}
            </button>
          </div>
          {crlState.status === 'ok' && (
            <div className="text-xs text-emerald-600 mt-1">{crlState.msg}</div>
          )}
          {crlState.status === 'err' && (
            <div className="text-xs text-red-600 mt-1">{crlState.msg}</div>
          )}
        </div>

        <div>
          <div className="text-xs text-ink-muted mb-1">OCSP Responder (RFC 6960 §A.1)</div>
          <div className="flex items-center gap-2">
            <code className="font-mono text-xs bg-surface-muted px-2 py-1 rounded text-ink flex-1 break-all">{ocspURL}</code>
            <button
              onClick={handleCheckOCSP}
              disabled={ocspState.status === 'loading' || !serialNumber}
              title={!serialNumber ? 'Serial number unavailable — cert not yet issued' : ''}
              className="text-xs px-3 py-1 rounded border border-surface-border text-brand-400 hover:text-brand-500 hover:border-brand-300 disabled:opacity-50 transition-colors"
            >
              {ocspState.status === 'loading' ? 'Checking…' : 'Check OCSP status'}
            </button>
          </div>
          {ocspState.status === 'ok' && (
            <div className="text-xs text-emerald-600 mt-1">{ocspState.msg}</div>
          )}
          {ocspState.status === 'err' && (
            <div className="text-xs text-red-600 mt-1">{ocspState.msg}</div>
          )}
          {!serialNumber && ocspState.status === 'idle' && (
            <div className="text-xs text-ink-faint mt-1">Serial number unavailable — issue the cert first.</div>
          )}
        </div>
      </div>

      <p className="text-xs text-ink-faint mt-4">
        Both endpoints run unauthenticated under <code className="font-mono">/.well-known/pki/</code> per RFC 8615 so relying parties can validate revocation without API keys. The CRL is pre-generated by the scheduler (configurable via <code className="font-mono">CERTCTL_CRL_GENERATION_INTERVAL</code>); OCSP is signed by the per-issuer responder cert (RFC 6960 §2.6).
      </p>
    </div>
  );
}

function InlinePolicyEditor({ certId, currentPolicyId, currentProfileId }: { certId: string; currentPolicyId: string; currentProfileId: string }) {
  const [editing, setEditing] = useState(false);
  const [policyId, setPolicyId] = useState(currentPolicyId);
  const [profileId, setProfileId] = useState(currentProfileId);

  // G-1: swap from getPolicies (compliance rules, pol-*) to getRenewalPolicies
  // (lifecycle policies, rp-*). managed_certificates.renewal_policy_id FK
  // points at renewal_policies(id); the previous getPolicies call populated
  // the dropdown with pol-* IDs that would 400/23503 at the server. See also
  // OnboardingWizard.tsx:603 and CertificatesPage.tsx:53 for the sibling fixes.
  const { data: policies } = useQuery({
    queryKey: ['renewal-policies'],
    queryFn: () => getRenewalPolicies(1, 500),
    enabled: editing,
  });

  const { data: profiles } = useQuery({
    queryKey: ['profiles'],
    queryFn: () => getProfiles(),
    enabled: editing,
  });

  const saveMutation = useTrackedMutation({
    mutationFn: () => updateCertificate(certId, {
      renewal_policy_id: policyId,
      certificate_profile_id: profileId,
    }),
    invalidates: [['certificate', certId]],
    onSuccess: () => {
      setEditing(false);
    },
  });

  if (!editing) {
    return (
      <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-ink-muted">Policy & Profile</h3>
          <button onClick={() => setEditing(true)} className="text-xs text-brand-400 hover:text-brand-500 transition-colors">
            Edit
          </button>
        </div>
        <InfoRow label="Renewal Policy" value={currentPolicyId || '—'} />
        <InfoRow label="Certificate Profile" value={currentProfileId || '—'} />
      </div>
    );
  }

  return (
    <div className="bg-surface border border-surface-border border-brand-400 rounded p-5 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-brand-500">Edit Policy & Profile</h3>
        <div className="flex gap-2">
          <button onClick={() => { setEditing(false); setPolicyId(currentPolicyId); setProfileId(currentProfileId); }}
            className="text-xs text-ink-muted hover:text-ink">Cancel</button>
          <button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}
            className="text-xs text-brand-400 hover:text-brand-500 font-medium disabled:opacity-50">
            {saveMutation.isPending ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
      {saveMutation.isError && (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-3">
          {saveMutation.error instanceof Error ? saveMutation.error.message : 'Failed to save'}
        </div>
      )}
      <div className="space-y-3">
        <div>
          <label className="text-xs text-ink-muted block mb-1">Renewal Policy</label>
          <select value={policyId} onChange={e => setPolicyId(e.target.value)}
            className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink">
            <option value="">None</option>
            {policies?.data?.map(p => (
              // G-1: RenewalPolicy has no `type` field (that was PolicyRule).
              // Show the human-readable name + renewal window so operators can
              // pick the correct lifecycle policy at a glance.
              <option key={p.id} value={p.id}>{p.name} ({p.renewal_window_days}d window)</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-ink-muted block mb-1">Certificate Profile</label>
          <select value={profileId} onChange={e => setProfileId(e.target.value)}
            className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink">
            <option value="">None</option>
            {profiles?.data?.map(p => (
              <option key={p.id} value={p.id}>{p.name} — max TTL {p.max_ttl_seconds ? `${Math.round(p.max_ttl_seconds / 86400)}d` : '∞'}</option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}

export default function CertificateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [showDeploy, setShowDeploy] = useState(false);
  const [deployTargetId, setDeployTargetId] = useState('');
  const [showRevoke, setShowRevoke] = useState(false);
  const [revokeReason, setRevokeReason] = useState('unspecified');
  const [showExport, setShowExport] = useState(false);
  const [pkcs12Password, setPkcs12Password] = useState('');
  const [exporting, setExporting] = useState(false);

  const { data: cert, isLoading, error, refetch } = useQuery({
    queryKey: ['certificate', id],
    queryFn: () => getCertificate(id!),
    enabled: !!id,
  });

  const { data: versions } = useQuery({
    queryKey: ['certificate-versions', id],
    queryFn: () => getCertificateVersions(id!),
    enabled: !!id,
  });

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => getTargets(),
    enabled: showDeploy,
  });

  // Fetch profile for EKU display (S/MIME, code signing badges)
  const { data: profile } = useQuery({
    queryKey: ['profile', cert?.certificate_profile_id],
    queryFn: () => getProfile(cert!.certificate_profile_id),
    enabled: !!cert?.certificate_profile_id,
  });

  const renewMutation = useTrackedMutation({
    mutationFn: () => triggerRenewal(id!),
    invalidates: [['certificate', id], ['certificates']],
  });

  const deployMutation = useTrackedMutation({
    mutationFn: () => triggerDeployment(id!, deployTargetId),
    invalidates: [['certificate', id]],
    onSuccess: () => {
      setShowDeploy(false);
      setDeployTargetId('');
    },
  });

  const archiveMutation = useTrackedMutation({
    mutationFn: () => archiveCertificate(id!),
    invalidates: [['certificates']],
    onSuccess: () => {
      navigate('/certificates');
    },
  });

  const revokeMutation = useTrackedMutation({
    mutationFn: () => revokeCertificate(id!, revokeReason),
    invalidates: [['certificate', id], ['certificates']],
    onSuccess: () => {
      setShowRevoke(false);
      setRevokeReason('unspecified');
    },
  });

  const handleExportPEM = async () => {
    setExporting(true);
    try {
      const blob = await downloadCertificatePEM(id!);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${cert?.common_name || id}.pem`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Export failed: ${err instanceof Error ? err.message : err}`);
    } finally {
      setExporting(false);
    }
  };

  const handleExportPKCS12 = async () => {
    setExporting(true);
    try {
      const blob = await exportCertificatePKCS12(id!, pkcs12Password);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${cert?.common_name || id}.p12`;
      a.click();
      URL.revokeObjectURL(url);
      setShowExport(false);
      setPkcs12Password('');
    } catch (err) {
      alert(`Export failed: ${err instanceof Error ? err.message : err}`);
    } finally {
      setExporting(false);
    }
  };

  if (isLoading) {
    return (
      <>
        <PageHeader title="Certificate" />
        <div className="flex items-center justify-center flex-1 text-slate-400">Loading...</div>
      </>
    );
  }

  if (error || !cert) {
    return (
      <>
        <PageHeader title="Certificate" />
        <ErrorState error={error as Error || new Error('Not found')} onRetry={() => refetch()} />
      </>
    );
  }

  // Derive certificate metadata from latest version. Per-issuance fields
  // (serial_number, fingerprint_sha256, key_algorithm, key_size, issued_at)
  // live on `CertificateVersion`, NOT on `ManagedCertificate` — the Go
  // domain has always been this way; the TS interface used to lie about
  // it via optional `cert.X?` declarations that always returned undefined
  // on list responses (D-5 / cat-f-ae0d06b6588f). Post-D-5 the TS type
  // makes the missing-data case explicit, and every read goes through
  // `latestVersion?.field` here.
  const latestVersion = versions?.data?.[0];
  const serialNumber = latestVersion?.serial_number;
  const fingerprintSha256 = latestVersion?.fingerprint_sha256;
  const issuedAt = latestVersion?.not_before;
  const keyAlgorithm = latestVersion?.key_algorithm;
  const keySize = latestVersion?.key_size;

  const days = daysUntil(cert.expires_at);
  const isRevoked = cert.status === 'Revoked';
  const isArchived = cert.status === 'Archived';
  const canRevoke = !isRevoked && !isArchived;

  return (
    <>
      <PageHeader
        title={cert.common_name}
        subtitle={cert.id}
        action={
          <div className="flex gap-2">
            <button onClick={() => navigate('/certificates')} className="btn btn-ghost text-xs">
              Back
            </button>
            <button
              onClick={handleExportPEM}
              disabled={exporting}
              className="btn btn-ghost text-xs border border-surface-border disabled:opacity-50"
            >
              {exporting ? 'Exporting...' : 'Export PEM'}
            </button>
            <button
              onClick={() => setShowExport(true)}
              className="btn btn-ghost text-xs border border-surface-border"
            >
              Export PKCS#12
            </button>
            <button
              onClick={() => setShowDeploy(true)}
              disabled={isArchived || isRevoked}
              className="btn btn-ghost text-xs border border-surface-border disabled:opacity-50"
            >
              Deploy
            </button>
            <button
              onClick={() => renewMutation.mutate()}
              disabled={renewMutation.isPending || isArchived || isRevoked || cert.status === 'RenewalInProgress'}
              className="btn btn-primary text-xs disabled:opacity-50"
            >
              {renewMutation.isPending ? 'Renewing...' : 'Trigger Renewal'}
            </button>
            {canRevoke && (
              <button
                onClick={() => setShowRevoke(true)}
                className="btn btn-ghost text-xs text-amber-400 hover:text-amber-300 border border-amber-600/50"
              >
                Revoke
              </button>
            )}
            {!isArchived && (
              <button
                onClick={() => { if (confirm('Archive this certificate? This cannot be undone.')) archiveMutation.mutate(); }}
                disabled={archiveMutation.isPending}
                className="btn btn-ghost text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
              >
                {archiveMutation.isPending ? 'Archiving...' : 'Archive'}
              </button>
            )}
          </div>
        }
      />
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {renewMutation.isSuccess && (
          <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 rounded px-4 py-3 text-sm">
            Renewal triggered successfully. A renewal job has been created.
          </div>
        )}
        {renewMutation.isError && (
          <div className="bg-red-50 border border-red-200 text-red-700 rounded px-4 py-3 text-sm">
            Failed to trigger renewal: {renewMutation.error instanceof Error ? renewMutation.error.message : 'Unknown error'}
          </div>
        )}
        {deployMutation.isSuccess && (
          <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 rounded px-4 py-3 text-sm">
            Deployment triggered. A deployment job has been created.
          </div>
        )}
        {deployMutation.isError && (
          <div className="bg-red-50 border border-red-200 text-red-700 rounded px-4 py-3 text-sm">
            Failed to deploy: {deployMutation.error instanceof Error ? deployMutation.error.message : 'Unknown error'}
          </div>
        )}
        {archiveMutation.isError && (
          <div className="bg-red-50 border border-red-200 text-red-700 rounded px-4 py-3 text-sm">
            Failed to archive: {archiveMutation.error instanceof Error ? archiveMutation.error.message : 'Unknown error'}
          </div>
        )}
        {revokeMutation.isSuccess && (
          <div className="bg-amber-50 border border-amber-200 text-amber-700 rounded px-4 py-3 text-sm">
            Certificate revoked successfully. It has been added to the CRL.
          </div>
        )}
        {revokeMutation.isError && (
          <div className="bg-red-50 border border-red-200 text-red-700 rounded px-4 py-3 text-sm">
            Failed to revoke: {revokeMutation.error instanceof Error ? revokeMutation.error.message : 'Unknown error'}
          </div>
        )}

        {/* Revocation Banner */}
        {isRevoked && (
          <div className="bg-red-50 border border-red-200 rounded px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded bg-red-100 flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              </div>
              <div>
                <div className="text-sm font-medium text-red-700">Certificate Revoked</div>
                <div className="text-xs text-red-600 mt-0.5">
                  Reason: {REVOCATION_REASONS.find(r => r.value === cert.revocation_reason)?.label || cert.revocation_reason || 'Unspecified'}
                  {cert.revoked_at && <> &middot; Revoked {formatDateTime(cert.revoked_at)}</>}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Deployment Status Timeline */}
        <DeploymentTimeline certId={id!} certStatus={cert.status} createdAt={cert.created_at} issuedAt={issuedAt} />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Certificate Info */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Certificate Details</h3>
            <InfoRow label="Status" value={<StatusBadge status={cert.status} />} />
            <InfoRow label="Common Name" value={cert.common_name} />
            <InfoRow label="SANs" value={cert.sans?.length ? (
              <span className="text-sm">
                {cert.sans.map((san, i) => {
                  const isEmail = san.includes('@');
                  return (
                    <span key={san}>
                      {i > 0 && ', '}
                      {isEmail ? (
                        <span className="inline-flex items-center gap-1">
                          <span className="text-xs text-purple-600 bg-purple-50 px-1 rounded">email</span>
                          <span>{san}</span>
                        </span>
                      ) : san}
                    </span>
                  );
                })}
              </span>
            ) : '—'} />
            <InfoRow label="Serial Number" value={serialNumber || '—'} />
            <InfoRow label="Fingerprint" value={
              fingerprintSha256 ? <span className="font-mono text-xs">{fingerprintSha256.slice(0, 24)}...</span> : '—'
            } />
            {/* D-4 (cat-f-cert_detail_page_key_render_fallback): mirror the
                latestVersion fallback used for serialNumber / fingerprintSha256
                above. Pre-D-4 these rows accessed `cert.key_algorithm` /
                `cert.key_size` directly — both phantom Certificate fields per
                D-5 (cat-f-ae0d06b6588f), so the rows always rendered '—'. */}
            <InfoRow label="Key Algorithm" value={keyAlgorithm || '—'} />
            <InfoRow label="Key Size" value={keySize != null ? `${keySize} bits` : '—'} />
            {profile?.allowed_ekus && profile.allowed_ekus.length > 0 && (
              <InfoRow label="Extended Key Usage" value={
                <div className="flex flex-wrap gap-1">
                  {profile.allowed_ekus.map(eku => {
                    const ekuStyles: Record<string, string> = {
                      serverAuth: 'bg-blue-50 text-blue-700',
                      clientAuth: 'bg-green-50 text-green-700',
                      emailProtection: 'bg-purple-50 text-purple-700',
                      codeSigning: 'bg-amber-50 text-amber-700',
                      timeStamping: 'bg-teal-50 text-teal-700',
                    };
                    const ekuLabels: Record<string, string> = {
                      serverAuth: 'TLS Server',
                      clientAuth: 'TLS Client',
                      emailProtection: 'S/MIME',
                      codeSigning: 'Code Signing',
                      timeStamping: 'Timestamping',
                    };
                    return (
                      <span key={eku} className={`text-xs px-1.5 py-0.5 rounded font-medium ${ekuStyles[eku] || 'bg-gray-50 text-gray-700'}`}>
                        {ekuLabels[eku] || eku}
                      </span>
                    );
                  })}
                </div>
              } />
            )}
          </div>

          {/* Lifecycle */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Lifecycle</h3>
            <InfoRow label="Issued" value={formatDate(issuedAt)} />
            <InfoRow label="Expires" value={
              <span className={isRevoked ? 'text-red-600 line-through' : expiryColor(days)}>
                {formatDate(cert.expires_at)} ({days <= 0 ? 'expired' : `${days} days`})
              </span>
            } />
            <InfoRow label="Environment" value={cert.environment || '—'} />
            <InfoRow label="Issuer" value={cert.issuer_id} />
            <InfoRow label="Owner" value={cert.owner_id} />
            <InfoRow label="Team" value={cert.team_id} />
            {isRevoked && (
              <>
                <InfoRow label="Revoked At" value={
                  <span className="text-red-600">{cert.revoked_at ? formatDateTime(cert.revoked_at) : '—'}</span>
                } />
                <InfoRow label="Revocation Reason" value={
                  <span className="text-red-600">
                    {REVOCATION_REASONS.find(r => r.value === cert.revocation_reason)?.label || cert.revocation_reason || '—'}
                  </span>
                } />
              </>
            )}
            <InfoRow label="Created" value={formatDateTime(cert.created_at)} />
            <InfoRow label="Updated" value={formatDateTime(cert.updated_at)} />
          </div>
        </div>

        {/* Inline Policy Editor */}
        <InlinePolicyEditor
          certId={id!}
          currentPolicyId={cert.renewal_policy_id || ''}
          currentProfileId={cert.certificate_profile_id || ''}
        />

        {/* Revocation Endpoints (CRL + OCSP) — Phase 5 */}
        <RevocationEndpointsCard issuerId={cert.issuer_id} serialNumber={serialNumber} />

        {/* Tags */}
        {cert.tags && Object.keys(cert.tags).length > 0 && (
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Tags</h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(cert.tags).map(([k, v]) => (
                <span key={k} className="badge badge-neutral">{k}: {v}</span>
              ))}
            </div>
          </div>
        )}

        {/* Version History */}
        <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-ink-muted mb-4">
            Version History {versions?.data?.length ? `(${versions.data.length})` : ''}
          </h3>
          {!versions?.data?.length ? (
            <p className="text-sm text-ink-faint">No versions yet</p>
          ) : (
            <div className="space-y-3">
              {versions.data.map((v, idx) => (
                <div key={v.id} className="flex items-center justify-between py-2 border-b border-surface-border/50 last:border-0">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-ink">Version {versions.data.length - idx}</span>
                      {idx === 0 && <span className="text-xs bg-brand-100 text-brand-700 px-1.5 py-0.5 rounded">Current</span>}
                    </div>
                    <div className="text-xs text-ink-faint font-mono">{v.serial_number}</div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <div className="text-sm text-ink-muted">{formatDate(v.not_before)} — {formatDate(v.not_after)}</div>
                      <div className="text-xs text-ink-faint">{formatDateTime(v.created_at)}</div>
                    </div>
                    {idx > 0 && cert?.status !== 'Archived' && cert?.status !== 'Revoked' && (
                      <button
                        onClick={() => setShowDeploy(true)}
                        className="text-xs text-amber-600 hover:text-amber-700 border border-amber-300 px-2 py-1 rounded hover:bg-amber-50 transition-colors"
                        title="Redeploy this version to targets"
                      >
                        Rollback
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Deploy Modal */}
      {showDeploy && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowDeploy(false)}>
          <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-ink mb-4">Deploy Certificate</h2>
            {deployMutation.isError && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-3">
                {deployMutation.error instanceof Error ? deployMutation.error.message : 'Unknown error'}
              </div>
            )}
            <label className="text-xs text-ink-muted block mb-2">Select Target</label>
            <select
              value={deployTargetId}
              onChange={e => setDeployTargetId(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink mb-4"
            >
              <option value="">Choose a target...</option>
              {targets?.data?.map(t => (
                <option key={t.id} value={t.id}>{t.name} ({t.type})</option>
              ))}
            </select>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowDeploy(false)} className="btn btn-ghost text-sm">Cancel</button>
              <button
                onClick={() => deployMutation.mutate()}
                disabled={!deployTargetId || deployMutation.isPending}
                className="btn btn-primary text-sm disabled:opacity-50"
              >
                {deployMutation.isPending ? 'Deploying...' : 'Deploy'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* PKCS#12 Export Modal */}
      {showExport && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowExport(false)}>
          <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-ink mb-2">Export PKCS#12</h2>
            <p className="text-sm text-ink-muted mb-4">
              Downloads a .p12 file containing the certificate chain. Private keys are not included (they remain on the agent).
            </p>
            <label className="text-xs text-ink-muted block mb-2">Password (optional)</label>
            <input
              type="password"
              value={pkcs12Password}
              onChange={e => setPkcs12Password(e.target.value)}
              placeholder="Leave empty for no encryption"
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink mb-4 focus:outline-none focus:border-brand-400"
            />
            <div className="flex justify-end gap-3">
              <button onClick={() => { setShowExport(false); setPkcs12Password(''); }} className="btn btn-ghost text-sm">
                Cancel
              </button>
              <button
                onClick={handleExportPKCS12}
                disabled={exporting}
                className="btn btn-primary text-sm disabled:opacity-50"
              >
                {exporting ? 'Exporting...' : 'Download .p12'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Revoke Modal */}
      {showRevoke && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowRevoke(false)}>
          <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-red-700 mb-2">Revoke Certificate</h2>
            <p className="text-sm text-ink-muted mb-4">
              This action cannot be undone. The certificate will be added to the CRL and marked as revoked.
            </p>
            {revokeMutation.isError && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-3">
                {revokeMutation.error instanceof Error ? revokeMutation.error.message : 'Unknown error'}
              </div>
            )}
            <label className="text-xs text-ink-muted block mb-2">Revocation Reason (RFC 5280)</label>
            <select
              value={revokeReason}
              onChange={e => setRevokeReason(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink mb-4"
            >
              {REVOCATION_REASONS.map(r => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
            <div className="flex justify-end gap-3">
              <button onClick={() => { setShowRevoke(false); setRevokeReason('unspecified'); }} className="btn btn-ghost text-sm">
                Cancel
              </button>
              <button
                onClick={() => revokeMutation.mutate()}
                disabled={revokeMutation.isPending}
                className="btn text-sm bg-red-600 hover:bg-red-500 text-white disabled:opacity-50"
              >
                {revokeMutation.isPending ? 'Revoking...' : 'Revoke Certificate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
