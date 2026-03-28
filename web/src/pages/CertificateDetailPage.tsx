import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getCertificate, getCertificateVersions, triggerRenewal, triggerDeployment, archiveCertificate, revokeCertificate, updateCertificate, getTargets, getJobs, getPolicies, getProfiles, downloadCertificatePEM, exportCertificatePKCS12 } from '../api/client';
import { REVOCATION_REASONS } from '../api/types';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDate, formatDateTime, daysUntil, expiryColor, timeAgo } from '../api/utils';
import type { Job } from '../api/types';

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

function DeploymentTimeline({ certId, certStatus, createdAt, issuedAt }: { certId: string; certStatus: string; createdAt: string; issuedAt: string }) {
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

  return (
    <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
      <h3 className="text-sm font-semibold text-ink-muted mb-4">Lifecycle Timeline</h3>
      <div className="pl-1">
        <TimelineStep label="Requested" status={getRequestedStatus()} time={getRequestedTime()} />
        <TimelineStep label="Issued" status={getIssuedStatus()} time={getIssuedTime()} />
        <TimelineStep label="Deploying" status={getDeployStatus()} time={getDeployTime()} />
        <TimelineStep label={certStatus === 'Revoked' ? 'Revoked' : certStatus === 'Expired' ? 'Expired' : 'Active'}
          status={getActiveStatus()} time={getActiveTime()} isLast />
      </div>
    </div>
  );
}

function InlinePolicyEditor({ certId, currentPolicyId, currentProfileId }: { certId: string; currentPolicyId: string; currentProfileId: string }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [policyId, setPolicyId] = useState(currentPolicyId);
  const [profileId, setProfileId] = useState(currentProfileId);

  const { data: policies } = useQuery({
    queryKey: ['policies'],
    queryFn: () => getPolicies(),
    enabled: editing,
  });

  const { data: profiles } = useQuery({
    queryKey: ['profiles'],
    queryFn: () => getProfiles(),
    enabled: editing,
  });

  const saveMutation = useMutation({
    mutationFn: () => updateCertificate(certId, {
      renewal_policy_id: policyId,
      certificate_profile_id: profileId,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificate', certId] });
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
              <option key={p.id} value={p.id}>{p.name} ({p.type})</option>
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
  const queryClient = useQueryClient();
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

  const renewMutation = useMutation({
    mutationFn: () => triggerRenewal(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificate', id] });
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
    },
  });

  const deployMutation = useMutation({
    mutationFn: () => triggerDeployment(id!, deployTargetId),
    onSuccess: () => {
      setShowDeploy(false);
      setDeployTargetId('');
      queryClient.invalidateQueries({ queryKey: ['certificate', id] });
    },
  });

  const archiveMutation = useMutation({
    mutationFn: () => archiveCertificate(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
      navigate('/certificates');
    },
  });

  const revokeMutation = useMutation({
    mutationFn: () => revokeCertificate(id!, revokeReason),
    onSuccess: () => {
      setShowRevoke(false);
      setRevokeReason('unspecified');
      queryClient.invalidateQueries({ queryKey: ['certificate', id] });
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
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
        <DeploymentTimeline certId={id!} certStatus={cert.status} createdAt={cert.created_at} issuedAt={cert.issued_at} />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Certificate Info */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Certificate Details</h3>
            <InfoRow label="Status" value={<StatusBadge status={cert.status} />} />
            <InfoRow label="Common Name" value={cert.common_name} />
            <InfoRow label="SANs" value={cert.sans?.length ? cert.sans.join(', ') : '—'} />
            <InfoRow label="Serial Number" value={cert.serial_number || '—'} />
            <InfoRow label="Fingerprint" value={
              cert.fingerprint ? <span className="font-mono text-xs">{cert.fingerprint.slice(0, 24)}...</span> : '—'
            } />
            <InfoRow label="Key Algorithm" value={cert.key_algorithm || '—'} />
            <InfoRow label="Key Size" value={cert.key_size ? `${cert.key_size} bits` : '—'} />
          </div>

          {/* Lifecycle */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Lifecycle</h3>
            <InfoRow label="Issued" value={formatDate(cert.issued_at)} />
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
                      <span className="text-sm text-ink">Version {v.version}</span>
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
                <option key={t.id} value={t.id}>{t.name} ({t.type} — {t.hostname})</option>
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
