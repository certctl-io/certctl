import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getCertificate, getCertificateVersions, triggerRenewal, triggerDeployment, archiveCertificate, revokeCertificate, getTargets } from '../api/client';
import { REVOCATION_REASONS } from '../api/types';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDate, formatDateTime, daysUntil, expiryColor } from '../api/utils';

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-2 border-b border-slate-700/50">
      <span className="text-sm text-slate-400">{label}</span>
      <span className="text-sm text-slate-200">{value}</span>
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
              onClick={() => setShowDeploy(true)}
              disabled={isArchived || isRevoked}
              className="btn btn-ghost text-xs border border-slate-600 disabled:opacity-50"
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
          <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg px-4 py-3 text-sm">
            Renewal triggered successfully. A renewal job has been created.
          </div>
        )}
        {renewMutation.isError && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-4 py-3 text-sm">
            Failed to trigger renewal: {renewMutation.error instanceof Error ? renewMutation.error.message : 'Unknown error'}
          </div>
        )}
        {deployMutation.isSuccess && (
          <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg px-4 py-3 text-sm">
            Deployment triggered. A deployment job has been created.
          </div>
        )}
        {deployMutation.isError && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-4 py-3 text-sm">
            Failed to deploy: {deployMutation.error instanceof Error ? deployMutation.error.message : 'Unknown error'}
          </div>
        )}
        {archiveMutation.isError && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-4 py-3 text-sm">
            Failed to archive: {archiveMutation.error instanceof Error ? archiveMutation.error.message : 'Unknown error'}
          </div>
        )}
        {revokeMutation.isSuccess && (
          <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-lg px-4 py-3 text-sm">
            Certificate revoked successfully. It has been added to the CRL.
          </div>
        )}
        {revokeMutation.isError && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-4 py-3 text-sm">
            Failed to revoke: {revokeMutation.error instanceof Error ? revokeMutation.error.message : 'Unknown error'}
          </div>
        )}

        {/* Revocation Banner */}
        {isRevoked && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              </div>
              <div>
                <div className="text-sm font-medium text-red-400">Certificate Revoked</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Reason: {REVOCATION_REASONS.find(r => r.value === cert.revocation_reason)?.label || cert.revocation_reason || 'Unspecified'}
                  {cert.revoked_at && <> &middot; Revoked {formatDateTime(cert.revoked_at)}</>}
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Certificate Info */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Certificate Details</h3>
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
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Lifecycle</h3>
            <InfoRow label="Issued" value={formatDate(cert.issued_at)} />
            <InfoRow label="Expires" value={
              <span className={isRevoked ? 'text-red-400 line-through' : expiryColor(days)}>
                {formatDate(cert.expires_at)} ({days <= 0 ? 'expired' : `${days} days`})
              </span>
            } />
            <InfoRow label="Environment" value={cert.environment || '—'} />
            <InfoRow label="Issuer" value={cert.issuer_id} />
            <InfoRow label="Profile" value={cert.certificate_profile_id || '—'} />
            <InfoRow label="Renewal Policy" value={cert.renewal_policy_id || '—'} />
            <InfoRow label="Owner" value={cert.owner_id} />
            <InfoRow label="Team" value={cert.team_id} />
            {isRevoked && (
              <>
                <InfoRow label="Revoked At" value={
                  <span className="text-red-400">{cert.revoked_at ? formatDateTime(cert.revoked_at) : '—'}</span>
                } />
                <InfoRow label="Revocation Reason" value={
                  <span className="text-red-400">
                    {REVOCATION_REASONS.find(r => r.value === cert.revocation_reason)?.label || cert.revocation_reason || '—'}
                  </span>
                } />
              </>
            )}
            <InfoRow label="Created" value={formatDateTime(cert.created_at)} />
            <InfoRow label="Updated" value={formatDateTime(cert.updated_at)} />
          </div>
        </div>

        {/* Tags */}
        {cert.tags && Object.keys(cert.tags).length > 0 && (
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Tags</h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(cert.tags).map(([k, v]) => (
                <span key={k} className="badge badge-neutral">{k}: {v}</span>
              ))}
            </div>
          </div>
        )}

        {/* Version History */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">
            Version History {versions?.data?.length ? `(${versions.data.length})` : ''}
          </h3>
          {!versions?.data?.length ? (
            <p className="text-sm text-slate-500">No versions yet</p>
          ) : (
            <div className="space-y-3">
              {versions.data.map((v) => (
                <div key={v.id} className="flex items-center justify-between py-2 border-b border-slate-700/50 last:border-0">
                  <div>
                    <div className="text-sm text-slate-200">Version {v.version}</div>
                    <div className="text-xs text-slate-500 font-mono">{v.serial_number}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm text-slate-300">{formatDate(v.not_before)} — {formatDate(v.not_after)}</div>
                    <div className="text-xs text-slate-500">{formatDateTime(v.created_at)}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Deploy Modal */}
      {showDeploy && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowDeploy(false)}>
          <div className="bg-slate-800 border border-slate-600 rounded-xl p-6 w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-slate-200 mb-4">Deploy Certificate</h2>
            {deployMutation.isError && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-3 py-2 text-sm mb-3">
                {deployMutation.error instanceof Error ? deployMutation.error.message : 'Unknown error'}
              </div>
            )}
            <label className="text-xs text-slate-400 block mb-2">Select Target</label>
            <select
              value={deployTargetId}
              onChange={e => setDeployTargetId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 mb-4"
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

      {/* Revoke Modal */}
      {showRevoke && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowRevoke(false)}>
          <div className="bg-slate-800 border border-slate-600 rounded-xl p-6 w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-red-400 mb-2">Revoke Certificate</h2>
            <p className="text-sm text-slate-400 mb-4">
              This action cannot be undone. The certificate will be added to the CRL and marked as revoked.
            </p>
            {revokeMutation.isError && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-3 py-2 text-sm mb-3">
                {revokeMutation.error instanceof Error ? revokeMutation.error.message : 'Unknown error'}
              </div>
            )}
            <label className="text-xs text-slate-400 block mb-2">Revocation Reason (RFC 5280)</label>
            <select
              value={revokeReason}
              onChange={e => setRevokeReason(e.target.value)}
              className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 mb-4"
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
