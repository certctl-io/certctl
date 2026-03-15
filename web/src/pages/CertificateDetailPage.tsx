import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getCertificate, getCertificateVersions, triggerRenewal } from '../api/client';
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

  const renewMutation = useMutation({
    mutationFn: () => triggerRenewal(id!),
    onSuccess: () => {
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
              onClick={() => renewMutation.mutate()}
              disabled={renewMutation.isPending || cert.status === 'Archived' || cert.status === 'RenewalInProgress'}
              className="btn btn-primary text-xs disabled:opacity-50"
            >
              {renewMutation.isPending ? 'Renewing...' : 'Trigger Renewal'}
            </button>
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
            Failed to trigger renewal: {(renewMutation.error as Error).message}
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
              <span className={expiryColor(days)}>
                {formatDate(cert.expires_at)} ({days <= 0 ? 'expired' : `${days} days`})
              </span>
            } />
            <InfoRow label="Environment" value={cert.environment || '—'} />
            <InfoRow label="Issuer" value={cert.issuer_id} />
            <InfoRow label="Renewal Policy" value={cert.renewal_policy_id || '—'} />
            <InfoRow label="Owner" value={cert.owner_id} />
            <InfoRow label="Team" value={cert.team_id} />
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
    </>
  );
}
