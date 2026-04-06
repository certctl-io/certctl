import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getJob, getJobVerification, getAuditEvents } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime, timeAgo } from '../api/utils';

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-2 border-b border-surface-border/50">
      <span className="text-sm text-ink-muted">{label}</span>
      <span className="text-sm text-ink">{value}</span>
    </div>
  );
}

function VerificationBadge({ status }: { status?: string }) {
  if (!status) return <span className="text-xs text-ink-faint">—</span>;
  const styles: Record<string, string> = {
    success: 'bg-emerald-100 text-emerald-700',
    failed: 'bg-red-100 text-red-700',
    pending: 'bg-yellow-100 text-yellow-700',
    skipped: 'bg-gray-100 text-gray-600',
  };
  const labels: Record<string, string> = {
    success: 'Verified',
    failed: 'Failed',
    pending: 'Pending',
    skipped: 'Skipped',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${styles[status] || 'bg-gray-100 text-gray-600'}`}>
      {labels[status] || status}
    </span>
  );
}

export default function JobDetailPage() {
  const { id } = useParams<{ id: string }>();

  const { data: job, isLoading, error, refetch } = useQuery({
    queryKey: ['job', id],
    queryFn: () => getJob(id!),
    enabled: !!id,
    refetchInterval: 10000,
  });

  const { data: verification } = useQuery({
    queryKey: ['job-verification', id],
    queryFn: () => getJobVerification(id!),
    enabled: !!id && job?.type === 'Deployment' && job?.status === 'Completed',
    retry: false,
  });

  const { data: auditData } = useQuery({
    queryKey: ['audit', { resource_id: id }],
    queryFn: () => getAuditEvents({ resource_id: id!, per_page: '10' }),
    enabled: !!id,
  });

  if (error) {
    return (
      <>
        <PageHeader title="Job Details" />
        <ErrorState error={error as Error} onRetry={() => refetch()} />
      </>
    );
  }

  if (isLoading || !job) {
    return (
      <>
        <PageHeader title="Job Details" />
        <div className="flex items-center justify-center py-20">
          <div className="text-sm text-ink-muted">Loading job...</div>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={`Job ${job.id}`}
        subtitle={`${job.type} job`}
      />

      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Job details */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Job Information</h3>
            <InfoRow label="ID" value={<span className="font-mono text-xs">{job.id}</span>} />
            <InfoRow label="Type" value={job.type} />
            <InfoRow label="Status" value={<StatusBadge status={job.status} />} />
            <InfoRow label="Certificate" value={
              <Link to={`/certificates/${job.certificate_id}`} className="text-xs text-accent hover:text-accent-bright font-mono">
                {job.certificate_id}
              </Link>
            } />
            {job.agent_id && (
              <InfoRow label="Agent" value={
                <Link to={`/agents/${job.agent_id}`} className="text-xs text-accent hover:text-accent-bright font-mono">
                  {job.agent_id}
                </Link>
              } />
            )}
            {job.target_id && (
              <InfoRow label="Target" value={
                <Link to={`/targets/${job.target_id}`} className="text-xs text-accent hover:text-accent-bright font-mono">
                  {job.target_id}
                </Link>
              } />
            )}
            <InfoRow label="Attempts" value={`${job.attempts} / ${job.max_attempts}`} />
            {job.last_error && (
              <InfoRow label="Error" value={
                <span className="text-red-600 text-xs">{job.last_error}</span>
              } />
            )}
          </div>

          {/* Timeline */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Timeline</h3>
            <InfoRow label="Created" value={formatDateTime(job.created_at)} />
            <InfoRow label="Scheduled" value={formatDateTime(job.scheduled_at)} />
            {job.started_at && <InfoRow label="Started" value={formatDateTime(job.started_at)} />}
            {job.completed_at && <InfoRow label="Completed" value={formatDateTime(job.completed_at)} />}
            {job.completed_at && job.started_at && (
              <InfoRow label="Duration" value={timeAgo(job.started_at)} />
            )}
          </div>
        </div>

        {/* Verification section — only for deployment jobs */}
        {job.type === 'Deployment' && (
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Post-Deployment Verification</h3>
            {job.verification_status ? (
              <div className="space-y-0">
                <InfoRow label="Status" value={<VerificationBadge status={job.verification_status} />} />
                {job.verified_at && <InfoRow label="Verified At" value={formatDateTime(job.verified_at)} />}
                {job.verification_fingerprint && (
                  <InfoRow label="Fingerprint" value={<span className="font-mono text-xs">{job.verification_fingerprint}</span>} />
                )}
                {job.verification_error && (
                  <InfoRow label="Error" value={<span className="text-red-600 text-xs">{job.verification_error}</span>} />
                )}
                {verification && verification.verified && (
                  <InfoRow label="Expected Fingerprint" value={<span className="font-mono text-xs">{verification.expected_fingerprint}</span>} />
                )}
              </div>
            ) : (
              <div className="text-sm text-ink-faint py-4 text-center">
                {job.status === 'Completed' ? 'No verification data recorded' : 'Verification runs after deployment completes'}
              </div>
            )}
          </div>
        )}

        {/* Audit trail */}
        {auditData && auditData.data.length > 0 && (
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Related Audit Events</h3>
            <div className="space-y-2">
              {auditData.data.map(event => (
                <div key={event.id} className="flex items-center justify-between py-2 border-b border-surface-border/50 last:border-0">
                  <div>
                    <span className="text-sm text-ink">{event.action}</span>
                    <span className="text-xs text-ink-faint ml-2">by {event.actor}</span>
                  </div>
                  <span className="text-xs text-ink-muted">{formatDateTime(event.timestamp)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
