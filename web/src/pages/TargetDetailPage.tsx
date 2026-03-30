import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getTarget, getJobs } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Job } from '../api/types';

const typeLabels: Record<string, string> = {
  nginx: 'NGINX',
  apache: 'Apache',
  haproxy: 'HAProxy',
  traefik: 'Traefik',
  caddy: 'Caddy',
  f5_bigip: 'F5 BIG-IP',
  iis: 'IIS',
};

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-2 border-b border-surface-border/50">
      <span className="text-sm text-ink-muted">{label}</span>
      <span className="text-sm text-ink">{value}</span>
    </div>
  );
}

export default function TargetDetailPage() {
  const { id } = useParams<{ id: string }>();

  const { data: target, isLoading, error, refetch } = useQuery({
    queryKey: ['target', id],
    queryFn: () => getTarget(id!),
    enabled: !!id,
  });

  // Deployment jobs for this target
  const { data: jobsData } = useQuery({
    queryKey: ['jobs', { target_id: id, type: 'Deployment' }],
    queryFn: () => getJobs({ target_id: id! }),
    enabled: !!id,
  });

  if (error) {
    return (
      <>
        <PageHeader title="Target Details" />
        <ErrorState error={error as Error} onRetry={() => refetch()} />
      </>
    );
  }

  if (isLoading || !target) {
    return (
      <>
        <PageHeader title="Target Details" />
        <div className="flex items-center justify-center py-20">
          <div className="text-sm text-ink-muted">Loading target...</div>
        </div>
      </>
    );
  }

  const jobColumns: Column<Job>[] = [
    {
      key: 'id',
      label: 'Job',
      render: (j) => (
        <Link to={`/jobs/${j.id}`} className="font-mono text-xs text-accent hover:text-accent-bright">
          {j.id}
        </Link>
      ),
    },
    { key: 'status', label: 'Status', render: (j) => <StatusBadge status={j.status} /> },
    { key: 'cert', label: 'Certificate', render: (j) => (
      <Link to={`/certificates/${j.certificate_id}`} className="text-xs text-accent hover:text-accent-bright font-mono">
        {j.certificate_id}
      </Link>
    )},
    { key: 'completed', label: 'Completed', render: (j) => <span className="text-xs text-ink-muted">{formatDateTime(j.completed_at)}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (j) => {
        if (!j.verification_status) return <span className="text-xs text-ink-faint">—</span>;
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
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${styles[j.verification_status] || 'bg-gray-100 text-gray-600'}`}>
            {labels[j.verification_status] || j.verification_status}
          </span>
        );
      },
    },
  ];

  return (
    <>
      <PageHeader
        title={target.name}
        subtitle={typeLabels[target.type] || target.type}
      />

      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Target info */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Target Information</h3>
            <InfoRow label="ID" value={<span className="font-mono text-xs">{target.id}</span>} />
            <InfoRow label="Name" value={target.name} />
            <InfoRow label="Type" value={typeLabels[target.type] || target.type} />
            <InfoRow label="Hostname" value={target.hostname || '—'} />
            <InfoRow label="Status" value={<StatusBadge status={target.status} />} />
            {target.agent_id && (
              <InfoRow label="Agent" value={
                <Link to={`/agents/${target.agent_id}`} className="text-xs text-accent hover:text-accent-bright font-mono">
                  {target.agent_id}
                </Link>
              } />
            )}
            <InfoRow label="Created" value={formatDateTime(target.created_at)} />
          </div>

          {/* Config */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Configuration</h3>
            {target.config && Object.keys(target.config).length > 0 ? (
              <div className="space-y-0">
                {Object.entries(target.config).map(([key, val]) => (
                  <InfoRow key={key} label={key.replace(/_/g, ' ')} value={
                    <span className="font-mono text-xs truncate max-w-xs inline-block">{String(val)}</span>
                  } />
                ))}
              </div>
            ) : (
              <div className="text-sm text-ink-faint py-4 text-center">No configuration data</div>
            )}
          </div>
        </div>

        {/* Deployment history */}
        <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-ink-muted mb-4">
            Deployment History {jobsData ? `(${jobsData.total})` : ''}
          </h3>
          <DataTable
            columns={jobColumns}
            data={jobsData?.data || []}
            isLoading={!jobsData}
            emptyMessage="No deployments to this target"
          />
        </div>
      </div>
    </>
  );
}
