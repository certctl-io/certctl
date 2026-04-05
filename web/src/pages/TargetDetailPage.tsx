import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getTarget, getJobs, updateTarget, testTargetConnection } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Job } from '../api/types';

const typeLabels: Record<string, string> = {
  NGINX: 'NGINX',
  Apache: 'Apache',
  HAProxy: 'HAProxy',
  Traefik: 'Traefik',
  Caddy: 'Caddy',
  F5: 'F5 BIG-IP',
  IIS: 'IIS',
  Envoy: 'Envoy',
  Postfix: 'Postfix',
  Dovecot: 'Dovecot',
  SSH: 'SSH',
};

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-2 border-b border-surface-border/50">
      <span className="text-sm text-ink-muted">{label}</span>
      <span className="text-sm text-ink">{value}</span>
    </div>
  );
}

function TestStatusIndicator({ status, testedAt }: { status?: string; testedAt?: string }) {
  if (!status || status === 'untested') {
    return <span className="text-xs text-ink-faint">Not tested</span>;
  }
  const styles: Record<string, string> = {
    success: 'bg-emerald-100 text-emerald-700',
    failed: 'bg-red-100 text-red-700',
  };
  const labels: Record<string, string> = {
    success: 'Connected',
    failed: 'Failed',
  };
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${styles[status] || 'bg-gray-100 text-gray-600'}`}>
        {labels[status] || status}
      </span>
      {testedAt && <span className="text-xs text-ink-faint">{formatDateTime(testedAt)}</span>}
    </span>
  );
}

function SourceBadge({ source }: { source?: string }) {
  if (!source || source === 'database') {
    return <span className="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 font-medium">GUI</span>;
  }
  if (source === 'env') {
    return <span className="text-xs px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 font-medium">Env Var</span>;
  }
  return <span className="text-xs text-ink-faint">{source}</span>;
}

export default function TargetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [isEditing, setIsEditing] = useState(false);
  const [editName, setEditName] = useState('');

  const updateMutation = useMutation({
    mutationFn: (data: Partial<{ name: string }>) => updateTarget(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['target', id] });
      setIsEditing(false);
    },
  });

  const testMutation = useMutation({
    mutationFn: () => testTargetConnection(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['target', id] });
    },
  });

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
        action={
          <div className="flex gap-2">
            <button
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending}
              className="px-3 py-1.5 border border-surface-border rounded text-ink text-xs hover:bg-surface-hover transition-colors font-medium disabled:opacity-50"
            >
              {testMutation.isPending ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              onClick={() => {
                setEditName(target.name);
                setIsEditing(true);
              }}
              className="px-3 py-1.5 border border-surface-border rounded text-ink text-xs hover:bg-surface-hover transition-colors font-medium"
            >
              Edit
            </button>
          </div>
        }
      />

      {/* Test connection result banner */}
      {testMutation.isSuccess && (
        <div className="mx-6 mt-2 p-3 bg-emerald-50 border border-emerald-200 rounded text-sm text-emerald-700">
          Agent connection test passed — agent is online and responsive.
        </div>
      )}
      {testMutation.isError && (
        <div className="mx-6 mt-2 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">
          Connection test failed: {(testMutation.error as Error).message}
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Target info */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Target Information</h3>
            <InfoRow label="ID" value={<span className="font-mono text-xs">{target.id}</span>} />
            <InfoRow label="Name" value={target.name} />
            <InfoRow label="Type" value={typeLabels[target.type] || target.type} />
            <InfoRow label="Enabled" value={<StatusBadge status={target.enabled ? 'Enabled' : 'Disabled'} />} />
            <InfoRow label="Source" value={<SourceBadge source={target.source} />} />
            <InfoRow label="Test Status" value={<TestStatusIndicator status={target.test_status} testedAt={target.last_tested_at} />} />
            {target.agent_id && (
              <InfoRow label="Agent" value={
                <Link to={`/agents/${target.agent_id}`} className="text-xs text-accent hover:text-accent-bright font-mono">
                  {target.agent_id}
                </Link>
              } />
            )}
            <InfoRow label="Created" value={formatDateTime(target.created_at)} />
            {target.updated_at && <InfoRow label="Updated" value={formatDateTime(target.updated_at)} />}
          </div>

          {/* Config */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Configuration</h3>
            {target.config && Object.keys(target.config).length > 0 ? (
              <div className="space-y-0">
                {Object.entries(target.config).map(([key, val]) => {
                  const sensitiveKeys = ['password', 'secret', 'token', 'key', 'winrm_password'];
                  const isSensitive = sensitiveKeys.some(s => key.toLowerCase().includes(s));
                  const displayVal = isSensitive && val ? '********' : String(val);
                  return (
                    <InfoRow key={key} label={key.replace(/_/g, ' ')} value={
                      <span className="font-mono text-xs truncate max-w-xs inline-block">{displayVal}</span>
                    } />
                  );
                })}
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

      {/* Edit Modal */}
      {isEditing && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setIsEditing(false)}>
          <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-ink mb-4">Edit Target</h2>
            {updateMutation.isError && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">
                {(updateMutation.error as Error).message}
              </div>
            )}
            <form onSubmit={e => { e.preventDefault(); updateMutation.mutate({ name: editName }); }} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Name</label>
                <input value={editName} onChange={e => setEditName(e.target.value)} className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
              </div>
              <div className="flex gap-2 pt-2">
                <button type="submit" disabled={updateMutation.isPending} className="flex-1 btn btn-primary disabled:opacity-50">
                  {updateMutation.isPending ? 'Saving...' : 'Save'}
                </button>
                <button type="button" onClick={() => setIsEditing(false)} className="flex-1 btn btn-ghost">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
