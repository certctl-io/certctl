import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getJobs, cancelJob, approveRenewal, rejectRenewal } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Job } from '../api/types';

function RejectModal({ job, onClose, onReject }: { job: Job; onClose: () => void; onReject: (reason: string) => void }) {
  const [reason, setReason] = useState('');
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-surface-border">
          <h3 className="text-lg font-semibold text-ink">Reject Job</h3>
          <p className="text-sm text-ink-muted mt-1">
            Rejecting job <span className="font-mono text-xs">{job.id}</span> for certificate <span className="font-mono text-xs">{job.certificate_id}</span>
          </p>
        </div>
        <div className="px-6 py-4">
          <label className="block text-sm font-medium text-ink mb-1">Reason</label>
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Why is this renewal being rejected?"
            className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            rows={3}
          />
        </div>
        <div className="px-6 py-3 border-t border-surface-border flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-sm text-ink-muted hover:text-ink rounded border border-surface-border">
            Cancel
          </button>
          <button
            onClick={() => onReject(reason)}
            disabled={!reason.trim()}
            className="px-4 py-2 text-sm text-white bg-red-600 hover:bg-red-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Reject
          </button>
        </div>
      </div>
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

export default function JobsPage() {
  const [statusFilter, setStatusFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [rejectingJob, setRejectingJob] = useState<Job | null>(null);
  const queryClient = useQueryClient();

  const params: Record<string, string> = {};
  if (statusFilter) params.status = statusFilter;
  if (typeFilter) params.type = typeFilter;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['jobs', params],
    queryFn: () => getJobs(params),
    refetchInterval: 10000,
  });

  const cancelMutation = useMutation({
    mutationFn: cancelJob,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['jobs'] }),
  });

  const approveMutation = useMutation({
    mutationFn: approveRenewal,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['jobs'] }),
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => rejectRenewal(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      setRejectingJob(null);
    },
  });

  const awaitingCount = data?.data?.filter(j => j.status === 'AwaitingApproval').length || 0;

  const columns: Column<Job>[] = [
    {
      key: 'id',
      label: 'Job',
      render: (j) => (
        <div>
          <Link to={`/jobs/${j.id}`} className="font-mono text-xs text-accent hover:text-accent-bright" onClick={(e) => e.stopPropagation()}>
            {j.id}
          </Link>
          <div className="text-xs text-ink-faint">{j.type}</div>
        </div>
      ),
    },
    { key: 'status', label: 'Status', render: (j) => <StatusBadge status={j.status} /> },
    { key: 'cert', label: 'Certificate', render: (j) => <span className="text-xs text-ink-muted font-mono">{j.certificate_id}</span> },
    {
      key: 'agent',
      label: 'Agent',
      render: (j) => j.agent_id ? (
        <Link to={`/agents/${j.agent_id}`} className="text-xs text-accent hover:text-accent-bright font-mono" onClick={(e) => e.stopPropagation()}>
          {j.agent_id}
        </Link>
      ) : (
        <span className="text-xs text-ink-faint">—</span>
      ),
    },
    {
      key: 'attempts',
      label: 'Attempts',
      render: (j) => <span className="text-ink-muted">{j.attempts}/{j.max_attempts}</span>,
    },
    { key: 'scheduled', label: 'Scheduled', render: (j) => <span className="text-xs text-ink-muted">{formatDateTime(j.scheduled_at)}</span> },
    { key: 'completed', label: 'Completed', render: (j) => <span className="text-xs text-ink-muted">{formatDateTime(j.completed_at)}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (j) => j.type === 'Deployment' ? <VerificationBadge status={j.verification_status} /> : <span className="text-xs text-ink-faint">—</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (j) => (
        <div className="flex gap-2">
          {j.status === 'AwaitingApproval' && (
            <>
              <button
                onClick={(e) => { e.stopPropagation(); approveMutation.mutate(j.id); }}
                disabled={approveMutation.isPending}
                className="text-xs text-green-600 hover:text-green-700 font-medium"
              >
                Approve
              </button>
              <button
                onClick={(e) => { e.stopPropagation(); setRejectingJob(j); }}
                className="text-xs text-red-500 hover:text-red-600 font-medium"
              >
                Reject
              </button>
            </>
          )}
          {(j.status === 'Pending' || j.status === 'Running') && (
            <button
              onClick={(e) => { e.stopPropagation(); cancelMutation.mutate(j.id); }}
              className="text-xs text-red-400 hover:text-red-300"
            >
              Cancel
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Jobs" subtitle={data ? `${data.total} jobs` : undefined} />

      {/* Pending approval banner */}
      {awaitingCount > 0 && (
        <div className="mx-6 mt-3 px-4 py-2.5 bg-amber-50 border border-amber-200 rounded-lg flex items-center gap-2">
          <svg className="w-4 h-4 text-amber-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          <span className="text-sm text-amber-800">
            <strong>{awaitingCount}</strong> job{awaitingCount !== 1 ? 's' : ''} awaiting approval
          </span>
          {statusFilter !== 'AwaitingApproval' && (
            <button
              onClick={() => setStatusFilter('AwaitingApproval')}
              className="text-xs text-amber-700 hover:text-amber-900 underline ml-1"
            >
              Show only
            </button>
          )}
        </div>
      )}

      <div className="px-6 py-3 flex gap-3 border-b border-surface-border/50">
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All statuses</option>
          <option value="Pending">Pending</option>
          <option value="AwaitingApproval">Awaiting Approval</option>
          <option value="AwaitingCSR">Awaiting CSR</option>
          <option value="Running">Running</option>
          <option value="Completed">Completed</option>
          <option value="Failed">Failed</option>
          <option value="Cancelled">Cancelled</option>
        </select>
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All types</option>
          <option value="Renewal">Renewal</option>
          <option value="Issuance">Issuance</option>
          <option value="Deployment">Deployment</option>
          <option value="Validation">Validation</option>
        </select>
      </div>
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No jobs found" />
        )}
      </div>

      {rejectingJob && (
        <RejectModal
          job={rejectingJob}
          onClose={() => setRejectingJob(null)}
          onReject={(reason) => rejectMutation.mutate({ id: rejectingJob.id, reason })}
        />
      )}
    </>
  );
}
