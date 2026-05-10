import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  listApprovals,
  approveApproval,
  rejectApproval,
  type ApprovalRequest,
  type ApprovalState,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';

// =============================================================================
// Bundle 1 Phase 9 + Phase 10 — Approvals queue.
//
// Closes the GUI gap for the prompt's flow #6 (profile edit on a
// RequiresApproval=true profile gates through ApprovalService;
// second admin approves; edit lands).
//
// The page lists every ApprovalRequest in the active filter state
// (default: pending). Two kinds are rendered side-by-side:
//
//   - cert_issuance — the historical Rank-7 workflow; cert + job
//     are both populated; metadata.common_name surfaces.
//   - profile_edit — Bundle 1 Phase 9 closure; cert + job are empty,
//     payload carries the pending profile diff (rendered as a
//     collapsible JSON preview).
//
// Same-actor self-approve is rejected server-side with HTTP 403; the
// page surfaces the error inline. Approve / reject actions are HIDDEN
// when the caller's actor_id equals requested_by, so the operator
// can't even click the wrong button.
// =============================================================================

export default function ApprovalsPage() {
  const me = useAuthMe();
  const qc = useQueryClient();
  const [filterState, setFilterState] = useState<ApprovalState>('pending');

  const query = useQuery({
    queryKey: ['approvals', filterState],
    queryFn: () => listApprovals(filterState),
    staleTime: 15_000,
    refetchInterval: 30_000,
  });

  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const handleApprove = async (req: ApprovalRequest) => {
    const note = window.prompt('Approval note (optional):') ?? '';
    setBusy(req.id);
    setActionError(null);
    try {
      await approveApproval(req.id, note);
      qc.invalidateQueries({ queryKey: ['approvals'] });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleReject = async (req: ApprovalRequest) => {
    const note = window.prompt('Reason for rejection:') ?? '';
    if (!note) return;
    setBusy(req.id);
    setActionError(null);
    try {
      await rejectApproval(req.id, note);
      qc.invalidateQueries({ queryKey: ['approvals'] });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  if (query.isLoading) return <PageHeader title="Approvals" subtitle="Loading…" />;
  if (query.error) {
    return (
      <div className="space-y-4">
        <PageHeader title="Approvals" />
        <ErrorState
          error={query.error as Error}
          onRetry={() => qc.invalidateQueries({ queryKey: ['approvals'] })}
        />
      </div>
    );
  }

  const items = query.data?.data ?? [];
  const myID = me.data?.actor_id ?? '';

  return (
    <div className="space-y-4" data-testid="approvals-page">
      <PageHeader
        title="Approvals queue"
        subtitle="Two-person integrity / four-eyes principle. The requester cannot self-approve — same-actor approvals are rejected server-side."
        action={
          <select
            value={filterState}
            onChange={e => setFilterState(e.target.value as ApprovalState)}
            className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm"
            data-testid="approvals-state-filter"
          >
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
            <option value="expired">Expired</option>
          </select>
        }
      />
      {actionError && (
        <div
          className="bg-red-50 border border-red-200 text-red-700 text-sm p-3 rounded"
          data-testid="approvals-action-error"
        >
          {actionError}
        </div>
      )}
      {items.length === 0 ? (
        <div
          className="bg-surface border border-surface-border rounded p-8 text-center text-sm text-ink-muted"
          data-testid="approvals-empty"
        >
          No {filterState} approvals.
        </div>
      ) : (
        <div className="bg-surface border border-surface-border rounded">
          <table className="w-full text-sm" data-testid="approvals-table">
            <thead className="bg-surface-muted text-xs uppercase tracking-wide text-ink-muted">
              <tr>
                <th className="text-left px-3 py-2">ID</th>
                <th className="text-left px-3 py-2">Kind</th>
                <th className="text-left px-3 py-2">Profile</th>
                <th className="text-left px-3 py-2">Requested by</th>
                <th className="text-left px-3 py-2">Created</th>
                <th className="px-3 py-2 w-44"></th>
              </tr>
            </thead>
            <tbody>
              {items.map(req => {
                const isMine = req.requested_by === myID;
                const isPending = req.state === 'pending';
                return (
                  <tr
                    key={req.id}
                    className="border-t border-surface-border align-top"
                    data-testid={`approvals-row-${req.id}`}
                  >
                    <td className="px-3 py-2 font-mono text-xs">{req.id}</td>
                    <td className="px-3 py-2">
                      <span
                        className={
                          'inline-block px-2 py-0.5 rounded text-xs ' +
                          (req.kind === 'profile_edit'
                            ? 'bg-amber-100 text-amber-800'
                            : 'bg-surface-muted')
                        }
                      >
                        {req.kind}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{req.profile_id}</td>
                    <td className="px-3 py-2 text-xs">
                      {req.requested_by}
                      {isMine && <span className="ml-2 text-amber-700">(you)</span>}
                    </td>
                    <td className="px-3 py-2 text-xs text-ink-muted">
                      {new Date(req.created_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-right">
                      {isPending && !isMine && (
                        <div className="flex gap-1 justify-end">
                          <button
                            className="btn btn-primary text-xs"
                            onClick={() => handleApprove(req)}
                            disabled={busy === req.id}
                            data-testid={`approvals-approve-${req.id}`}
                          >
                            Approve
                          </button>
                          <button
                            className="btn btn-ghost text-xs"
                            onClick={() => handleReject(req)}
                            disabled={busy === req.id}
                            data-testid={`approvals-reject-${req.id}`}
                          >
                            Reject
                          </button>
                        </div>
                      )}
                      {isPending && isMine && (
                        <span
                          className="text-xs text-ink-muted italic"
                          data-testid={`approvals-self-locked-${req.id}`}
                        >
                          self-approve blocked
                        </span>
                      )}
                      {!isPending && (
                        <span className="text-xs text-ink-muted">{req.state}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
