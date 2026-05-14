import { Fragment, useState } from 'react';
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
import Timestamp from '../../components/Timestamp';
import ErrorState from '../../components/ErrorState';
import { STALE_TIME } from '../../api/queryConstants';

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
//     field-level before/after diff via PayloadPreview).
//
// Same-actor self-approve is rejected server-side with HTTP 403; the
// page surfaces the error inline. Approve / reject actions are HIDDEN
// when the caller's actor_id equals requested_by, so the operator
// can't even click the wrong button.
//
// Audit 2026-05-11 A-5 — payload preview. The MED-10 closure claim
// said the GUI rendered a "raw JSON preview" but the verifier found
// zero payload rendering — approvers had to click Approve blind. This
// page now renders an inline expandable panel per row that dispatches
// to one of three components by `kind`:
//
//   - kind=profile_edit → ProfileEditDiff: field-level before/after
//     table. The whole point of the four-eyes principle is "the
//     approver sees what's changing"; rendering this as a flat field
//     diff is materially more useful than a unified line-diff for the
//     small flat-object profile shape.
//   - kind=cert_issuance → IssuanceRequestPreview: CN / SANs /
//     profile / key algo / must-staple / validity. Catches the
//     wildcard-against-corp-internal-profile attack at review time.
//   - any other kind → generic JSON <pre>. Forward-compat for
//     future approval kinds added to migration 000033's enum.
//
// The payload arrives as a base64-encoded JSON string (Go json-encodes
// []byte to base64 by default; see internal/domain/approval.go:41).
// decodePayload() handles the decode + parse + null/error guard.
// =============================================================================

// decodePayload base64-decodes the wire payload and JSON-parses the
// result. Returns the parsed shape or null on any failure (empty
// payload, malformed base64, malformed JSON). The component layer
// renders the generic fallback in that case so the approver still
// sees *something* — silent failure on the payload preview defeats
// the entire fix.
//
// Exported for test reach.
export function decodePayload(payload: string | undefined): unknown {
  if (!payload) return null;
  try {
    // atob throws on invalid base64; the surrounding try/catch falls
    // through to null which the caller renders as "Unable to decode
    // payload" in the generic branch.
    const decoded = atob(payload);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

// =============================================================================
// PayloadPreview — kind dispatch.
// =============================================================================

function PayloadPreview({ kind, payload }: { kind: string; payload: string | undefined }) {
  const decoded = decodePayload(payload);

  if (decoded === null && payload) {
    return (
      <div
        className="text-xs text-red-700"
        data-testid="approval-payload-decode-error"
      >
        Unable to decode payload (base64 / JSON parse failed). Raw value:{' '}
        <code className="break-all">{payload}</code>
      </div>
    );
  }

  if (decoded === null) {
    return (
      <div
        className="text-xs text-ink-muted italic"
        data-testid="approval-payload-empty"
      >
        No payload attached.
      </div>
    );
  }

  if (kind === 'profile_edit') {
    return <ProfileEditDiff payload={decoded} />;
  }
  if (kind === 'cert_issuance') {
    return <IssuanceRequestPreview payload={decoded} />;
  }
  // Forward-compat fallback for future kinds.
  return (
    <pre
      className="text-xs bg-surface-muted p-3 rounded overflow-x-auto"
      data-testid="approval-payload-generic-json"
    >
      {JSON.stringify(decoded, null, 2)}
    </pre>
  );
}

// =============================================================================
// ProfileEditDiff — field-level before/after table.
// =============================================================================

function ProfileEditDiff({ payload }: { payload: unknown }) {
  const envelope = payload as { before?: Record<string, unknown>; after?: Record<string, unknown> };
  const before = envelope?.before ?? {};
  const after = envelope?.after ?? {};
  const allKeys = Array.from(new Set([...Object.keys(before), ...Object.keys(after)])).sort();
  const changedKeys = allKeys.filter(k => JSON.stringify(before[k]) !== JSON.stringify(after[k]));

  if (changedKeys.length === 0) {
    return (
      <div
        className="text-xs text-ink-muted italic"
        data-testid="approval-profile-edit-no-changes"
      >
        No field changes detected.
      </div>
    );
  }
  return (
    <table
      className="text-xs w-full border border-surface-border"
      data-testid="approval-profile-edit-diff"
    >
      <thead className="bg-surface-muted">
        <tr>
          <th className="text-left px-2 py-1 font-medium">Field</th>
          <th className="text-left px-2 py-1 font-medium">Before</th>
          <th className="text-left px-2 py-1 font-medium">After</th>
        </tr>
      </thead>
      <tbody>
        {changedKeys.map(k => (
          <tr
            key={k}
            className="border-t border-surface-border"
            data-testid={`approval-profile-edit-row-${k}`}
          >
            <td className="px-2 py-1 font-mono"><code>{k}</code></td>
            <td className="px-2 py-1 font-mono break-all bg-red-50">
              {renderValue(before[k])}
            </td>
            <td className="px-2 py-1 font-mono break-all bg-green-50">
              {renderValue(after[k])}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// renderValue stringifies a payload value for the diff cells. Renders
// undefined as a visually distinct "(unset)" sentinel so the approver
// can tell a field was added (before=unset) vs flipped (before=value).
function renderValue(v: unknown) {
  if (v === undefined) {
    return <span className="text-ink-muted italic">(unset)</span>;
  }
  return JSON.stringify(v);
}

// =============================================================================
// IssuanceRequestPreview — definition list of the load-bearing fields.
// =============================================================================

function IssuanceRequestPreview({ payload }: { payload: unknown }) {
  const p = payload as {
    subject_common_name?: string;
    common_name?: string;
    sans?: string[];
    profile_id?: string;
    key_algorithm?: string;
    must_staple?: boolean;
    validity_days?: number;
    requester_actor_id?: string;
  };
  // The certificate-service issuance request uses `subject_common_name`
  // on some paths and `common_name` on others; surface either.
  const cn = p.subject_common_name ?? p.common_name ?? '—';
  return (
    <dl
      className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs"
      data-testid="approval-cert-issuance-preview"
    >
      <dt className="text-ink-muted">Common Name</dt>
      <dd className="font-mono">{cn}</dd>
      <dt className="text-ink-muted">SANs</dt>
      <dd className="font-mono">{(p.sans ?? []).join(', ') || '—'}</dd>
      <dt className="text-ink-muted">Profile</dt>
      <dd className="font-mono">{p.profile_id ?? '—'}</dd>
      <dt className="text-ink-muted">Key algorithm</dt>
      <dd className="font-mono">{p.key_algorithm ?? '—'}</dd>
      <dt className="text-ink-muted">Must-staple</dt>
      <dd>{p.must_staple === undefined ? '—' : p.must_staple ? 'yes' : 'no'}</dd>
      <dt className="text-ink-muted">Validity (days)</dt>
      <dd>{p.validity_days ?? '—'}</dd>
      {p.requester_actor_id && (
        <>
          <dt className="text-ink-muted">Requester (payload-claimed)</dt>
          <dd className="font-mono">{p.requester_actor_id}</dd>
        </>
      )}
    </dl>
  );
}

export default function ApprovalsPage() {
  const me = useAuthMe();
  const qc = useQueryClient();
  const [filterState, setFilterState] = useState<ApprovalState>('pending');

  const query = useQuery({
    queryKey: ['approvals', filterState],
    queryFn: () => listApprovals(filterState),
    staleTime: STALE_TIME.REAL_TIME,   // approval queue — operator-facing
    refetchInterval: 30_000,
  });

  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // Audit 2026-05-11 A-5 — per-row payload preview expansion.
  // Single-string state (rather than a Set) because most operators
  // only inspect one approval at a time; widening to multi-select
  // is a trivial future change if the workflow demands it.
  const [expandedID, setExpandedID] = useState<string | null>(null);

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
                <th className="px-3 py-2 w-24">Payload</th>
                <th className="px-3 py-2 w-44"></th>
              </tr>
            </thead>
            <tbody>
              {items.map(req => {
                const isMine = req.requested_by === myID;
                const isPending = req.state === 'pending';
                const isExpanded = expandedID === req.id;
                return (
                  <Fragment key={req.id}>
                    <tr
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
                        <Timestamp iso={req.created_at} />
                      </td>
                      <td className="px-3 py-2">
                        {/* Audit 2026-05-11 A-5 — payload preview toggle.
                            Always rendered (even when payload is empty)
                            so the approver can verify there ISN'T a
                            payload they might have missed. */}
                        <button
                          className="btn btn-ghost text-xs"
                          onClick={() => setExpandedID(isExpanded ? null : req.id)}
                          data-testid={`approvals-preview-toggle-${req.id}`}
                          aria-expanded={isExpanded}
                        >
                          {isExpanded ? 'Hide' : 'Preview'}
                        </button>
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
                    {isExpanded && (
                      <tr
                        className="border-t border-surface-border bg-surface-muted/40"
                        data-testid={`approvals-payload-preview-${req.id}`}
                      >
                        <td colSpan={7} className="px-3 py-3">
                          <PayloadPreview kind={req.kind} payload={req.payload} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
