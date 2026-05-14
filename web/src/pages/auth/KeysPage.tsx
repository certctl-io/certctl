import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import {
  authListKeys,
  authListRoles,
  authAssignKeyRole,
  authRevokeKeyRole,
  type AuthKeyEntry,
  type AuthRole,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';
import ConfirmDialog from '../../components/ConfirmDialog';
import { STALE_TIME } from '../../api/queryConstants';

// =============================================================================
// Bundle 1 Phase 10 — KeysPage.
//
// Lists every actor in the active tenant with at least one role grant
// (the GET /v1/auth/keys surface added in Phase 7). Operators use this
// page to audit key→role assignments and to grant / revoke roles in
// place of running `certctl auth keys scope-down`. The synthetic
// actor-demo-anon row is shown but flagged "system-managed" with
// disabled actions; the server-side reserved-actor guard rejects
// mutations regardless.
// =============================================================================

const DEMO_ANON = 'actor-demo-anon';

export default function KeysPage() {
  const me = useAuthMe();
  const qc = useQueryClient();

  const keysQuery = useQuery<AuthKeyEntry[], Error>({
    queryKey: ['auth', 'keys'],
    queryFn: authListKeys,
    staleTime: STALE_TIME.REAL_TIME,   // operator-facing live data
  });
  const rolesQuery = useQuery<AuthRole[], Error>({
    queryKey: ['auth', 'roles'],
    queryFn: authListRoles,
    staleTime: STALE_TIME.REFERENCE,   // role catalogue, slow-changing
  });

  const [assignTarget, setAssignTarget] = useState<AuthKeyEntry | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // UX-H2 closure — replace window.confirm() with ConfirmDialog.
  const [confirmRevoke, setConfirmRevoke] = useState<
    { entry: AuthKeyEntry; roleID: string } | null
  >(null);

  const canAssign = me.hasPerm('auth.role.assign') || me.isAdmin();
  const canRevoke = me.hasPerm('auth.role.assign') || me.isAdmin();

  const handleRevoke = (entry: AuthKeyEntry, roleID: string) => {
    if (entry.actor_id === DEMO_ANON) return;
    setConfirmRevoke({ entry, roleID });
  };

  const performRevoke = async () => {
    if (!confirmRevoke) return;
    const { entry, roleID } = confirmRevoke;
    setConfirmRevoke(null);
    setBusy(true);
    setActionError(null);
    try {
      await authRevokeKeyRole(entry.actor_id, roleID);
      toast.success(`Revoked ${roleID} from ${entry.actor_id}`);
      qc.invalidateQueries({ queryKey: ['auth', 'keys'] });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setActionError(msg);
      toast.error(`Revoke failed: ${msg}`);
    } finally {
      setBusy(false);
    }
  };

  if (keysQuery.isLoading) return <PageHeader title="API keys" subtitle="Loading…" />;
  if (keysQuery.error) {
    return (
      <div className="space-y-4">
        <PageHeader title="API keys" />
        <ErrorState
          error={keysQuery.error}
          onRetry={() => qc.invalidateQueries({ queryKey: ['auth', 'keys'] })}
        />
      </div>
    );
  }

  const keys = keysQuery.data ?? [];

  return (
    <div className="space-y-4" data-testid="keys-page">
      <PageHeader
        title="API keys"
        subtitle="Every API key in the active tenant. Bundle 1 backfills existing keys to r-admin; use scope-down (CLI) or per-row revoke + assign here to narrow."
      />
      {actionError && (
        <div
          className="bg-red-50 border border-red-200 text-red-700 text-sm p-3 rounded"
          data-testid="keys-action-error"
        >
          {actionError}
        </div>
      )}
      {keys.length === 0 ? (
        <div
          className="bg-surface border border-surface-border rounded p-8 text-center text-sm text-ink-muted"
          data-testid="keys-empty"
        >
          No API keys with role grants yet. Configure CERTCTL_API_KEYS_NAMED or run the bootstrap flow to mint one.
        </div>
      ) : (
        <div className="bg-surface border border-surface-border rounded">
          <table className="w-full text-sm" data-testid="keys-table">
            <thead className="bg-surface-muted text-xs uppercase tracking-wide text-ink-muted">
              <tr>
                <th className="text-left px-3 py-2">Actor</th>
                <th className="text-left px-3 py-2">Type</th>
                <th className="text-left px-3 py-2">Roles</th>
                <th className="px-3 py-2 w-32"></th>
              </tr>
            </thead>
            <tbody>
              {keys.map(k => {
                const isDemo = k.actor_id === DEMO_ANON;
                return (
                  <tr key={k.actor_id} className="border-t border-surface-border align-top">
                    <td className="px-3 py-2 font-mono text-xs">
                      {k.actor_id}
                      {isDemo && <span className="ml-2 text-ink-faint">(system-managed)</span>}
                    </td>
                    <td className="px-3 py-2 text-xs">{k.actor_type}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {k.role_ids.map(r => (
                          <span
                            key={r}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-muted text-xs"
                            data-testid={`keys-role-tag-${k.actor_id}-${r}`}
                          >
                            {r}
                            {canRevoke && !isDemo && (
                              <button
                                className="text-ink-muted hover:text-red-700"
                                onClick={() => handleRevoke(k, r)}
                                disabled={busy}
                                data-testid={`keys-revoke-${k.actor_id}-${r}`}
                                title={`Revoke ${r}`}
                              >
                                ×
                              </button>
                            )}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-right">
                      {canAssign && !isDemo && (
                        <button
                          className="btn btn-ghost text-xs"
                          onClick={() => setAssignTarget(k)}
                          data-testid={`keys-assign-${k.actor_id}`}
                        >
                          Assign role
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {assignTarget && (
        <AssignRoleModal
          actor={assignTarget}
          roles={rolesQuery.data ?? []}
          onClose={() => setAssignTarget(null)}
          onSuccess={() => {
            setAssignTarget(null);
            qc.invalidateQueries({ queryKey: ['auth', 'keys'] });
          }}
        />
      )}
      <ConfirmDialog
        open={confirmRevoke !== null}
        title="Revoke role grant"
        message={
          confirmRevoke
            ? `Revoke ${confirmRevoke.roleID} from ${confirmRevoke.entry.actor_id}? The actor will lose every permission scoped to that role on the next request.`
            : ''
        }
        confirmLabel="Revoke"
        destructive
        onConfirm={performRevoke}
        onCancel={() => setConfirmRevoke(null)}
      />
    </div>
  );
}

interface AssignProps {
  actor: AuthKeyEntry;
  roles: AuthRole[];
  onClose: () => void;
  onSuccess: () => void;
}

function AssignRoleModal({ actor, roles, onClose, onSuccess }: AssignProps) {
  const [roleID, setRoleID] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Audit 2026-05-10 HIGH-10 GUI half — scope + expiry inputs.
  const [scopeType, setScopeType] = useState<'global' | 'profile' | 'issuer'>('global');
  const [scopeID, setScopeID] = useState('');
  const [expiresAt, setExpiresAt] = useState(''); // <input type="datetime-local"> value

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleID) return;
    if (scopeType !== 'global' && !scopeID.trim()) {
      setError(`scope_id is required when scope_type is ${scopeType}`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // datetime-local emits "YYYY-MM-DDTHH:MM"; promote to RFC3339 by
      // appending :00Z (UTC). Operators wanting a non-UTC expiry can
      // submit via curl; the GUI keeps the UX simple.
      const expiry = expiresAt ? `${expiresAt}:00Z` : undefined;
      await authAssignKeyRole(actor.actor_id, roleID, {
        scope_type: scopeType,
        scope_id: scopeType === 'global' ? undefined : scopeID.trim(),
        expires_at: expiry,
      });
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl"
        onClick={e => e.stopPropagation()}
        data-testid="assign-role-modal"
      >
        <h2 className="text-lg font-semibold mb-4">Assign role to {actor.actor_id}</h2>
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>
        )}
        <form onSubmit={submit} className="space-y-4">
          <select
            value={roleID}
            onChange={e => setRoleID(e.target.value)}
            className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
            required
            data-testid="assign-role-select"
          >
            <option value="">Select a role…</option>
            {roles
              .filter(r => !actor.role_ids.includes(r.id))
              .map(r => (
                <option key={r.id} value={r.id}>
                  {r.name} ({r.id})
                </option>
              ))}
          </select>
          {/* Audit 2026-05-10 HIGH-10 GUI half — scope picker. */}
          <div>
            <label className="block text-xs text-ink-muted mb-1">Scope</label>
            <select
              value={scopeType}
              onChange={(e) => setScopeType(e.target.value as 'global' | 'profile' | 'issuer')}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
              data-testid="assign-role-scope-type"
            >
              <option value="global">Global (no scope)</option>
              <option value="profile">Per profile</option>
              <option value="issuer">Per issuer</option>
            </select>
          </div>
          {scopeType !== 'global' && (
            <div>
              <label className="block text-xs text-ink-muted mb-1">
                Scope ID ({scopeType})
              </label>
              <input
                type="text"
                value={scopeID}
                onChange={(e) => setScopeID(e.target.value)}
                placeholder={scopeType === 'profile' ? 'p-acme-corp' : 'iss-internal-pki'}
                className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
                data-testid="assign-role-scope-id"
                required
              />
            </div>
          )}
          {/* Audit 2026-05-10 HIGH-10 GUI half — expiry input. */}
          <div>
            <label className="block text-xs text-ink-muted mb-1">
              Expires at (optional; UTC)
            </label>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
              data-testid="assign-role-expires-at"
            />
          </div>
          <div className="flex gap-2 pt-2">
            <button
              type="submit"
              disabled={busy || !roleID}
              className="flex-1 btn btn-primary disabled:opacity-50"
              data-testid="assign-role-submit"
            >
              {busy ? 'Assigning…' : 'Assign'}
            </button>
            <button type="button" onClick={onClose} className="flex-1 btn btn-ghost" data-testid="assign-role-cancel">
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
