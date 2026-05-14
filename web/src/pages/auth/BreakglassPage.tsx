import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../../hooks/useTrackedMutation';
import {
  breakglassListCredentials,
  breakglassSetPassword,
  breakglassUnlock,
  breakglassRemove,
  type BreakglassCredentialRow,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import Timestamp from '../../components/Timestamp';
import ErrorState from '../../components/ErrorState';

// =============================================================================
// BreakglassPage — Audit 2026-05-10 CRIT-4 closure.
//
// Admin GUI for the break-glass admin path. Lists credentialed actors,
// supports password rotation, unlock, and credential removal. Every
// action is auditing-heavy by design — break-glass is the deliberate
// SSO-bypass path, intended for use during SSO incidents only.
//
// Route: /auth/breakglass
// Permission: auth.breakglass.admin
//
// Backend:
//   GET    /api/v1/auth/breakglass/credentials                     (list)
//   POST   /api/v1/auth/breakglass/credentials                     (set/rotate password)
//   POST   /api/v1/auth/breakglass/credentials/{actor_id}/unlock   (unlock after lockout)
//   DELETE /api/v1/auth/breakglass/credentials/{actor_id}          (remove credential)
//
// Surface invisibility: every backend endpoint returns 404 when
// CERTCTL_BREAKGLASS_ENABLED=false; the page renders a "disabled"
// banner in that case (the list query 404s and we treat that as the
// disabled-on-server signal).
// =============================================================================

export default function BreakglassPage() {
  const { isLoading: meLoading, hasPerm } = useAuthMe();

  // Permission gate. If meLoading, render nothing (avoid flicker).
  const canAdmin = hasPerm('auth.breakglass.admin');

  const {
    data: rows,
    isLoading,
    error: loadErr,
  } = useQuery({
    queryKey: ['breakglass', 'credentials'],
    queryFn: () => breakglassListCredentials(),
    enabled: canAdmin,
    retry: false,
  });

  const setPwd = useTrackedMutation({
    mutationFn: ({ actorID, password }: { actorID: string; password: string }) =>
      breakglassSetPassword(actorID, password),
    invalidates: [['breakglass']],
  });
  const unlock = useTrackedMutation({
    mutationFn: (actorID: string) => breakglassUnlock(actorID),
    invalidates: [['breakglass']],
  });
  const remove = useTrackedMutation({
    mutationFn: (actorID: string) => breakglassRemove(actorID),
    invalidates: [['breakglass']],
  });

  // Modal state.
  const [pwdModalActorID, setPwdModalActorID] = useState<string | null>(null);
  const [removeModalActorID, setRemoveModalActorID] = useState<string | null>(null);
  // New-credential row form state (separate from rotation modal).
  const [newActorID, setNewActorID] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('');
  const [newFormError, setNewFormError] = useState<string | null>(null);

  if (meLoading) return null;

  if (!canAdmin) {
    return (
      <div className="p-6">
        <PageHeader title="Break-glass" subtitle="Admin-only SSO-bypass recovery path" />
        <ErrorState
          title="Forbidden"
          message="You need auth.breakglass.admin to view this page."
        />
      </div>
    );
  }

  // 404 from the list endpoint == server has CERTCTL_BREAKGLASS_ENABLED=false.
  const disabledOnServer =
    loadErr instanceof Error && /not enabled|404|disabled/i.test(loadErr.message);

  return (
    <div className="p-6 max-w-5xl">
      <PageHeader
        title="Break-glass admin"
        subtitle="SSO-bypass recovery path — every action audited. Use only during SSO incidents."
      />

      <div
        className="bg-amber-50 border border-amber-200 rounded p-4 mb-6 text-sm text-amber-900"
        data-testid="breakglass-banner"
      >
        <strong>Security note.</strong> Break-glass credentials bypass your IdP entirely. Set
        the password under <code className="bg-amber-100 px-1 rounded">CERTCTL_BREAKGLASS_ENABLED=true</code> only when SSO
        is broken; remove the credential once SSO recovers. Every action here is recorded in the audit log under the
        <code className="bg-amber-100 px-1 rounded">auth</code> category.
      </div>

      {disabledOnServer && (
        <ErrorState
          title="Break-glass disabled on server"
          message="The server is running with CERTCTL_BREAKGLASS_ENABLED=false. Set it to true on the certctl-server process to enable this surface."
          data-testid="breakglass-disabled-banner"
        />
      )}

      {!disabledOnServer && (
        <>
          {/* Create-new-credential form */}
          <section className="bg-surface border border-surface-border rounded p-6 mb-6">
            <h2 className="text-base font-semibold text-ink mb-3">Set or rotate password</h2>
            <form
              onSubmit={async e => {
                e.preventDefault();
                setNewFormError(null);
                if (newPassword !== newPasswordConfirm) {
                  setNewFormError('Passwords do not match.');
                  return;
                }
                if (newPassword.length < 12) {
                  setNewFormError('Password must be at least 12 characters.');
                  return;
                }
                try {
                  await setPwd.mutateAsync({ actorID: newActorID.trim(), password: newPassword });
                  setNewActorID('');
                  setNewPassword('');
                  setNewPasswordConfirm('');
                } catch (err) {
                  setNewFormError(err instanceof Error ? err.message : 'Could not set password.');
                }
              }}
              className="space-y-3"
              data-testid="breakglass-new-form"
            >
              <div>
                <label className="block text-xs font-medium text-ink-muted mb-1">Actor ID</label>
                <input
                  type="text"
                  value={newActorID}
                  onChange={e => setNewActorID(e.target.value)}
                  placeholder="actor-..."
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm focus:outline-none focus:border-brand-400"
                  data-testid="breakglass-new-actor-id"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-ink-muted mb-1">Password</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    autoComplete="new-password"
                    className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm focus:outline-none focus:border-brand-400"
                    data-testid="breakglass-new-password"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-ink-muted mb-1">Confirm password</label>
                  <input
                    type="password"
                    value={newPasswordConfirm}
                    onChange={e => setNewPasswordConfirm(e.target.value)}
                    autoComplete="new-password"
                    className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm focus:outline-none focus:border-brand-400"
                    data-testid="breakglass-new-password-confirm"
                  />
                </div>
              </div>
              {newFormError && (
                <div
                  className="bg-red-50 border border-red-200 rounded px-3 py-2 text-xs text-red-700"
                  data-testid="breakglass-new-error"
                >
                  {newFormError}
                </div>
              )}
              <button
                type="submit"
                disabled={!newActorID.trim() || !newPassword || setPwd.isPending}
                className="bg-brand-400 hover:bg-brand-500 text-white px-4 py-2 text-sm font-medium rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                data-testid="breakglass-new-submit"
              >
                {setPwd.isPending ? 'Setting…' : 'Set password'}
              </button>
            </form>
          </section>

          {/* Credential list */}
          <section className="bg-surface border border-surface-border rounded p-6">
            <h2 className="text-base font-semibold text-ink mb-3">Credentialed actors</h2>
            {isLoading ? (
              <p className="text-sm text-ink-muted">Loading…</p>
            ) : !rows || rows.length === 0 ? (
              <p className="text-sm text-ink-muted">No break-glass credentials configured.</p>
            ) : (
              <table className="w-full text-sm" data-testid="breakglass-credentials-table">
                <thead>
                  <tr className="border-b border-surface-border">
                    <th className="text-left py-2 font-medium text-ink-muted">Actor</th>
                    <th className="text-left py-2 font-medium text-ink-muted">Last password change</th>
                    <th className="text-left py-2 font-medium text-ink-muted">Failures</th>
                    <th className="text-left py-2 font-medium text-ink-muted">Locked until</th>
                    <th className="text-right py-2 font-medium text-ink-muted">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row: BreakglassCredentialRow) => {
                    const isLocked = row.locked_until && new Date(row.locked_until) > new Date();
                    return (
                      <tr
                        key={row.actor_id}
                        className="border-b border-surface-border last:border-0"
                        data-testid={`breakglass-row-${row.actor_id}`}
                      >
                        <td className="py-3 font-mono text-xs">{row.actor_id}</td>
                        <td className="py-3 text-xs text-ink-muted">
                          <Timestamp iso={row.last_password_change_at} />
                        </td>
                        <td className="py-3 text-xs">
                          {row.failure_count > 0 ? (
                            <span className="text-red-700 font-medium">{row.failure_count}</span>
                          ) : (
                            <span className="text-ink-muted">0</span>
                          )}
                        </td>
                        <td className="py-3 text-xs text-ink-muted">
                          {isLocked ? (
                            <span className="text-red-700">
                              <Timestamp iso={row.locked_until!} />
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="py-3 text-right space-x-2">
                          <button
                            onClick={() => setPwdModalActorID(row.actor_id)}
                            className="text-xs text-brand-400 hover:underline"
                            data-testid={`breakglass-rotate-${row.actor_id}`}
                          >
                            Rotate
                          </button>
                          <button
                            onClick={() => unlock.mutate(row.actor_id)}
                            disabled={!isLocked || unlock.isPending}
                            className="text-xs text-amber-700 hover:underline disabled:opacity-30 disabled:no-underline disabled:cursor-not-allowed"
                            data-testid={`breakglass-unlock-${row.actor_id}`}
                          >
                            Unlock
                          </button>
                          <button
                            onClick={() => setRemoveModalActorID(row.actor_id)}
                            className="text-xs text-red-700 hover:underline"
                            data-testid={`breakglass-remove-${row.actor_id}`}
                          >
                            Remove
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}

      {/* Rotate-password modal */}
      {pwdModalActorID && (
        <RotatePasswordModal
          actorID={pwdModalActorID}
          onClose={() => setPwdModalActorID(null)}
          onSubmit={async pwd => {
            await setPwd.mutateAsync({ actorID: pwdModalActorID, password: pwd });
            setPwdModalActorID(null);
          }}
        />
      )}

      {/* Remove-credential confirmation modal */}
      {removeModalActorID && (
        <RemoveCredentialModal
          actorID={removeModalActorID}
          onClose={() => setRemoveModalActorID(null)}
          onConfirm={async () => {
            await remove.mutateAsync(removeModalActorID);
            setRemoveModalActorID(null);
          }}
        />
      )}
    </div>
  );
}

function RotatePasswordModal({
  actorID,
  onClose,
  onSubmit,
}: {
  actorID: string;
  onClose: () => void;
  onSubmit: (pwd: string) => Promise<void>;
}) {
  const [pwd, setPwd] = useState('');
  const [pwdConfirm, setPwdConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      data-testid="breakglass-rotate-modal"
    >
      <div className="bg-surface rounded-lg p-6 max-w-md w-full shadow-xl">
        <h3 className="text-lg font-semibold mb-2">Rotate password for {actorID}</h3>
        <p className="text-xs text-ink-muted mb-4">
          This revokes every active session for the target actor after the password is rotated.
        </p>
        <form
          onSubmit={async e => {
            e.preventDefault();
            setError(null);
            if (pwd !== pwdConfirm) {
              setError('Passwords do not match.');
              return;
            }
            if (pwd.length < 12) {
              setError('Password must be at least 12 characters.');
              return;
            }
            setSubmitting(true);
            try {
              await onSubmit(pwd);
            } catch (err) {
              setError(err instanceof Error ? err.message : 'Rotation failed.');
              setSubmitting(false);
            }
          }}
          className="space-y-3"
        >
          <input
            type="password"
            value={pwd}
            onChange={e => setPwd(e.target.value)}
            autoComplete="new-password"
            placeholder="New password (≥12 chars)"
            className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm focus:outline-none focus:border-brand-400"
            data-testid="breakglass-rotate-password"
          />
          <input
            type="password"
            value={pwdConfirm}
            onChange={e => setPwdConfirm(e.target.value)}
            autoComplete="new-password"
            placeholder="Confirm password"
            className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm focus:outline-none focus:border-brand-400"
            data-testid="breakglass-rotate-password-confirm"
          />
          {error && (
            <div className="bg-red-50 border border-red-200 rounded px-3 py-2 text-xs text-red-700">
              {error}
            </div>
          )}
          <div className="flex gap-2 justify-end pt-2">
            <button type="button" onClick={onClose} className="px-3 py-2 text-sm">
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !pwd || !pwdConfirm}
              className="bg-brand-400 hover:bg-brand-500 text-white px-4 py-2 text-sm font-medium rounded disabled:opacity-50"
              data-testid="breakglass-rotate-submit"
            >
              {submitting ? 'Rotating…' : 'Rotate'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function RemoveCredentialModal({
  actorID,
  onClose,
  onConfirm,
}: {
  actorID: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}) {
  const [confirmText, setConfirmText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const matched = confirmText === actorID;

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      data-testid="breakglass-remove-modal"
    >
      <div className="bg-surface rounded-lg p-6 max-w-md w-full shadow-xl">
        <h3 className="text-lg font-semibold mb-2 text-red-700">Remove break-glass credential</h3>
        <p className="text-sm text-ink-muted mb-4">
          This deletes the break-glass credential for{' '}
          <code className="bg-page px-1 rounded text-xs">{actorID}</code>. The actor will not be
          able to use the break-glass login path until a new password is set.
        </p>
        <p className="text-xs text-ink-muted mb-2">Type the actor ID to confirm:</p>
        <input
          type="text"
          value={confirmText}
          onChange={e => setConfirmText(e.target.value)}
          placeholder={actorID}
          className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm mb-4 focus:outline-none focus:border-red-400"
          data-testid="breakglass-remove-confirm-input"
        />
        <div className="flex gap-2 justify-end">
          <button type="button" onClick={onClose} className="px-3 py-2 text-sm">
            Cancel
          </button>
          <button
            type="button"
            disabled={!matched || submitting}
            onClick={async () => {
              setSubmitting(true);
              await onConfirm();
            }}
            className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 text-sm font-medium rounded disabled:opacity-50 disabled:cursor-not-allowed"
            data-testid="breakglass-remove-confirm-submit"
          >
            {submitting ? 'Removing…' : 'Remove credential'}
          </button>
        </div>
      </div>
    </div>
  );
}
