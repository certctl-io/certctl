import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { authListUsers, authDeactivateUser, authReactivateUser, type AuthUser } from '../../api/client';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';
import { STALE_TIME } from '../../api/queryConstants';

// =============================================================================
// Audit 2026-05-10 MED-11 closure — Federated-user admin GUI.
//
// Lists every federated identity in the active tenant (one row per
// (oidc_provider_id, oidc_subject) tuple) with last-login + OIDC
// binding visible. Admins can soft-delete a user via the Deactivate
// button — server-side sets `deactivated_at` and cascade-revokes
// active sessions in the same operation. The row is the OIDC binding
// so destroying it would re-mint a fresh user on next login under the
// same subject (losing the audit trail); deactivation preserves
// forensics.
// =============================================================================

export default function UsersPage() {
  const qc = useQueryClient();
  const [providerFilter, setProviderFilter] = useState('');
  const [pending, setPending] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const usersQuery = useQuery<AuthUser[], Error>({
    queryKey: ['auth', 'users', providerFilter],
    queryFn: () => authListUsers(providerFilter || undefined),
    staleTime: STALE_TIME.REAL_TIME,   // operator-facing user list
  });

  async function deactivate(u: AuthUser) {
    if (!confirm(`Deactivate user ${u.email} (${u.id})?\n\n` +
      `This sets deactivated_at on the row and revokes every active session.\n` +
      `The row is preserved (audit trail) — a future login under the same OIDC subject will fail.`)) {
      return;
    }
    setPending(u.id);
    setErr(null);
    try {
      await authDeactivateUser(u.id);
      await qc.invalidateQueries({ queryKey: ['auth', 'users'] });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(null);
    }
  }

  // Audit 2026-05-11 A-2 — Reactivate inverse. Clears deactivated_at;
  // the next OIDC login under the same (provider, subject) tuple
  // proceeds normally. Sessions revoked at deactivation stay revoked
  // (the cascade is irreversible by design — the user must complete
  // a fresh login).
  async function reactivate(u: AuthUser) {
    if (!confirm(`Reactivate user ${u.email} (${u.id})?\n\n` +
      `This clears deactivated_at. The user can OIDC-login again. ` +
      `Previously-revoked sessions stay revoked.`)) {
      return;
    }
    setPending(u.id);
    setErr(null);
    try {
      await authReactivateUser(u.id);
      await qc.invalidateQueries({ queryKey: ['auth', 'users'] });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(null);
    }
  }

  return (
    <div>
      <PageHeader title="Federated Users" subtitle="One row per (oidc_provider_id, oidc_subject) tuple." />
      {/* FE-M6 closure 2026-05-14: migrated 9 inline-style attrs in this
          page to Tailwind utility classes. Pre-closure these were the
          single biggest concentration of style={...} in production tsx.
          Closes the "static styles in inline-attr position" half of
          FE-M6; load-bearing dynamic styles (Tooltip Floating-UI, chart
          color props, computed widths) remain inline by necessity. */}
      <div className="mb-4">
        <label className="mr-2">Filter by provider:</label>
        <input
          type="text"
          placeholder="op-keycloak (leave empty for all)"
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
          className="w-[280px] p-1"
        />
      </div>
      {err && <ErrorState message={err} />}
      {usersQuery.isLoading && <p>Loading users…</p>}
      {usersQuery.error && <ErrorState message={usersQuery.error.message} />}
      {usersQuery.data && (
        <table className="w-full border-collapse">
          <thead>
            <tr className="border-b-2 border-gray-300 text-left">
              <th>ID</th>
              <th>Email</th>
              <th>Display Name</th>
              <th>Provider</th>
              <th>Last Login</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {usersQuery.data.map((u) => {
              const deactivated = Boolean(u.deactivated_at);
              return (
                <tr
                  key={u.id}
                  className={
                    'border-b border-gray-200 ' +
                    (deactivated ? 'opacity-50' : 'opacity-100')
                  }
                >
                  <td><code>{u.id}</code></td>
                  <td>{u.email}</td>
                  <td>{u.display_name}</td>
                  <td><code>{u.oidc_provider_id}</code></td>
                  <td>{u.last_login_at}</td>
                  <td>{deactivated ? `Deactivated ${u.deactivated_at}` : 'Active'}</td>
                  <td>
                    {!deactivated && (
                      <button
                        onClick={() => deactivate(u)}
                        disabled={pending === u.id}
                        className="px-3 py-1"
                      >
                        {pending === u.id ? 'Deactivating…' : 'Deactivate'}
                      </button>
                    )}
                    {deactivated && (
                      <button
                        onClick={() => reactivate(u)}
                        disabled={pending === u.id}
                        className="px-3 py-1"
                      >
                        {pending === u.id ? 'Reactivating…' : 'Reactivate'}
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {usersQuery.data.length === 0 && (
              <tr><td colSpan={7} className="p-3 text-center">No users matching filter.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}
