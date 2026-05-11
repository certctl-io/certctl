import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { authListUsers, authDeactivateUser, type AuthUser } from '../../api/client';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';

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
    staleTime: 30_000,
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

  return (
    <div>
      <PageHeader title="Federated Users" subtitle="One row per (oidc_provider_id, oidc_subject) tuple." />
      <div style={{ marginBottom: 16 }}>
        <label style={{ marginRight: 8 }}>Filter by provider:</label>
        <input
          type="text"
          placeholder="op-keycloak (leave empty for all)"
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
          style={{ width: 280, padding: 4 }}
        />
      </div>
      {err && <ErrorState message={err} />}
      {usersQuery.isLoading && <p>Loading users…</p>}
      {usersQuery.error && <ErrorState message={usersQuery.error.message} />}
      {usersQuery.data && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #ccc', textAlign: 'left' }}>
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
                <tr key={u.id} style={{ borderBottom: '1px solid #eee', opacity: deactivated ? 0.5 : 1 }}>
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
                        style={{ padding: '4px 12px' }}
                      >
                        {pending === u.id ? 'Deactivating…' : 'Deactivate'}
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {usersQuery.data.length === 0 && (
              <tr><td colSpan={7} style={{ padding: 12, textAlign: 'center' }}>No users matching filter.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}
