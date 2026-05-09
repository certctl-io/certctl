import { useQuery } from '@tanstack/react-query';
import { authBootstrapAvailable } from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';

// =============================================================================
// Bundle 1 Phase 10 — AuthSettingsPage (stub).
//
// Surfaces:
//
//   - The current actor's identity, roles, effective permissions
//     (from /v1/auth/me — already cached by useAuthMe).
//   - Bootstrap-endpoint availability so a fresh-deploy operator
//     knows whether they can mint the first admin via curl. Shows
//     "available" pre-admin, "closed" after the first admin lands.
//
// Bundle 2 will extend this page with OIDC provider config + session
// management. Bundle 1 ships only the stub so the route exists and
// the navigation entry is wired.
// =============================================================================

export default function AuthSettingsPage() {
  const me = useAuthMe();
  const bootstrapQuery = useQuery({
    queryKey: ['auth', 'bootstrap', 'available'],
    queryFn: authBootstrapAvailable,
    staleTime: 60_000,
    retry: 0,
  });

  return (
    <div className="space-y-4" data-testid="auth-settings-page">
      <PageHeader
        title="Auth settings"
        subtitle="Bundle 1 RBAC — your identity + bootstrap status. Bundle 2 will add OIDC provider config + session management here."
      />

      <section className="bg-surface border border-surface-border rounded">
        <header className="px-4 py-3 border-b border-surface-border">
          <div className="text-sm font-semibold">Current identity</div>
          <div className="text-xs text-ink-muted">From /api/v1/auth/me</div>
        </header>
        <div className="px-4 py-3 text-sm space-y-2" data-testid="auth-settings-identity">
          {me.isLoading && <div className="text-ink-muted">Loading…</div>}
          {me.error && <div className="text-red-700">{me.error.message}</div>}
          {me.data && (
            <>
              <div>
                <span className="text-ink-muted">Actor:</span>{' '}
                <span className="font-mono">{me.data.actor_id}</span>{' '}
                <span className="text-xs text-ink-muted">({me.data.actor_type})</span>
              </div>
              <div>
                <span className="text-ink-muted">Tenant:</span>{' '}
                <span className="font-mono">{me.data.tenant_id}</span>
              </div>
              <div>
                <span className="text-ink-muted">Admin:</span>{' '}
                <span data-testid="auth-settings-admin">{me.data.admin ? 'yes' : 'no'}</span>
              </div>
              <div>
                <span className="text-ink-muted">Roles:</span>{' '}
                <span data-testid="auth-settings-roles">{me.data.roles.join(', ') || '(none)'}</span>
              </div>
              <div>
                <span className="text-ink-muted">Effective permissions:</span>{' '}
                <span data-testid="auth-settings-permcount">{me.data.effective_permissions.length}</span>
              </div>
              {me.data.effective_permissions.length > 0 && (
                <details className="text-xs">
                  <summary className="cursor-pointer text-ink-muted">Show permission list</summary>
                  <ul className="mt-2 ml-4 list-disc">
                    {me.data.effective_permissions.map((p, i) => (
                      <li key={i} className="font-mono">
                        {p.permission} @ {p.scope_type}
                        {p.scope_id ? ` (${p.scope_id})` : ''}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </>
          )}
        </div>
      </section>

      <section className="bg-surface border border-surface-border rounded">
        <header className="px-4 py-3 border-b border-surface-border">
          <div className="text-sm font-semibold">Bootstrap endpoint</div>
          <div className="text-xs text-ink-muted">Bundle 1 Phase 6 — mints the first admin API key when no admin exists yet.</div>
        </header>
        <div className="px-4 py-3 text-sm space-y-2" data-testid="auth-settings-bootstrap">
          {bootstrapQuery.isLoading && <div className="text-ink-muted">Probing…</div>}
          {bootstrapQuery.error && (
            <div className="text-red-700 text-xs">Could not reach /v1/auth/bootstrap: {bootstrapQuery.error.message}</div>
          )}
          {bootstrapQuery.data && (
            <>
              <div>
                <span className="text-ink-muted">Status:</span>{' '}
                <span
                  className={
                    bootstrapQuery.data.available ? 'text-amber-700 font-semibold' : 'text-ink'
                  }
                  data-testid="auth-settings-bootstrap-status"
                >
                  {bootstrapQuery.data.available ? 'OPEN — first-admin path callable' : 'closed'}
                </span>
              </div>
              {bootstrapQuery.data.available && (
                <div className="text-xs text-amber-700">
                  Run: <code className="font-mono">curl -X POST $URL/api/v1/auth/bootstrap -d &apos;{'{'}&quot;token&quot;:&quot;…&quot;,&quot;actor_name&quot;:&quot;first-admin&quot;{'}'}&apos;</code> to mint the first admin key.
                </div>
              )}
              {!bootstrapQuery.data.available && (
                <div className="text-xs text-ink-muted">
                  Either CERTCTL_BOOTSTRAP_TOKEN is unset, an admin already exists, or the strategy was already consumed.
                </div>
              )}
            </>
          )}
        </div>
      </section>
    </div>
  );
}
