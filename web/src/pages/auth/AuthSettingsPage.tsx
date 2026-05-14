import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { authBootstrapAvailable, authRuntimeConfig } from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import { STALE_TIME } from '../../api/queryConstants';
import { getTimestampPref, setTimestampPref, type TimestampMode } from '../../api/timestampPref';

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
    staleTime: STALE_TIME.REFERENCE,   // slow-changing auth-runtime data
    retry: 0,
  });
  // Audit 2026-05-10 MED-12 — Auth runtime config panel. Gated
  // auth.role.assign server-side; query failure (403) is silently
  // swallowed (panel hidden) for non-admin viewers.
  const runtimeQuery = useQuery({
    queryKey: ['auth', 'runtime-config'],
    queryFn: authRuntimeConfig,
    staleTime: STALE_TIME.REFERENCE,   // slow-changing auth-runtime data
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

      {/* Audit 2026-05-10 MED-12 — Auth runtime config panel. */}
      {runtimeQuery.data && (
        <section className="bg-surface border border-surface-border rounded" data-testid="auth-settings-runtime-config">
          <header className="px-4 py-3 border-b border-surface-border">
            <div className="text-sm font-semibold">Auth runtime config</div>
            <div className="text-xs text-ink-muted">
              Deployed CERTCTL_* values gated `auth.role.assign`. Sensitive values (tokens,
              secrets, CIDRs) surface as <em>set/unset</em> or counts only — never raw bytes.
            </div>
          </header>
          <div className="px-4 py-3 text-sm">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="text-ink-muted text-left">
                  <th className="py-1 pr-4">Setting</th>
                  <th className="py-1">Value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(runtimeQuery.data)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([k, v]) => (
                    <tr key={k} className="border-t border-surface-border">
                      <td className="py-1 pr-4">{k}</td>
                      <td className="py-1">{v || <span className="text-ink-muted">(empty)</span>}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Phase 6 closure (I18N-H3): operator timestamp-display preference. */}
      <TimestampPreferenceCard />
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────
// Timestamp-display preference (Phase 6 I18N-H3)
// ──────────────────────────────────────────────────────────────────

function TimestampPreferenceCard() {
  const [mode, setMode] = useState<TimestampMode>(() => getTimestampPref().mode);
  const [customTz, setCustomTz] = useState<string>(() => getTimestampPref().customTz);

  function persist(next: { mode: TimestampMode; customTz: string }) {
    setMode(next.mode);
    setCustomTz(next.customTz);
    setTimestampPref(next);
  }

  return (
    <section className="bg-surface border border-surface-border rounded shadow-sm" data-testid="timestamp-pref-card">
      <div className="px-4 py-3 border-b border-surface-border">
        <div className="text-sm font-semibold">Timestamp display</div>
        <div className="text-xs text-ink-muted">
          Default UTC matches the server audit log byte-for-byte. Pick Local for browser time;
          Custom for a specific IANA timezone (e.g. <code>America/New_York</code>).
        </div>
      </div>
      <div className="px-4 py-3 text-sm space-y-3">
        <div className="flex items-center gap-4">
          {(['utc', 'local', 'custom'] as const).map((m) => (
            <label key={m} className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="radio"
                name="timestamp-mode"
                value={m}
                checked={mode === m}
                onChange={() => persist({ mode: m, customTz })}
                data-testid={`timestamp-mode-${m}`}
              />
              <span className="capitalize">{m === 'utc' ? 'UTC' : m}</span>
            </label>
          ))}
        </div>
        {mode === 'custom' && (
          <div>
            <label className="block text-xs font-medium text-ink-muted mb-1">IANA timezone</label>
            <input
              type="text"
              value={customTz}
              onChange={(e) => persist({ mode, customTz: e.target.value })}
              placeholder="America/New_York"
              spellCheck={false}
              className="w-full px-2 py-1 border border-surface-border rounded bg-page text-ink font-mono text-xs"
              data-testid="timestamp-custom-tz-input"
            />
          </div>
        )}
      </div>
    </section>
  );
}
