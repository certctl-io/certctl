import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { listSessions, revokeSession, type SessionInfo } from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';

// =============================================================================
// Bundle 2 Phase 8 — SessionsPage.
//
// Renders the caller's active sessions by default. When the caller
// holds auth.session.list.all, an "All actors" toggle exposes the
// admin view (every active session in the tenant).
//
// Routes:
//   /auth/sessions — admin all-actors view + own sessions toggle.
// API:
//   GET    /api/v1/auth/sessions                   (own; auth.session.list)
//   GET    /api/v1/auth/sessions?actor_id=<other>  (admin; auth.session.list.all)
//   DELETE /api/v1/auth/sessions/{id}              (own bypass + auth.session.revoke)
//
// Permission gating: page itself requires auth.session.list. Switch
// to all-actors view requires auth.session.list.all. Revoke action
// is shown for: (a) the caller's own sessions (own-bypass at the
// handler), AND (b) any session when caller holds auth.session.revoke.
// Server-side enforcement is the load-bearing layer; client-side
// hide is UX.
// =============================================================================

type ViewMode = 'self' | 'all';

export default function SessionsPage() {
  const { data: me, hasPerm } = useAuthMe();
  const queryClient = useQueryClient();

  const canList = hasPerm('auth.session.list');
  const canListAll = hasPerm('auth.session.list.all');
  const canRevokeAny = hasPerm('auth.session.revoke');

  const [view, setView] = useState<ViewMode>('self');
  const [filterActorID, setFilterActorID] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Effective actor_id query param when in admin view.
  const effectiveActorID = view === 'all' ? filterActorID.trim() : '';

  const { data, isLoading, error: loadErr } = useQuery({
    queryKey: ['sessions', view, effectiveActorID],
    queryFn: () =>
      effectiveActorID ? listSessions(effectiveActorID, 'User') : listSessions(),
    enabled: canList,
  });

  if (!canList) {
    return (
      <div className="p-8">
        <PageHeader title="Sessions" subtitle="Active session management" />
        <ErrorState error={new Error('You need the auth.session.list permission to view sessions.')} />
      </div>
    );
  }

  const handleRevoke = async (s: SessionInfo) => {
    if (!window.confirm(`Revoke session ${s.id} for ${s.actor_id}? They will be logged out.`)) return;
    try {
      await revokeSession(s.id);
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const callerActorID = me?.actor_id || '';

  return (
    <div className="p-8 space-y-6">
      <PageHeader title="Sessions" subtitle="Active session management" />

      {error && (
        <div
          className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
          data-testid="sessions-page-error"
        >
          {error}
        </div>
      )}

      <div className="flex gap-2 items-center">
        <button
          onClick={() => setView('self')}
          className={
            view === 'self'
              ? 'px-3 py-1.5 text-sm bg-brand-600 text-white rounded'
              : 'px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink'
          }
          data-testid="sessions-view-self"
        >
          My sessions
        </button>
        {canListAll && (
          <button
            onClick={() => setView('all')}
            className={
              view === 'all'
                ? 'px-3 py-1.5 text-sm bg-brand-600 text-white rounded'
                : 'px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink'
            }
            data-testid="sessions-view-all"
          >
            All actors (admin)
          </button>
        )}
        {view === 'all' && (
          <input
            value={filterActorID}
            onChange={e => setFilterActorID(e.target.value)}
            placeholder="Filter by actor_id (e.g. u-alice)"
            className="ml-2 flex-1 px-2 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
            data-testid="sessions-actor-id-filter"
          />
        )}
      </div>

      {isLoading && (
        <div className="text-sm text-ink-muted" data-testid="sessions-loading">
          Loading sessions…
        </div>
      )}
      {loadErr && <ErrorState error={loadErr instanceof Error ? loadErr : new Error(String(loadErr))} />}

      {data && data.sessions && data.sessions.length === 0 && (
        <div
          className="bg-surface border border-surface-border rounded p-6 text-center"
          data-testid="sessions-empty"
        >
          <p className="text-ink-muted text-sm">No active sessions.</p>
        </div>
      )}

      {data && data.sessions && data.sessions.length > 0 && (
        <div className="bg-surface border border-surface-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-page border-b border-surface-border">
              <tr>
                <th className="text-left px-4 py-2 font-medium text-ink">Session ID</th>
                <th className="text-left px-4 py-2 font-medium text-ink">Actor</th>
                <th className="text-left px-4 py-2 font-medium text-ink">IP</th>
                <th className="text-left px-4 py-2 font-medium text-ink">Last seen</th>
                <th className="text-left px-4 py-2 font-medium text-ink">Absolute expiry</th>
                <th className="text-right px-4 py-2 font-medium text-ink">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.sessions.map((s: SessionInfo) => {
                const isOwn = s.actor_id === callerActorID;
                const showRevoke = isOwn || canRevokeAny;
                return (
                  <tr
                    key={s.id}
                    className="border-b border-surface-border hover:bg-page"
                    data-testid={`session-row-${s.id}`}
                  >
                    <td className="px-4 py-2 font-mono text-xs">{s.id}</td>
                    <td className="px-4 py-2">
                      <span className="font-mono text-xs">{s.actor_id}</span>
                      <span className="ml-1 text-ink-muted">({s.actor_type})</span>
                      {isOwn && (
                        <span
                          className="ml-2 inline-block px-1.5 py-0.5 text-2xs rounded bg-brand-50 text-brand-700"
                          data-testid={`session-self-pill-${s.id}`}
                        >
                          you
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-ink-muted">{s.ip_address || '—'}</td>
                    <td className="px-4 py-2 text-ink-muted">
                      {s.last_seen_at ? new Date(s.last_seen_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-2 text-ink-muted">
                      {s.absolute_expires_at ? new Date(s.absolute_expires_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-2 text-right">
                      {showRevoke && (
                        <button
                          onClick={() => handleRevoke(s)}
                          className="text-xs text-red-600 hover:underline"
                          data-testid={`session-revoke-${s.id}`}
                        >
                          Revoke
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
    </div>
  );
}
