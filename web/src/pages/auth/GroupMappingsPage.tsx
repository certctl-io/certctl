import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  listGroupMappings,
  addGroupMapping,
  removeGroupMapping,
  authListRoles,
  type GroupRoleMapping,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';
import { formatDate } from '../../api/utils';

// =============================================================================
// Bundle 2 Phase 8 — GroupMappingsPage.
//
// Per-OIDC-provider group→role mappings. The OIDC service consults the
// list at HandleCallback time (Phase 3) to translate IdP-supplied
// group claims into role IDs that get attached to the post-login
// session. Empty mapping list ⇒ no users can authenticate via this
// provider (fail-closed); operators add at least one mapping before
// rolling out OIDC.
//
// Routes:
//   /auth/oidc/providers/{id}/mappings — this page.
// API:
//   GET    /api/v1/auth/oidc/group-mappings?provider_id={id}
//   POST   /api/v1/auth/oidc/group-mappings
//   DELETE /api/v1/auth/oidc/group-mappings/{id}
// Permissions: auth.oidc.list (page) + auth.oidc.edit (add/remove).
// =============================================================================

export default function GroupMappingsPage() {
  const { id: providerID } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const { hasPerm } = useAuthMe();

  const canList = hasPerm('auth.oidc.list');
  const canEdit = hasPerm('auth.oidc.edit');

  const [groupName, setGroupName] = useState('');
  const [roleID, setRoleID] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading, error: loadErr } = useQuery({
    queryKey: ['group-mappings', providerID],
    queryFn: () => listGroupMappings(providerID || ''),
    enabled: canList && !!providerID,
  });
  const { data: rolesData } = useQuery({
    queryKey: ['auth-roles'],
    queryFn: authListRoles,
    enabled: canEdit,
  });

  if (!canList) {
    return (
      <div className="p-8">
        <PageHeader title="Group → role mappings" subtitle="" />
        <ErrorState error={new Error('You need the auth.oidc.list permission to view mappings.')} />
      </div>
    );
  }

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupName.trim() || !roleID || !providerID) return;
    setSubmitting(true);
    setError(null);
    try {
      await addGroupMapping(providerID, groupName.trim(), roleID);
      setGroupName('');
      setRoleID('');
      queryClient.invalidateQueries({ queryKey: ['group-mappings', providerID] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRemove = async (mappingID: string, displayName: string) => {
    if (!window.confirm(`Remove the mapping for "${displayName}"?`)) return;
    try {
      await removeGroupMapping(mappingID);
      queryClient.invalidateQueries({ queryKey: ['group-mappings', providerID] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="p-8 space-y-6">
      <PageHeader
        title="Group → role mappings"
        subtitle={`Provider · ${providerID}`}
        action={
          <Link
            to={`/auth/oidc/providers/${encodeURIComponent(providerID || '')}`}
            className="text-sm text-brand-600 hover:underline"
          >
            ← Provider
          </Link>
        }
      />

      {error && (
        <div
          className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
          data-testid="group-mappings-error"
        >
          {error}
        </div>
      )}

      {canEdit && (
        <form
          onSubmit={handleAdd}
          className="bg-surface border border-surface-border rounded p-4 space-y-3"
          data-testid="group-mappings-add-form"
        >
          <h2 className="text-sm font-semibold text-ink">Add mapping</h2>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-ink mb-1">IdP group name</label>
              <input
                value={groupName}
                onChange={e => setGroupName(e.target.value)}
                placeholder="engineers"
                className="w-full px-2 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="group-mappings-group-name-input"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-ink mb-1">certctl role</label>
              <select
                value={roleID}
                onChange={e => setRoleID(e.target.value)}
                className="w-full px-2 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="group-mappings-role-select"
              >
                <option value="">Select role…</option>
                {(rolesData || []).map(r => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.id})
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                disabled={submitting || !groupName.trim() || !roleID}
                className="w-full px-3 py-1.5 text-sm bg-brand-600 text-white rounded hover:bg-brand-700 disabled:opacity-50"
                data-testid="group-mappings-add-button"
              >
                {submitting ? 'Adding…' : 'Add mapping'}
              </button>
            </div>
          </div>
        </form>
      )}

      {isLoading && (
        <div className="text-sm text-ink-muted" data-testid="group-mappings-loading">
          Loading mappings…
        </div>
      )}
      {loadErr && <ErrorState error={loadErr instanceof Error ? loadErr : new Error(String(loadErr))} />}

      {data && data.mappings.length === 0 && (
        <div
          className="bg-surface border border-surface-border rounded p-6 text-center"
          data-testid="group-mappings-empty"
        >
          <p className="text-ink-muted text-sm">
            No mappings configured for this provider. Until at least one mapping exists, OIDC logins
            via this provider fail closed (no roles → 401 to the user).
          </p>
        </div>
      )}

      {data && data.mappings.length > 0 && (
        <div className="bg-surface border border-surface-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-page border-b border-surface-border">
              <tr>
                <th className="text-left px-4 py-2 font-medium text-ink">IdP group</th>
                <th className="text-left px-4 py-2 font-medium text-ink">certctl role</th>
                <th className="text-left px-4 py-2 font-medium text-ink">Created</th>
                <th className="text-right px-4 py-2 font-medium text-ink">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.mappings.map((m: GroupRoleMapping) => (
                <tr
                  key={m.id}
                  className="border-b border-surface-border hover:bg-page"
                  data-testid={`group-mapping-row-${m.id}`}
                >
                  <td className="px-4 py-2 font-mono text-xs">{m.group_name}</td>
                  <td className="px-4 py-2 font-mono text-xs">{m.role_id}</td>
                  <td className="px-4 py-2 text-ink-muted">
                    {formatDate(m.created_at)}
                  </td>
                  <td className="px-4 py-2 text-right">
                    {canEdit && (
                      <button
                        onClick={() => handleRemove(m.id, m.group_name)}
                        className="text-xs text-red-600 hover:underline"
                        data-testid={`group-mapping-remove-${m.id}`}
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
