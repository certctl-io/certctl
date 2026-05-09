import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { authListRoles, authCreateRole, type AuthRole } from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';

// =============================================================================
// Bundle 1 Phase 10 — RolesPage.
//
// Lists every role in the active tenant. Render-time permission gating:
//
//   - The "Create role" button is HIDDEN when the caller lacks
//     auth.role.create. Server-side enforcement still 403s an
//     end-run; the hide is UX, not security.
//   - Every row links to /auth/roles/:id; that page in turn gates
//     the edit / delete / add-permission affordances.
//
// data-testid attributes flag every interactive element so the future
// E2E suite (Playwright or equivalent) can assert behaviour without
// brittle CSS selectors.
// =============================================================================

interface CreateRoleModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

function CreateRoleModal({ isOpen, onClose, onSuccess }: CreateRoleModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await authCreateRole({ name: name.trim(), description: description.trim() });
      setName('');
      setDescription('');
      setDirty(false);
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    if (dirty && !window.confirm('Discard unsaved changes?')) return;
    setName('');
    setDescription('');
    setDirty(false);
    setError(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={handleClose}>
      <div
        className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl"
        onClick={e => e.stopPropagation()}
        data-testid="create-role-modal"
      >
        <h2 className="text-lg font-semibold text-ink mb-4">Create role</h2>
        {error && (
          <div
            className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
            data-testid="create-role-error"
          >
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => {
                setName(e.target.value);
                setDirty(true);
              }}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
              placeholder="release-manager"
              required
              data-testid="create-role-name"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <textarea
              value={description}
              onChange={e => {
                setDescription(e.target.value);
                setDirty(true);
              }}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
              rows={3}
              placeholder="What this role grants"
              data-testid="create-role-description"
            />
          </div>
          <div className="flex gap-2 pt-2">
            <button
              type="submit"
              disabled={submitting || !name.trim()}
              className="flex-1 btn btn-primary disabled:opacity-50"
              data-testid="create-role-submit"
            >
              {submitting ? 'Creating…' : 'Create role'}
            </button>
            <button
              type="button"
              onClick={handleClose}
              className="flex-1 btn btn-ghost"
              data-testid="create-role-cancel"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function RolesPage() {
  const me = useAuthMe();
  const qc = useQueryClient();
  const rolesQuery = useQuery<AuthRole[], Error>({
    queryKey: ['auth', 'roles'],
    queryFn: authListRoles,
    staleTime: 30_000,
  });

  const [createOpen, setCreateOpen] = useState(false);

  const canCreate = me.hasPerm('auth.role.create') || me.isAdmin();

  if (rolesQuery.isLoading) {
    return (
      <div className="space-y-4">
        <PageHeader title="Roles" subtitle="Loading…" />
      </div>
    );
  }

  if (rolesQuery.error) {
    return (
      <div className="space-y-4">
        <PageHeader title="Roles" />
        <ErrorState
          error={rolesQuery.error}
          onRetry={() => qc.invalidateQueries({ queryKey: ['auth', 'roles'] })}
        />
      </div>
    );
  }

  const roles = rolesQuery.data ?? [];

  return (
    <div className="space-y-4" data-testid="roles-page">
      <PageHeader
        title="Roles"
        subtitle="RBAC primitives — every API key holds zero or more roles. The auditor split is enforced server-side."
        action={
          canCreate ? (
            <button
              className="btn btn-primary"
              onClick={() => setCreateOpen(true)}
              data-testid="roles-create-button"
            >
              Create role
            </button>
          ) : undefined
        }
      />
      {roles.length === 0 ? (
        <div
          className="bg-surface border border-surface-border rounded p-8 text-center text-sm text-ink-muted"
          data-testid="roles-empty"
        >
          No roles. Bundle 1 seeds 7 default roles on first migration; if this list is empty,
          the migration may not have applied. Check `migrations/000029_rbac.up.sql`.
        </div>
      ) : (
        <div className="bg-surface border border-surface-border rounded">
          <table className="w-full text-sm" data-testid="roles-table">
            <thead className="bg-surface-muted text-xs uppercase tracking-wide text-ink-muted">
              <tr>
                <th className="text-left px-3 py-2">Role ID</th>
                <th className="text-left px-3 py-2">Name</th>
                <th className="text-left px-3 py-2">Description</th>
              </tr>
            </thead>
            <tbody>
              {roles.map(role => (
                <tr key={role.id} className="border-t border-surface-border">
                  <td className="px-3 py-2 font-mono">{role.id}</td>
                  <td className="px-3 py-2">
                    <Link
                      to={`/auth/roles/${role.id}`}
                      className="text-brand-500 hover:underline"
                      data-testid={`roles-link-${role.id}`}
                    >
                      {role.name}
                    </Link>
                  </td>
                  <td className="px-3 py-2 text-ink-muted">{role.description || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CreateRoleModal
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        onSuccess={() => {
          setCreateOpen(false);
          qc.invalidateQueries({ queryKey: ['auth', 'roles'] });
        }}
      />
    </div>
  );
}
