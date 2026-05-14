import { useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import {
  authGetRole,
  authListPermissions,
  authUpdateRole,
  authDeleteRole,
  authAddRolePermission,
  authRemoveRolePermission,
  type AuthPermission,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';
import ConfirmDialog from '../../components/ConfirmDialog';

// =============================================================================
// Bundle 1 Phase 10 — RoleDetailPage.
//
// Shows a single role plus its current permission grants. Surfaces:
//
//   - Edit role modal (auth.role.edit)
//   - Delete role action (auth.role.delete) — disabled when actors hold
//     the role (server returns 409; UX surfaces via ErrorState).
//   - Add permission picker (auth.role.edit) populated from the
//     canonical catalogue.
//   - Remove permission action per row (auth.role.edit).
//
// Each action is HIDDEN when the caller lacks the permission. The
// server still 403s an end-run; client-side hide is UX, not security.
// =============================================================================

// Audit 2026-05-10 LOW-11 — default role ids the server seeds via
// migrations 000029 + 000039. The backend rejects DELETE on any of
// these with HTTP 409; this set mirrors the seed so the GUI hides
// the Delete button on system roles. Keep in sync with the migrations.
const DEFAULT_ROLE_IDS = new Set([
  'r-admin',
  'r-operator',
  'r-viewer',
  'r-agent',
  'r-mcp',
  'r-cli',
  'r-auditor',
]);

export default function RoleDetailPage() {
  const { id = '' } = useParams<{ id: string }>();
  const me = useAuthMe();
  const qc = useQueryClient();
  const navigate = useNavigate();

  const detailQuery = useQuery({
    queryKey: ['auth', 'role', id],
    queryFn: () => authGetRole(id),
    enabled: Boolean(id),
    staleTime: 30_000,
  });
  const permsCatalogue = useQuery<AuthPermission[], Error>({
    queryKey: ['auth', 'permissions'],
    queryFn: authListPermissions,
    staleTime: 5 * 60_000,
  });

  const [editOpen, setEditOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  // UX-H2 closure — replace window.confirm with ConfirmDialog.
  const [confirmDelete, setConfirmDelete] = useState(false);

  const canEdit = me.hasPerm('auth.role.edit') || me.isAdmin();
  const canDelete = me.hasPerm('auth.role.delete') || me.isAdmin();

  if (detailQuery.isLoading) return <PageHeader title="Role" subtitle="Loading…" />;
  if (detailQuery.error || !detailQuery.data)
    return (
      <div className="space-y-4">
        <PageHeader title="Role" />
        <ErrorState
          error={detailQuery.error ?? new Error('not found')}
          onRetry={() => qc.invalidateQueries({ queryKey: ['auth', 'role', id] })}
        />
      </div>
    );

  const { role, permissions } = detailQuery.data;

  const handleDelete = () => {
    setConfirmDelete(true);
  };

  const performDelete = async () => {
    setConfirmDelete(false);
    setSubmitting(true);
    setActionError(null);
    try {
      await authDeleteRole(role.id);
      toast.success(`Role ${role.name} deleted`);
      navigate('/auth/roles');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setActionError(msg);
      toast.error(`Delete failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  // Audit 2026-05-10 MED-8 — extended permission grant body with
  // scope_type + scope_id. The select dropdown drives `perm`; scope
  // inputs are read from inline state hoisted from the form below.
  const handleAddPermission = async (perm: string, scope?: { scope_type?: string; scope_id?: string }) => {
    setSubmitting(true);
    setActionError(null);
    try {
      await authAddRolePermission(role.id, { permission: perm, ...(scope ?? {}) });
      qc.invalidateQueries({ queryKey: ['auth', 'role', role.id] });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRemovePermission = async (perm: string) => {
    setSubmitting(true);
    setActionError(null);
    try {
      await authRemoveRolePermission(role.id, perm);
      qc.invalidateQueries({ queryKey: ['auth', 'role', role.id] });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const grantedPermNames = new Set(permissions.map(p => p.permission_id));
  const availablePerms = (permsCatalogue.data ?? []).filter(p => !grantedPermNames.has(p.name));

  return (
    <div className="space-y-4" data-testid={`role-detail-${role.id}`}>
      <PageHeader
        title={role.name}
        subtitle={`Role ID: ${role.id} · ${permissions.length} permission(s)`}
        action={
          <div className="flex gap-2">
            <Link to="/auth/roles" className="btn btn-ghost" data-testid="role-back">
              Back
            </Link>
            {canEdit && (
              <button
                className="btn btn-primary"
                onClick={() => setEditOpen(true)}
                data-testid="role-edit-button"
              >
                Edit
              </button>
            )}
            {canDelete && (
              // Audit 2026-05-10 LOW-11 closure — hide Delete on
              // default roles. The backend already rejects deletion of
              // default roles (DELETE returns 409 with
              // 'cannot delete default role'); this is pure UX so
              // operators don't click a button that's destined to fail.
              DEFAULT_ROLE_IDS.has(role.id) ? (
                <span
                  className="text-xs text-ink-muted"
                  title="System role; cannot be deleted."
                  data-testid="role-delete-disabled-tooltip"
                >
                  System role (cannot be deleted)
                </span>
              ) : (
                <button
                  className="btn btn-danger"
                  onClick={handleDelete}
                  disabled={submitting}
                  data-testid="role-delete-button"
                >
                  Delete
                </button>
              )
            )}
          </div>
        }
      />
      {actionError && (
        <div
          className="bg-red-50 border border-red-200 text-red-700 text-sm p-3 rounded"
          data-testid="role-action-error"
        >
          {actionError}
        </div>
      )}
      <div className="bg-surface border border-surface-border rounded p-4 space-y-2">
        <div className="text-xs uppercase tracking-wide text-ink-muted">Description</div>
        <div className="text-sm">{role.description || <span className="text-ink-muted">(none)</span>}</div>
      </div>

      <div className="bg-surface border border-surface-border rounded">
        <div className="px-4 py-3 border-b border-surface-border flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold">Permissions ({permissions.length})</div>
            <div className="text-xs text-ink-muted">
              Permissions granted at the listed scope. Global wins over more-specific scopes.
            </div>
          </div>
          {canEdit && availablePerms.length > 0 && (
            <AddPermissionForm
              availablePerms={availablePerms.map((p) => p.name)}
              onSubmit={(perm, scope) => void handleAddPermission(perm, scope)}
            />
          )}
        </div>
        {permissions.length === 0 ? (
          <div className="p-6 text-sm text-ink-muted text-center" data-testid="role-permissions-empty">
            No permissions granted. {canEdit ? 'Use the picker above to add some.' : ''}
          </div>
        ) : (
          <table className="w-full text-sm" data-testid="role-permissions-table">
            <thead className="bg-surface-muted text-xs uppercase tracking-wide text-ink-muted">
              <tr>
                <th className="text-left px-3 py-2">Permission</th>
                <th className="text-left px-3 py-2">Scope</th>
                {canEdit && <th className="px-3 py-2 w-24"></th>}
              </tr>
            </thead>
            <tbody>
              {permissions.map(p => {
                const permName = lookupPermNameByID(permsCatalogue.data ?? [], p.permission_id);
                return (
                  <tr key={p.permission_id} className="border-t border-surface-border">
                    <td className="px-3 py-2 font-mono text-xs">{permName}</td>
                    <td className="px-3 py-2 text-xs">
                      {p.scope_type}
                      {p.scope_id ? ` (${p.scope_id})` : ''}
                    </td>
                    {canEdit && (
                      <td className="px-3 py-2 text-right">
                        <button
                          className="btn btn-ghost text-xs"
                          onClick={() => handleRemovePermission(permName)}
                          disabled={submitting}
                          data-testid={`role-remove-${permName}`}
                        >
                          Remove
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {editOpen && (
        <EditRoleModal
          roleId={role.id}
          initialName={role.name}
          initialDescription={role.description ?? ''}
          onClose={() => setEditOpen(false)}
          onSuccess={() => {
            setEditOpen(false);
            qc.invalidateQueries({ queryKey: ['auth', 'role', role.id] });
            qc.invalidateQueries({ queryKey: ['auth', 'roles'] });
          }}
        />
      )}
      <ConfirmDialog
        open={confirmDelete}
        title="Delete role"
        message={`Delete role ${role.name}? Every actor currently holding this role grant will lose those permissions. This cannot be undone.`}
        confirmLabel="Delete role"
        destructive
        onConfirm={performDelete}
        onCancel={() => setConfirmDelete(false)}
      />
    </div>
  );
}

function lookupPermNameByID(catalogue: AuthPermission[], id: string): string {
  // The role-permissions response uses permission_id which the server
  // populates as the canonical permission NAME (the schema treats
  // permission name as the row id surrogate). Belt-and-braces
  // fallback: if the catalogue knows the id, return its display name.
  const m = catalogue.find(p => p.id === id || p.name === id);
  return m?.name ?? id;
}

interface EditModalProps {
  roleId: string;
  initialName: string;
  initialDescription: string;
  onClose: () => void;
  onSuccess: () => void;
}

function EditRoleModal({ roleId, initialName, initialDescription, onClose, onSuccess }: EditModalProps) {
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(initialDescription);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty = name !== initialName || description !== initialDescription;

  const handleClose = () => {
    if (dirty && !window.confirm('Discard unsaved changes?')) return;
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await authUpdateRole(roleId, { name: name.trim(), description: description.trim() });
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={handleClose}>
      <div
        className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl"
        onClick={e => e.stopPropagation()}
        data-testid="edit-role-modal"
      >
        <h2 className="text-lg font-semibold text-ink mb-4">Edit role</h2>
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
              required
              data-testid="edit-role-name"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm"
              rows={3}
              data-testid="edit-role-description"
            />
          </div>
          <div className="flex gap-2 pt-2">
            <button
              type="submit"
              disabled={submitting || !dirty || !name.trim()}
              className="flex-1 btn btn-primary disabled:opacity-50"
              data-testid="edit-role-submit"
            >
              {submitting ? 'Saving…' : 'Save'}
            </button>
            <button type="button" onClick={handleClose} className="flex-1 btn btn-ghost" data-testid="edit-role-cancel">
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// =============================================================================
// Audit 2026-05-10 MED-8 closure — Add-permission form with scope picker.
// =============================================================================

interface AddPermissionFormProps {
  availablePerms: string[];
  onSubmit: (perm: string, scope?: { scope_type?: string; scope_id?: string }) => void;
}

function AddPermissionForm({ availablePerms, onSubmit }: AddPermissionFormProps) {
  const [perm, setPerm] = useState('');
  const [scopeType, setScopeType] = useState<'global' | 'profile' | 'issuer'>('global');
  const [scopeID, setScopeID] = useState('');
  return (
    <div className="flex items-center gap-2">
      <select
        className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm"
        value={perm}
        onChange={(e) => setPerm(e.target.value)}
        data-testid="role-add-permission-select"
      >
        <option value="">Add permission…</option>
        {availablePerms.map((p) => (
          <option key={p} value={p}>{p}</option>
        ))}
      </select>
      <select
        className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm"
        value={scopeType}
        onChange={(e) => setScopeType(e.target.value as 'global' | 'profile' | 'issuer')}
        data-testid="role-add-permission-scope-type"
      >
        <option value="global">Global</option>
        <option value="profile">Profile</option>
        <option value="issuer">Issuer</option>
      </select>
      {scopeType !== 'global' && (
        <input
          type="text"
          placeholder={scopeType === 'profile' ? 'p-acme-corp' : 'iss-internal-pki'}
          value={scopeID}
          onChange={(e) => setScopeID(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm"
          data-testid="role-add-permission-scope-id"
        />
      )}
      <button
        type="button"
        className="btn btn-primary"
        disabled={!perm || (scopeType !== 'global' && !scopeID.trim())}
        onClick={() => {
          if (!perm) return;
          if (scopeType === 'global') {
            onSubmit(perm);
          } else {
            onSubmit(perm, { scope_type: scopeType, scope_id: scopeID.trim() });
          }
          setPerm('');
          setScopeID('');
        }}
        data-testid="role-add-permission-submit"
      >
        Add
      </button>
    </div>
  );
}
