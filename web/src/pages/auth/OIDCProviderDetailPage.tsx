import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  listOIDCProviders,
  updateOIDCProvider,
  deleteOIDCProvider,
  refreshOIDCProvider,
  type OIDCProvider,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';

// =============================================================================
// Bundle 2 Phase 8 — OIDCProviderDetailPage.
//
// One row per provider — edit (PUT), delete (DELETE), and refresh
// discovery cache (POST .../refresh). Edit modal shares the create-
// modal field set; the client_secret field is OPTIONAL on edit (empty
// preserves the existing ciphertext on the server). Delete is gated
// behind a typed-confirmation dialog AND surfaces 409 Conflict (the
// server's ErrOIDCProviderInUse) as a non-destructive error so the
// operator knows to revoke active sessions first. Refresh discovery
// cache fires the server's RefreshKeys → re-runs the IdP downgrade-
// attack defense AND re-fetches JWKS; common operator action when an
// IdP rotates keys mid-day.
//
// Permission gates: the page itself requires auth.oidc.list. Edit
// and refresh require auth.oidc.edit. Delete requires
// auth.oidc.delete. Mappings link is rendered for any caller with
// auth.oidc.list.
// =============================================================================

export default function OIDCProviderDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { hasPerm } = useAuthMe();

  const canList = hasPerm('auth.oidc.list');
  const canEdit = hasPerm('auth.oidc.edit');
  const canDelete = hasPerm('auth.oidc.delete');

  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState('');
  const [editIssuerURL, setEditIssuerURL] = useState('');
  const [editClientID, setEditClientID] = useState('');
  const [editClientSecret, setEditClientSecret] = useState('');
  const [editRedirectURI, setEditRedirectURI] = useState('');
  const [editFetchUserinfo, setEditFetchUserinfo] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  const { data, isLoading, error: loadErr } = useQuery({
    queryKey: ['oidc-providers'],
    queryFn: listOIDCProviders,
    enabled: canList,
  });

  if (!canList) {
    return (
      <div className="p-8">
        <PageHeader title="OIDC provider" subtitle="Identity provider configuration" />
        <ErrorState error={new Error("You need the auth.oidc.list permission to view OIDC providers.")} />
      </div>
    );
  }

  const provider: OIDCProvider | undefined = data?.providers.find(p => p.id === id);

  if (isLoading) {
    return <div className="p-8 text-sm text-ink-muted" data-testid="oidc-provider-detail-loading">Loading…</div>;
  }
  if (loadErr || !provider) {
    return (
      <div className="p-8">
        <PageHeader title="OIDC provider" subtitle="Identity provider configuration" />
        <ErrorState error={loadErr instanceof Error ? loadErr : new Error("Provider not found")} />
        <Link to="/auth/oidc/providers" className="text-sm text-brand-600 hover:underline">
          ← Back to providers
        </Link>
      </div>
    );
  }

  const startEdit = () => {
    setEditName(provider.name);
    setEditIssuerURL(provider.issuer_url);
    setEditClientID(provider.client_id);
    setEditClientSecret('');
    setEditRedirectURI(provider.redirect_uri);
    setEditFetchUserinfo(provider.fetch_userinfo || false);
    setError(null);
    setSuccess(null);
    setEditing(true);
  };

  const cancelEdit = () => {
    setEditing(false);
    setError(null);
  };

  const saveEdit = async () => {
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      const req: Parameters<typeof updateOIDCProvider>[1] = {
        name: editName,
        issuer_url: editIssuerURL,
        client_id: editClientID,
        redirect_uri: editRedirectURI,
        groups_claim_path: provider.groups_claim_path,
        groups_claim_format: provider.groups_claim_format,
        fetch_userinfo: editFetchUserinfo,
        scopes: provider.scopes,
        iat_window_seconds: provider.iat_window_seconds,
        jwks_cache_ttl_seconds: provider.jwks_cache_ttl_seconds,
      };
      if (editClientSecret) req.client_secret = editClientSecret;
      await updateOIDCProvider(provider.id, req);
      setSuccess('Provider updated');
      setEditing(false);
      queryClient.invalidateQueries({ queryKey: ['oidc-providers'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const doRefresh = async () => {
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      await refreshOIDCProvider(provider.id);
      setSuccess('Discovery + JWKS refreshed; IdP downgrade defense re-run');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const doDelete = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await deleteOIDCProvider(provider.id);
      navigate('/auth/oidc/providers');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <PageHeader
        title={provider.name}
        subtitle={`OIDC provider · ${provider.id}`}
        action={
          <Link to="/auth/oidc/providers" className="text-sm text-brand-600 hover:underline">
            ← All providers
          </Link>
        }
      />

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700" data-testid="oidc-provider-detail-error">
          {error}
        </div>
      )}
      {success && (
        <div className="p-3 bg-green-50 border border-green-200 rounded text-sm text-green-700" data-testid="oidc-provider-detail-success">
          {success}
        </div>
      )}

      <div className="bg-surface border border-surface-border rounded p-5 space-y-4">
        <h2 className="text-base font-semibold text-ink">Configuration</h2>
        {!editing ? (
          <dl className="grid grid-cols-3 gap-y-2 text-sm">
            <dt className="text-ink-muted col-span-1">Issuer URL</dt>
            <dd className="col-span-2 font-mono text-xs">{provider.issuer_url}</dd>
            <dt className="text-ink-muted col-span-1">Client ID</dt>
            <dd className="col-span-2 font-mono text-xs">{provider.client_id}</dd>
            <dt className="text-ink-muted col-span-1">Redirect URI</dt>
            <dd className="col-span-2 font-mono text-xs">{provider.redirect_uri}</dd>
            <dt className="text-ink-muted col-span-1">Groups claim</dt>
            <dd className="col-span-2 font-mono text-xs">
              {provider.groups_claim_path} ({provider.groups_claim_format})
            </dd>
            <dt className="text-ink-muted col-span-1">Userinfo fallback</dt>
            <dd className="col-span-2">{provider.fetch_userinfo ? 'enabled' : 'disabled'}</dd>
            <dt className="text-ink-muted col-span-1">Scopes</dt>
            <dd className="col-span-2 font-mono text-xs">{(provider.scopes || []).join(', ')}</dd>
            <dt className="text-ink-muted col-span-1">IAT window</dt>
            <dd className="col-span-2">{provider.iat_window_seconds}s</dd>
          </dl>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Display name</label>
              <input
                value={editName}
                onChange={e => setEditName(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Issuer URL</label>
              <input
                value={editIssuerURL}
                onChange={e => setEditIssuerURL(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-issuer-url"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Client ID</label>
              <input
                value={editClientID}
                onChange={e => setEditClientID(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-client-id"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">
                Client secret (leave blank to keep current)
              </label>
              <input
                type="password"
                value={editClientSecret}
                onChange={e => setEditClientSecret(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-client-secret"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Redirect URI</label>
              <input
                value={editRedirectURI}
                onChange={e => setEditRedirectURI(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-redirect-uri"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-ink">
              <input
                type="checkbox"
                checked={editFetchUserinfo}
                onChange={e => setEditFetchUserinfo(e.target.checked)}
                data-testid="oidc-provider-edit-fetch-userinfo"
              />
              <span>Fetch groups from userinfo endpoint when ID token claim is empty</span>
            </label>
          </div>
        )}
      </div>

      <div className="bg-surface border border-surface-border rounded p-5 space-y-3">
        <h2 className="text-base font-semibold text-ink">Actions</h2>
        <div className="flex flex-wrap gap-2">
          {canEdit && !editing && (
            <button
              onClick={startEdit}
              className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
              data-testid="oidc-provider-edit-button"
            >
              Edit
            </button>
          )}
          {editing && (
            <>
              <button
                onClick={saveEdit}
                disabled={submitting}
                className="px-3 py-1.5 text-sm bg-brand-600 text-white rounded hover:bg-brand-700 disabled:opacity-50"
                data-testid="oidc-provider-save-button"
              >
                {submitting ? 'Saving…' : 'Save'}
              </button>
              <button
                onClick={cancelEdit}
                className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
                data-testid="oidc-provider-cancel-edit-button"
              >
                Cancel
              </button>
            </>
          )}
          {canEdit && (
            <button
              onClick={doRefresh}
              disabled={submitting}
              className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink disabled:opacity-50"
              data-testid="oidc-provider-refresh-button"
              title="Re-fetch IdP discovery doc + JWKS; re-runs IdP downgrade defense"
            >
              Refresh discovery cache
            </button>
          )}
          <Link
            to={`/auth/oidc/providers/${encodeURIComponent(provider.id)}/mappings`}
            className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
            data-testid="oidc-provider-mappings-link"
          >
            Group → role mappings
          </Link>
          {canDelete && !confirmDelete && (
            <button
              onClick={() => setConfirmDelete(true)}
              className="ml-auto px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700"
              data-testid="oidc-provider-delete-button"
            >
              Delete
            </button>
          )}
        </div>

        {confirmDelete && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-800" data-testid="oidc-provider-delete-confirm">
            <p className="mb-2">
              Type <span className="font-mono font-semibold">{provider.name}</span> to confirm deletion.
              Deletion is refused (HTTP 409) when any user has authenticated via this provider; revoke
              their sessions first.
            </p>
            <div className="flex gap-2">
              <input
                value={deleteConfirmText}
                onChange={e => setDeleteConfirmText(e.target.value)}
                className="flex-1 px-2 py-1 text-sm border border-red-300 rounded bg-white"
                data-testid="oidc-provider-delete-confirm-input"
              />
              <button
                onClick={doDelete}
                disabled={submitting || deleteConfirmText !== provider.name}
                className="px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50"
                data-testid="oidc-provider-delete-confirm-button"
              >
                {submitting ? 'Deleting…' : 'Delete provider'}
              </button>
              <button
                onClick={() => {
                  setConfirmDelete(false);
                  setDeleteConfirmText('');
                }}
                className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
                data-testid="oidc-provider-delete-cancel-button"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
