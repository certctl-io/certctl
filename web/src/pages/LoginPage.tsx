import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthProvider';
import { getAuthInfo, breakglassLogin, type AuthInfoOIDCProvider } from '../api/client';

// =============================================================================
// LoginPage — Bundle 2 Phase 8 / multi-mode entry surface.
//
// Pre-Bundle-2: API-key-only sign-in form.
// Post-Bundle-2: when `/auth/info` reports `oidc_providers[]`, the
// page renders one "Sign in with X" button per provider; clicking
// navigates to the provider's `login_url` (which 302s through the
// IdP and back to /auth/oidc/callback). The API-key form remains as
// a fallback for Bearer-mode deployments.
//
// Audit 2026-05-10 CRIT-4 closure: an inline break-glass form below
// the API-key form lets admins recover during SSO incidents without
// crafting curl commands. The link is intentionally low-key
// (text-amber-600 small text) — break-glass is the deliberate-bypass
// path, not the everyday-login path.
// =============================================================================

export default function LoginPage() {
  const { login, error: authError } = useAuth();
  const navigate = useNavigate();
  const [key, setKey] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [providers, setProviders] = useState<AuthInfoOIDCProvider[]>([]);

  // Break-glass inline form state.
  const [showBreakglass, setShowBreakglass] = useState(false);
  const [bgActorID, setBgActorID] = useState('');
  const [bgPassword, setBgPassword] = useState('');
  const [bgError, setBgError] = useState<string | null>(null);
  const [bgSubmitting, setBgSubmitting] = useState(false);

  const error = localError || authError;

  // On mount, fetch /auth/info and extract any configured OIDC
  // providers so we can render the "Sign in with X" buttons. Errors
  // are non-fatal — fall back to the API-key form.
  useEffect(() => {
    getAuthInfo()
      .then(info => {
        if (info.oidc_providers && info.oidc_providers.length > 0) {
          setProviders(info.oidc_providers);
        }
      })
      .catch(() => {
        // Server may be pre-Phase-6; ignore.
      });
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!key.trim()) return;
    setSubmitting(true);
    setLocalError(null);
    try {
      await login(key.trim());
    } catch {
      setLocalError('Invalid API key. Check your key and try again.');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleBreakglassSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!bgActorID.trim() || !bgPassword) return;
    setBgSubmitting(true);
    setBgError(null);
    try {
      await breakglassLogin(bgActorID.trim(), bgPassword);
      // breakglassLogin sets the session cookie via Set-Cookie; navigate
      // to the dashboard, which the AuthProvider will re-validate via
      // its session-cookie path on next render.
      navigate('/');
    } catch (err) {
      setBgError(err instanceof Error ? err.message : 'Break-glass login failed.');
    } finally {
      setBgSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-page flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-brand-400 mb-2">certctl</h1>
          <p className="text-sm text-ink-muted uppercase tracking-wider">Certificate Control Plane</p>
        </div>

        {providers.length > 0 && (
          <div
            className="bg-surface border border-surface-border rounded p-6 space-y-3 shadow-sm mb-4"
            data-testid="login-oidc-providers"
          >
            <p className="text-sm font-medium text-ink-muted text-center">Sign in with your identity provider</p>
            {providers.map(p => (
              <a
                key={p.id}
                href={p.login_url}
                className="block w-full text-center bg-brand-400 hover:bg-brand-500 text-white py-2.5 text-sm font-medium rounded transition-colors"
                data-testid={`login-oidc-button-${p.id}`}
              >
                Sign in with {p.display_name}
              </a>
            ))}
          </div>
        )}

        <form
          onSubmit={handleSubmit}
          className="bg-surface border border-surface-border rounded p-6 space-y-4 shadow-sm"
          data-testid="login-api-key-form"
        >
          {providers.length > 0 && (
            <p className="text-xs text-ink-muted text-center pb-2 border-b border-surface-border">
              — or sign in with API key —
            </p>
          )}
          <div>
            <label htmlFor="api-key" className="block text-sm font-medium text-ink-muted mb-1.5">
              API Key
            </label>
            <input
              id="api-key"
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="Enter your API key"
              autoFocus={providers.length === 0}
              className="w-full bg-white border border-surface-border rounded px-3 py-2.5 text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
              data-testid="login-api-key-input"
            />
          </div>

          {error && (
            <div
              className="bg-red-50 border border-red-200 rounded px-3 py-2 text-sm text-red-700"
              data-testid="login-error"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !key.trim()}
            className="w-full bg-brand-400 hover:bg-brand-500 text-white py-2.5 text-sm font-medium rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            data-testid="login-api-key-submit"
          >
            {submitting ? 'Verifying...' : 'Sign In'}
          </button>

          <p className="text-xs text-ink-muted text-center">
            The API key is set via <code className="text-ink-faint bg-page px-1 py-0.5 rounded">CERTCTL_AUTH_SECRET</code> on the server.
          </p>
        </form>

        {/* Break-glass entry — low-visibility on purpose. CRIT-4 closure. */}
        <div className="mt-4 text-center" data-testid="login-breakglass-entry">
          {!showBreakglass ? (
            <button
              type="button"
              onClick={() => setShowBreakglass(true)}
              className="text-xs text-amber-600 hover:text-amber-700 hover:underline"
              data-testid="login-breakglass-toggle"
            >
              Use break-glass account (SSO outage recovery)
            </button>
          ) : (
            <form
              onSubmit={handleBreakglassSubmit}
              className="bg-amber-50 border border-amber-200 rounded p-4 mt-4 space-y-3 text-left"
              data-testid="login-breakglass-form"
            >
              <p className="text-xs font-medium text-amber-900">
                Break-glass admin login — every action is audited. Use only during SSO incidents.
              </p>
              <div>
                <label htmlFor="bg-actor-id" className="block text-xs font-medium text-amber-900 mb-1">
                  Actor ID
                </label>
                <input
                  id="bg-actor-id"
                  type="text"
                  value={bgActorID}
                  onChange={e => setBgActorID(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="actor-..."
                  className="w-full bg-white border border-amber-300 rounded px-3 py-2 text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500/20"
                  data-testid="login-breakglass-actor-id"
                />
              </div>
              <div>
                <label htmlFor="bg-password" className="block text-xs font-medium text-amber-900 mb-1">
                  Password
                </label>
                <input
                  id="bg-password"
                  type="password"
                  value={bgPassword}
                  onChange={e => setBgPassword(e.target.value)}
                  autoComplete="off"
                  className="w-full bg-white border border-amber-300 rounded px-3 py-2 text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500/20"
                  data-testid="login-breakglass-password"
                />
              </div>
              {bgError && (
                <div
                  className="bg-red-50 border border-red-200 rounded px-3 py-2 text-xs text-red-700"
                  data-testid="login-breakglass-error"
                >
                  {bgError}
                </div>
              )}
              <div className="flex gap-2">
                <button
                  type="submit"
                  disabled={bgSubmitting || !bgActorID.trim() || !bgPassword}
                  className="flex-1 bg-amber-600 hover:bg-amber-700 text-white py-2 text-sm font-medium rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  data-testid="login-breakglass-submit"
                >
                  {bgSubmitting ? 'Signing in…' : 'Sign in (break-glass)'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowBreakglass(false);
                    setBgActorID('');
                    setBgPassword('');
                    setBgError(null);
                  }}
                  className="px-3 py-2 text-sm font-medium text-amber-900 hover:bg-amber-100 rounded transition-colors"
                  data-testid="login-breakglass-cancel"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
