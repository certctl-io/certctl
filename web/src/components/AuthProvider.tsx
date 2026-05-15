import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';
import { getAuthInfo, checkAuth, setApiKey, logout as apiLogout } from '../api/client';

interface AuthState {
  loading: boolean;
  authRequired: boolean;
  authenticated: boolean;
  authType: string;
  // M-003: named-key identity + admin flag surfaced from /auth/check so admin-
  // only GUI affordances (e.g., bulk-revoke) can be hidden from non-admin
  // callers. These are UX hints — authorization remains enforced server-side.
  user: string;
  admin: boolean;
  login: (key: string) => Promise<void>;
  logout: () => void;
  error: string | null;
}

const AuthContext = createContext<AuthState>({
  loading: true,
  authRequired: false,
  authenticated: false,
  authType: 'none',
  user: '',
  admin: false,
  login: async () => {},
  logout: () => {},
  error: null,
});

export function useAuth() {
  return useContext(AuthContext);
}

export default function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [authRequired, setAuthRequired] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [authType, setAuthType] = useState('none');
  const [user, setUser] = useState('');
  const [admin, setAdmin] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Check if server requires auth on mount
  useEffect(() => {
    getAuthInfo()
      .then((info) => {
        setAuthType(info.auth_type);
        setAuthRequired(info.required);
        if (!info.required) {
          // CERTCTL_AUTH_TYPE=none: the server treats every caller as
          // anonymous with admin=false. Mirror that locally so gated
          // affordances stay hidden.
          setAuthenticated(true);
          setUser('');
          setAdmin(false);
        }
      })
      .catch(() => {
        // If auth/info fails, assume no auth required (server may be old version)
        setAuthenticated(true);
        setUser('');
        setAdmin(false);
      })
      .finally(() => setLoading(false));
  }, []);

  // Listen for 401 events from the API client.
  //
  // Audit 2026-05-10 HIGH-8 — the API client now attaches a cause
  // category to the event detail (parsed from the WWW-Authenticate
  // header). When a cause is recognised, redirect to
  // /login?session_expired=<cause> so the LoginPage renders OIDC-aware
  // re-login wording instead of the generic "session expired" + API-key
  // copy. Cookie-mode (OIDC) and Bearer-mode (API-key) callers share
  // the same wire shape; the LoginPage banner is purely UX.
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<{ cause?: string }>).detail;
      const cause = detail?.cause || '';
      setAuthenticated(false);
      setApiKey(null);
      setUser('');
      setAdmin(false);
      // Generic copy; the LoginPage will overlay a cause-specific
      // banner when ?session_expired=<cause> is present.
      setError('Session expired. Please re-enter your API key.');
      // Forward the cause to the LoginPage. window.location is used
      // (not React Router's navigate) because this listener fires
      // outside any route component's render and we want a hard
      // navigation that clears any stale state.
      //
      // Hotfix #19 (GitHub #13): always hard-navigate to /login on a
      // 401, regardless of cause. Pre-Hotfix-19 the conditional only
      // redirected when cause was a non-'invalid_token' OIDC
      // session-expiry category (idle_timeout / absolute_timeout /
      // back_channel_revoked). Bare 401s (refresh-after-login wipes
      // the in-memory apiKey → no Authorization header → server
      // returns 401 with no WWW-Authenticate header → cause === '')
      // fell through to an in-place AuthGate state flip that
      // unmounted BrowserRouter under an in-flight <Link>, triggering
      // a react-router-dom invariant that surfaced via ErrorBoundary
      // as "Something went wrong." The unconditional hard-navigation
      // forecloses the in-place tear-down path; cause-aware UX is
      // preserved by forwarding ?session_expired= only when cause is
      // non-empty.
      if (window.location.pathname !== '/login') {
        const url = cause
          ? '/login?' + new URLSearchParams({ session_expired: cause }).toString()
          : '/login';
        window.location.href = url;
      }
    };
    window.addEventListener('certctl:auth-required', handler);
    return () => window.removeEventListener('certctl:auth-required', handler);
  }, []);

  const login = useCallback(async (key: string) => {
    setError(null);
    try {
      // /auth/check returns {status, user, admin}. Capture user + admin so the
      // GUI can hide admin-only affordances (bulk revoke, etc.).
      const resp = await checkAuth(key);
      setApiKey(key);
      setAuthenticated(true);
      setUser(resp.user ?? '');
      setAdmin(Boolean(resp.admin));
    } catch {
      setError('Invalid API key');
      throw new Error('Invalid API key');
    }
  }, []);

  const logout = useCallback(() => {
    // Bundle 2 Phase 8 — fire POST /auth/logout so the server can revoke the
    // session row + clear the HttpOnly session cookie. The API logout helper
    // sends `credentials: 'include'`. Errors are swallowed (the user's intent
    // is still to be logged out locally; e.g. cookie already expired).
    void apiLogout().catch(() => undefined);
    setApiKey(null);
    setAuthenticated(false);
    setUser('');
    setAdmin(false);
    setError(null);
  }, []);

  return (
    <AuthContext.Provider value={{ loading, authRequired, authenticated, authType, user, admin, login, logout, error }}>
      {/*
        Audit 2026-05-10 LOW-1 closure — demo-mode banner. When the
        server reports auth_type=none, every caller is the anonymous
        admin. Rendering a sticky red banner above the layout makes
        sure operators see this on every page; HIGH-12's startup
        check already fails closed for unsafe binds (0.0.0.0 / ::
        without CERTCTL_DEMO_MODE_ACK=true), so reaching this banner
        means the operator either ran on loopback or acknowledged
        the bypass — but the GUI still surfaces the state plainly.
      */}
      {authType === 'none' && !loading && (
        // FE-M6 closure 2026-05-14: was a 6-prop style={...} attr;
        // migrated to Tailwind utilities. Same visual: red banner,
        // white text, 8px/16px padding, 13px semibold center.
        <div
          data-testid="demo-mode-banner"
          role="alert"
          className="bg-red-700 text-white px-4 py-2 text-[13px] font-semibold text-center"
        >
          ⚠️ Demo mode active (CERTCTL_AUTH_TYPE=none). Every caller is anonymous admin.
          Production deployments MUST set CERTCTL_AUTH_TYPE=api-key or oidc.
        </div>
      )}
      {children}
    </AuthContext.Provider>
  );
}
