import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';
import { getAuthInfo, checkAuth, setApiKey } from '../api/client';

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

  // Listen for 401 events from the API client
  useEffect(() => {
    const handler = () => {
      setAuthenticated(false);
      setApiKey(null);
      setUser('');
      setAdmin(false);
      setError('Session expired. Please re-enter your API key.');
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
    setApiKey(null);
    setAuthenticated(false);
    setUser('');
    setAdmin(false);
    setError(null);
  }, []);

  return (
    <AuthContext.Provider value={{ loading, authRequired, authenticated, authType, user, admin, login, logout, error }}>
      {children}
    </AuthContext.Provider>
  );
}
