import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';
import { getAuthInfo, checkAuth, setApiKey } from '../api/client';

interface AuthState {
  loading: boolean;
  authRequired: boolean;
  authenticated: boolean;
  authType: string;
  login: (key: string) => Promise<void>;
  logout: () => void;
  error: string | null;
}

const AuthContext = createContext<AuthState>({
  loading: true,
  authRequired: false,
  authenticated: false,
  authType: 'none',
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
  const [error, setError] = useState<string | null>(null);

  // Check if server requires auth on mount
  useEffect(() => {
    getAuthInfo()
      .then((info) => {
        setAuthType(info.auth_type);
        setAuthRequired(info.required);
        if (!info.required) {
          setAuthenticated(true);
        }
      })
      .catch(() => {
        // If auth/info fails, assume no auth required (server may be old version)
        setAuthenticated(true);
      })
      .finally(() => setLoading(false));
  }, []);

  // Listen for 401 events from the API client
  useEffect(() => {
    const handler = () => {
      setAuthenticated(false);
      setApiKey(null);
      setError('Session expired. Please re-enter your API key.');
    };
    window.addEventListener('certctl:auth-required', handler);
    return () => window.removeEventListener('certctl:auth-required', handler);
  }, []);

  const login = useCallback(async (key: string) => {
    setError(null);
    try {
      await checkAuth(key);
      setApiKey(key);
      setAuthenticated(true);
    } catch {
      setError('Invalid API key');
      throw new Error('Invalid API key');
    }
  }, []);

  const logout = useCallback(() => {
    setApiKey(null);
    setAuthenticated(false);
    setError(null);
  }, []);

  return (
    <AuthContext.Provider value={{ loading, authRequired, authenticated, authType, login, logout, error }}>
      {children}
    </AuthContext.Provider>
  );
}
