import type { ReactNode } from 'react';
import { useAuth } from './AuthProvider';
import LoginPage from '../pages/LoginPage';

export default function AuthGate({ children }: { children: ReactNode }) {
  const { loading, authRequired, authenticated } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-blue-400 mb-2">certctl</h1>
          <p className="text-sm text-slate-400">Connecting...</p>
        </div>
      </div>
    );
  }

  if (authRequired && !authenticated) {
    return <LoginPage />;
  }

  return <>{children}</>;
}
