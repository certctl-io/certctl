import { useState } from 'react';
import { useAuth } from '../components/AuthProvider';

export default function LoginPage() {
  const { login, error: authError } = useAuth();
  const [key, setKey] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const error = localError || authError;

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

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-blue-400 mb-2">certctl</h1>
          <p className="text-sm text-slate-400 uppercase tracking-wider">Certificate Control Plane</p>
        </div>

        <form onSubmit={handleSubmit} className="card p-6 space-y-4">
          <div>
            <label htmlFor="api-key" className="block text-sm font-medium text-slate-300 mb-1.5">
              API Key
            </label>
            <input
              id="api-key"
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="Enter your API key"
              autoFocus
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !key.trim()}
            className="w-full btn-primary py-2.5 text-sm font-medium rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting ? 'Verifying...' : 'Sign In'}
          </button>

          <p className="text-xs text-slate-500 text-center">
            The API key is set via <code className="text-slate-400">CERTCTL_AUTH_SECRET</code> on the server.
          </p>
        </form>
      </div>
    </div>
  );
}
