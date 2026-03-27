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
    <div className="min-h-screen bg-page flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-brand-400 mb-2">certctl</h1>
          <p className="text-sm text-ink-muted uppercase tracking-wider">Certificate Control Plane</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-surface border border-surface-border rounded p-6 space-y-4 shadow-sm">
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
              autoFocus
              className="w-full bg-white border border-surface-border rounded px-3 py-2.5 text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20"
            />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !key.trim()}
            className="w-full bg-brand-400 hover:bg-brand-500 text-white py-2.5 text-sm font-medium rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting ? 'Verifying...' : 'Sign In'}
          </button>

          <p className="text-xs text-ink-muted text-center">
            The API key is set via <code className="text-ink-faint bg-page px-1 py-0.5 rounded">CERTCTL_AUTH_SECRET</code> on the server.
          </p>
        </form>
      </div>
    </div>
  );
}
