import { useQuery } from '@tanstack/react-query';
import { getMetrics, getPrometheusMetrics, getHealth } from '../api/client';
import PageHeader from '../components/PageHeader';
import ErrorState from '../components/ErrorState';

function MetricCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-surface border border-surface-border rounded p-4 shadow-sm">
      <div className="text-xs text-ink-muted mb-1">{label}</div>
      <div className="text-2xl font-bold text-ink">{value}</div>
      {sub && <div className="text-xs text-ink-faint mt-1">{sub}</div>}
    </div>
  );
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export default function ObservabilityPage() {
  const { data: metrics, isLoading, error, refetch } = useQuery({
    queryKey: ['metrics'],
    queryFn: getMetrics,
    refetchInterval: 15000,
  });

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 15000,
  });

  const { data: promText } = useQuery({
    queryKey: ['prometheus-metrics'],
    queryFn: getPrometheusMetrics,
    refetchInterval: 30000,
    retry: false,
  });

  if (error) {
    return (
      <>
        <PageHeader title="Observability" />
        <ErrorState error={error as Error} onRetry={() => refetch()} />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Observability"
        subtitle={health ? `Server: ${health.status}` : undefined}
      />

      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
        {/* Health status */}
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${health?.status === 'ok' ? 'bg-emerald-500' : 'bg-red-500'}`} />
          <span className="text-sm text-ink font-medium">
            Server {health?.status === 'ok' ? 'Healthy' : 'Unhealthy'}
          </span>
          {metrics && (
            <span className="text-xs text-ink-faint ml-auto">
              Uptime: {formatUptime(metrics.uptime.uptime_seconds)} | Started: {new Date(metrics.uptime.server_started).toLocaleString()}
            </span>
          )}
        </div>

        {/* Gauge metrics */}
        {isLoading && (
          <div className="text-sm text-ink-muted py-10 text-center">Loading metrics...</div>
        )}

        {metrics && (
          <>
            <div>
              <h3 className="text-sm font-semibold text-ink-muted mb-3">Certificate Gauges</h3>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <MetricCard label="Total" value={metrics.gauge.certificate_total} />
                <MetricCard label="Active" value={metrics.gauge.certificate_active} />
                <MetricCard label="Expiring Soon" value={metrics.gauge.certificate_expiring_soon} />
                <MetricCard label="Expired" value={metrics.gauge.certificate_expired} />
                <MetricCard label="Revoked" value={metrics.gauge.certificate_revoked} />
              </div>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-ink-muted mb-3">Agent & Job Gauges</h3>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <MetricCard label="Total Agents" value={metrics.gauge.agent_total} />
                <MetricCard label="Online Agents" value={metrics.gauge.agent_online} />
                <MetricCard label="Pending Jobs" value={metrics.gauge.job_pending} />
              </div>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-ink-muted mb-3">Counters</h3>
              <div className="grid grid-cols-2 md:grid-cols-2 gap-3">
                <MetricCard label="Jobs Completed (total)" value={metrics.counter.job_completed_total} />
                <MetricCard label="Jobs Failed (total)" value={metrics.counter.job_failed_total} />
              </div>
            </div>
          </>
        )}

        {/* Prometheus config */}
        <div>
          <h3 className="text-sm font-semibold text-ink-muted mb-3">Prometheus Integration</h3>
          <div className="bg-surface border border-surface-border rounded p-4 shadow-sm">
            <p className="text-sm text-ink mb-3">
              Add this scrape target to your <code className="text-xs bg-surface-muted px-1 py-0.5 rounded">prometheus.yml</code>:
            </p>
            <pre className="bg-ink text-white rounded p-4 text-xs overflow-x-auto font-mono">
{`scrape_configs:
  - job_name: 'certctl'
    metrics_path: '/api/v1/metrics/prometheus'
    scheme: 'https'
    bearer_token: '<YOUR_API_KEY>'
    static_configs:
      - targets: ['<CERTCTL_HOST>:443']`}
            </pre>
          </div>
        </div>

        {/* Live Prometheus output */}
        {promText && (
          <div>
            <h3 className="text-sm font-semibold text-ink-muted mb-3">Live Prometheus Output</h3>
            <div className="bg-surface border border-surface-border rounded shadow-sm">
              <div className="px-4 py-2 border-b border-surface-border flex items-center justify-between">
                <span className="text-xs text-ink-faint font-mono">GET /api/v1/metrics/prometheus</span>
                <span className="text-xs text-ink-faint">text/plain</span>
              </div>
              <pre className="p-4 text-xs text-ink-muted overflow-x-auto font-mono max-h-96 overflow-y-auto whitespace-pre">
                {promText}
              </pre>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
