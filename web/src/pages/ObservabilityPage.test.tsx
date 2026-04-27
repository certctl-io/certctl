import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): ObservabilityPage XSS-hardening + render coverage.
//
// ObservabilityPage renders server health + metrics. The Prometheus text
// payload (getPrometheusMetrics) is operator-facing free-form text; the
// existing implementation renders it inside a controlled <pre>{text}</pre>
// surface, which React's text-interpolation escapes automatically. This test
// pins that contract so a future refactor that switched to
// dangerouslySetInnerHTML for "rich" rendering wouldn't slip past CI.
//
// Pins:
//   1. Page renders.
//   2. health.status / metrics fields containing literal <script> payloads
//      do NOT execute.
//   3. The literal payload text appears as escaped content.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getMetrics: vi.fn(),
  getPrometheusMetrics: vi.fn(),
  getHealth: vi.fn(),
}));

import ObservabilityPage from './ObservabilityPage';
import * as client from '../api/client';

function renderWithQuery(ui: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const xssPayload = '<script data-xss="observability">window.__xss_pwned__=1;</script>';

describe('ObservabilityPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when metrics + health resolve', async () => {
    vi.mocked(client.getMetrics).mockResolvedValue({
      gauge: {
        certificate_total: 0,
        certificate_active: 0,
        certificate_expiring_soon: 0,
        certificate_expired: 0,
        certificate_revoked: 0,
        agent_total: 0,
        agent_online: 0,
        job_pending: 0,
      },
      counter: { job_completed_total: 0, job_failed_total: 0 },
      uptime: { uptime_seconds: 3600, server_started: new Date().toISOString(), measured_at: new Date().toISOString() },
    } as never);
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok' } as never);
    vi.mocked(client.getPrometheusMetrics).mockResolvedValue('# HELP up The current up state\nup 1\n' as never);

    renderWithQuery(<ObservabilityPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Observability' })).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in health.status / Prometheus text', async () => {
    vi.mocked(client.getMetrics).mockResolvedValue({
      gauge: {
        certificate_total: 0,
        certificate_active: 0,
        certificate_expiring_soon: 0,
        certificate_expired: 0,
        certificate_revoked: 0,
        agent_total: 0,
        agent_online: 0,
        job_pending: 0,
      },
      counter: { job_completed_total: 0, job_failed_total: 0 },
      uptime: { uptime_seconds: 3600, server_started: new Date().toISOString(), measured_at: new Date().toISOString() },
    } as never);
    vi.mocked(client.getHealth).mockResolvedValue({ status: xssPayload } as never);
    vi.mocked(client.getPrometheusMetrics).mockResolvedValue(xssPayload as never);

    renderWithQuery(<ObservabilityPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Observability' })).toBeInTheDocument();
    });

    const liveScripts = document.querySelectorAll('script[data-xss="observability"]');
    expect(liveScripts.length, 'observability data must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'observability <script> body must not have executed',
    ).toBeUndefined();
  });

  it('renders the literal Prometheus payload as escaped text', async () => {
    vi.mocked(client.getMetrics).mockResolvedValue({
      gauge: {
        certificate_total: 0,
        certificate_active: 0,
        certificate_expiring_soon: 0,
        certificate_expired: 0,
        certificate_revoked: 0,
        agent_total: 0,
        agent_online: 0,
        job_pending: 0,
      },
      counter: { job_completed_total: 0, job_failed_total: 0 },
      uptime: { uptime_seconds: 3600, server_started: new Date().toISOString(), measured_at: new Date().toISOString() },
    } as never);
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok' } as never);
    vi.mocked(client.getPrometheusMetrics).mockResolvedValue(xssPayload as never);

    renderWithQuery(<ObservabilityPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="observability">');
    });
  });
});
