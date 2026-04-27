import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): HealthMonitorPage XSS-hardening + render
// coverage. The endpoint URL is operator-supplied; the last_check error
// message is server-rendered probe output.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  listHealthChecks: vi.fn(),
  createHealthCheck: vi.fn(),
  deleteHealthCheck: vi.fn(),
  acknowledgeHealthCheck: vi.fn(),
  getHealthCheckSummary: vi.fn(),
}));

import HealthMonitorPage from './HealthMonitorPage';
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

const xssPayload = '<script data-xss="health">window.__xss_pwned__=1;</script>';

const xssCheck = {
  id: 'hc-xss-001',
  endpoint: xssPayload,
  status: 'failing',
  last_error: xssPayload,
  last_checked_at: new Date().toISOString(),
  acknowledged: false,
};

describe('HealthMonitorPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
    vi.mocked(client.getHealthCheckSummary).mockResolvedValue({ total: 0, failing: 0, ok: 0 } as never);
  });

  it('renders the page header when listHealthChecks resolves', async () => {
    vi.mocked(client.listHealthChecks).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 100 } as never);
    renderWithQuery(<HealthMonitorPage />);
    await waitFor(() => {
      expect(screen.getByText(/Health/i)).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in endpoint / last_error', async () => {
    vi.mocked(client.listHealthChecks).mockResolvedValue({
      data: [xssCheck],
      total: 1,
      page: 1,
      per_page: 100,
    } as never);
    renderWithQuery(<HealthMonitorPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="health">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="health"]');
    expect(liveScripts.length, 'health-check fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'health-check <script> body must not have executed',
    ).toBeUndefined();
  });
});
