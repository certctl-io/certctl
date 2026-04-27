import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): JobsPage XSS-hardening + render coverage.
// Job error_message is upstream-CA / target-side text — operator-controllable.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getJobs: vi.fn(),
  cancelJob: vi.fn(),
  approveRenewal: vi.fn(),
  rejectRenewal: vi.fn(),
}));

import JobsPage from './JobsPage';
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

const xssPayload = '<script data-xss="jobs">window.__xss_pwned__=1;</script>';

const xssJob = {
  id: 'j-xss-001',
  type: xssPayload,
  status: 'Failed',
  certificate_id: xssPayload,
  agent_id: xssPayload,
  error_message: xssPayload,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('JobsPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when getJobs resolves', async () => {
    vi.mocked(client.getJobs).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderWithQuery(<JobsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Jobs' })).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in job fields', async () => {
    vi.mocked(client.getJobs).mockResolvedValue({ data: [xssJob], total: 1, page: 1, per_page: 50 } as never);
    renderWithQuery(<JobsPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="jobs">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="jobs"]');
    expect(liveScripts.length, 'job fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'job <script> body must not have executed',
    ).toBeUndefined();
  });
});
