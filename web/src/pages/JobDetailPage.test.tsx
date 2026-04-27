import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): JobDetailPage XSS-hardening + render coverage.
//
// JobDetailPage surfaces the job's status / type / error_message / verification
// payload / audit-event fan-out. Job error_message is server-rendered upstream
// CA error text (ACME, DigiCert, etc.) — those CAs return free-form strings
// that the M-004 MCP fence handles inside LLM context, but a defensive XSS
// layer is needed in the GUI rendering path too.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getJob: vi.fn(),
  getJobVerification: vi.fn(),
  getAuditEvents: vi.fn(),
}));

import JobDetailPage from './JobDetailPage';
import * as client from '../api/client';

function renderRoute(ui: ReactNode, path = '/jobs/j-xss-001') {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/jobs/:id" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const xssPayload = '<script data-xss="job-detail">window.__xss_pwned__=1;</script>';

const xssJob = {
  id: 'j-xss-001',
  type: xssPayload,
  status: 'Failed',
  certificate_id: 'mc-xss',
  agent_id: 'a-xss',
  error_message: xssPayload,
  details: { reason: xssPayload },
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('JobDetailPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page when getJob resolves', async () => {
    vi.mocked(client.getJob).mockResolvedValue({ ...xssJob, type: 'renewal', error_message: '' } as never);
    vi.mocked(client.getJobVerification).mockResolvedValue(null as never);
    vi.mocked(client.getAuditEvents).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 10 } as never);
    renderRoute(<JobDetailPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /j-xss-001/ })).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in job error_message / type / details', async () => {
    vi.mocked(client.getJob).mockResolvedValue(xssJob as never);
    vi.mocked(client.getJobVerification).mockResolvedValue(null as never);
    vi.mocked(client.getAuditEvents).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 10 } as never);
    renderRoute(<JobDetailPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="job-detail">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="job-detail"]');
    expect(liveScripts.length, 'job fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'job <script> body must not have executed',
    ).toBeUndefined();
  });
});
