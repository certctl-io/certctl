import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): TargetDetailPage XSS-hardening + render coverage.
//
// TargetDetailPage surfaces the target's name, type, config (operator-supplied
// host/port/path), and last_test_message (target-side error string from a
// connection probe). A target that returns an attacker-controlled error
// payload must not execute as script when rendered.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getTarget: vi.fn(),
  getJobs: vi.fn(),
  updateTarget: vi.fn(),
  testTargetConnection: vi.fn(),
}));

import TargetDetailPage from './TargetDetailPage';
import * as client from '../api/client';

function renderRoute(ui: ReactNode, path = '/targets/t-xss-001') {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/targets/:id" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const xssPayload = '<script data-xss="target-detail">window.__xss_pwned__=1;</script>';

const xssTarget = {
  id: 't-xss-001',
  name: xssPayload,
  type: 'nginx',
  agent_id: 'a-xss',
  config: { host: xssPayload, path: xssPayload },
  last_tested_at: new Date().toISOString(),
  last_test_status: 'failed',
  last_test_message: xssPayload,
};

describe('TargetDetailPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when getTarget resolves', async () => {
    vi.mocked(client.getTarget).mockResolvedValue({ ...xssTarget, name: 'Plain Name' } as never);
    vi.mocked(client.getJobs).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderRoute(<TargetDetailPage />);
    await waitFor(() => {
      expect(screen.getByText('Plain Name')).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in name / config / test message', async () => {
    vi.mocked(client.getTarget).mockResolvedValue(xssTarget as never);
    vi.mocked(client.getJobs).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderRoute(<TargetDetailPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="target-detail">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="target-detail"]');
    expect(liveScripts.length, 'target fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'target <script> body must not have executed',
    ).toBeUndefined();
  });
});
