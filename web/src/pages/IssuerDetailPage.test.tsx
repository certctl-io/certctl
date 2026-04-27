import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): IssuerDetailPage XSS-hardening + render coverage.
//
// IssuerDetailPage surfaces the issuer's name, type, config blob keys, and
// last_test_message (operator-supplied or upstream-CA-supplied error string).
// A misconfigured-on-purpose CA or MITM that injects a <script> payload into
// the test-result message must not execute when surfaced in the GUI.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getIssuer: vi.fn(),
  testIssuerConnection: vi.fn(),
  getCertificates: vi.fn(),
}));

import IssuerDetailPage from './IssuerDetailPage';
import * as client from '../api/client';

function renderRoute(ui: ReactNode, path = '/issuers/iss-xss-001') {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/issuers/:id" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const xssPayload = '<script data-xss="issuer-detail">window.__xss_pwned__=1;</script>';

const xssIssuer = {
  id: 'iss-xss-001',
  name: xssPayload,
  type: xssPayload,
  enabled: true,
  config: { acme_directory_url: xssPayload, eab_kid: xssPayload },
  last_tested_at: new Date().toISOString(),
  last_test_status: 'failed',
  last_test_message: xssPayload,
};

describe('IssuerDetailPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when getIssuer resolves', async () => {
    vi.mocked(client.getIssuer).mockResolvedValue({ ...xssIssuer, name: 'Plain Name', type: 'acme' } as never);
    vi.mocked(client.getCertificates).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderRoute(<IssuerDetailPage />);
    await waitFor(() => {
      expect(screen.getByText('Plain Name')).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in name / config / test message', async () => {
    vi.mocked(client.getIssuer).mockResolvedValue(xssIssuer as never);
    vi.mocked(client.getCertificates).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderRoute(<IssuerDetailPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="issuer-detail">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="issuer-detail"]');
    expect(liveScripts.length, 'issuer fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'issuer <script> body must not have executed',
    ).toBeUndefined();
  });
});
