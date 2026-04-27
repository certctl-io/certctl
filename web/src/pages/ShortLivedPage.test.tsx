import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): ShortLivedPage XSS-hardening + render coverage.
//
// ShortLivedPage renders a filtered subset of certificates (those tied to a
// short-lived profile or with <1h remaining). Cert subject DN / SAN / id /
// environment / issuer_id all flow into JSX text — these are operator-
// controlled or CSR-controlled fields and a careless refactor that switched
// to dangerouslySetInnerHTML would let an attacker-controlled CSR deliver
// an XSS payload via subject DN.
//
// Pins:
//   1. Page renders.
//   2. Cert fields containing literal <script> payloads do NOT execute.
//   3. The literal payload text appears as escaped content.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getCertificates: vi.fn(),
  getProfiles: vi.fn(),
}));

import ShortLivedPage from './ShortLivedPage';
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

const inOneHour = new Date(Date.now() + 30 * 60 * 1000).toISOString();
const xssPayload = '<script data-xss="shortlived">window.__xss_pwned__=1;</script>';

const xssCert = {
  id: 'mc-xss-001',
  name: xssPayload,
  common_name: xssPayload,
  status: 'Active',
  environment: xssPayload,
  issuer_id: xssPayload,
  certificate_profile_id: 'cp-shortlived',
  expires_at: inOneHour,
  created_at: new Date().toISOString(),
};

describe('ShortLivedPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when certs resolve', async () => {
    vi.mocked(client.getCertificates).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.getProfiles).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderWithQuery(<ShortLivedPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Short-Lived Credentials' })).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads embedded in cert fields', async () => {
    vi.mocked(client.getCertificates).mockResolvedValue({
      data: [xssCert],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.getProfiles).mockResolvedValue({
      data: [{ id: 'cp-shortlived', name: 'Short-lived', allow_short_lived: true, max_ttl_seconds: 60 }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);

    renderWithQuery(<ShortLivedPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Short-Lived Credentials' })).toBeInTheDocument();
    });

    const liveScripts = document.querySelectorAll('script[data-xss="shortlived"]');
    expect(liveScripts.length, 'cert subject must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'cert <script> body must not have executed',
    ).toBeUndefined();
  });

  it('renders the literal payload as escaped text', async () => {
    vi.mocked(client.getCertificates).mockResolvedValue({
      data: [xssCert],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.getProfiles).mockResolvedValue({
      data: [{ id: 'cp-shortlived', name: 'Short-lived', allow_short_lived: true, max_ttl_seconds: 60 }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);

    renderWithQuery(<ShortLivedPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="shortlived">');
    });
  });
});
