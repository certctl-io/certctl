import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): CertificateDetailPage XSS-hardening + render
// coverage.
//
// CertificateDetailPage surfaces cert subject DN, SANs, issuer DN, version
// history, deployment job error messages — every one of these is either
// CSR-controlled (subject / SANs) or upstream-CA / target-side error text.
// The M-004 MCP fence handles inside-LLM safety; this test pins GUI XSS
// safety on the same data.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getCertificate: vi.fn(),
  getCertificateVersions: vi.fn(),
  getTargets: vi.fn(),
  getProfile: vi.fn(),
  getProfiles: vi.fn(),
  getJobs: vi.fn(),
  getRenewalPolicies: vi.fn(),
  triggerRenewal: vi.fn(),
  triggerDeployment: vi.fn(),
  archiveCertificate: vi.fn(),
  revokeCertificate: vi.fn(),
  updateCertificate: vi.fn(),
  downloadCertificatePEM: vi.fn(),
  exportCertificatePKCS12: vi.fn(),
}));

import CertificateDetailPage from './CertificateDetailPage';
import * as client from '../api/client';

function renderRoute(ui: ReactNode, path = '/certificates/mc-xss-001') {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/certificates/:id" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const xssPayload = '<script data-xss="cert-detail">window.__xss_pwned__=1;</script>';

const xssCert = {
  id: 'mc-xss-001',
  name: xssPayload,
  common_name: xssPayload,
  sans: [xssPayload, 'plain.example.com'],
  status: 'Active',
  environment: xssPayload,
  issuer_id: 'iss-xss',
  certificate_profile_id: 'cp-xss',
  owner_id: 'o-xss',
  team_id: 't-xss',
  renewal_policy_id: 'rp-xss',
  expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
  created_at: new Date().toISOString(),
  not_before: new Date(Date.now() - 86400000).toISOString(),
  not_after: new Date(Date.now() + 30 * 86400000).toISOString(),
  serial_number: xssPayload,
  fingerprint_sha256: xssPayload,
  pem_encoded: xssPayload,
};

describe('CertificateDetailPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;

    // Wire defaults for the sidecar queries — every page render fans out
    // 7+ queries and any unmocked call will reject and surface an error
    // boundary instead of the page body.
    vi.mocked(client.getCertificate).mockResolvedValue(xssCert as never);
    vi.mocked(client.getCertificateVersions).mockResolvedValue([] as never);
    vi.mocked(client.getTargets).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.getProfile).mockResolvedValue({ id: 'cp-xss', name: 'Profile' } as never);
    vi.mocked(client.getProfiles).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.getRenewalPolicies).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 500 } as never);
    vi.mocked(client.getJobs).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
  });

  it('renders the page when getCertificate resolves', async () => {
    vi.mocked(client.getCertificate).mockResolvedValue({ ...xssCert, common_name: 'plain.example.com' } as never);
    renderRoute(<CertificateDetailPage />);
    await waitFor(() => {
      expect(screen.getByText('plain.example.com')).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in cert subject / SANs / serial / pem', async () => {
    renderRoute(<CertificateDetailPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="cert-detail">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="cert-detail"]');
    expect(liveScripts.length, 'cert fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'cert <script> body must not have executed',
    ).toBeUndefined();
  });
});
