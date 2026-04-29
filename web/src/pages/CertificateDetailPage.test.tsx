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
  // CRL/OCSP-Responder Phase 5: revocation-panel mocks. fetchCRL +
  // getOCSPStatus are exercised by the "Test CRL fetch" / "Check OCSP
  // status" buttons; getAdminCRLCache backs the admin cache-age badge
  // and is gated by useAuth().admin at the call site.
  getOCSPStatus: vi.fn(),
  fetchCRL: vi.fn(),
  getAdminCRLCache: vi.fn(),
}));

// AuthProvider's useAuth hook is read by the new RevocationEndpointsCard to
// decide whether to render the cache-age badge. Mock it to keep the test
// independent of the real auth bootstrap (getAuthInfo / checkAuth).
vi.mock('../components/AuthProvider', () => ({
  useAuth: () => ({
    loading: false,
    authRequired: false,
    authenticated: true,
    authType: 'none',
    user: '',
    admin: false,
    login: vi.fn(),
    logout: vi.fn(),
    error: null,
  }),
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
  updated_at: new Date().toISOString(),
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
    // Default: no real network for the revocation panel — buttons remain
    // idle until a test exercises them. getAdminCRLCache resolves to an
    // empty rows array since the test mocks useAuth().admin = false.
    vi.mocked(client.fetchCRL).mockResolvedValue({ byteLength: 1234, contentType: 'application/pkix-crl' } as never);
    vi.mocked(client.getOCSPStatus).mockResolvedValue(new ArrayBuffer(256) as never);
    vi.mocked(client.getAdminCRLCache).mockResolvedValue({ cache_rows: [], row_count: 0, generated_at: new Date().toISOString() } as never);
  });

  it('renders the page when getCertificate resolves', async () => {
    vi.mocked(client.getCertificate).mockResolvedValue({ ...xssCert, common_name: 'plain.example.com' } as never);
    renderRoute(<CertificateDetailPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'plain.example.com' })).toBeInTheDocument();
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

// -----------------------------------------------------------------------------
// CRL/OCSP-Responder Phase 5: Revocation Endpoints panel coverage.
//
// Pins:
//   1. The CRL distribution point + OCSP responder URLs render with the
//      issuer_id substituted in (relying parties copy these straight into
//      curl/openssl, so the format is load-bearing).
//   2. Clicking "Test CRL fetch" calls fetchCRL(issuer_id) and surfaces the
//      byte-count success message — confirms the button is wired and not
//      decorative.
//   3. Clicking "Check OCSP status" calls getOCSPStatus(issuer_id, serial)
//      and surfaces the DER byte-count success message.
//   4. The admin cache-age badge stays HIDDEN when useAuth().admin is false
//      (the hook is mocked to admin: false at the top of this file). Stops
//      a regression where the badge silently leaks generation cadence to
//      non-admin viewers.
// -----------------------------------------------------------------------------

describe('CertificateDetailPage — Revocation Endpoints panel (Phase 5)', () => {
  const plainCert = {
    id: 'mc-rev-001',
    name: 'rev.example.com',
    common_name: 'rev.example.com',
    sans: ['rev.example.com'],
    status: 'Active',
    environment: 'prod',
    issuer_id: 'iss-local-prod',
    certificate_profile_id: 'cp-tls',
    owner_id: 'o-ops',
    team_id: 't-platform',
    renewal_policy_id: 'rp-30d',
    expires_at: new Date(Date.now() + 90 * 86400000).toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const certVersion = {
    id: 'cv-1',
    certificate_id: 'mc-rev-001',
    serial_number: 'a1b2c3d4',
    fingerprint_sha256: 'deadbeef'.repeat(8),
    not_before: new Date(Date.now() - 86400000).toISOString(),
    not_after: new Date(Date.now() + 90 * 86400000).toISOString(),
    key_algorithm: 'ECDSA',
    key_size: 256,
    created_at: new Date().toISOString(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getCertificate).mockResolvedValue(plainCert as never);
    vi.mocked(client.getCertificateVersions).mockResolvedValue({ data: [certVersion], total: 1, page: 1, per_page: 50 } as never);
    vi.mocked(client.getTargets).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.getProfile).mockResolvedValue({ id: 'cp-tls', name: 'TLS' } as never);
    vi.mocked(client.getProfiles).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.getRenewalPolicies).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 500 } as never);
    vi.mocked(client.getJobs).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.fetchCRL).mockResolvedValue({ byteLength: 4096, contentType: 'application/pkix-crl' } as never);
    vi.mocked(client.getOCSPStatus).mockResolvedValue(new ArrayBuffer(312) as never);
    vi.mocked(client.getAdminCRLCache).mockResolvedValue({ cache_rows: [], row_count: 0, generated_at: new Date().toISOString() } as never);
  });

  it('renders the CRL distribution point + OCSP responder URLs with the issuer_id substituted', async () => {
    const { fireEvent: _fe } = await import('@testing-library/react');
    void _fe;
    renderRoute(<CertificateDetailPage />, '/certificates/mc-rev-001');
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Revocation Endpoints' })).toBeInTheDocument();
    });

    // Both URLs include the issuer_id segment under /.well-known/pki/.
    // window.location.origin in jsdom is http://localhost:3000.
    expect(screen.getByText('http://localhost:3000/.well-known/pki/crl/iss-local-prod')).toBeInTheDocument();
    expect(screen.getByText('http://localhost:3000/.well-known/pki/ocsp/iss-local-prod')).toBeInTheDocument();
  });

  it('"Test CRL fetch" button calls fetchCRL(issuer_id) and shows the byte-count success message', async () => {
    const { fireEvent } = await import('@testing-library/react');
    renderRoute(<CertificateDetailPage />, '/certificates/mc-rev-001');
    const btn = await screen.findByRole('button', { name: /Test CRL fetch/i });
    fireEvent.click(btn);
    await waitFor(() => {
      expect(client.fetchCRL).toHaveBeenCalledWith('iss-local-prod');
      expect(screen.getByText(/OK — 4,096 bytes/)).toBeInTheDocument();
    });
  });

  it('"Check OCSP status" button calls getOCSPStatus(issuer_id, serial_hex) and shows DER byte-count', async () => {
    const { fireEvent } = await import('@testing-library/react');
    renderRoute(<CertificateDetailPage />, '/certificates/mc-rev-001');
    const btn = await screen.findByRole('button', { name: /Check OCSP status/i });
    fireEvent.click(btn);
    await waitFor(() => {
      expect(client.getOCSPStatus).toHaveBeenCalledWith('iss-local-prod', 'a1b2c3d4');
      expect(screen.getByText(/OCSP response received — 312 bytes/)).toBeInTheDocument();
    });
  });

  it('hides the admin cache-age badge when useAuth().admin is false (no information leak to non-admin)', async () => {
    renderRoute(<CertificateDetailPage />, '/certificates/mc-rev-001');
    await screen.findByRole('heading', { name: 'Revocation Endpoints' });
    // None of the badge variants ("Cache fresh" / "Cache stale" / "Not yet
    // generated") should appear for a non-admin caller.
    expect(screen.queryByText(/Cache fresh/i)).toBeNull();
    expect(screen.queryByText(/Cache stale/i)).toBeNull();
    expect(screen.queryByText(/Not yet generated/i)).toBeNull();
    // And the admin endpoint must not have been hit at all.
    expect(client.getAdminCRLCache).not.toHaveBeenCalled();
  });
});
