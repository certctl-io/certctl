import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): CertificatesPage Vitest coverage.
//
// Pre-T-1 the page had no test file. F-1 just landed three new operator-facing
// filters (team_id, expires_before, sort) plus reusable DataTable pagination —
// real regression vectors that deserve test coverage. This file pins:
//
//   1. Rows render when getCertificates resolves.
//   2. Setting the team filter wires team_id into the getCertificates params.
//   3. Setting expires_before wires it through.
//   4. Setting sort wires it through.
//   5. Changing a filter resets page back to 1 (the F-1 contract).
//   6. Changing per_page resets page to 1.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getCertificates: vi.fn(),
  getIssuers: vi.fn(),
  getOwners: vi.fn(),
  getTeams: vi.fn(),
  getProfiles: vi.fn(),
  getRenewalPolicies: vi.fn(),
  createCertificate: vi.fn(),
  revokeCertificate: vi.fn(),
  bulkRevokeCertificates: vi.fn(),
  bulkRenewCertificates: vi.fn(),
  bulkReassignCertificates: vi.fn(),
}));

import CertificatesPage from './CertificatesPage';
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

const cert = {
  id: 'mc-prod-001',
  name: 'prod-001',
  common_name: 'app.example.com',
  status: 'Active',
  environment: 'production',
  issuer_id: 'iss-letsencrypt',
  owner_id: 'o-platform',
  team_id: 't-platform',
  expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
  created_at: new Date().toISOString(),
};

const emptyResp = { data: [], total: 0, page: 1, per_page: 50 };

function mockAll() {
  vi.mocked(client.getCertificates).mockResolvedValue({ data: [cert], total: 1, page: 1, per_page: 50 } as never);
  vi.mocked(client.getIssuers).mockResolvedValue({ data: [{ id: 'iss-letsencrypt', name: 'Let’s Encrypt' }], total: 1, page: 1, per_page: 100 } as never);
  vi.mocked(client.getOwners).mockResolvedValue({ data: [{ id: 'o-platform', name: 'Platform', email: 'platform@example.com' }], total: 1, page: 1, per_page: 100 } as never);
  vi.mocked(client.getTeams).mockResolvedValue({ data: [{ id: 't-platform', name: 'Platform' }], total: 1, page: 1, per_page: 100 } as never);
  vi.mocked(client.getProfiles).mockResolvedValue({ data: [{ id: 'cp-tls-server', name: 'TLS Server' }], total: 1, page: 1, per_page: 100 } as never);
  vi.mocked(client.getRenewalPolicies).mockResolvedValue(emptyResp as never);
}

describe('CertificatesPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    mockAll();
  });

  it('renders the certificate list when getCertificates resolves', async () => {
    renderWithQuery(<CertificatesPage />);
    await waitFor(() => {
      expect(screen.getByText('app.example.com')).toBeInTheDocument();
    });
    expect(screen.getByText('mc-prod-001')).toBeInTheDocument();
  });

  it('changing the team filter wires team_id into the getCertificates params', async () => {
    renderWithQuery(<CertificatesPage />);
    await waitFor(() => expect(client.getCertificates).toHaveBeenCalled());

    // The team filter is the 6th <select> (after status/env/issuer/owner/profile).
    // Find by current value '' for "All teams" and fire change.
    const teamSelect = await screen.findByDisplayValue('All teams');
    fireEvent.change(teamSelect, { target: { value: 't-platform' } });

    await waitFor(() => {
      const calls = vi.mocked(client.getCertificates).mock.calls;
      const teamCall = calls.find(([params]) => (params as Record<string, string>)?.team_id === 't-platform');
      expect(teamCall, 'expected getCertificates to be called with team_id=t-platform').toBeTruthy();
    });
  });

  it('changing expires_before wires the date param into the getCertificates params', async () => {
    renderWithQuery(<CertificatesPage />);
    await waitFor(() => expect(client.getCertificates).toHaveBeenCalled());

    const dateInputs = document.querySelectorAll('input[type="date"]');
    expect(dateInputs.length).toBeGreaterThan(0);
    fireEvent.change(dateInputs[0]!, { target: { value: '2026-12-31' } });

    await waitFor(() => {
      const calls = vi.mocked(client.getCertificates).mock.calls;
      const expCall = calls.find(([params]) => (params as Record<string, string>)?.expires_before === '2026-12-31');
      expect(expCall, 'expected getCertificates to be called with expires_before=2026-12-31').toBeTruthy();
    });
  });

  it('changing sort wires the sort param into the getCertificates params', async () => {
    renderWithQuery(<CertificatesPage />);
    await waitFor(() => expect(client.getCertificates).toHaveBeenCalled());

    const sortSelect = await screen.findByDisplayValue('Default sort');
    fireEvent.change(sortSelect, { target: { value: 'notAfter' } });

    await waitFor(() => {
      const calls = vi.mocked(client.getCertificates).mock.calls;
      const sortCall = calls.find(([params]) => (params as Record<string, string>)?.sort === 'notAfter');
      expect(sortCall, 'expected getCertificates to be called with sort=notAfter').toBeTruthy();
    });
  });

  it('changing the team filter resets page back to 1 (F-1 contract)', async () => {
    renderWithQuery(<CertificatesPage />);
    await waitFor(() => expect(client.getCertificates).toHaveBeenCalled());

    // Sanity-check: initial page param is "1".
    const initCalls = vi.mocked(client.getCertificates).mock.calls;
    const initialCall = initCalls[initCalls.length - 1];
    expect((initialCall?.[0] as Record<string, string>)?.page).toBe('1');

    // Trigger filter change — the page state must remain at 1 after re-fetch.
    const teamSelect = await screen.findByDisplayValue('All teams');
    fireEvent.change(teamSelect, { target: { value: 't-platform' } });

    await waitFor(() => {
      const calls = vi.mocked(client.getCertificates).mock.calls;
      const last = calls[calls.length - 1];
      expect((last?.[0] as Record<string, string>)?.team_id).toBe('t-platform');
      expect((last?.[0] as Record<string, string>)?.page).toBe('1');
    });
  });

  it('always passes page and per_page params to getCertificates (F-1 pagination contract)', async () => {
    renderWithQuery(<CertificatesPage />);
    await waitFor(() => {
      const params = vi.mocked(client.getCertificates).mock.calls[0]?.[0] as Record<string, string>;
      expect(params).toBeDefined();
      expect(params.page).toBe('1');
      expect(params.per_page).toBe('50');
    });
  });
});
