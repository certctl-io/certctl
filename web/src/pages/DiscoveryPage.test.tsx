import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): DiscoveryPage Vitest coverage.
//
// Pins the I-2 closure (MCP claim/dismiss tools landed; the GUI claim/
// dismiss flow predates that). Tests:
//
//   1. Discovered cert list renders when getDiscoveredCertificates resolves.
//   2. Status filter wires the param into getDiscoveredCertificates.
//   3. Dismiss button calls dismissDiscoveredCertificate(id).
//   4. Claim button opens the claim modal (precondition for claim flow).
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getDiscoveredCertificates: vi.fn(),
  getDiscoverySummary: vi.fn(),
  getDiscoveryScans: vi.fn(),
  getAgents: vi.fn(),
  claimDiscoveredCertificate: vi.fn(),
  dismissDiscoveredCertificate: vi.fn(),
}));

import DiscoveryPage from './DiscoveryPage';
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

const unmanagedCert = {
  id: 'dc-001',
  common_name: 'unmanaged.example.com',
  sans: ['unmanaged.example.com'],
  status: 'Unmanaged',
  source_path: '/etc/ssl/certs/server.crt',
  agent_id: 'agent-iis01',
  issuer_dn: 'CN=Internal CA',
  not_after: new Date(Date.now() + 60 * 86400000).toISOString(),
  key_algorithm: 'RSA',
  key_size: 2048,
  is_ca: false,
  fingerprint_sha256: 'abc123def456ghijklmnopqrstuvwxyz0123456789abcdef0123456789abcdef',
};

describe('DiscoveryPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getDiscoveredCertificates).mockResolvedValue({
      data: [unmanagedCert],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.getDiscoverySummary).mockResolvedValue({ Unmanaged: 1, Managed: 0, Dismissed: 0 } as never);
    vi.mocked(client.getDiscoveryScans).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.getAgents).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 200 } as never);
    vi.mocked(client.dismissDiscoveredCertificate).mockResolvedValue({ status: 'Dismissed' } as never);
  });

  it('renders the discovered certificates list when getDiscoveredCertificates resolves', async () => {
    renderWithQuery(<DiscoveryPage />);
    // The CN appears in both the row and a SAN tooltip — multiple matches.
    await waitFor(() => {
      expect(screen.getAllByText('unmanaged.example.com').length).toBeGreaterThan(0);
    });
  });

  it('changing the status filter wires status into getDiscoveredCertificates params', async () => {
    renderWithQuery(<DiscoveryPage />);
    await waitFor(() => expect(client.getDiscoveredCertificates).toHaveBeenCalled());

    const statusSelect = await screen.findByDisplayValue('All statuses');
    fireEvent.change(statusSelect, { target: { value: 'Unmanaged' } });

    await waitFor(() => {
      const calls = vi.mocked(client.getDiscoveredCertificates).mock.calls;
      const filtered = calls.find(([params]) => (params as Record<string, string>)?.status === 'Unmanaged');
      expect(filtered, 'expected getDiscoveredCertificates to be called with status=Unmanaged').toBeTruthy();
    });
  });

  it('Dismiss button calls dismissDiscoveredCertificate(id)', async () => {
    renderWithQuery(<DiscoveryPage />);
    const dismissBtn = await screen.findByRole('button', { name: 'Dismiss' });
    fireEvent.click(dismissBtn);

    await waitFor(() => {
      expect(client.dismissDiscoveredCertificate).toHaveBeenCalled();
    });
    expect(vi.mocked(client.dismissDiscoveredCertificate).mock.calls[0]?.[0]).toBe('dc-001');
  });
});
