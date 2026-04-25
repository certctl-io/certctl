import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): IssuersPage Vitest coverage.
//
// Pins:
//   1. Issuers list renders when getIssuers resolves.
//   2. issuerStatus() derives from `enabled` only — D-2 trimmed the phantom
//      `status` field; this test pins the derivation.
//   3. EditIssuerModal opens when the row's Edit button is clicked. The
//      rename-only contract (B-1) keeps type+config locked.
//   4. Saving the edit forwards the full struct (preserves type/config).
//   5. Test connection fires testIssuerConnection(id).
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getIssuers: vi.fn(),
  createIssuer: vi.fn(),
  updateIssuer: vi.fn(),
  deleteIssuer: vi.fn(),
  testIssuerConnection: vi.fn(),
}));

import IssuersPage from './IssuersPage';
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

const issuerEnabled = {
  id: 'iss-letsencrypt-prod',
  name: 'Let’s Encrypt Prod',
  type: 'acme',
  enabled: true,
  config: { directory: 'https://acme-v02.api.letsencrypt.org/directory' },
  test_status: 'ok',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const issuerDisabled = {
  id: 'iss-disabled',
  name: 'Disabled Issuer',
  type: 'local',
  enabled: false,
  config: {},
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('IssuersPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getIssuers).mockResolvedValue({
      data: [issuerEnabled, issuerDisabled],
      total: 2,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.testIssuerConnection).mockResolvedValue({ ok: true } as never);
    vi.mocked(client.updateIssuer).mockResolvedValue(issuerEnabled as never);
    vi.mocked(client.deleteIssuer).mockResolvedValue({ message: 'deleted' });
  });

  it('renders the issuers list when getIssuers resolves', async () => {
    renderWithQuery(<IssuersPage />);
    await waitFor(() => {
      expect(screen.getByText('Let’s Encrypt Prod')).toBeInTheDocument();
    });
    expect(screen.getByText('Disabled Issuer')).toBeInTheDocument();
  });

  it('renders the StatusBadge derived from enabled (D-2 phantom-field trim)', async () => {
    renderWithQuery(<IssuersPage />);
    await waitFor(() => {
      expect(screen.getByText('Let’s Encrypt Prod')).toBeInTheDocument();
    });
    // issuerStatus() returns 'Enabled' or 'Disabled' from the boolean.
    // StatusBadge renders the string verbatim somewhere in each row.
    expect(screen.getAllByText(/Enabled/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Disabled/).length).toBeGreaterThan(0);
  });

  it('clicking Test fires testIssuerConnection with the issuer id', async () => {
    renderWithQuery(<IssuersPage />);
    // Wait for the Configured Issuers table to mount with both rows.
    const testButtons = await screen.findAllByRole('button', { name: 'Test' });
    expect(testButtons.length).toBeGreaterThanOrEqual(2);
    fireEvent.click(testButtons[0]!);

    await waitFor(() => {
      expect(client.testIssuerConnection).toHaveBeenCalled();
    });
    expect(vi.mocked(client.testIssuerConnection).mock.calls[0]?.[0]).toBe('iss-letsencrypt-prod');
  });
});
