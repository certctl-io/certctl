import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): PoliciesPage Vitest coverage.
//
// The page renders the D-006/D-008 TitleCase PolicyType + PolicySeverity
// contract. It owns the create / toggle-enabled / delete CRUD surface for
// pol-* compliance rules. This file pins:
//
//   1. Rule list renders when getPolicies resolves.
//   2. Severity badge is keyed on the TitleCase enum (Warning/Error/Critical).
//   3. Toggling enabled calls updatePolicy(id, { enabled: !current }).
//   4. Delete calls deletePolicy(id) when the confirm dialog returns true.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getPolicies: vi.fn(),
  createPolicy: vi.fn(),
  updatePolicy: vi.fn(),
  deletePolicy: vi.fn(),
}));

import PoliciesPage from './PoliciesPage';
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

const policyEnabled = {
  id: 'pol-key-length',
  name: 'Key Length Enforcement',
  type: 'CertificateLifetime' as const,
  severity: 'Critical' as const,
  config: { min_bits: 2048 },
  enabled: true,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const policyWarning = {
  id: 'pol-allowed-issuers',
  name: 'Approved CA Issuers',
  type: 'AllowedIssuers' as const,
  severity: 'Warning' as const,
  config: { allowed: ['iss-letsencrypt'] },
  enabled: true,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('PoliciesPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getPolicies).mockResolvedValue({
      data: [policyEnabled, policyWarning],
      total: 2,
      page: 1,
      per_page: 50,
    });
    vi.mocked(client.updatePolicy).mockResolvedValue(policyEnabled);
    vi.mocked(client.deletePolicy).mockResolvedValue({ message: 'deleted' });
  });

  it('renders the policy list when getPolicies resolves', async () => {
    renderWithQuery(<PoliciesPage />);
    await waitFor(() => {
      expect(screen.getByText('Key Length Enforcement')).toBeInTheDocument();
    });
    expect(screen.getByText('Approved CA Issuers')).toBeInTheDocument();
  });

  it('renders the TitleCase severity (D-006/D-008 contract)', async () => {
    renderWithQuery(<PoliciesPage />);
    await waitFor(() => {
      expect(screen.getByText('Key Length Enforcement')).toBeInTheDocument();
    });
    // Critical badge text appears in both the column cell and the severity
    // count chip — at least one match. Pre-D-006 the severity dropdown was
    // keyed on lowercase strings that never matched the backend's TitleCase
    // enum; this assertion pins the post-D-006 contract.
    await waitFor(() => {
      expect(screen.getAllByText('Critical').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Warning').length).toBeGreaterThan(0);
    });
  });

  it('toggling Enabled calls updatePolicy with the inverted enabled flag', async () => {
    renderWithQuery(<PoliciesPage />);
    await waitFor(() => expect(client.getPolicies).toHaveBeenCalled());

    const enabledBtn = (await screen.findAllByRole('button', { name: /^Enabled$/ }))[0]!;
    fireEvent.click(enabledBtn);

    await waitFor(() => {
      expect(client.updatePolicy).toHaveBeenCalledWith('pol-key-length', { enabled: false });
    });
  });

  it('Delete calls deletePolicy(id) when confirm returns true', async () => {
    const origConfirm = globalThis.confirm;
    const confirmFn = vi.fn(() => true);
    globalThis.confirm = confirmFn;
    try {
      renderWithQuery(<PoliciesPage />);
      await waitFor(() => {
        expect(screen.getByText('Key Length Enforcement')).toBeInTheDocument();
      });

      // Click the first row's Delete button (pol-key-length renders first).
      // The button is rendered as a <button> with className text-red-*; query
      // by accessible role + name. There are two rows so two Delete buttons.
      const deleteButtons = await screen.findAllByRole('button', { name: 'Delete' });
      expect(deleteButtons.length).toBeGreaterThanOrEqual(2);
      fireEvent.click(deleteButtons[0]!);

      // The confirm prompt is fired synchronously inside the onClick. If the
      // user-presented prompt returns true, the deletePolicy mutation fires.
      await waitFor(() => {
        expect(confirmFn).toHaveBeenCalled();
      });
      // The mutation invalidates the policies query on success; that's enough
      // proof the delete path executed end-to-end. The exact id is the first
      // row in the mocked dataset.
      await waitFor(() => {
        expect(client.deletePolicy).toHaveBeenCalled();
      });
      expect(vi.mocked(client.deletePolicy).mock.calls[0]?.[0]).toBe('pol-key-length');
    } finally {
      globalThis.confirm = origConfirm;
    }
  });
});
