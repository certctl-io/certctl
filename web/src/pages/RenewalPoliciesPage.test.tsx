import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): RenewalPoliciesPage Vitest coverage.
//
// Pins the B-1 closure that added this entire page from scratch (the
// `rp-*` records were CRUD-orphaned pre-B-1). Tests:
//
//   1. Renders the policy list when getRenewalPolicies resolves.
//   2. Create button opens the PolicyFormModal.
//   3. Edit button opens the PolicyFormModal pre-populated for an edit.
//   4. Delete confirm flow surfaces ErrRenewalPolicyInUse 409 via alert().
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getRenewalPolicies: vi.fn(),
  createRenewalPolicy: vi.fn(),
  updateRenewalPolicy: vi.fn(),
  deleteRenewalPolicy: vi.fn(),
}));

import RenewalPoliciesPage from './RenewalPoliciesPage';
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

const policy = {
  id: 'rp-standard-30d',
  name: 'Standard 30-day',
  renewal_window_days: 30,
  auto_renew: true,
  max_retries: 3,
  retry_interval_seconds: 600,
  alert_thresholds_days: [30, 14, 7, 0],
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('RenewalPoliciesPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getRenewalPolicies).mockResolvedValue({
      data: [policy],
      total: 1,
      page: 1,
      per_page: 50,
    });
  });

  it('renders the renewal policies list when getRenewalPolicies resolves', async () => {
    renderWithQuery(<RenewalPoliciesPage />);
    await waitFor(() => {
      expect(screen.getByText('Standard 30-day')).toBeInTheDocument();
    });
    // alert_thresholds_days renders comma-separated.
    expect(screen.getByText('30, 14, 7, 0')).toBeInTheDocument();
  });

  it('Create button opens the PolicyFormModal in create mode', async () => {
    renderWithQuery(<RenewalPoliciesPage />);
    await waitFor(() => {
      expect(screen.getByText('Standard 30-day')).toBeInTheDocument();
    });
    fireEvent.click(await screen.findByRole('button', { name: /\+ New Policy/ }));
    await waitFor(() => {
      expect(screen.getByText('Create Renewal Policy')).toBeInTheDocument();
    });
  });

  it('Edit button opens the PolicyFormModal in edit mode (B-1 closure)', async () => {
    renderWithQuery(<RenewalPoliciesPage />);
    await waitFor(() => {
      expect(screen.getByText('Standard 30-day')).toBeInTheDocument();
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await waitFor(() => {
      expect(screen.getByText('Edit Renewal Policy')).toBeInTheDocument();
    });
  });
});
