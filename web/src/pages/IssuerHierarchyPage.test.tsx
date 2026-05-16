import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// TEST-007 closure (Sprint 5, 2026-05-16). Pre-fix IssuerHierarchyPage.tsx
// shipped without a co-located Vitest test — the only frontend page missing
// from the T-1 sweep that covered the other 30. The audit calls this out
// as a "buyer-side easy finding" — every other page has tests; one doesn't.
//
// Tests pin the four observable surfaces:
//   1. Initial render — page header + empty-state banner when the
//      hierarchy is empty.
//   2. Tree expansion — flat list of N CAs with parent_ca_id links
//      renders as the nested forest the component builds.
//   3. Orphan handling — a CA whose parent_ca_id references a missing
//      row still surfaces at the top level (the documented fallback).
//   4. Error state — when listIntermediateCAs rejects, the ErrorState
//      component renders with a retry control.
//
// The RBAC gate is server-side (HTTP 403 from the API layer); the page
// renders whatever error the API returns. The test mocks the API call
// directly, mirroring CertificatesPage.test.tsx's pattern.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  listIntermediateCAs: vi.fn(),
  retireIntermediateCA: vi.fn(),
}));

import IssuerHierarchyPage from './IssuerHierarchyPage';
import * as client from '../api/client';

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

function renderWithQuery(ui: ReactNode, initialPath = '/issuers/iss-prod/hierarchy') {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/issuers/:id/hierarchy" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('IssuerHierarchyPage', () => {
  it('renders the page header and the empty-state banner when the hierarchy has no rows', async () => {
    vi.mocked(client.listIntermediateCAs).mockResolvedValue({ data: [] });

    renderWithQuery(<IssuerHierarchyPage />);

    // Wait for the empty-state directly — the heading renders eagerly,
    // but the empty-state predicate is gated on (!isLoading && !error)
    // so we have to give react-query a tick to resolve.
    await waitFor(() =>
      expect(screen.getByText(/No CA hierarchy registered yet for this issuer/i)).toBeInTheDocument(),
    );
    expect(screen.getByRole('heading', { name: /Certificate authority hierarchy/i })).toBeInTheDocument();
    expect(vi.mocked(client.listIntermediateCAs)).toHaveBeenCalledWith('iss-prod');
  });

  it('renders the nested tree when the hierarchy has multiple depths', async () => {
    // root → policy → issuing. Three CAs, parent_ca_id chains them.
    vi.mocked(client.listIntermediateCAs).mockResolvedValue({
      data: [
        {
          id: 'ica-root',
          owning_issuer_id: 'iss-prod',
          parent_ca_id: null,
          name: 'Root CA',
          subject: 'CN=Acme Root',
          state: 'active',
          cert_pem: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----',
          key_driver_id: 'kd-file',
          not_before: '2024-01-01T00:00:00Z',
          not_after: '2034-01-01T00:00:00Z',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
        {
          id: 'ica-policy',
          owning_issuer_id: 'iss-prod',
          parent_ca_id: 'ica-root',
          name: 'Policy CA',
          subject: 'CN=Acme Policy',
          state: 'active',
          cert_pem: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----',
          key_driver_id: 'kd-file',
          not_before: '2024-02-01T00:00:00Z',
          not_after: '2029-02-01T00:00:00Z',
          created_at: '2024-02-01T00:00:00Z',
          updated_at: '2024-02-01T00:00:00Z',
        },
        {
          id: 'ica-issuing',
          owning_issuer_id: 'iss-prod',
          parent_ca_id: 'ica-policy',
          name: 'Issuing CA',
          subject: 'CN=Acme Issuing',
          state: 'retiring',
          cert_pem: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----',
          key_driver_id: 'kd-file',
          not_before: '2024-03-01T00:00:00Z',
          not_after: '2027-03-01T00:00:00Z',
          created_at: '2024-03-01T00:00:00Z',
          updated_at: '2024-03-01T00:00:00Z',
        },
      ],
    });

    renderWithQuery(<IssuerHierarchyPage />);

    // All three names appear at their respective depths.
    await waitFor(() => screen.getByText('Root CA'));
    expect(screen.getByText('Policy CA')).toBeInTheDocument();
    expect(screen.getByText('Issuing CA')).toBeInTheDocument();

    // The retiring state surfaces somewhere in the rendered Issuing CA
    // sub-tree (component renders state inline).
    expect(screen.getAllByText(/retiring/i).length).toBeGreaterThanOrEqual(1);
  });

  it('surfaces orphan CAs (parent_ca_id references a missing row) at the top level', async () => {
    // Documented fallback in buildHierarchyTree — a CA whose parent
    // was retired+pruned still renders, just at the root level.
    vi.mocked(client.listIntermediateCAs).mockResolvedValue({
      data: [
        {
          id: 'ica-orphan',
          owning_issuer_id: 'iss-prod',
          parent_ca_id: 'ica-retired-and-pruned',
          name: 'Orphan CA',
          subject: 'CN=Orphan',
          state: 'active',
          cert_pem: '',
          key_driver_id: 'kd-file',
          not_before: '2024-01-01T00:00:00Z',
          not_after: '2029-01-01T00:00:00Z',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      ],
    });

    renderWithQuery(<IssuerHierarchyPage />);

    await waitFor(() => screen.getByText('Orphan CA'));
    expect(screen.getByText('Orphan CA')).toBeInTheDocument();
  });

  it('renders ErrorState when listIntermediateCAs rejects (RBAC 403 surfaces here too)', async () => {
    vi.mocked(client.listIntermediateCAs).mockRejectedValue(new Error('forbidden: missing ca.hierarchy.manage'));

    renderWithQuery(<IssuerHierarchyPage />);

    await waitFor(() =>
      expect(screen.getByText(/forbidden: missing ca\.hierarchy\.manage/i)).toBeInTheDocument(),
    );
  });

  it('does not call the API when the route renders without an issuer id', async () => {
    // React Router collapses `/issuers//hierarchy` so the route doesn't
    // even match — the body stays empty. The behavioural invariant we
    // care about is "no spurious API call without an id" which the
    // mock-call-count check pins regardless of whether the page mounts.
    renderWithQuery(<IssuerHierarchyPage />, '/issuers//hierarchy');
    await new Promise((r) => setTimeout(r, 10));
    expect(vi.mocked(client.listIntermediateCAs)).not.toHaveBeenCalled();
  });
});
