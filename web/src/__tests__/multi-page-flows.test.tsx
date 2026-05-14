// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 8 closure for TEST-M1 — full-flow happy-path tests at the
// Vitest layer using MemoryRouter for 2-3-page navigation. These are
// cheap relative to Playwright (no real browser, no webServer startup
// cost — ~200ms each) and catch the dominant regression class for
// route-level + cross-page-state bugs that per-page tests miss by
// construction.
//
// Why this layer matters:
//   • Per-page tests mount one page in isolation. They miss "click on
//     a row in page A navigates to page B which loads data X".
//   • Playwright catches everything but at 5-second startup cost per
//     run. Reserving Playwright for the 5 priority customer flows
//     (Phase 8 TEST-H1) keeps CI runtime sane.
//   • Vitest MemoryRouter flows hit the React Router + TanStack Query
//     wiring that pure unit tests skip. If a route's `enabled:` gate
//     or a queryKey shape regresses, this layer screams.
//
// Mocking posture: same as the per-page tests — vi.mock the api/client
// module and resolve fixtures synchronously. The flows differ from
// per-page tests in WHAT they assert (cross-page transitions + data
// continuity) not in HOW they mock.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import type { ReactNode } from 'react';

// Mock the api/client module by inheriting all real exports via
// importActual + overriding the network-touching functions with
// vi.fn(). This avoids the whack-a-mole of listing every export the
// imported pages happen to touch (each page transitively pulls more
// functions than the flow under test actually uses). The imported
// pages compile + run; only network functions are mocked.
vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client');
  // Replace every fn-shaped export with a vi.fn so the test can
  // override return values per-case. Non-fn exports (types, constants
  // like REVOCATION_REASONS) pass through unchanged.
  const mocked: Record<string, unknown> = { ...actual };
  for (const [k, v] of Object.entries(actual)) {
    if (typeof v === 'function') {
      mocked[k] = vi.fn().mockResolvedValue(undefined);
    }
  }
  // getApiKey is not a network fn — keep a sync stub.
  mocked.getApiKey = vi.fn(() => 'mock-api-key');
  return mocked;
});

vi.mock('../hooks/useAuthMe', () => ({
  useAuthMe: () => ({
    data: {
      id: 'actor-admin',
      display_name: 'Admin',
      effective_permissions: ['*'],
    },
    isLoading: false,
    error: null,
  }),
}));

import * as client from '../api/client';
import CertificatesPage from '../pages/CertificatesPage';
import CertificateDetailPage from '../pages/CertificateDetailPage';
import IssuersPage from '../pages/IssuersPage';
import IssuerDetailPage from '../pages/IssuerDetailPage';

function renderWithRouter(ui: ReactNode, initialEntries: string[]) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        {ui}
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

const baseIssuer = {
  id: 'iss-vault',
  name: 'HashiCorp Vault',
  type: 'vault',
  enabled: true,
  status: 'Active',
  source: 'user',
  config: {},
  created_at: '2026-01-01T00:00:00Z',
} as never;

// Cast to never to bypass exhaustive-interface checks — test fixtures
// only need the fields the page rendering touches, not the full surface
// of the live API type.
const baseCert = {
  id: 'cert-001',
  name: 'Production API',
  common_name: 'api.example.com',
  status: 'Active',
  issuer_id: 'iss-vault',
  owner_id: 'o-alice',
  team_id: 't-platform',
  renewal_policy_id: 'rp-default',
  environment: 'production',
  created_at: '2026-05-01T00:00:00Z',
  updated_at: '2026-05-01T00:00:00Z',
  expires_at: '2027-05-01T00:00:00Z',
  not_after:  '2027-05-01T00:00:00Z',
  not_before: '2026-05-01T00:00:00Z',
  certificate_profile_id: null,
  sans: [],
  tags: [],
} as never;

describe('Multi-page Vitest flows — Phase 8 TEST-M1', () => {
  describe('Certificates list → detail row click → CertificateDetailPage data continuity', () => {
    it('clicking a certificate row navigates to /certificates/:id and the detail page loads the same cert', async () => {
      vi.mocked(client.getCertificates).mockResolvedValue({
        data: [baseCert],
        total: 1,
        page: 1,
        per_page: 25,
      });
      vi.mocked(client.getCertificate).mockResolvedValue(baseCert);
      vi.mocked(client.getCertificateVersions).mockResolvedValue([] as never);
      vi.mocked(client.getTargets).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 25 });
      vi.mocked(client.getJobs).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 25 });
      vi.mocked(client.getProfile).mockResolvedValue(undefined as never);

      renderWithRouter(
        <Routes>
          <Route path="/certificates" element={<CertificatesPage />} />
          <Route path="/certificates/:id" element={<CertificateDetailPage />} />
        </Routes>,
        ['/certificates'],
      );

      // 1. List page renders the row.
      await waitFor(() => expect(screen.getAllByText('api.example.com')[0]).toBeInTheDocument());
      expect(vi.mocked(client.getCertificates)).toHaveBeenCalled();

      // 2. Click the row — DataTable wires onRowClick to navigate.
      fireEvent.click(screen.getAllByText('api.example.com')[0]);

      // 3. Detail page mounted with the same id → calls getCertificate('cert-001').
      await waitFor(() => {
        expect(vi.mocked(client.getCertificate)).toHaveBeenCalledWith('cert-001');
      });

      // 4. Detail page surfaces the same common_name the list showed.
      // Function matcher (NOT regex) — closes CodeQL alert #36
      // (js/regex/missing-regexp-anchor). Same case-insensitive
      // substring semantics as the original /api\.example\.com/i but
      // no regex for CodeQL to flag. Function form also tolerates the
      // detail page rendering the cn inside a labelled cell ("Common
      // name: api.example.com") where exact-match string would fail.
      await waitFor(() => {
        expect(
          screen.getAllByText((content) =>
            content.toLowerCase().includes('api.example.com'),
          ).length,
        ).toBeGreaterThan(0);
      });
    });

    it('navigation preserves the cert id from URL — direct deep-link to /certificates/:id works without a list pre-fetch', async () => {
      vi.mocked(client.getCertificate).mockResolvedValue(baseCert);
      vi.mocked(client.getCertificateVersions).mockResolvedValue([] as never);
      vi.mocked(client.getTargets).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 25 });
      vi.mocked(client.getJobs).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 25 });
      vi.mocked(client.getProfile).mockResolvedValue(undefined as never);

      renderWithRouter(
        <Routes>
          <Route path="/certificates/:id" element={<CertificateDetailPage />} />
        </Routes>,
        ['/certificates/cert-001'],
      );

      await waitFor(() => {
        expect(vi.mocked(client.getCertificate)).toHaveBeenCalledWith('cert-001');
      });
      expect(vi.mocked(client.getCertificates)).not.toHaveBeenCalled();
    });
  });

  describe('Issuers list → row click → IssuerDetailPage data continuity', () => {
    it('clicking an issuer row navigates to /issuers/:id and the detail page loads the same issuer', async () => {
      vi.mocked(client.getIssuers).mockResolvedValue({
        data: [baseIssuer],
        total: 1,
        page: 1,
        per_page: 25,
      });
      vi.mocked(client.getIssuer).mockResolvedValue(baseIssuer);
      vi.mocked(client.getCertificates).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 25 });

      renderWithRouter(
        <Routes>
          <Route path="/issuers" element={<IssuersPage />} />
          <Route path="/issuers/:id" element={<IssuerDetailPage />} />
        </Routes>,
        ['/issuers'],
      );

      await waitFor(() => expect(screen.getByText('HashiCorp Vault')).toBeInTheDocument());
      expect(vi.mocked(client.getIssuers)).toHaveBeenCalled();

      fireEvent.click(screen.getByText('HashiCorp Vault'));

      await waitFor(() => {
        expect(vi.mocked(client.getIssuer)).toHaveBeenCalledWith('iss-vault');
      });
    });
  });

});
