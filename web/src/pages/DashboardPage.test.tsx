import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// UX-001 Phase 4 — DashboardPage onboarding wizard entry/exit contract
//
// DashboardPage is the arbiter of when the OnboardingWizard is visible. Two
// triggers must both work:
//
//   1. First-run detection: no certificates + no user-configured issuers +
//      no dismissal flag → auto-open the wizard.
//
//   2. Re-entry via URL: `?onboarding=1` query param forces the wizard open
//      even for users who already have certs or have previously dismissed it.
//      This is the other end of the Layout "Setup guide" contract tested in
//      Layout.test.tsx.
//
// And the close path must clean up after itself:
//
//   3. On dismiss, DashboardPage must (a) set
//      `certctl:onboarding-dismissed=true` in localStorage so it doesn't
//      auto-reopen on refresh, and (b) strip the `?onboarding=1` query param
//      via setSearchParams(..., { replace: true }) so a subsequent refresh
//      doesn't relaunch the wizard either.
// -----------------------------------------------------------------------------

// Mock the entire API client. vi.mock factories are hoisted above the imports
// that follow, so these stubs are in effect when DashboardPage's module graph
// resolves.
vi.mock('../api/client', () => ({
  getCertificates: vi.fn(),
  getAgents: vi.fn(),
  getJobs: vi.fn(),
  getNotifications: vi.fn(),
  getHealth: vi.fn(),
  getDashboardSummary: vi.fn(),
  getCertificatesByStatus: vi.fn(),
  getExpirationTimeline: vi.fn(),
  getJobTrends: vi.fn(),
  getIssuanceRate: vi.fn(),
  previewDigest: vi.fn(),
  sendDigest: vi.fn(),
  getIssuers: vi.fn(),
}));

// Replace OnboardingWizard with a paper-thin stub so these tests exercise the
// entry/exit contract without pulling OnboardingWizard's (heavy) query tree
// and step machinery into the fixture. OnboardingWizard's own behaviour is
// covered in OnboardingWizard.test.tsx.
vi.mock('./OnboardingWizard', () => ({
  default: ({ onDismiss }: { onDismiss: () => void }) => (
    <div data-testid="onboarding-wizard">
      <button type="button" data-testid="wizard-dismiss-btn" onClick={onDismiss}>
        dismiss
      </button>
    </div>
  ),
}));

import DashboardPage from './DashboardPage';
import * as client from '../api/client';

// Location probe: renders current pathname+search into the DOM so we can
// assert that setSearchParams(next, { replace: true }) actually stripped the
// `?onboarding=1` query param without relying on router internals.
function LocationProbe() {
  const loc = useLocation();
  return (
    <div data-testid="location-probe">
      {loc.pathname}
      {loc.search}
    </div>
  );
}

function renderDashboard(initialEntry = '/') {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
    },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <LocationProbe />
        <Routes>
          <Route path="/" element={<DashboardPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Canonical "empty but well-formed" stubs for every query DashboardPage calls
// unconditionally. Returning data (rather than leaving queries pending) lets
// the component pass its `summary !== undefined && issuersData !== undefined`
// gate and compute isFirstRun in a single render pass.
function stubAllQueriesEmpty() {
  vi.mocked(client.getHealth).mockResolvedValue({ status: 'healthy' } as never);
  vi.mocked(client.getDashboardSummary).mockResolvedValue({
    total_certificates: 0,
    expiring_certificates: 0,
    expired_certificates: 0,
    revoked_certificates: 0,
    active_agents: 0,
    pending_jobs: 0,
    completed_jobs: 0,
    failed_jobs: 0,
    notifications_dead: 0,
  } as never);
  vi.mocked(client.getIssuers).mockResolvedValue({
    data: [],
    total: 0,
    page: 1,
    per_page: 100,
  } as never);
  vi.mocked(client.getCertificatesByStatus).mockResolvedValue([] as never);
  vi.mocked(client.getExpirationTimeline).mockResolvedValue([] as never);
  vi.mocked(client.getJobTrends).mockResolvedValue([] as never);
  vi.mocked(client.getIssuanceRate).mockResolvedValue([] as never);
  vi.mocked(client.getCertificates).mockResolvedValue({
    data: [],
    total: 0,
    page: 1,
    per_page: 100,
  } as never);
  vi.mocked(client.getJobs).mockResolvedValue({
    data: [],
    total: 0,
    page: 1,
    per_page: 100,
  } as never);
}

describe('DashboardPage — UX-001 onboarding wizard entry/exit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    localStorage.clear();
    stubAllQueriesEmpty();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it('auto-opens the wizard on first run (no certs, no user-configured issuers, no dismissal)', async () => {
    renderDashboard('/');

    // First-run detection runs after the summary + issuers queries resolve.
    // The wizard is gated behind a setTimeout(..., 0) in DashboardPage to
    // avoid setState-during-render, so we waitFor the stub to appear.
    await waitFor(() => {
      expect(screen.getByTestId('onboarding-wizard')).toBeInTheDocument();
    });
  });

  it('opens the wizard when URL has ?onboarding=1, even with dismissal flag set', async () => {
    // Simulate a user who dismissed the wizard previously and is now clicking
    // the sidebar "Setup guide" button, which navigates to /?onboarding=1.
    localStorage.setItem('certctl:onboarding-dismissed', 'true');

    // Give the fixture non-zero counts so first-run detection would *not*
    // fire on its own. Only the query-param override should open the wizard.
    vi.mocked(client.getDashboardSummary).mockResolvedValue({
      total_certificates: 42,
      expiring_certificates: 0,
      expired_certificates: 0,
      revoked_certificates: 0,
      active_agents: 3,
      pending_jobs: 0,
      completed_jobs: 0,
      failed_jobs: 0,
      notifications_dead: 0,
    } as never);
    vi.mocked(client.getIssuers).mockResolvedValue({
      data: [{ id: 'iss-prod', name: 'Prod ACME', type: 'ACME', source: 'database' }],
      total: 1,
      page: 1,
      per_page: 100,
    } as never);

    renderDashboard('/?onboarding=1');

    await waitFor(() => {
      expect(screen.getByTestId('onboarding-wizard')).toBeInTheDocument();
    });
  });

  it('onDismiss sets localStorage flag and strips ?onboarding=1 from the URL', async () => {
    renderDashboard('/?onboarding=1');

    // Wait for the wizard to open.
    await waitFor(() => {
      expect(screen.getByTestId('onboarding-wizard')).toBeInTheDocument();
    });

    // Sanity: URL still carries the re-entry signal before dismiss.
    expect(screen.getByTestId('location-probe').textContent).toContain('onboarding=1');

    fireEvent.click(screen.getByTestId('wizard-dismiss-btn'));

    // After dismiss: localStorage is set, so a future refresh won't re-open.
    await waitFor(() => {
      expect(localStorage.getItem('certctl:onboarding-dismissed')).toBe('true');
    });

    // The wizard is torn down.
    await waitFor(() => {
      expect(screen.queryByTestId('onboarding-wizard')).not.toBeInTheDocument();
    });

    // And the `?onboarding=1` query param is stripped via replace: true so
    // refreshing the page won't reopen the wizard via the URL path either.
    await waitFor(() => {
      const probe = screen.getByTestId('location-probe').textContent ?? '';
      expect(probe).not.toContain('onboarding=1');
    });
  });

  it('does not open the wizard when dismissed and URL has no onboarding param', async () => {
    localStorage.setItem('certctl:onboarding-dismissed', 'true');
    renderDashboard('/');

    // Give queries a tick to settle.
    await waitFor(() => {
      expect(screen.getByText(/System healthy|Checking system status/i)).toBeInTheDocument();
    });

    // The wizard should NOT have auto-opened — dismissal flag is respected
    // when the URL doesn't carry the override signal.
    expect(screen.queryByTestId('onboarding-wizard')).not.toBeInTheDocument();
  });
});
