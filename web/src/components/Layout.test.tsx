import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

// -----------------------------------------------------------------------------
// UX-001 Phase 4 — Layout "Setup guide" re-entry button
//
// Phase 2 added a persistent "Setup guide" button to the sidebar so operators
// who dismissed the onboarding wizard (or closed it mid-flow) can always walk
// themselves back in. The button must:
//
//   1. Render with the accessible name "Setup guide".
//   2. On click, clear the `certctl:onboarding-dismissed` localStorage key so
//      DashboardPage's first-run detection re-engages.
//   3. On click, navigate to `/?onboarding=1` — the query-param re-entry
//      signal DashboardPage reads via useSearchParams. The query param is the
//      contract between Layout and DashboardPage; without it, a user who
//      already has certs + issuers would not see the wizard again.
// -----------------------------------------------------------------------------

// Intercept useNavigate so we can assert the destination path without having
// to configure every route segment the wizard might push to.
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

// Layout pulls auth state from AuthProvider to decide whether to render the
// logout button. Tests don't care about auth — stub the hook with an anonymous
// session so Layout renders without needing a real AuthProvider wrapper.
vi.mock('./AuthProvider', () => ({
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

// Imported after vi.mock so the mocks are in effect when Layout's module graph
// resolves.
import Layout from './Layout';

function renderLayout() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<div data-testid="outlet-root">root</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe('Layout — UX-001 Setup guide sidebar button', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it('renders a "Setup guide" button in the sidebar', () => {
    renderLayout();

    // Red-to-green guard: if the button is removed or renamed, this catches
    // it. We match by accessible name so the assertion survives className /
    // icon churn.
    expect(screen.getByRole('button', { name: /Setup guide/i })).toBeInTheDocument();
  });

  it('clears the onboarding-dismissed localStorage key on click', () => {
    localStorage.setItem('certctl:onboarding-dismissed', 'true');
    expect(localStorage.getItem('certctl:onboarding-dismissed')).toBe('true');

    renderLayout();
    fireEvent.click(screen.getByRole('button', { name: /Setup guide/i }));

    // DashboardPage reads this key synchronously to decide whether the first-
    // run wizard can auto-open. Leaving it set would suppress the wizard even
    // after navigation, defeating the re-entry contract.
    expect(localStorage.getItem('certctl:onboarding-dismissed')).toBeNull();
  });

  it('navigates to /?onboarding=1 on click', () => {
    renderLayout();
    fireEvent.click(screen.getByRole('button', { name: /Setup guide/i }));

    // The `?onboarding=1` query param is the explicit signal DashboardPage
    // checks via useSearchParams. Asserting the exact path pins the contract
    // both ends rely on.
    expect(mockNavigate).toHaveBeenCalledTimes(1);
    expect(mockNavigate).toHaveBeenCalledWith('/?onboarding=1');
  });

  it('tolerates localStorage access failure without throwing', () => {
    // Some browsers / privacy modes throw on localStorage access. Layout
    // wraps the removal in try/catch so the navigation still fires. Simulate
    // the failure and verify the navigation path is unaffected.
    const original = Storage.prototype.removeItem;
    Storage.prototype.removeItem = vi.fn(() => {
      throw new Error('localStorage unavailable');
    });

    try {
      renderLayout();
      fireEvent.click(screen.getByRole('button', { name: /Setup guide/i }));

      expect(mockNavigate).toHaveBeenCalledWith('/?onboarding=1');
    } finally {
      Storage.prototype.removeItem = original;
    }
  });
});
