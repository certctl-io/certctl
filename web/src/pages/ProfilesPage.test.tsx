import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): ProfilesPage XSS-hardening + render coverage.
// Profile name + description are operator-supplied free text.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getProfiles: vi.fn(),
  deleteProfile: vi.fn(),
  createProfile: vi.fn(),
  updateProfile: vi.fn(),
}));

import ProfilesPage from './ProfilesPage';
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

const xssPayload = '<script data-xss="profiles">window.__xss_pwned__=1;</script>';

const xssProfile = {
  id: 'cp-xss-001',
  name: xssPayload,
  description: xssPayload,
  max_ttl_seconds: 3600,
  allow_short_lived: false,
  ekus: [xssPayload],
  key_usages: [xssPayload],
  san_types: [xssPayload],
  created_at: new Date().toISOString(),
};

describe('ProfilesPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when getProfiles resolves', async () => {
    vi.mocked(client.getProfiles).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderWithQuery(<ProfilesPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /Certificate Profiles/i })).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in profile name / description / EKUs', async () => {
    vi.mocked(client.getProfiles).mockResolvedValue({
      data: [xssProfile],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    renderWithQuery(<ProfilesPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="profiles">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="profiles"]');
    expect(liveScripts.length, 'profile fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'profile <script> body must not have executed',
    ).toBeUndefined();
  });
});
