import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): AuditPage XSS-hardening + render coverage.
//
// AuditPage renders audit-event rows with action / actor / actor_type /
// resource_type / resource_id / details fields. Audit events are written by
// the server but their detail fields can contain operator-supplied content
// (e.g., reason strings on certificate_revoked events). H-008 / M-022 already
// ship the redactor that scrubs PII + credentials from audit details, but the
// rendering path also has to be XSS-safe in case a non-PII free-text field
// (action, resource_type, etc.) reflects attacker-controllable bytes.
//
// Pins:
//   1. Page renders.
//   2. Audit events containing literal <script> payloads do NOT execute.
//   3. The literal payload text appears as escaped content.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getAuditEvents: vi.fn(),
}));

import AuditPage from './AuditPage';
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

const xssPayload = '<script data-xss="audit">window.__xss_pwned__=1;</script>';

const xssEvent = {
  id: 'ae-xss-001',
  action: xssPayload,
  actor: xssPayload,
  actor_type: xssPayload,
  resource_type: xssPayload,
  resource_id: xssPayload,
  details: { note: xssPayload },
  timestamp: new Date().toISOString(),
};

describe('AuditPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when audit events resolve', async () => {
    vi.mocked(client.getAuditEvents).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderWithQuery(<AuditPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Audit Trail' })).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads embedded in audit-event fields', async () => {
    vi.mocked(client.getAuditEvents).mockResolvedValue({
      data: [xssEvent],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);

    renderWithQuery(<AuditPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Audit Trail' })).toBeInTheDocument();
    });

    const liveScripts = document.querySelectorAll('script[data-xss="audit"]');
    expect(liveScripts.length, 'audit event must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'audit event <script> body must not have executed',
    ).toBeUndefined();
  });

  it('renders the literal payload as escaped text', async () => {
    vi.mocked(client.getAuditEvents).mockResolvedValue({
      data: [xssEvent],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);

    renderWithQuery(<AuditPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="audit">');
    });
  });
});
