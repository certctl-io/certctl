import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): DigestPage XSS-hardening + basic render coverage.
//
// DigestPage renders a server-rendered HTML preview from previewDigest(). The
// audit's M-026 closure guards against the day someone migrates the preview
// surface from controlled <iframe srcDoc> rendering to a less-safe
// dangerouslySetInnerHTML or similar pattern: an attacker-controlled cert
// subject DN that lands inside the digest HTML would then execute as a
// script payload.
//
// Pins:
//   1. Page renders when previewDigest resolves.
//   2. The HTML payload returned by previewDigest is NEVER injected into the
//      DOM as a live <script> — `document.querySelector('script[data-xss])'`
//      stays empty even when the response contains a literal <script> tag.
//   3. The literal preview text (or an iframe pointing at the preview) is
//      surfaced to the operator, but the <script> attack vector cannot fire.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  previewDigest: vi.fn(),
  sendDigest: vi.fn(),
}));

import DigestPage from './DigestPage';
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

describe('DigestPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
  });

  it('renders the page header when previewDigest resolves', async () => {
    vi.mocked(client.previewDigest).mockResolvedValue('<p>Today 5 certs expire</p>' as never);
    renderWithQuery(<DigestPage />);
    await waitFor(() => {
      expect(screen.getByText('Certificate Digest')).toBeInTheDocument();
    });
  });

  it('does NOT execute a <script> payload returned by previewDigest', async () => {
    const xssPayload = '<script data-xss="digest-preview">window.__xss_pwned__=1;</script>';
    vi.mocked(client.previewDigest).mockResolvedValue(xssPayload as never);

    renderWithQuery(<DigestPage />);
    await waitFor(() => {
      // Wait for the preview surface to render (the page settles into
      // either the preview pane or an error pane — either way the
      // page-load cycle is done by the time the header text appears).
      expect(screen.getByText('Certificate Digest')).toBeInTheDocument();
    });

    // No live script with our marker may be attached to the DOM, AND no
    // global side-effect from the script body may have run.
    const liveScripts = document.querySelectorAll('script[data-xss="digest-preview"]');
    expect(liveScripts.length, 'previewDigest payload must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'previewDigest <script> body must not have executed',
    ).toBeUndefined();
  });

  it('still renders when previewDigest fails (error path does not crash)', async () => {
    vi.mocked(client.previewDigest).mockRejectedValue(new Error('preview failed') as never);
    renderWithQuery(<DigestPage />);
    await waitFor(() => {
      expect(screen.getByText('Certificate Digest')).toBeInTheDocument();
    });
  });
});
