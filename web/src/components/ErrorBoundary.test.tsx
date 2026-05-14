import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import ErrorBoundary from './ErrorBoundary';

// Phase 9 FE-L1 closure tests — pin the new contract:
//   • Error rendered → "Reload Page" + "Copy details" buttons visible.
//   • "Copy details" populates navigator.clipboard with a JSON payload
//     containing message, stack, componentStack, userAgent, url,
//     buildVersion, timestamp.
//   • Telemetry POST is gated on VITE_ERROR_TELEMETRY_URL (unset =
//     no fetch; set = single sendBeacon-or-fetch call).
//   • Error-details <details> block stays collapsed by default.

function Boom(): never {
  throw new Error('test-boundary-trip');
}

function silenceConsole(fn: () => void | Promise<void>) {
  // React + jsdom log the component error to console.error; mute for
  // test-output cleanliness without losing real-error visibility in
  // dev (we restore the original after).
  const origError = console.error;
  console.error = () => {};
  try {
    return fn();
  } finally {
    console.error = origError;
  }
}

describe('ErrorBoundary — Phase 9 FE-L1 expansion', () => {
  beforeEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders children when no error', () => {
    render(
      <ErrorBoundary>
        <span>healthy</span>
      </ErrorBoundary>,
    );
    expect(screen.getByText('healthy')).toBeInTheDocument();
  });

  it('renders fallback + Reload + Copy buttons when child throws', () => {
    silenceConsole(() => {
      render(
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>,
      );
    });
    expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    // "test-boundary-trip" appears in the <p> message AND inside the
    // <pre> stack trace — assert at least one match exists.
    expect(screen.getAllByText(/test-boundary-trip/).length).toBeGreaterThan(0);
    expect(screen.getByTestId('error-boundary-reload')).toBeInTheDocument();
    expect(screen.getByTestId('error-boundary-copy')).toBeInTheDocument();
  });

  it('Copy details writes a JSON payload to navigator.clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });

    silenceConsole(() => {
      render(
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>,
      );
    });

    fireEvent.click(screen.getByTestId('error-boundary-copy'));

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const arg = writeText.mock.calls[0][0] as string;
    const payload = JSON.parse(arg);
    expect(payload.message).toBe('test-boundary-trip');
    expect(typeof payload.stack).toBe('string');
    expect(typeof payload.componentStack).toBe('string');
    expect(typeof payload.userAgent).toBe('string');
    expect(typeof payload.url).toBe('string');
    expect(typeof payload.buildVersion).toBe('string');
    expect(typeof payload.timestamp).toBe('string');

    await waitFor(() => {
      expect(screen.getByTestId('error-boundary-copy')).toHaveTextContent(/Copied/);
    });
  });

  it('error-details <details> block is collapsed by default', () => {
    silenceConsole(() => {
      render(
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>,
      );
    });
    const details = screen.getByText('Error details').closest('details');
    expect(details).toBeTruthy();
    expect(details).not.toHaveAttribute('open');
  });

  it('does NOT POST telemetry when VITE_ERROR_TELEMETRY_URL is unset (default)', () => {
    // The constant is evaluated at module-load; in the test env
    // import.meta.env.VITE_ERROR_TELEMETRY_URL is undefined, so the
    // telemetry hook is a no-op. Verify via fetch + sendBeacon spies.
    const fetchSpy = vi.fn().mockResolvedValue(new Response());
    globalThis.fetch = fetchSpy as never;
    const sendBeacon = vi.fn();
    Object.defineProperty(navigator, 'sendBeacon', {
      configurable: true,
      value: sendBeacon,
    });

    silenceConsole(() => {
      render(
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>,
      );
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(sendBeacon).not.toHaveBeenCalled();
  });
});
