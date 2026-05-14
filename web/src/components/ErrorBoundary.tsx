// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// ErrorBoundary — Phase 9 closure for FE-L1 (50-line stub with no copy-
// stack-trace affordance, no telemetry hook). Pre-Phase-9 a production
// exception left operators staring at a one-line "Something went wrong"
// with no way to capture the stack for a bug report.
//
// Phase 9 expansion adds:
//   • Full stack trace + component-stack rendered in a <details> block
//     (collapsed by default so the visual posture stays calm; expert
//     operators expand for triage).
//   • "Copy details" button that copies a structured JSON payload to
//     the clipboard for paste into a bug report or Slack thread.
//     Payload: { message, stack, componentStack, userAgent, url,
//     buildVersion, timestamp }.
//   • Optional telemetry POST gated on the VITE_ERROR_TELEMETRY_URL
//     build-time env var. When set, the boundary fires a single POST
//     with the same payload to the configured endpoint. No-op when
//     unset (no Sentry-class endpoint is part of certctl-server v2;
//     this hook is forward-compat for when one lands).
//
// Pairs with Phase 9's PERF-M2 closure: vite.config.ts now emits
// `sourcemap: 'hidden'` so a future Sentry release-artifact upload
// can symbolicate these stack traces against the unminified source.

import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  copyStatus: 'idle' | 'copied' | 'failed';
}

interface ErrorPayload {
  message: string;
  stack: string;
  componentStack: string;
  userAgent: string;
  url: string;
  buildVersion: string;
  timestamp: string;
}

/**
 * Buildversion is injected by Vite at build time via define() —
 * falling back to 'dev' if missing means local dev doesn't fail to
 * compile.
 */
const BUILD_VERSION = (
  typeof __APP_VERSION__ !== 'undefined' ? __APP_VERSION__ : 'dev'
);

declare const __APP_VERSION__: string;

/**
 * Optional Sentry-class endpoint. When set, the boundary POSTs the
 * error payload as JSON. Empty / unset = no telemetry (the safe
 * default; v2 certctl-server doesn't expose a /telemetry/errors
 * endpoint).
 */
const TELEMETRY_URL = (
  // Vite exposes build-time env vars on import.meta.env (typed as
  // `unknown` in TS until vite/client types load). Cast through unknown
  // so the unset-undefined path stays sound.
  (import.meta.env as Record<string, string | undefined>)
    .VITE_ERROR_TELEMETRY_URL || ''
);

function buildPayload(error: Error, errorInfo: ErrorInfo | null): ErrorPayload {
  return {
    message:        error.message || 'Unknown error',
    stack:          error.stack || '(no stack)',
    componentStack: errorInfo?.componentStack || '(no component stack)',
    userAgent:      typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
    url:            typeof window !== 'undefined' ? window.location.href : 'unknown',
    buildVersion:   BUILD_VERSION,
    timestamp:      new Date().toISOString(),
  };
}

async function copyToClipboard(text: string): Promise<boolean> {
  // Prefer navigator.clipboard (modern + async). Falls back to the
  // execCommand path only if clipboard isn't available (e.g. old
  // browsers, file://, http:// in some browsers). Returns true on
  // success.
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through */ }
  // Legacy fallback — works in jsdom for tests + on http origins.
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand?.('copy') ?? false;
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

function postTelemetry(payload: ErrorPayload): void {
  if (!TELEMETRY_URL) return;
  // Best-effort fire-and-forget. We deliberately don't await — a slow
  // telemetry endpoint MUST NOT block the user's "click Reload" path.
  // navigator.sendBeacon is the right primitive for this case (queued
  // by the browser, survives navigation) but it requires a Blob; fall
  // back to fetch() with keepalive: true otherwise.
  try {
    const body = JSON.stringify(payload);
    if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
      navigator.sendBeacon(TELEMETRY_URL, new Blob([body], { type: 'application/json' }));
      return;
    }
    fetch(TELEMETRY_URL, {
      method:      'POST',
      headers:     { 'Content-Type': 'application/json' },
      body,
      keepalive:   true,
    }).catch(() => { /* swallow; telemetry must never raise */ });
  } catch { /* swallow */ }
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null, copyStatus: 'idle' };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught component error:', error, errorInfo);
    this.setState({ errorInfo });
    postTelemetry(buildPayload(error, errorInfo));
  }

  handleCopy = async () => {
    if (!this.state.error) return;
    const payload = buildPayload(this.state.error, this.state.errorInfo);
    const ok = await copyToClipboard(JSON.stringify(payload, null, 2));
    this.setState({ copyStatus: ok ? 'copied' : 'failed' });
    // Reset to idle after 2s so the operator can copy again if needed.
    setTimeout(() => this.setState({ copyStatus: 'idle' }), 2_000);
  };

  handleReload = () => {
    this.setState({ hasError: false, error: null, errorInfo: null, copyStatus: 'idle' });
    window.location.reload();
  };

  render() {
    if (!this.state.hasError || !this.state.error) {
      return this.props.children;
    }
    const payload = buildPayload(this.state.error, this.state.errorInfo);
    const copyLabel =
      this.state.copyStatus === 'copied' ? 'Copied!' :
      this.state.copyStatus === 'failed' ? 'Copy failed' :
      'Copy details';

    return (
      <div className="flex items-center justify-center min-h-screen bg-page">
        <div className="max-w-2xl w-full p-8" role="alert" aria-live="assertive">
          <h1 className="text-xl font-semibold text-red-700 mb-2">Something went wrong</h1>
          <p className="text-sm text-ink-muted mb-4">
            {this.state.error.message || 'An unexpected error occurred'}
          </p>

          <div className="flex gap-2 mb-4">
            <button
              type="button"
              onClick={this.handleReload}
              className="px-4 py-2 bg-brand-500 text-white rounded text-sm hover:bg-brand-600"
              data-testid="error-boundary-reload"
            >
              Reload Page
            </button>
            <button
              type="button"
              onClick={this.handleCopy}
              className="px-4 py-2 bg-surface border border-surface-border text-ink rounded text-sm hover:bg-surface-muted"
              data-testid="error-boundary-copy"
              aria-live="polite"
            >
              {copyLabel}
            </button>
          </div>

          {/* Stack trace collapsed by default. Expert operators expand
              for triage; copy-button surfaces the same payload as JSON
              for paste into bug reports. */}
          <details className="bg-surface border border-surface-border rounded p-3 text-xs font-mono text-ink-muted">
            <summary className="cursor-pointer text-ink select-none">Error details</summary>
            <div className="mt-3 space-y-3">
              <div>
                <div className="text-ink-faint uppercase tracking-wide mb-1">Build</div>
                <div>{payload.buildVersion} · {payload.timestamp}</div>
              </div>
              <div>
                <div className="text-ink-faint uppercase tracking-wide mb-1">Stack</div>
                <pre className="whitespace-pre-wrap break-words text-2xs">{payload.stack}</pre>
              </div>
              <div>
                <div className="text-ink-faint uppercase tracking-wide mb-1">Component stack</div>
                <pre className="whitespace-pre-wrap break-words text-2xs">{payload.componentStack}</pre>
              </div>
            </div>
          </details>
        </div>
      </div>
    );
  }
}
