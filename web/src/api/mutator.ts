// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// ARCH-001-A closure (Sprint 5, 2026-05-16). Shared fetch mutator
// referenced from web/orval.config.ts. Every generated useQuery /
// useMutation hook routes through this function so we can wire
// the existing hand-written client.ts auth / CSRF / event semantics
// in one place instead of mirroring them across 162+ generated tools.
//
// The migration plan (per orval.config.ts header comment) is per-
// consumer — pages flip from `client.ts` imports to `generated/`
// imports one at a time; both styles share the same fetch semantics
// because this mutator delegates to the same primitives.
//
// Key contracts this mutator preserves from the hand-written
// `fetchJSON` in src/api/client.ts:
//
//   - `credentials: 'include'` so the session cookie flows.
//   - CSRF-token header on state-changing methods (POST/PUT/PATCH/DELETE)
//     reading from the auth context's CSRF surface.
//   - 401 dispatches a `certctl:auth-required` CustomEvent that
//     AuthProvider's listener consumes. Hotfix #19 (GitHub #13)
//     unconditionally redirects to /login on this event.
//   - AbortController support so React Query / generated hooks can
//     cancel in-flight requests on unmount.
//
// The body shape is whatever the operation expects; orval threads
// the input type through TypeScript so callers stay type-safe.

import { fetchJSON } from './client';

interface CertctlFetchOptions {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  params?: Record<string, string | number | boolean | undefined | null>;
  data?: unknown;
  signal?: AbortSignal;
  headers?: Record<string, string>;
  // Orval emits `responseType` (e.g. 'blob' / 'text' / 'arraybuffer')
  // for routes whose response shape isn't JSON — CRL / OCSP / cert
  // downloads. fetchJSON ignores it today (those routes are excluded
  // from MCP coverage for the same reason — they're binary). Accept
  // the field so the generated tsc stays clean; consumers needing the
  // raw bytes should reach for the hand-written client.ts API.
  responseType?: 'json' | 'blob' | 'text' | 'arraybuffer' | 'stream';
}

/**
 * certctlFetch is the orval-generated-hook shim that delegates to
 * the existing hand-written fetchJSON. Generated hooks receive the
 * deserialised JSON; on error they receive the rejected promise.
 */
export const certctlFetch = async <T>({
  url,
  method,
  params,
  data,
  signal,
  headers,
}: CertctlFetchOptions): Promise<T> => {
  // Build the URL with query params. Orval emits params separately
  // from the path so we can serialise them consistently.
  const u = new URL(url, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null) continue;
      u.searchParams.append(k, String(v));
    }
  }
  // Strip the origin so fetchJSON's BASE-relative prefix logic works.
  const pathAndQuery = `${u.pathname}${u.search}`;

  const init: RequestInit = { method };
  if (data !== undefined) {
    init.body = typeof data === 'string' ? data : JSON.stringify(data);
  }
  if (signal) init.signal = signal;
  if (headers) init.headers = headers;

  return fetchJSON<T>(pathAndQuery, init);
};

// Orval's default export contract — the generated hooks import this
// symbol by the name set in orval.config.ts `override.mutator.name`.
export default certctlFetch;
