// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package oidc

// SEC-001 closure (Sprint 1, 2026-05-16). Pre-fix, two OIDC discovery
// call sites passed the bare request context to gooidc.NewProvider:
//
//   - test_discovery.go:65  (dry-run validator from the GUI)
//   - service.go:1066       (runtime provider load on first cache miss)
//
// Acquisition-audit follow-up SEC-020 + SEC-021 (Sprint 1 follow-up,
// 2026-05-16) extended the same wrap to two adjacent call sites that
// the original SEC-001 sweep missed:
//
//   - service.go::fetchUserinfoGroups (~L948-961, SEC-020 closure) —
//     the userinfo-fallback path called entry.provider.UserInfo(ctx, ts)
//     with bare ctx. go-oidc/v3 Provider.UserInfo derives its HTTP
//     client from the context via getClient(ctx) (oidc.go:61-65);
//     without an override, the internal doRequest falls through to
//     http.DefaultClient.
//   - internal/api/handler/auth_session_oidc_bcl.go::Verify (~L125,
//     SEC-021 closure) — the back-channel-logout verifier performs a
//     per-request discovery re-fetch via gooidc.NewProvider(ctx, ...)
//     with bare ctx; SafeOIDCContext now wraps before the call.
//
// Context-key shape: gooidc.ClientContext is implemented as
//   context.WithValue(ctx, oauth2.HTTPClient, client)
// (go-oidc v3.18.0 oidc.go:57-59). Both go-oidc's getClient AND
// golang.org/x/oauth2's internal.ContextClient read oauth2.HTTPClient,
// so the SINGLE SafeOIDCContext wrap covers go-oidc-driven HTTP calls
// (Provider.UserInfo / NewProvider discovery / Verifier JWKS) AND
// oauth2-driven HTTP calls (Config.TokenSource refresh / Exchange).
// No additional context.WithValue(ctx, oauth2.HTTPClient, ...) is
// required alongside the wrap.
//
// gooidc.NewProvider derives its HTTP client from the context via
// oidc.ClientContext; with no override it falls through to
// http.DefaultClient. The default client has no SSRF guard, so an admin
// with `auth.oidc.create` could induce server-side HTTPS egress to
// loopback (127.0.0.1, ::1), RFC 1918 (10/8 / 172.16/12 / 192.168/16),
// link-local (169.254.169.254 — cloud-instance metadata), and IPv6
// link-local (fe80::/10).
//
// The companion JWKS reachability probe (jwksReachable + jwksProbeClient
// in this package) was already routed through SafeHTTPDialContext via
// the Bundle 5 R6 closure; the discovery + claims path bypassed that
// guard.
//
// This file adds the symmetric guard for the discovery leg:
//
//   - oidcDiscoveryClient — an *http.Client wrapping a Transport whose
//     DialContext is SafeHTTPDialContext, sized to the same outbound
//     budget as jwksProbeClient (oidcOutboundTimeout = 10s).
//   - SafeOIDCContext(ctx) — returns a context that gooidc.NewProvider
//     and the resulting Verifier will use for every outbound call.
//
// The two call sites above are rewritten to thread their context through
// SafeOIDCContext before NewProvider runs. The fail-closed posture is
// owned by validation.SafeHTTPDialContext — DNS-rebinding-safe by
// re-resolving at dial time and rejecting any reserved address that
// surfaces in the resolution.
//
// Defense-in-depth: domain/types.go.Validate also calls
// validation.ValidateSafeURL on the persisted IssuerURL at provider-
// creation time so reserved-address issuers fail before they ever reach
// the cache + dial path.

import (
	"context"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/certctl-io/certctl/internal/validation"
)

// oidcDiscoveryClient is the *http.Client gooidc.NewProvider uses for
// the discovery doc fetch + the per-Verifier JWKS read it issues
// internally on first sig-verify. Routed through SafeHTTPDialContext
// so the dial-time guard re-resolves the issuer host and rejects
// loopback / link-local / private / cloud-metadata before any HTTP
// byte goes out. Mirrors jwksProbeClient (test_discovery.go) so both
// outbound paths share an identical SSRF posture.
//
// Package-level var so the test suite can swap it for an
// SSRF-guard-bypassed client when exercising the discovery code path
// against httptest.NewServer (which binds to 127.0.0.1 and would
// otherwise be refused). Mirrors the webhook/slack/teams test-seam
// pattern. Production code never reassigns this var.
var oidcDiscoveryClient = &http.Client{
	Timeout: oidcOutboundTimeout,
	Transport: &http.Transport{
		DialContext:           validation.SafeHTTPDialContext(oidcOutboundTimeout),
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// SafeOIDCContext returns a derived context that carries the SSRF-safe
// discovery http.Client. Pass the result to gooidc.NewProvider so that
// the discovery doc fetch + the internal JWKS fetch the resulting
// Verifier issues both run through SafeHTTPDialContext.
//
// Callers SHOULD use this wrapper for every gooidc.NewProvider call
// site; the package's own callers (service.go runtime load,
// test_discovery.go dry-run validator) do this unconditionally.
func SafeOIDCContext(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, oidcDiscoveryClient)
}

// validateIssuerSSRF is the package-level seam tests substitute for the
// static issuer-URL SSRF gate. Production callers always run through
// validation.ValidateSafeURL; tests using httptest.NewServer (which
// binds to 127.0.0.1) swap this to a no-op in setup_test.go so the
// loopback URL doesn't trip the early-fail rail. Mirrors the
// jwksProbeClient / oidcDiscoveryClient test-seam pattern. Production
// code MUST NOT reassign this var.
var validateIssuerSSRF = validation.ValidateSafeURL
