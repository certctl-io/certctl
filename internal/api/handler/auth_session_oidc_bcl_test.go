// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
)

// Acquisition-audit SEC-021 closure (Sprint 1 follow-up to SEC-001,
// 2026-05-16). DefaultBCLVerifier.Verify performs a per-request
// discovery re-fetch via gooidc.NewProvider(ctx, matched.IssuerURL).
// Pre-fix, the bare ctx fell through to http.DefaultClient at the dial
// layer — no SSRF guard, no DNS-rebinding re-resolve. The fix wraps
// ctx via oidcsvc.SafeOIDCContext so the dial-time
// validation.SafeHTTPDialContext refuses reserved-address answers
// (loopback / link-local / cloud-metadata).
//
// This test pins the wrap end-to-end:
//
//  1. Construct a stubProviderRepo with one provider whose IssuerURL is
//     a literal-loopback http:// URL (the literal-IP class that
//     SafeHTTPDialContext.isReservedIPForDial refuses up-front, before
//     any DNS resolution attempt).
//  2. Hand-roll a 3-segment JWT whose payload base64url-decodes to
//     {"iss":"<loopback url>"} so peekIssuer extracts the matching
//     issuer and provs.List() returns the seeded provider.
//  3. Call Verify. The discovery NewProvider call now routes through
//     SafeOIDCContext; SafeHTTPDialContext sees the literal 127.0.0.1
//     and refuses with "refusing to dial reserved address <ip>".
//  4. Assert the returned error wraps that rejection (substring match
//     on "refusing to dial" / "reserved address") rather than a
//     generic connect-refused or "did not respond" wrap.
//
// Companion to TestFetchUserinfoGroups_SSRF_BlocksReservedAddress in
// internal/auth/oidc/service_test.go which exercises the same wrap on
// the userinfo-fallback leg. Together they pin the post-SEC-001 sweep.
func TestDefaultBCLVerifier_SSRF_BlocksReservedAddress(t *testing.T) {
	// Literal-loopback issuer URL. Port :1 keeps the URL syntactically
	// valid; SafeHTTPDialContext refuses on the literal-IP check before
	// the dial-time TCP connect, so the port choice is moot.
	const reservedIssuer = "http://127.0.0.1:1"

	provs := &stubProviderRepo{
		provs: []*oidcdomain.OIDCProvider{
			{ID: "op-loopback", IssuerURL: reservedIssuer, ClientID: "test-client"},
		},
	}
	v := NewDefaultBCLVerifier(provs, "t-default", nil)

	// Hand-roll the JWT. peekIssuer (see auth_session_oidc_bcl.go) parses
	// only the iss claim from the 2nd segment (payload), so the header +
	// signature segments only need to be syntactically present.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + reservedIssuer + `"}`))
	logoutToken := header + "." + payload + ".sig"

	_, _, _, _, _, err := v.Verify(context.Background(), logoutToken)
	if err == nil {
		t.Fatal("Verify against literal-loopback issuer URL: expected SSRF reject; got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "refusing to dial") && !strings.Contains(msg, "reserved address") {
		t.Errorf("Verify err = %q; want SafeHTTPDialContext reserved-address rejection", msg)
	}
	// Also confirm the error is wrapped through the Verify "provider
	// discovery:" prefix so callers can distinguish a discovery-time
	// dial failure from a signature-verification failure.
	if !strings.Contains(msg, "provider discovery") {
		t.Errorf("Verify err = %q; want \"provider discovery:\" wrap", msg)
	}
}
