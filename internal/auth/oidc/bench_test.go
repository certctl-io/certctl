package oidc

import (
	"context"
	"sort"
	"testing"
	"time"
)

// =============================================================================
// Bundle 2 Phase 14 — OIDC token validation benchmark (steady state).
//
// Measures the warm-JWKS-cache OIDC HandleCallback path against an
// in-process mockIdP. The mockIdP runs as an httptest.Server on
// localhost so the "exchange code for tokens" round-trip + the
// JWKS-cache hit are both purely local; there is NO real network
// latency in this measurement.
//
// Phase 14 target: p99 < 5ms.
//
// What this benchmark covers:
//   - parseCookie + pre-login row consume (in-memory stubPreLogin)
//   - OAuth2 Exchange against the mockIdP /token endpoint
//     (httptest.Server local-loopback, ~50-200 µs typical)
//   - go-oidc's id_token verification (JWKS cache lookup + RSA-2048
//     signature verify + alg pin)
//   - certctl service-layer re-verification (iss / aud / azp /
//     at_hash / exp / iat / nonce)
//   - Group-claim resolution (groupclaim/resolver.go)
//   - Group→role mapping (in-memory stubMappings)
//   - User upsert (in-memory stubUsers)
//   - Session mint via stubSessions
//
// What this benchmark does NOT cover:
//   - JWKS network refetch (that's the Phase-14 ColdCache benchmark
//     in bench_keycloak_test.go; build-tagged under integration).
//   - Real-network IdP latency (steady state assumes JWKS cache is
//     warm; the local-loopback /token call is the "control" for
//     the production cost of a same-region IdP /token call).
//
// The cold-cache OIDC measurement runs against a live Keycloak
// container per the Phase 10 fixture; see bench_keycloak_test.go
// (//go:build integration).
//
// Run via:
//   go test -bench BenchmarkOIDC_SteadyState -benchmem -run='^$' \
//     ./internal/auth/oidc/
//
// The full Phase 14 result table lives at docs/operator/auth-benchmarks.md.
// =============================================================================

// reportOIDCPercentiles is identical in shape to the session
// benchmark's reportPercentiles, duplicated here so the two
// benchmark files don't share a helper across the package boundary.
func reportOIDCPercentiles(b *testing.B, samples []time.Duration) {
	b.Helper()
	if len(samples) == 0 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p := func(pct float64) time.Duration {
		idx := int(float64(len(samples)) * pct / 100.0)
		if idx >= len(samples) {
			idx = len(samples) - 1
		}
		return samples[idx]
	}
	b.ReportMetric(float64(p(50).Microseconds()), "p50_us/op")
	b.ReportMetric(float64(p(95).Microseconds()), "p95_us/op")
	b.ReportMetric(float64(p(99).Microseconds()), "p99_us/op")
	b.ReportMetric(float64(samples[len(samples)-1].Microseconds()), "max_us/op")
}

// BenchmarkOIDC_SteadyState measures the OIDC HandleCallback p99
// against an in-process mockIdP. Warm JWKS cache (the first iteration
// triggers the cache load via getOrLoad; subsequent iterations hit
// the cached entry).
//
// Phase 14 target: p99 < 5ms.
func BenchmarkOIDC_SteadyState(b *testing.B) {
	idp := newMockIdPForBench(b)
	svc, pl := newBenchServiceWithProviderAndPL(b, idp.URL(), "op-bench")

	// Pre-warm the JWKS cache so the first iteration's measurement
	// doesn't include the discovery + JWKS load.
	if err := svc.RefreshKeys(context.Background(), "op-bench"); err != nil {
		b.Fatalf("RefreshKeys (warm): %v", err)
	}

	ctx := context.Background()
	samples := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Each iteration needs a fresh pre-login row (HandleCallback
		// consumes the row atomically + single-use). State + nonce +
		// verifier are stable; the cookie value is unique per call.
		cookie, _, err := pl.CreatePreLogin(ctx, "op-bench", "bench-state", "test-nonce-fixed", "verifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		if err != nil {
			b.Fatalf("CreatePreLogin: %v", err)
		}

		start := time.Now()
		_, err = svc.HandleCallback(ctx, cookie, "bench-code", "bench-state", "", "10.0.0.1", "bench/1.0")
		elapsed := time.Since(start)
		if err != nil {
			b.Fatalf("HandleCallback: %v", err)
		}
		samples = append(samples, elapsed)
	}
	b.StopTimer()
	reportOIDCPercentiles(b, samples)
}

// ---------------------------------------------------------------------------
// Benchmark-local helpers (versions of the service_test.go helpers
// that take a *testing.B instead of *testing.T).
// ---------------------------------------------------------------------------

func newMockIdPForBench(b *testing.B) *mockIdP {
	b.Helper()
	// newMockIdP takes *testing.T; we pass an adapter via the public
	// interface. Since *testing.T and *testing.B both satisfy
	// testing.TB, we adapt by using a synthetic T wrapper.
	return newMockIdPWithTB(b)
}

func newBenchServiceWithProviderAndPL(b *testing.B, idpURL, providerID string) (*Service, *stubPreLogin) {
	b.Helper()
	prov := makeProvider(idpURL, providerID)
	pl := newStubPreLogin()
	mappings := &stubMappings{roleIDs: []string{"r-operator"}}
	users := newStubUsers()
	sessions := &stubSessions{}
	svc := NewService(
		&stubProviderLookup{provider: prov},
		mappings,
		users,
		sessions,
		pl,
		"",
	)
	return svc, pl
}
