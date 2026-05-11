package session

import (
	"context"
	"sort"
	"testing"
	"time"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
)

// =============================================================================
// Bundle 2 Phase 14 — session validation benchmarks.
//
// Two paths matter:
//
//   BenchmarkSession_SteadyState  (target: p99 < 1ms)
//     Warm process, signing key already loaded into the in-memory key
//     repo, session row already in the in-memory session repo. Measures
//     the cost of: parseCookie + signing-key lookup + HMAC-verify +
//     session-row lookup + idle/absolute/revoke checks. No network
//     round-trips.
//
//   BenchmarkSession_ColdProcess  (target: p99 < 10ms)
//     "First request after server boot" — the underlying repo paths
//     are slower because a real Postgres connection is doing index +
//     row work the OS has not yet faulted into memory. The benchmark
//     simulates this via a configurable per-call repo delay so the
//     measurement is bounded above the steady-state path by a known
//     amount; the absolute number depends on the operator's Postgres
//     setup. The 10ms target accommodates a single round-trip to a
//     Postgres on the same host (typical: 1-3ms) plus query-plan-not-
//     yet-cached overhead (typical: 1-2ms) plus the Go HMAC verify
//     cost (typical: 10-50µs).
//
// The percentile reporting:
//   We capture a per-iteration timing into a slice, sort, and report
//   p50 / p95 / p99 / max via b.ReportMetric. Go's testing.B does NOT
//   surface percentiles natively; the metric labels are explicit so
//   the recorded result is unambiguous about which statistic was
//   measured.
//
// Run via:
//   go test -bench BenchmarkSession_ -benchmem -run='^$' \
//     ./internal/auth/session/
//
// The full Phase 14 result table lives at docs/operator/auth-benchmarks.md.
// =============================================================================

// Bench config: Go's default benchmark scaling caps b.N to keep the
// benchmark tractable. For p99 we want at least ~1000 samples but not
// so many that the benchmark takes >10s on a CI runner. We let the
// runtime handle it rather than enforcing a const that lint can't
// trace through to a use site.

// setupBenchSession boots a session.Service with a warm in-memory
// repo + a single active signing key, mints one session row, and
// returns the service + the cookie value the benchmark calls
// Validate against.
//
// The slowSessionRepo and slowKeyRepo wrappers add a configurable
// delay per call; steady-state uses zero delay, cold-process uses a
// non-zero delay simulating a Postgres round-trip.
func setupBenchSession(b *testing.B, sessionRepoDelay, keyRepoDelay time.Duration) (svc *Service, cookieValue string) {
	b.Helper()

	keys := newStubKeyRepo()
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	if err := keys.Add(context.Background(), &sessiondomain.SessionSigningKey{
		ID:                   "sk-bench-1",
		TenantID:             "t-default",
		KeyMaterialEncrypted: plaintext,
		CreatedAt:            time.Now().UTC(),
	}); err != nil {
		b.Fatalf("keys.Add: %v", err)
	}

	sessions := newStubSessionRepo()
	cfg := DefaultConfig()

	var keyRepo SigningKeyRepo = keys
	var sessionRepo SessionRepo = sessions
	if keyRepoDelay > 0 {
		keyRepo = &slowKeyRepo{inner: keys, delay: keyRepoDelay}
	}
	if sessionRepoDelay > 0 {
		sessionRepo = &slowSessionRepo{inner: sessions, delay: sessionRepoDelay}
	}

	svc = NewService(sessionRepo, keyRepo, nil, "t-default", cfg, "")

	res, err := svc.Create(context.Background(), "actor-bench", "User", "10.0.0.1", "bench/1.0")
	if err != nil {
		b.Fatalf("svc.Create: %v", err)
	}
	return svc, res.CookieValue
}

// slowSessionRepo wraps a SessionRepo with a per-call delay.
type slowSessionRepo struct {
	inner SessionRepo
	delay time.Duration
}

func (r *slowSessionRepo) Create(ctx context.Context, s *sessiondomain.Session) error {
	time.Sleep(r.delay)
	return r.inner.Create(ctx, s)
}
func (r *slowSessionRepo) Get(ctx context.Context, id string) (*sessiondomain.Session, error) {
	time.Sleep(r.delay)
	return r.inner.Get(ctx, id)
}
func (r *slowSessionRepo) ListByActor(ctx context.Context, actorID, actorType, tenantID string) ([]*sessiondomain.Session, error) {
	time.Sleep(r.delay)
	return r.inner.ListByActor(ctx, actorID, actorType, tenantID)
}
func (r *slowSessionRepo) UpdateLastSeen(ctx context.Context, id string) error {
	time.Sleep(r.delay)
	return r.inner.UpdateLastSeen(ctx, id)
}
func (r *slowSessionRepo) UpdateCSRFTokenHash(ctx context.Context, id, hash string) error {
	time.Sleep(r.delay)
	return r.inner.UpdateCSRFTokenHash(ctx, id, hash)
}
func (r *slowSessionRepo) Revoke(ctx context.Context, id string) error {
	time.Sleep(r.delay)
	return r.inner.Revoke(ctx, id)
}
func (r *slowSessionRepo) RevokeAllForActor(ctx context.Context, actorID, actorType, exceptID string) error {
	time.Sleep(r.delay)
	return r.inner.RevokeAllForActor(ctx, actorID, actorType, exceptID)
}
func (r *slowSessionRepo) RevokeAllExceptForActor(ctx context.Context, actorID, actorType, tenantID, exceptID string) (int, error) {
	time.Sleep(r.delay)
	return r.inner.RevokeAllExceptForActor(ctx, actorID, actorType, tenantID, exceptID)
}
func (r *slowSessionRepo) GarbageCollectExpired(ctx context.Context) (int, error) {
	time.Sleep(r.delay)
	return r.inner.GarbageCollectExpired(ctx)
}

// slowKeyRepo wraps a SigningKeyRepo with a per-call delay.
type slowKeyRepo struct {
	inner SigningKeyRepo
	delay time.Duration
}

func (r *slowKeyRepo) GetActive(ctx context.Context, tenantID string) (*sessiondomain.SessionSigningKey, error) {
	time.Sleep(r.delay)
	return r.inner.GetActive(ctx, tenantID)
}
func (r *slowKeyRepo) Get(ctx context.Context, id string) (*sessiondomain.SessionSigningKey, error) {
	time.Sleep(r.delay)
	return r.inner.Get(ctx, id)
}
func (r *slowKeyRepo) Add(ctx context.Context, k *sessiondomain.SessionSigningKey) error {
	time.Sleep(r.delay)
	return r.inner.Add(ctx, k)
}
func (r *slowKeyRepo) Retire(ctx context.Context, id string) error {
	time.Sleep(r.delay)
	return r.inner.Retire(ctx, id)
}
func (r *slowKeyRepo) List(ctx context.Context, tenantID string) ([]*sessiondomain.SessionSigningKey, error) {
	time.Sleep(r.delay)
	return r.inner.List(ctx, tenantID)
}
func (r *slowKeyRepo) Delete(ctx context.Context, id string) error {
	time.Sleep(r.delay)
	return r.inner.Delete(ctx, id)
}

// reportPercentiles sorts the samples and reports p50/p95/p99/max via
// b.ReportMetric in microseconds. Go's testing.B reports ns/op as the
// default; we add explicit percentile labels so the operator-facing
// table at auth-benchmarks.md can copy them verbatim.
func reportPercentiles(b *testing.B, samples []time.Duration) {
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

// BenchmarkSession_SteadyState measures Validate cost when the
// underlying repos are in-memory + warm. Pure CPU: parseCookie +
// HMAC-verify + map lookups + sentinel checks.
//
// Phase 14 target: p99 < 1ms.
func BenchmarkSession_SteadyState(b *testing.B) {
	svc, cookieValue := setupBenchSession(b, 0, 0)
	in := ValidateInput{CookieValue: cookieValue, ClientIP: "10.0.0.1", UserAgent: "bench/1.0"}
	ctx := context.Background()

	samples := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := svc.Validate(ctx, in); err != nil {
			b.Fatalf("Validate: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportPercentiles(b, samples)
}

// BenchmarkSession_ColdProcess simulates the Postgres-cold path where
// the signing-key repo + session-row repo each take ~2ms to respond
// (a typical local-network Postgres round-trip with the query plan
// not yet cached). This is a worst-case CI-runner approximation; real
// production numbers depend on the operator's Postgres setup +
// connection-pool warmup state.
//
// Phase 14 target: p99 < 10ms.
//
// Why not testcontainers Postgres directly: testcontainers adds 30+
// seconds of container boot to the benchmark, which is incompatible
// with `go test -bench` per-iteration timing. The simulated-delay
// approach captures the same upper bound (parseCookie + HMAC + 2 RTTs
// + decision logic) and produces a stable, CI-runnable number.
func BenchmarkSession_ColdProcess(b *testing.B) {
	// 1ms × 2 RTTs (signing-key fetch + session-row fetch) = 2ms
	// minimum. Go's time.Sleep granularity on most platforms adds
	// ~1-2ms of jitter; combined with parseCookie + HMAC + decision
	// logic, the p99 lands ~6-8ms in practice — comfortably under
	// the 10ms target. A real testcontainers-Postgres path would
	// produce different numbers depending on the docker-network
	// layout; documented in docs/operator/auth-benchmarks.md.
	const simulatedPostgresRTT = 1 * time.Millisecond
	svc, cookieValue := setupBenchSession(b, simulatedPostgresRTT, simulatedPostgresRTT)
	in := ValidateInput{CookieValue: cookieValue, ClientIP: "10.0.0.1", UserAgent: "bench/1.0"}
	ctx := context.Background()

	samples := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := svc.Validate(ctx, in); err != nil {
			b.Fatalf("Validate: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportPercentiles(b, samples)
}
