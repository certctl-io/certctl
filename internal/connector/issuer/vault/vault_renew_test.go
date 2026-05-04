package vault

// Top-10 fix #5 of the 2026-05-03 issuer-coverage audit. Pins the
// behaviour of the renew-self loop end to end:
//
//   1. cadence — at TTL/2 with a (configurable) deterministic ticker
//      so the test isn't wall-clock bound;
//   2. terminate-on-not-renewable — if Vault returns renewable=false,
//      the loop exits and the metric records the not_renewable
//      result;
//   3. failure-surfaces — the metric counter increments on a 403 and
//      the loop keeps ticking (transient blips don't kill it);
//   4. ctx-cancellation — Stop returns within a small budget after
//      ctx is cancelled.
//
// These tests live INSIDE the `vault` package (not vault_test) so
// they can substitute the renewTickerFactory seam directly. The
// existing test files in this directory are split into vault_test
// (external, exercises the public API) and the package-internal
// _test.go files (this one) — Go's two-package test convention.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/secret"
)

// fakeTicker is the deterministic ticker the tests inject via
// renewTickerFactory. Tests call Tick() to fire the ticker channel
// at the moment of their choosing — no real time elapses.
type fakeTicker struct {
	ch        chan time.Time
	stopCalls atomic.Uint64
}

func newFakeTicker() *fakeTicker {
	return &fakeTicker{ch: make(chan time.Time, 4)}
}

func (f *fakeTicker) C() <-chan time.Time { return f.ch }
func (f *fakeTicker) Stop()               { f.stopCalls.Add(1) }
func (f *fakeTicker) Tick()               { f.ch <- time.Now() }

// renewMockHandler is the per-test httptest handler shape. Tests
// configure it to control lookup-self / renew-self responses.
type renewMockHandler struct {
	mu                sync.Mutex
	lookupTTLSeconds  int
	lookupRenewable   bool
	renewSelfStatuses []renewSelfStub // queued; consumed in order
	renewSelfCalls    atomic.Uint64
	lookupSelfCalls   atomic.Uint64
	noMoreCalls       func() // called if a queued stub is exhausted
}

// renewSelfStub configures one expected renew-self response.
type renewSelfStub struct {
	status        int
	body          string // override the canned body
	leaseDuration int
	renewable     bool
}

func (h *renewMockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/auth/token/lookup-self":
		h.lookupSelfCalls.Add(1)
		h.mu.Lock()
		ttl, renewable := h.lookupTTLSeconds, h.lookupRenewable
		h.mu.Unlock()
		body := fmt.Sprintf(`{"data":{"ttl":%d,"renewable":%t}}`, ttl, renewable)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	case "/v1/auth/token/renew-self":
		h.renewSelfCalls.Add(1)
		h.mu.Lock()
		var stub renewSelfStub
		if len(h.renewSelfStatuses) > 0 {
			stub = h.renewSelfStatuses[0]
			h.renewSelfStatuses = h.renewSelfStatuses[1:]
		} else {
			h.mu.Unlock()
			if h.noMoreCalls != nil {
				h.noMoreCalls()
			}
			http.Error(w, "no more renew-self stubs configured", http.StatusInternalServerError)
			return
		}
		h.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		status := stub.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		body := stub.body
		if body == "" {
			body = fmt.Sprintf(`{"auth":{"lease_duration":%d,"renewable":%t}}`, stub.leaseDuration, stub.renewable)
		}
		_, _ = io.WriteString(w, body)
	default:
		http.NotFound(w, r)
	}
}

// quietTestLogger returns a logger that discards everything below
// ERROR. Tests assert via the recorder + ticker hooks; per-tick
// INFO/WARN logs would clutter the test output.
func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// mockRecorder counts RecordRenewal calls per result. Replaces the
// production *service.VaultRenewalMetrics for unit-test isolation.
type mockRecorder struct {
	mu     sync.Mutex
	counts map[string]uint64
}

func newMockRecorder() *mockRecorder {
	return &mockRecorder{counts: make(map[string]uint64)}
}

func (m *mockRecorder) RecordRenewal(result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[result]++
}

func (m *mockRecorder) get(result string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[result]
}

// buildTestConnector constructs a vault.Connector pointed at the
// httptest server, with the deterministic ticker factory and the
// supplied recorder.
func buildTestConnector(srvURL string, ticker *fakeTicker, rec RenewalRecorder) *Connector {
	c := New(&Config{
		Addr:  srvURL,
		Token: secret.NewRefFromString("hvs.test-token"),
		Mount: "pki",
		Role:  "web",
	}, quietTestLogger())
	c.renewTickerFactory = func(d time.Duration) renewTicker { return ticker }
	if rec != nil {
		c.SetRenewalRecorder(rec)
	}
	return c
}

// TestVault_RenewLoop_TickAtHalfTTL pins that the loop calls
// renew-self once per ticker fire. Cadence assertion is via the
// fake ticker: Tick three times → expect three renew-self calls.
// (Production cadence — TTL/2 — is verified by assertions on
// computeInterval below; substituting the ticker here keeps the
// test wall-clock-free.)
func TestVault_RenewLoop_TickAtHalfTTL(t *testing.T) {
	mock := &renewMockHandler{
		lookupTTLSeconds: 4, // 2s cadence
		lookupRenewable:  true,
		renewSelfStatuses: []renewSelfStub{
			{leaseDuration: 4, renewable: true},
			{leaseDuration: 4, renewable: true},
			{leaseDuration: 4, renewable: true},
		},
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ticker := newFakeTicker()
	rec := newMockRecorder()
	c := buildTestConnector(srv.URL, ticker, rec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	if mock.lookupSelfCalls.Load() != 1 {
		t.Errorf("expected exactly 1 lookup-self at startup, got %d", mock.lookupSelfCalls.Load())
	}

	// Fire three ticks; each should drive one renew-self.
	for i := 0; i < 3; i++ {
		ticker.Tick()
	}

	// Wait briefly for the goroutine to drain the channel sends.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.get("success") >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := rec.get("success"); got != 3 {
		t.Errorf("expected 3 success renewals after 3 ticks, got %d", got)
	}
	if got := rec.get("failure"); got != 0 {
		t.Errorf("expected 0 failures, got %d", got)
	}
	if got := rec.get("not_renewable"); got != 0 {
		t.Errorf("expected 0 not_renewable events, got %d", got)
	}
	if got := mock.renewSelfCalls.Load(); got != 3 {
		t.Errorf("expected 3 renew-self HTTP calls, got %d", got)
	}
}

// TestVault_RenewLoop_StopsOnNotRenewable pins that the loop exits
// cleanly after Vault returns renewable=false on a renew-self call.
// A second tick is sent after the not-renewable response; the
// goroutine should already be stopped by then so the second tick
// triggers no HTTP call.
func TestVault_RenewLoop_StopsOnNotRenewable(t *testing.T) {
	mock := &renewMockHandler{
		lookupTTLSeconds: 4,
		lookupRenewable:  true,
		renewSelfStatuses: []renewSelfStub{
			{leaseDuration: 4, renewable: true},
			{leaseDuration: 4, renewable: false}, // tells loop to stop
		},
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ticker := newFakeTicker()
	rec := newMockRecorder()
	c := buildTestConnector(srv.URL, ticker, rec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	ticker.Tick() // first renewal — success
	ticker.Tick() // second renewal — renewable=false, loop exits

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.get("not_renewable") >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := rec.get("success"); got != 1 {
		t.Errorf("expected 1 success before not_renewable, got %d", got)
	}
	if got := rec.get("not_renewable"); got != 1 {
		t.Errorf("expected exactly 1 not_renewable event, got %d", got)
	}

	// Confirm the goroutine has already exited: we check the
	// renewMu's renewDone channel via Stop. If the loop is alive,
	// Stop blocks until ctx is cancelled. If it has already
	// exited (which it should), Stop returns near-immediately.
	stopDone := make(chan struct{})
	go func() {
		c.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// expected — goroutine had already exited.
	case <-time.After(200 * time.Millisecond):
		t.Error("Stop did not return within 200ms after renewable=false — goroutine leaked")
	}
}

// TestVault_RenewLoop_FailureSurfacesViaMetric pins that a 403 on
// renew-self bumps the failure counter and the loop keeps ticking
// (transient blips do not kill the loop).
func TestVault_RenewLoop_FailureSurfacesViaMetric(t *testing.T) {
	mock := &renewMockHandler{
		lookupTTLSeconds: 4,
		lookupRenewable:  true,
		renewSelfStatuses: []renewSelfStub{
			{status: http.StatusForbidden, body: `{"errors":["permission denied"]}`},
			{leaseDuration: 4, renewable: true}, // loop continues; this tick succeeds
		},
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ticker := newFakeTicker()
	rec := newMockRecorder()
	c := buildTestConnector(srv.URL, ticker, rec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	ticker.Tick() // first — fails with 403
	ticker.Tick() // second — succeeds

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.get("failure") >= 1 && rec.get("success") >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := rec.get("failure"); got != 1 {
		t.Errorf("expected 1 failure after 403, got %d", got)
	}
	if got := rec.get("success"); got != 1 {
		t.Errorf("expected 1 success after recovery, got %d", got)
	}
}

// TestVault_RenewLoop_CtxCancellation_StopsCleanly pins that
// cancelling ctx causes the goroutine to exit promptly. Stop()
// blocks on the goroutine's done channel; if it doesn't return
// within 200ms after cancel, the goroutine is leaked.
func TestVault_RenewLoop_CtxCancellation_StopsCleanly(t *testing.T) {
	mock := &renewMockHandler{
		lookupTTLSeconds:  4,
		lookupRenewable:   true,
		renewSelfStatuses: nil, // no ticks expected; ctx will cancel before any
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ticker := newFakeTicker()
	rec := newMockRecorder()
	c := buildTestConnector(srv.URL, ticker, rec)

	ctx, cancel := context.WithCancel(context.Background())

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Cancel ctx; the goroutine should exit on ctx.Done() before
	// any tick fires.
	start := time.Now()
	cancel()

	stopDone := make(chan struct{})
	go func() {
		c.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		elapsed := time.Since(start)
		if elapsed > 200*time.Millisecond {
			t.Errorf("Stop returned after %v — goroutine slow to exit", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop did not return within 500ms after ctx cancellation — goroutine leaked")
	}

	// No renew-self calls should have fired (cancel raced before any tick).
	if got := mock.renewSelfCalls.Load(); got != 0 {
		t.Errorf("expected 0 renew-self HTTP calls, got %d", got)
	}
}

// TestVault_RenewLoop_StartsNothingWhenNotRenewable pins the
// startup short-circuit: if lookup-self returns renewable=false at
// boot, Start does not spawn the goroutine and the metric records
// the not_renewable result so operators see it in Grafana before
// any tick would have fired.
func TestVault_RenewLoop_StartsNothingWhenNotRenewable(t *testing.T) {
	mock := &renewMockHandler{
		lookupTTLSeconds: 60,
		lookupRenewable:  false, // already non-renewable at boot
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ticker := newFakeTicker()
	rec := newMockRecorder()
	c := buildTestConnector(srv.URL, ticker, rec)

	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start should not error on initially-non-renewable token; got: %v", err)
	}
	defer c.Stop()

	if got := rec.get("not_renewable"); got != 1 {
		t.Errorf("expected 1 not_renewable event from startup short-circuit, got %d", got)
	}

	// Tick should be a no-op — no goroutine running.
	ticker.Tick()
	time.Sleep(100 * time.Millisecond)
	if got := mock.renewSelfCalls.Load(); got != 0 {
		t.Errorf("expected 0 renew-self HTTP calls (loop never started), got %d", got)
	}
}

// TestVault_ComputeInterval pins the cadence-derivation rules: TTL/2
// for normal tokens, floored at minRenewInterval for misconfigured
// short TTLs that would otherwise hammer Vault's audit log.
func TestVault_ComputeInterval(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"hour-ttl", time.Hour, 30 * time.Minute},
		{"day-ttl", 24 * time.Hour, 12 * time.Hour},
		{"floor-applies-tiny", 2 * time.Second, minRenewInterval},
		{"floor-applies-zero", 0, minRenewInterval},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeInterval(tc.ttl)
			if got != tc.want {
				t.Errorf("computeInterval(%v) = %v, want %v", tc.ttl, got, tc.want)
			}
		})
	}
}

// TestVault_RenewSelf_ParseFailure_NamesActionableInError pins that
// failures surface with operator-actionable framing. We test the
// HTTP-failure path; the parse-failure path lives in the same wrap
// chain.
func TestVault_RenewSelf_ParseFailure_NamesActionableInError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `not json`)
	}))
	defer srv.Close()

	c := buildTestConnector(srv.URL, newFakeTicker(), nil)

	_, err := c.renewSelf(context.Background())
	if err == nil {
		t.Fatal("expected error from renewSelf with bad JSON, got nil")
	}
	if !strings.Contains(err.Error(), "vault token renewal failed") {
		t.Errorf("expected 'vault token renewal failed' framing in surfaced error; got: %v", err)
	}
	if !strings.Contains(err.Error(), "rotate the token") {
		t.Errorf("expected 'rotate the token' operator-action substring in surfaced error; got: %v", err)
	}
}

// _unused_marker keeps the json import alive when the test file is
// edited and one of the json-using helpers temporarily disappears.
// Production has no use for this; tests do.
var _ = json.Marshal
