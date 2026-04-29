package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// EST RFC 7030 hardening master bundle Phase 4.1: this test file holds the
// white-box tests for the SlidingWindowLimiter primitives that used to live
// in internal/scep/intune/rate_limit_test.go (TestPerDeviceRateLimiter_
// DefaultCapsHonored, TestPruneOlderThan, TestPruneOlderThan_NoOpWhen
// NothingToPrune). The behavioral coverage in intune/rate_limit_test.go
// stays — it exercises the wrapper's (subject, issuer)-composition contract
// + the empty-subject short-circuit + concurrent race-freedom.

func TestSlidingWindowLimiter_AllowsUpToCap(t *testing.T) {
	l := NewSlidingWindowLimiter(3, 24*time.Hour, 10)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Allow("k", now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("call %d should be allowed: %v", i+1, err)
		}
	}
	if err := l.Allow("k", now.Add(4*time.Minute)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("4th call should be rate-limited; got %v", err)
	}
}

func TestSlidingWindowLimiter_DistinctKeysIndependent(t *testing.T) {
	l := NewSlidingWindowLimiter(1, 24*time.Hour, 10)
	now := time.Now()

	if err := l.Allow("k-1", now); err != nil {
		t.Fatalf("first allow: %v", err)
	}
	if err := l.Allow("k-2", now); err != nil {
		t.Fatalf("different key must have its own bucket: %v", err)
	}
	if err := l.Allow("k-1", now.Add(1*time.Second)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("repeat key should be limited; got %v", err)
	}
}

func TestSlidingWindowLimiter_WindowExpiry(t *testing.T) {
	l := NewSlidingWindowLimiter(2, 1*time.Hour, 10)
	now := time.Now()

	if err := l.Allow("k", now); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow("k", now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Inside window — limited.
	if err := l.Allow("k", now.Add(45*time.Minute)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("inside-window 3rd call should be limited: %v", err)
	}
	// Past window — slots reopen.
	if err := l.Allow("k", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("past-window call should be allowed (window reset): %v", err)
	}
}

func TestSlidingWindowLimiter_DisabledBypass(t *testing.T) {
	l := NewSlidingWindowLimiter(0, 24*time.Hour, 10) // maxN=0 → disabled
	if !l.Disabled() {
		t.Fatal("limiter with maxN=0 must report Disabled()=true")
	}
	now := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Allow("k", now); err != nil {
			t.Fatalf("disabled limiter must allow everything: %v", err)
		}
	}
	if got := l.Len(); got != 0 {
		t.Errorf("disabled limiter Len() = %d, want 0", got)
	}
}

func TestSlidingWindowLimiter_NegativeCapDisabled(t *testing.T) {
	l := NewSlidingWindowLimiter(-1, 24*time.Hour, 10)
	if !l.Disabled() {
		t.Fatal("negative maxN must produce a disabled limiter")
	}
}

func TestSlidingWindowLimiter_EmptyKeyShortCircuits(t *testing.T) {
	// Empty key is the caller's defense-in-depth case — caller's validation
	// upstream should reject empty-key events first. Limiter must not build
	// a single shared bucket keyed by empty-key — that would be a chokepoint
	// for every empty-key event.
	l := NewSlidingWindowLimiter(1, 24*time.Hour, 10)
	now := time.Now()
	for i := 0; i < 50; i++ {
		if err := l.Allow("", now); err != nil {
			t.Fatalf("empty key must short-circuit (call %d): %v", i, err)
		}
	}
	if got := l.Len(); got != 0 {
		t.Errorf("Len after 50 empty-key calls = %d, want 0 (no bucket created)", got)
	}
}

func TestSlidingWindowLimiter_DefaultCapsHonored(t *testing.T) {
	// White-box test: exercises the constructor's default-fill branches.
	// Lives here (not in the intune wrapper test) because the fields
	// (window + cap) are package-private to ratelimit.
	l := NewSlidingWindowLimiter(5, 0, 0) // window=0 → 24h default; cap=0 → 100k default
	if l.window != 24*time.Hour {
		t.Errorf("default window = %v, want 24h", l.window)
	}
	if l.cap != 100_000 {
		t.Errorf("default cap = %d, want 100000", l.cap)
	}
}

func TestSlidingWindowLimiter_MapCapEvictsOldest(t *testing.T) {
	// Cap of 3 keys to exercise the eviction branch deterministically.
	l := NewSlidingWindowLimiter(2, 1*time.Hour, 3)
	now := time.Now()

	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("k-%d", i)
		if err := l.Allow(key, now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if l.Len() != 3 {
		t.Fatalf("Len = %d, want 3", l.Len())
	}

	// 4th key forces eviction of k-0 (its newest timestamp is oldest).
	if err := l.Allow("k-3", now.Add(10*time.Minute)); err != nil {
		t.Fatalf("4th-key insert: %v", err)
	}
	if l.Len() != 3 {
		t.Errorf("Len after at-cap insert = %d, want 3 (cap honored)", l.Len())
	}
}

func TestSlidingWindowLimiter_ConcurrentRaceFree(t *testing.T) {
	if testing.Short() {
		t.Skip("race-style test under -short")
	}
	l := NewSlidingWindowLimiter(50, 24*time.Hour, 10000)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			now := time.Now()
			key := fmt.Sprintf("k-%d", id)
			for i := 0; i < 30; i++ {
				_ = l.Allow(key, now)
			}
		}(g)
	}
	wg.Wait()
	if got := l.Len(); got != 20 {
		t.Errorf("expected 20 distinct keys; got %d", got)
	}
}

// White-box tests for the unexported pruneOlderThan helper. Live in this
// package because the helper is package-private to ratelimit. The test
// surface used to live in intune/rate_limit_test.go before the Phase 4.1
// extraction.
func TestPruneOlderThan(t *testing.T) {
	t0 := time.Now()
	in := []time.Time{
		t0.Add(-3 * time.Hour),    // pruned (older than cutoff)
		t0.Add(-2 * time.Hour),    // pruned (older than cutoff)
		t0.Add(-1 * time.Hour),    // survives (-60m is NEWER than the -90m cutoff)
		t0.Add(-30 * time.Minute), // survives
		t0,                        // survives
	}
	out := pruneOlderThan(in, t0.Add(-90*time.Minute))
	if len(out) != 3 {
		t.Fatalf("len(out) = %d, want 3 (-1h, -30m, t0 all newer than -90m cutoff)", len(out))
	}
	if !out[0].Equal(t0.Add(-1 * time.Hour)) {
		t.Errorf("out[0] = %v, want -1h (oldest surviving entry)", out[0])
	}
}

func TestPruneOlderThan_NoOpWhenNothingToPrune(t *testing.T) {
	t0 := time.Now()
	in := []time.Time{t0.Add(-1 * time.Minute), t0}
	out := pruneOlderThan(in, t0.Add(-1*time.Hour))
	// Same slice header (no copy needed).
	if len(out) != len(in) {
		t.Fatalf("len(out) = %d, want %d", len(out), len(in))
	}
}
