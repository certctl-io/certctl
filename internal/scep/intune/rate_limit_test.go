package intune

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPerDeviceRateLimiter_AllowsUpToCap(t *testing.T) {
	l := NewPerDeviceRateLimiter(3, 24*time.Hour, 10)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Allow("device-1", "issuer-A", now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("call %d should be allowed: %v", i+1, err)
		}
	}
	if err := l.Allow("device-1", "issuer-A", now.Add(4*time.Minute)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("4th call should be rate-limited; got %v", err)
	}
}

func TestPerDeviceRateLimiter_DistinctKeysIndependent(t *testing.T) {
	l := NewPerDeviceRateLimiter(1, 24*time.Hour, 10)
	now := time.Now()

	if err := l.Allow("device-1", "issuer-A", now); err != nil {
		t.Fatalf("first allow: %v", err)
	}
	// Different subject — independent bucket.
	if err := l.Allow("device-2", "issuer-A", now); err != nil {
		t.Fatalf("different subject must have its own bucket: %v", err)
	}
	// Different issuer — also independent.
	if err := l.Allow("device-1", "issuer-B", now); err != nil {
		t.Fatalf("different issuer must have its own bucket: %v", err)
	}
	// Same key as call 1 — must be limited.
	if err := l.Allow("device-1", "issuer-A", now.Add(1*time.Second)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("repeat key should be limited; got %v", err)
	}
}

func TestPerDeviceRateLimiter_WindowExpiry(t *testing.T) {
	l := NewPerDeviceRateLimiter(2, 1*time.Hour, 10)
	now := time.Now()

	if err := l.Allow("dev", "iss", now); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow("dev", "iss", now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Inside window — limited.
	if err := l.Allow("dev", "iss", now.Add(45*time.Minute)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("inside-window 3rd call should be limited: %v", err)
	}
	// Past window — slots reopen.
	if err := l.Allow("dev", "iss", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("past-window call should be allowed (window reset): %v", err)
	}
}

func TestPerDeviceRateLimiter_DisabledBypass(t *testing.T) {
	l := NewPerDeviceRateLimiter(0, 24*time.Hour, 10) // maxN=0 → disabled
	if !l.Disabled() {
		t.Fatal("limiter with maxN=0 must report Disabled()=true")
	}
	now := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Allow("dev", "iss", now); err != nil {
			t.Fatalf("disabled limiter must allow everything: %v", err)
		}
	}
	// Disabled limiter doesn't track buckets.
	if got := l.Len(); got != 0 {
		t.Errorf("disabled limiter Len() = %d, want 0", got)
	}
}

func TestPerDeviceRateLimiter_NegativeCapDisabled(t *testing.T) {
	l := NewPerDeviceRateLimiter(-1, 24*time.Hour, 10)
	if !l.Disabled() {
		t.Fatal("negative maxN must produce a disabled limiter")
	}
}

func TestPerDeviceRateLimiter_EmptySubjectShortCircuits(t *testing.T) {
	// Empty subject is the caller's defense-in-depth case (claim validation
	// upstream should reject empty-subject claims first). Limiter must not
	// build a single shared bucket keyed by empty-subject — that would
	// be a fleet-wide chokepoint.
	l := NewPerDeviceRateLimiter(1, 24*time.Hour, 10)
	now := time.Now()
	for i := 0; i < 50; i++ {
		if err := l.Allow("", "iss", now); err != nil {
			t.Fatalf("empty subject must short-circuit (call %d): %v", i, err)
		}
	}
	if got := l.Len(); got != 0 {
		t.Errorf("Len after 50 empty-subject calls = %d, want 0 (no bucket created)", got)
	}
}

func TestPerDeviceRateLimiter_DefaultCapsHonored(t *testing.T) {
	l := NewPerDeviceRateLimiter(5, 0, 0) // window=0 → 24h default; cap=0 → 100k default
	if l.window != 24*time.Hour {
		t.Errorf("default window = %v, want 24h", l.window)
	}
	if l.cap != 100_000 {
		t.Errorf("default cap = %d, want 100000", l.cap)
	}
}

func TestPerDeviceRateLimiter_MapCapEvictsOldest(t *testing.T) {
	// Cap of 3 keys to exercise the eviction branch deterministically.
	l := NewPerDeviceRateLimiter(2, 1*time.Hour, 3)
	now := time.Now()

	// Insert 3 distinct keys with increasing timestamps.
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("dev-%d", i)
		if err := l.Allow(key, "iss", now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if l.Len() != 3 {
		t.Fatalf("Len = %d, want 3", l.Len())
	}

	// 4th key forces eviction of dev-0 (its newest timestamp is oldest).
	if err := l.Allow("dev-3", "iss", now.Add(10*time.Minute)); err != nil {
		t.Fatalf("4th-key insert: %v", err)
	}
	if l.Len() != 3 {
		t.Errorf("Len after at-cap insert = %d, want 3 (cap honored)", l.Len())
	}
}

func TestPerDeviceRateLimiter_ConcurrentRaceFree(t *testing.T) {
	if testing.Short() {
		t.Skip("race-style test under -short")
	}
	l := NewPerDeviceRateLimiter(50, 24*time.Hour, 10000)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			now := time.Now()
			key := fmt.Sprintf("dev-%d", id)
			for i := 0; i < 30; i++ {
				_ = l.Allow(key, "iss", now)
			}
		}(g)
	}
	wg.Wait()
	if got := l.Len(); got != 20 {
		t.Errorf("expected 20 distinct keys; got %d", got)
	}
}

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
