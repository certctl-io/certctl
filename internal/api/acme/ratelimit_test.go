// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"sync"
	"testing"
	"time"
)

// Phase 5 — RateLimiter unit tests.

func TestRateLimiter_DisabledWhenPerHourZero(t *testing.T) {
	r := NewRateLimiter()
	for i := 0; i < 10000; i++ {
		if !r.Allow(ActionNewOrder, "acc-1", 0) {
			t.Fatalf("Allow returned false on call %d with perHour=0", i)
		}
	}
}

func TestRateLimiter_DisabledWhenPerHourNegative(t *testing.T) {
	r := NewRateLimiter()
	if !r.Allow(ActionNewOrder, "acc-1", -5) {
		t.Errorf("Allow returned false with perHour=-5; expected always-allow")
	}
}

func TestRateLimiter_BucketCapacity(t *testing.T) {
	// Frozen clock: a fresh bucket has perHour tokens. Drain exactly
	// that many; the next call must return false.
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	r := NewRateLimiter()
	r.SetClock(func() time.Time { return now })

	for i := 0; i < 100; i++ {
		if !r.Allow(ActionNewOrder, "acc-1", 100) {
			t.Fatalf("Allow returned false on call %d (within capacity)", i)
		}
	}
	if r.Allow(ActionNewOrder, "acc-1", 100) {
		t.Errorf("Allow returned true on the 101st call; expected limit hit")
	}
}

func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	// Frozen clock — drain acc-1 to zero, then acc-2 should still have
	// a full bucket (separate key).
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	r := NewRateLimiter()
	r.SetClock(func() time.Time { return now })

	for i := 0; i < 100; i++ {
		_ = r.Allow(ActionNewOrder, "acc-1", 100)
	}
	if r.Allow(ActionNewOrder, "acc-1", 100) {
		t.Errorf("acc-1 should be rate-limited")
	}
	if !r.Allow(ActionNewOrder, "acc-2", 100) {
		t.Errorf("acc-2 should be unaffected by acc-1's bucket; expected allow")
	}
}

func TestRateLimiter_PerActionIsolation(t *testing.T) {
	// Same key but different actions get different buckets.
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	r := NewRateLimiter()
	r.SetClock(func() time.Time { return now })

	for i := 0; i < 5; i++ {
		_ = r.Allow(ActionKeyChange, "acc-1", 5)
	}
	if r.Allow(ActionKeyChange, "acc-1", 5) {
		t.Errorf("ActionKeyChange should be rate-limited")
	}
	// ActionNewOrder for the same key has its own (empty) bucket.
	if !r.Allow(ActionNewOrder, "acc-1", 100) {
		t.Errorf("ActionNewOrder for same key should be allowed (different bucket)")
	}
}

func TestRateLimiter_RefillOverTime(t *testing.T) {
	// Drain bucket; advance the clock; expect tokens replenished.
	current := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	r := NewRateLimiter()
	r.SetClock(func() time.Time { return current })

	for i := 0; i < 100; i++ {
		_ = r.Allow(ActionNewOrder, "acc-1", 100)
	}
	if r.Allow(ActionNewOrder, "acc-1", 100) {
		t.Fatalf("expected limit hit after draining bucket")
	}
	// Advance by 36 seconds: at 100/hour = 100/3600 tokens/sec ≈
	// 0.0278/sec. 36 * 0.0278 = 1.00 tokens — exactly enough for 1
	// more call.
	current = current.Add(36 * time.Second)
	if !r.Allow(ActionNewOrder, "acc-1", 100) {
		t.Errorf("Allow returned false after 36s elapsed; expected ≥1 token replenished")
	}
}

func TestRateLimiter_RetryAfter(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	r := NewRateLimiter()
	r.SetClock(func() time.Time { return now })

	// Drain to zero.
	for i := 0; i < 100; i++ {
		_ = r.Allow(ActionNewOrder, "acc-1", 100)
	}
	d := r.RetryAfter(ActionNewOrder, "acc-1", 100)
	// 1 token at 100/hour = 36 seconds.
	if d < 35*time.Second || d > 37*time.Second {
		t.Errorf("RetryAfter = %v, expected ~36s", d)
	}
	// Allow above capacity — RetryAfter returns 0 on a fresh bucket.
	if zero := r.RetryAfter(ActionNewOrder, "acc-fresh", 100); zero != 0 {
		t.Errorf("RetryAfter for fresh bucket = %v, expected 0", zero)
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	// Hammer 200 goroutines × 200 calls each = 40000 calls against a
	// 1000-token bucket; assert no panic, no data race (run with -race),
	// and that no more than 1000 calls succeeded.
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	r := NewRateLimiter()
	r.SetClock(func() time.Time { return now })

	var (
		wg      sync.WaitGroup
		success int64
		mu      sync.Mutex
	)
	for g := 0; g < 200; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := int64(0)
			for i := 0; i < 200; i++ {
				if r.Allow(ActionNewOrder, "shared-acc", 1000) {
					local++
				}
			}
			mu.Lock()
			success += local
			mu.Unlock()
		}()
	}
	wg.Wait()
	if success > 1000 {
		t.Errorf("got %d successes, want ≤ 1000 (bucket capacity)", success)
	}
	if success < 1000 {
		t.Errorf("got %d successes, want exactly 1000 (frozen clock, no refill)", success)
	}
}
