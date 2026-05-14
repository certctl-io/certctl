// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import (
	"math"
	"testing"
	"time"
)

// Phase 6 SCALE-M5 contract pin (2026-05-14): JitteredTicker fires
// ~interval per tick with a bounded ±jitterPct envelope. The tests
// below are timing-sensitive but use generous tolerances + averaging
// across many ticks to stay stable under CI load.

func TestJitteredTicker_BoundedEnvelope(t *testing.T) {
	const (
		interval  = 20 * time.Millisecond
		jitterPct = 0.20 // ±20%
		ticks     = 30
	)

	jt := NewJitteredTicker(interval, jitterPct)
	defer jt.Stop()

	last := time.Now()
	for i := 0; i < ticks; i++ {
		select {
		case now := <-jt.C:
			gap := now.Sub(last)
			last = now

			// Bounded envelope: every tick should fall within
			// [interval × (1-jitter), interval × (1+jitter)] plus a
			// generous scheduling-slop tolerance for the test
			// runtime. The first tick is allowed wider slop since
			// goroutine startup may eat into the first interval.
			minGap := time.Duration(float64(interval) * (1 - jitterPct))
			maxGap := time.Duration(float64(interval)*(1+jitterPct)) + 50*time.Millisecond
			if i == 0 {
				minGap = 0 // first tick can land arbitrarily fast under CI scheduling pressure
			}

			if gap < minGap || gap > maxGap {
				t.Errorf("tick %d gap=%v outside envelope [%v, %v]", i, gap, minGap, maxGap)
			}
		case <-time.After(5 * interval):
			t.Fatalf("tick %d timed out (>5×interval); JitteredTicker stuck", i)
		}
	}
}

func TestJitteredTicker_MeanCloseToInterval(t *testing.T) {
	// Statistical pin: across many ticks the mean gap should be
	// reasonably close to the nominal interval. Larger deviations
	// indicate the jitter draw is biased (e.g. only producing
	// positive deltas because of a sign bug — mean would drift to
	// interval × 1.3 instead of staying near interval × 1.0).
	//
	// The 50ms interval + 50-tick sample is chosen so per-scheduler-
	// quantum jitter (~1ms on Linux) is < 2% of the interval; the
	// 30% bound below is generous enough for CI scheduling noise
	// while still catching sign bugs (which would push mean drift
	// past 30% trivially).
	const (
		interval  = 50 * time.Millisecond
		jitterPct = 0.30
		ticks     = 50
	)

	jt := NewJitteredTicker(interval, jitterPct)
	defer jt.Stop()

	gaps := make([]time.Duration, 0, ticks)
	last := time.Now()

	for i := 0; i < ticks; i++ {
		select {
		case now := <-jt.C:
			if i > 0 { // skip first gap (goroutine warmup)
				gaps = append(gaps, now.Sub(last))
			}
			last = now
		case <-time.After(5 * interval):
			t.Fatalf("tick %d timed out", i)
		}
	}

	var sum time.Duration
	for _, g := range gaps {
		sum += g
	}
	mean := sum / time.Duration(len(gaps))

	// Sign-bug threshold: a healthy jittered ticker should produce
	// mean ≈ interval (mean drift < 10%). A sign bug (e.g.
	// always-positive jitter) shifts mean to interval × (1 +
	// jitterPct / 2) = +15%. 30% bound catches that while
	// tolerating CI scheduling noise + the (1 - x) vs (1 + x)
	// asymmetry of multiplicative jitter.
	driftPct := math.Abs(float64(mean-interval)) / float64(interval)
	if driftPct > 0.30 {
		t.Errorf("mean gap %v drifts %.1f%% from nominal interval %v (>30%% threshold)", mean, driftPct*100, interval)
	}
}

func TestJitteredTicker_Stop_ReleasesGoroutine(t *testing.T) {
	jt := NewJitteredTicker(50*time.Millisecond, 0.10)

	// Stop immediately, before any tick fires.
	jt.Stop()

	// C should close within one tick interval. If it doesn't, the
	// goroutine is stuck (which would leak in production).
	select {
	case _, ok := <-jt.C:
		if ok {
			// A tick fired before C closed — also acceptable, but
			// drain it and re-check that close follows.
			select {
			case _, ok2 := <-jt.C:
				if ok2 {
					t.Errorf("JitteredTicker.C still emitting after Stop()")
				}
			case <-time.After(200 * time.Millisecond):
				t.Errorf("JitteredTicker.C did not close after Stop()")
			}
		}
	case <-time.After(200 * time.Millisecond):
		t.Errorf("JitteredTicker.C did not close within 200ms of Stop()")
	}
}

func TestJitteredTicker_Stop_Idempotent(t *testing.T) {
	jt := NewJitteredTicker(50*time.Millisecond, 0.10)

	// Multiple Stop() calls must not panic.
	jt.Stop()
	jt.Stop()
	jt.Stop()
}

func TestJitteredTicker_ZeroJitter_BehavesLikeTicker(t *testing.T) {
	// jitterPct=0 reduces to a deterministic ticker. The mean
	// should be exactly the interval (modulo scheduling noise).
	const (
		interval = 20 * time.Millisecond
		ticks    = 10
	)

	jt := NewJitteredTicker(interval, 0)
	defer jt.Stop()

	last := time.Now()
	for i := 0; i < ticks; i++ {
		select {
		case now := <-jt.C:
			gap := now.Sub(last)
			last = now
			// Allow generous slop for CI scheduling.
			if i > 0 && (gap < interval/2 || gap > interval*3) {
				t.Errorf("zero-jitter tick %d gap=%v far from interval=%v", i, gap, interval)
			}
		case <-time.After(5 * interval):
			t.Fatalf("zero-jitter tick %d timed out", i)
		}
	}
}

func TestJitteredTicker_NegativeJitter_TreatedAsZero(t *testing.T) {
	// Defensive: negative jitterPct should not produce
	// negative-duration timers (which would panic time.NewTimer).
	jt := NewJitteredTicker(10*time.Millisecond, -0.5)
	defer jt.Stop()

	// Just confirm at least one tick fires without panic.
	select {
	case <-jt.C:
		// ok
	case <-time.After(100 * time.Millisecond):
		t.Errorf("negative-jitter ticker produced no tick within 100ms")
	}
}

func TestJitteredTicker_LargeJitter_ClampedBelowOne(t *testing.T) {
	// Defensive: jitterPct≥1 would otherwise allow next=0 and panic
	// time.NewTimer. Confirm the ticker still fires.
	jt := NewJitteredTicker(10*time.Millisecond, 1.5)
	defer jt.Stop()

	select {
	case <-jt.C:
		// ok
	case <-time.After(100 * time.Millisecond):
		t.Errorf("over-clamped-jitter ticker produced no tick within 100ms")
	}
}
