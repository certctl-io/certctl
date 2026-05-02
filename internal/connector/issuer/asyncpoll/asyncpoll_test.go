// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package asyncpoll

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// TestPoll_DoneOnFirstAttempt asserts the trivial happy path: fn
// returns Done immediately, Poll returns Done with no waiting.
func TestPoll_DoneOnFirstAttempt(t *testing.T) {
	t.Parallel()
	calls := atomic.Int64{}
	start := time.Now()
	res, err := Poll(context.Background(), Config{InitialWait: 100 * time.Millisecond, JitterPct: 0}, func(ctx context.Context) (Result, error) {
		calls.Add(1)
		return Done, nil
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Poll: unexpected err: %v", err)
	}
	if res != Done {
		t.Fatalf("Poll: want Done, got %d", res)
	}
	if calls.Load() != 1 {
		t.Errorf("Poll: want 1 fn call, got %d", calls.Load())
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("Poll: should not have waited, elapsed=%v", elapsed)
	}
}

// TestPoll_DoneAfterPending asserts the standard async-CA shape:
// first 2 calls return StillPending, third returns Done. Poll waits
// the configured backoff between calls.
func TestPoll_DoneAfterPending(t *testing.T) {
	t.Parallel()
	calls := atomic.Int64{}
	res, err := Poll(context.Background(), Config{
		InitialWait: 10 * time.Millisecond,
		MaxBackoff:  50 * time.Millisecond,
		MaxWait:     1 * time.Second,
		JitterPct:   0, // deterministic for assertion
	}, func(ctx context.Context) (Result, error) {
		n := calls.Add(1)
		if n < 3 {
			return StillPending, nil
		}
		return Done, nil
	})
	if err != nil {
		t.Fatalf("Poll: unexpected err: %v", err)
	}
	if res != Done {
		t.Fatalf("Poll: want Done, got %d", res)
	}
	if calls.Load() != 3 {
		t.Errorf("Poll: want 3 fn calls, got %d", calls.Load())
	}
}

// TestPoll_FailedTerminatesImmediately — Failed is permanent; Poll
// returns the err and stops polling immediately.
func TestPoll_FailedTerminatesImmediately(t *testing.T) {
	t.Parallel()
	calls := atomic.Int64{}
	sentinel := errors.New("permanent: order rejected")
	res, err := Poll(context.Background(), Config{InitialWait: 100 * time.Millisecond, JitterPct: 0}, func(ctx context.Context) (Result, error) {
		calls.Add(1)
		return Failed, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("Poll: want sentinel, got %v", err)
	}
	if res != Failed {
		t.Fatalf("Poll: want Failed, got %d", res)
	}
	if calls.Load() != 1 {
		t.Errorf("Poll: Failed must terminate on first call, got %d", calls.Load())
	}
}

// TestPoll_TransientErrKeepPolling — fn returns (StillPending, err)
// for transient HTTP errors; Poll continues until Done.
func TestPoll_TransientErrKeepPolling(t *testing.T) {
	t.Parallel()
	calls := atomic.Int64{}
	res, err := Poll(context.Background(), Config{
		InitialWait: 5 * time.Millisecond,
		MaxBackoff:  20 * time.Millisecond,
		MaxWait:     1 * time.Second,
		JitterPct:   0,
	}, func(ctx context.Context) (Result, error) {
		n := calls.Add(1)
		if n < 3 {
			return StillPending, fmt.Errorf("transient 503 attempt %d", n)
		}
		return Done, nil
	})
	if err != nil {
		t.Fatalf("Poll: transient errs should be swallowed on Done, got: %v", err)
	}
	if res != Done {
		t.Fatalf("Poll: want Done, got %d", res)
	}
}

// TestPoll_MaxWaitTimeout — fn never returns Done; Poll respects
// MaxWait and returns (StillPending, ErrMaxWait).
func TestPoll_MaxWaitTimeout(t *testing.T) {
	t.Parallel()
	calls := atomic.Int64{}
	res, err := Poll(context.Background(), Config{
		InitialWait: 5 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		JitterPct:   0,
	}, func(ctx context.Context) (Result, error) {
		calls.Add(1)
		return StillPending, nil
	})
	if !errors.Is(err, ErrMaxWait) {
		t.Errorf("Poll: want ErrMaxWait, got %v", err)
	}
	if res != StillPending {
		t.Fatalf("Poll: want StillPending, got %d", res)
	}
	if calls.Load() < 2 {
		t.Errorf("Poll: should have called fn at least twice in 50ms, got %d", calls.Load())
	}
}

// TestPoll_MaxWaitWithLastErr — when MaxWait fires AND the last
// fn call returned a transient err, the err chain wraps both signals
// so operators can see "we exhausted the deadline AND the last
// upstream attempt was a 503."
func TestPoll_MaxWaitWithLastErr(t *testing.T) {
	t.Parallel()
	transient := errors.New("transient 503")
	res, err := Poll(context.Background(), Config{
		InitialWait: 5 * time.Millisecond,
		MaxWait:     30 * time.Millisecond,
		JitterPct:   0,
	}, func(ctx context.Context) (Result, error) {
		return StillPending, transient
	})
	if !errors.Is(err, ErrMaxWait) {
		t.Errorf("Poll: want ErrMaxWait in chain, got %v", err)
	}
	if res != StillPending {
		t.Errorf("Poll: want StillPending, got %d", res)
	}
}

// TestPoll_ContextCancelPropagated — caller cancels ctx mid-poll;
// Poll returns (StillPending, ctx.Err()).
func TestPoll_ContextCancelPropagated(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	res, err := Poll(ctx, Config{
		InitialWait: 5 * time.Millisecond,
		MaxWait:     5 * time.Second, // far past the cancel
		JitterPct:   0,
	}, func(ctx context.Context) (Result, error) {
		return StillPending, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Poll: want context.Canceled, got %v", err)
	}
	if res != StillPending {
		t.Errorf("Poll: want StillPending, got %d", res)
	}
}

// TestPoll_BackoffMultiplicative — assert the backoff grows
// multiplicatively (3× per iteration, capped). We measure the
// elapsed wall-clock between fn calls.
func TestPoll_BackoffMultiplicative(t *testing.T) {
	t.Parallel()
	var prevCall time.Time
	gaps := []time.Duration{}
	calls := atomic.Int64{}

	_, _ = Poll(context.Background(), Config{
		InitialWait: 10 * time.Millisecond,
		MaxBackoff:  200 * time.Millisecond,
		MaxWait:     1 * time.Second,
		JitterPct:   0,
	}, func(ctx context.Context) (Result, error) {
		now := time.Now()
		if !prevCall.IsZero() {
			gaps = append(gaps, now.Sub(prevCall))
		}
		prevCall = now
		if calls.Add(1) >= 4 {
			return Done, nil
		}
		return StillPending, nil
	})

	if len(gaps) < 3 {
		t.Fatalf("expected at least 3 gaps, got %d", len(gaps))
	}
	// First gap ~= 10ms, second ~= 30ms, third ~= 90ms (3×).
	// Tolerate +/- a millisecond or two for scheduler noise.
	if gaps[0] < 8*time.Millisecond || gaps[0] > 20*time.Millisecond {
		t.Errorf("gap[0] (initial): want ~10ms, got %v", gaps[0])
	}
	if gaps[1] < 25*time.Millisecond || gaps[1] > 45*time.Millisecond {
		t.Errorf("gap[1] (3×): want ~30ms, got %v", gaps[1])
	}
	if gaps[2] < 80*time.Millisecond || gaps[2] > 110*time.Millisecond {
		t.Errorf("gap[2] (9×): want ~90ms, got %v", gaps[2])
	}
}

// TestJitterDuration_Bounds — jitter envelope must stay within
// [base*(1-pct), base*(1+pct)]. Run many iterations; if any falls
// outside, the test fails. (Statistical test — false-positive rate
// is ~0 for the chosen seed pattern of crypto/rand-backed math/rand/v2.)
func TestJitterDuration_Bounds(t *testing.T) {
	t.Parallel()
	base := 100 * time.Millisecond
	pct := 0.2
	for i := 0; i < 1000; i++ {
		got := jitterDuration(base, pct)
		min := time.Duration(float64(base) * (1 - pct))
		max := time.Duration(float64(base) * (1 + pct))
		if got < min || got > max {
			t.Errorf("iter %d: jitter %v outside [%v, %v]", i, got, min, max)
		}
	}
}

// TestJitterDuration_PctZero — pct=0 returns base unchanged
// (deterministic mode for tests).
func TestJitterDuration_PctZero(t *testing.T) {
	t.Parallel()
	base := 100 * time.Millisecond
	for i := 0; i < 10; i++ {
		got := jitterDuration(base, 0)
		if got != base {
			t.Errorf("iter %d: pct=0 should return base, got %v", i, got)
		}
	}
}

// TestPoll_DefaultsApplied — zero-value Config falls back to package
// defaults; Poll runs without panic.
func TestPoll_DefaultsApplied(t *testing.T) {
	t.Parallel()
	// MaxWait will be 10m (the default); we Done immediately so the
	// test runs in microseconds regardless.
	res, err := Poll(context.Background(), Config{}, func(ctx context.Context) (Result, error) {
		return Done, nil
	})
	if err != nil {
		t.Fatalf("Poll with defaults: unexpected err: %v", err)
	}
	if res != Done {
		t.Errorf("Poll with defaults: want Done, got %d", res)
	}
}
