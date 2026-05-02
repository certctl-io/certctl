// Copyright (c) 2025 Certctl Contributors <certctl@proton.me>
//
// SPDX-License-Identifier: BSL-1.1
// See COPYING for license details.

package tlsprobe

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestVerifyWithExponentialBackoff_GrowthAndCap(t *testing.T) {
	cfg := RetryConfig{
		Attempts:       5,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     40 * time.Millisecond,
	}

	var callTimes []time.Time
	probe := func(ctx context.Context) error {
		callTimes = append(callTimes, time.Now())
		return errors.New("always fail")
	}

	ctx := context.Background()
	start := time.Now()
	err := VerifyWithExponentialBackoff(ctx, cfg, probe)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(callTimes) != 5 {
		t.Fatalf("expected 5 calls, got %d", len(callTimes))
	}

	// Assert gaps between attempts are approximately: 10ms, 20ms, 40ms, 40ms.
	// Allow ±20ms tolerance for scheduler noise.
	const tolerance = 20 * time.Millisecond
	expectedGaps := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		40 * time.Millisecond,
	}

	for i := 0; i < len(expectedGaps); i++ {
		gap := callTimes[i+1].Sub(callTimes[i])
		expected := expectedGaps[i]
		if gap < expected-tolerance || gap > expected+tolerance {
			t.Errorf("gap[%d]: expected ~%v, got %v", i, expected, gap)
		}
	}

	// Total wall time should be ~10+20+40+40 = 110ms
	totalTime := time.Since(start)
	expectedTotal := 110 * time.Millisecond
	if totalTime < expectedTotal-50*time.Millisecond || totalTime > expectedTotal+100*time.Millisecond {
		t.Errorf("total time: expected ~%v, got %v", expectedTotal, totalTime)
	}
}

func TestVerifyWithExponentialBackoff_StopsOnFirstSuccess(t *testing.T) {
	cfg := RetryConfig{
		Attempts:       3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     40 * time.Millisecond,
	}

	var callCount int
	probe := func(ctx context.Context) error {
		callCount++
		if callCount == 2 {
			return nil // success on second attempt
		}
		return errors.New("failed")
	}

	ctx := context.Background()
	start := time.Now()
	err := VerifyWithExponentialBackoff(ctx, cfg, probe)

	if err != nil {
		t.Fatalf("expected nil, got error: %v", err)
	}
	if callCount != 2 {
		t.Fatalf("expected 2 calls, got %d", callCount)
	}

	// Total wall time should be ~10ms (one wait between attempt 1 and 2).
	totalTime := time.Since(start)
	const tolerance = 20 * time.Millisecond
	if totalTime > tolerance {
		t.Errorf("total time: expected <~20ms, got %v", totalTime)
	}
}

func TestVerifyWithExponentialBackoff_CtxCancellation(t *testing.T) {
	cfg := RetryConfig{
		Attempts:       5,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1000 * time.Millisecond,
	}

	var callCount int
	probe := func(ctx context.Context) error {
		callCount++
		return errors.New("always fail")
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after allowing first attempt + partial wait
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := VerifyWithExponentialBackoff(ctx, cfg, probe)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	// Should have completed first attempt, then been cancelled during wait
	if callCount != 1 {
		t.Fatalf("expected 1 call before cancellation, got %d", callCount)
	}
}
