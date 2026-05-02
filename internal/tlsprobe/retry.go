// Copyright (c) 2025 Certctl Contributors <certctl@proton.me>
//
// SPDX-License-Identifier: BSL-1.1
// See COPYING for license details.

package tlsprobe

import (
	"context"
	"time"
)

// RetryConfig holds parameters for exponential-backoff retries.
// Zero values use defaults: 3 attempts, 1s initial, 16s max.
type RetryConfig struct {
	Attempts       int           // total attempts; 0 = use 3 default
	InitialBackoff time.Duration // base; 0 = use 1 * time.Second default
	MaxBackoff     time.Duration // cap; 0 = use 16 * time.Second default
}

// VerifyWithExponentialBackoff calls the probe at most cfg.Attempts times,
// waiting cfg.InitialBackoff, 2*InitialBackoff, 4*InitialBackoff, ... capped at
// cfg.MaxBackoff between consecutive attempts. Returns nil on first probe success;
// returns the last attempt's error on full exhaustion.
//
// The probe function returns:
//   - nil error on success → return immediately, no further attempts.
//   - non-nil error → wait the exponentially-growing backoff and retry.
//
// The ctx is checked between attempts; ctx cancellation aborts immediately.
//
// Top-10 fix #8 of the 2026-05-02 deployment-target audit re-run.
func VerifyWithExponentialBackoff(ctx context.Context, cfg RetryConfig, probe func(ctx context.Context) error) error {
	attempts := cfg.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	initial := cfg.InitialBackoff
	if initial <= 0 {
		initial = 1 * time.Second
	}
	max := cfg.MaxBackoff
	if max <= 0 {
		max = 16 * time.Second
	}

	backoff := initial
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > max {
				backoff = max
			}
		}
		if err := probe(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}
