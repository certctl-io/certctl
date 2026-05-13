// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package repository

import (
	"context"
	"errors"
	"time"
)

// ErrBCLJTIAlreadyConsumed is returned by BCLReplayRepository.ConsumeJTI
// when the (jti, issuer_url) pair has already been recorded. The
// handler maps this to OIDC BCL 1.0 §2.7 "still 200 + Cache-Control:
// no-store" with audit outcome=jti_replayed.
var ErrBCLJTIAlreadyConsumed = errors.New("oidc/bcl: jti already consumed for this issuer")

// BCLReplayRepository tracks the consumed-jti set used by the BCL
// logout-token replay defense. Audit 2026-05-10 HIGH-3 closure. Backed
// by the oidc_bcl_consumed_jtis table (migration 000040).
type BCLReplayRepository interface {
	// ConsumeJTI atomically records that a (jti, issuer_url) pair has
	// been consumed. The row's expires_at is set to now + ttl. Returns
	// ErrBCLJTIAlreadyConsumed when the pair was already recorded
	// (single-use semantics via INSERT...ON CONFLICT DO NOTHING).
	// Other errors (DB hiccup, connection reset) are transient — the
	// handler returns 503 so the IdP retries.
	ConsumeJTI(ctx context.Context, jti, issuerURL string, ttl time.Duration) error

	// SweepExpired removes rows whose expires_at is in the past.
	// Returns count deleted. Called from the scheduler GC loop.
	SweepExpired(ctx context.Context, now time.Time) (int, error)
}
