// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ACMERepository implements the ACME server's persistence layer
// (RFC 8555 + RFC 9773 ARI). Phase 1a wires only nonce operations
// (IssueNonce + ConsumeNonce); Phase 1b extends with account CRUD,
// Phase 2 with order/authz/challenge CRUD, Phase 4 with the
// key-rollover atomic update path.
type ACMERepository struct {
	db *sql.DB
}

// NewACMERepository constructs an ACMERepository wrapping the supplied
// *sql.DB. The constructor is symmetric with NewAuditRepository,
// NewProfileRepository, etc. — main.go owns the lifecycle.
func NewACMERepository(db *sql.DB) *ACMERepository {
	return &ACMERepository{db: db}
}

// IssueNonce inserts a new ACME nonce row with the given TTL. The
// caller (typically ACMEService.IssueNonce) is responsible for
// generating the nonce string itself via acme.GenerateNonce; this
// method is the persistence write.
//
// RFC 8555 §6.5: nonces issued by the server can be redeemed exactly
// once. The PRIMARY KEY guarantees insertion uniqueness; ConsumeNonce
// flips the `used` column atomically so a replay sees `used=true`.
func (r *ACMERepository) IssueNonce(ctx context.Context, nonce string, ttl time.Duration) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO acme_nonces (nonce, issued_at, expires_at, used)
		VALUES ($1, NOW(), $2, FALSE)
	`, nonce, time.Now().Add(ttl))
	if err != nil {
		return fmt.Errorf("acme: insert nonce: %w", err)
	}
	return nil
}

// ConsumeNonce flips the nonce's `used` column to true atomically.
// Returns sql.ErrNoRows if:
//
//   - the nonce was never issued (caller's payload was forged or
//     truncated)
//   - the nonce was already consumed (replay attempt)
//   - the nonce has expired (CERTCTL_ACME_SERVER_NONCE_TTL window
//     elapsed since issuance)
//
// All three failure modes are mapped by the JWS verifier (Phase 1b)
// to urn:ietf:params:acme:error:badNonce per RFC 8555 §6.5.1. Phase
// 1a does not yet call ConsumeNonce — the JWS-authenticated POST
// path arrives in Phase 1b.
//
// The single UPDATE statement is the atomic primitive: a concurrent
// second consume races for the same row, but only one of them flips
// `used` from false → true. Postgres's row-level locking serializes
// the writes; the loser's UPDATE matches zero rows (because used is
// already true) and returns sql.ErrNoRows.
func (r *ACMERepository) ConsumeNonce(ctx context.Context, nonce string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_nonces
		SET used = TRUE
		WHERE nonce = $1
		  AND used = FALSE
		  AND expires_at > NOW()
	`, nonce)
	if err != nil {
		return fmt.Errorf("acme: consume nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("acme: consume nonce rows affected: %w", err)
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
