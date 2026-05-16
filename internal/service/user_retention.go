// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Sprint 6 COMP-002-RETENTION closure. The control plane stores three
// PII surfaces:
//
//   users.email          — IdP-supplied login email.
//   users.display_name   — IdP-supplied human label.
//   users.oidc_subject   — IdP's stable identifier for the human.
//
// Pre-fix there was no in-code primitive for GDPR right-to-be-forgotten
// or for automatic retention purges of deactivated accounts. The
// admin-side deactivate flow at internal/api/handler/auth_users.go
// set users.deactivated_at but the PII columns stayed populated
// forever.
//
// This file delivers the two pieces the audit's fix called for:
//
//   Phase 1: DeleteUserPII(actorID) — operator-callable primitive that
//            scrubs the row's PII while keeping the audit attribution
//            chain intact (the row's id stays, so historical
//            audit_events.actor = user.id rows still resolve).
//   Phase 2: PurgeDeactivatedUsers(ctx) — walks every user whose
//            deactivated_at is older than the retention window and
//            calls DeleteUserPII on each. Scheduler loop calls this
//            on a tick (default 24h); the retention window itself
//            (default 30 days post-deactivate) is operator-tunable.
//
// Audit attribution invariant: DeleteUserPII replaces oidc_subject
// with sha256:<hex> rather than nullifying it. Three reasons:
//   1. Preserves the (oidc_provider_id, oidc_subject) UNIQUE
//      constraint — two purged users on the same provider still have
//      different oidc_subject values, so the constraint never trips.
//   2. The hash is a one-way fingerprint; the original IdP-side
//      identifier is unrecoverable post-purge. Re-login under the
//      same IdP subject mints a fresh u-id (different row) because
//      GetByOIDCSubject won't match the hashed token.
//   3. Forensic continuity: if an operator later needs to prove "a
//      user with subject X was deactivated then purged", they can
//      recompute sha256(X) and look it up.

// UserRetentionService exposes the DeleteUserPII + PurgeDeactivatedUsers
// primitives. The handler-side admin endpoint (when wired) calls
// DeleteUserPII directly; the scheduler's userRetentionLoop calls
// PurgeDeactivatedUsers.
type UserRetentionService struct {
	users    repository.UserRepository
	sessions repository.SessionRepository
	audit    *AuditService
	logger   *slog.Logger

	// retentionWindow is how long after deactivated_at a user's PII
	// stays in the table. The scheduler loop subtracts this from
	// time.Now() when computing the "purge before" threshold.
	retentionWindow time.Duration
	// purgeBatchCap bounds how many users a single PurgeDeactivatedUsers
	// call processes — keeps a single tick's blast radius predictable
	// even if a large backlog accumulates. Zero = unbounded (test default).
	purgeBatchCap int
}

// NewUserRetentionService wires the deps. The audit service is
// optional (nil = skip audit emission); production wiring in
// cmd/server/main.go passes the singleton.
func NewUserRetentionService(
	users repository.UserRepository,
	sessions repository.SessionRepository,
	audit *AuditService,
	logger *slog.Logger,
	retentionWindow time.Duration,
	purgeBatchCap int,
) *UserRetentionService {
	if retentionWindow <= 0 {
		retentionWindow = 30 * 24 * time.Hour
	}
	return &UserRetentionService{
		users:           users,
		sessions:        sessions,
		audit:           audit,
		logger:          logger,
		retentionWindow: retentionWindow,
		purgeBatchCap:   purgeBatchCap,
	}
}

// DeleteUserPII scrubs the named user's PII columns. Phase 1 fix per
// the COMP-002-RETENTION audit. Steps:
//
//  1. Load the user row. Returns repository.ErrUserNotFound if missing.
//  2. Revoke all active sessions for the actor (defense-in-depth — the
//     handler-side Deactivate path already does this, but a purge after
//     N days might catch sessions that were created post-deactivate via
//     some other path).
//  3. Zero the PII columns:
//     email        = ""
//     display_name = ""
//     oidc_subject = "sha256:" || hex(sha256(original))
//  4. Persist the row via UserRepository.Update.
//  5. Emit an audit event (auth category, action user.purge_pii) so the
//     scrub itself is on record.
//
// Returns nil on success. Idempotent: re-calling on an already-purged
// row hashes the already-hashed oidc_subject, which is a no-op semantic
// (the operator can tell purges happened by the "sha256:" prefix).
func (s *UserRetentionService) DeleteUserPII(ctx context.Context, userID string) error {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("user_retention: load %s: %w", userID, err)
	}

	// Defense-in-depth: revoke all sessions before the row mutates.
	if err := s.sessions.RevokeAllForActor(ctx, u.ID, string(domain.ActorTypeUser), u.TenantID); err != nil {
		// Log + continue; PII scrub is the load-bearing step. A
		// dangling-session row whose actor's PII is already gone is
		// less harmful than leaving the PII intact because the
		// session revoke failed.
		s.logger.Warn("user_retention: session revoke failed during PII scrub (continuing)",
			"user_id", userID, "error", err)
	}

	// Hash the oidc_subject IF it isn't already a "sha256:..." token.
	// Idempotent re-scrubs are safe; a second pass produces the same
	// hash of the hash, but the prefix lets operators tell the row was
	// already scrubbed.
	if !strings.HasPrefix(u.OIDCSubject, "sha256:") {
		sum := sha256.Sum256([]byte(u.OIDCSubject))
		u.OIDCSubject = "sha256:" + hex.EncodeToString(sum[:])
	}

	u.Email = "purged@redacted.local"    // domain.User.Validate requires plausible email format
	u.DisplayName = "[purged]"           // domain.User.Validate forbids leading/trailing whitespace
	u.WebAuthnCredentials = []byte(`[]`) // v3-reserved field — keep empty JSONB.

	if err := s.users.Update(ctx, u); err != nil {
		return fmt.Errorf("user_retention: update %s: %w", userID, err)
	}

	if s.audit != nil {
		_ = s.audit.RecordEventWithCategory(ctx,
			"system", domain.ActorTypeSystem,
			"user.purge_pii",
			domain.EventCategoryAuth,
			"user", userID,
			map[string]interface{}{
				"retained_id":             userID,
				"hashed_oidc_subject_set": true,
			},
		)
	}

	s.logger.Info("user_retention: PII scrubbed", "user_id", userID)
	return nil
}

// PurgeDeactivatedUsers enumerates every user whose deactivated_at is
// older than now - retentionWindow and calls DeleteUserPII on each.
// Returns (purged, failed) counts; logs individual failures at WARN
// and continues so a single bad row doesn't stall the rest of the
// batch. Bounded by purgeBatchCap when non-zero.
func (s *UserRetentionService) PurgeDeactivatedUsers(ctx context.Context) (int, int, error) {
	threshold := time.Now().Add(-s.retentionWindow)
	rows, err := s.users.ListDeactivatedBefore(ctx, threshold)
	if err != nil {
		return 0, 0, fmt.Errorf("user_retention: list deactivated: %w", err)
	}

	var purged, failed int
	for i, u := range rows {
		if s.purgeBatchCap > 0 && i >= s.purgeBatchCap {
			s.logger.Info("user_retention: batch cap reached; remaining rows deferred to next tick",
				"cap", s.purgeBatchCap, "remaining", len(rows)-i)
			break
		}
		// Skip rows that are already scrubbed — DeleteUserPII is
		// idempotent but skipping saves a transaction and an audit
		// row per tick.
		if strings.HasPrefix(u.OIDCSubject, "sha256:") &&
			strings.HasPrefix(u.Email, "purged@") {
			continue
		}
		if err := s.DeleteUserPII(ctx, u.ID); err != nil {
			s.logger.Warn("user_retention: purge failed (next tick will retry)",
				"user_id", u.ID, "error", err)
			failed++
			continue
		}
		purged++
	}
	if purged > 0 || failed > 0 {
		s.logger.Info("user_retention: purge sweep complete",
			"purged", purged,
			"failed", failed,
			"threshold", threshold.Format(time.RFC3339))
	}
	return purged, failed, nil
}

// RetentionWindow exposes the configured window for tests + the
// operator-facing "when will my account be scrubbed" GUI surface.
func (s *UserRetentionService) RetentionWindow() time.Duration {
	return s.retentionWindow
}

// userdomain is imported so the compiler recognises the type used by
// the repository contracts even though this file only consumes pointer
// values via the interface. Keep this blank ref so re-organising the
// file later doesn't accidentally drop the import.
var _ = (*userdomain.User)(nil)
