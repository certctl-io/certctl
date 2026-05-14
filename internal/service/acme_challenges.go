// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/certctl-io/certctl/internal/api/acme"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Phase 9 ARCH-M2 closure Sprint 9 (2026-05-14): extracted from
// internal/service/acme.go via the Option B sibling-file pattern.
// Package stays `service`; every external caller of
// `service.ACMEService.RespondToChallenge(...)` resolves the same
// way — pure mechanical relocation.
//
// This file holds the Phase 3 challenge dispatch + validator
// callback concern: the HTTP-facing RespondToChallenge entry point
// (which transitions the challenge to `processing` and submits it
// to the validator pool) plus the asynchronous recordChallengeOutcome
// callback (which persists the final challenge status and cascades
// the parent authz + order status). The authz read-side
// (LookupAuthz / ListAuthzsByOrder) lives in acme_authz.go.

// --- Phase 3 — challenge dispatch + validator callback -----------------

// ChallengeResponseShape is what RespondToChallenge returns to the
// handler: the post-dispatch challenge row (status=processing) so the
// handler can render it via acme.MarshalAuthorization-equivalent. The
// validator goroutine writes the final status (valid/invalid) as a
// callback after dispatch completes — clients fetching the challenge
// via authz GET get the eventual state.
type ChallengeResponseShape struct {
	Challenge *domain.ACMEChallenge
}

// RespondToChallenge handles POST /acme/profile/<id>/challenge/<chall_id>
// per RFC 8555 §7.5.1.
//
// Behavior:
//   - Look up the challenge + parent authz + parent order; assert the
//     account owns the order.
//   - If the challenge is already valid/invalid → idempotent return.
//   - If pending: transition to processing (atomic via WithinTx + audit).
//   - Submit to the validator pool with an onComplete callback that
//     transitions the challenge to valid/invalid in another WithinTx
//     (and cascades the parent authz status).
//   - Return the challenge in its current (processing) state; the
//     client polls authz/challenge for the eventual outcome.
func (s *ACMEService) RespondToChallenge(
	ctx context.Context,
	accountID, challengeID string,
	accountJWK *jose.JSONWebKey,
) (*domain.ACMEChallenge, error) {
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: respond-to-challenge requires SetTransactor + SetAuditService")
	}
	if s.validatorPool == nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, ErrACMEChallengePoolUnconfigured
	}
	// Phase 5 — per-challenge respond rate limit. Defends against retry
	// storms from a misbehaving client. Keyed by challengeID (not
	// accountID) so a flood against one challenge doesn't drain the
	// account's whole budget.
	if s.rateLimiter != nil && s.cfg.RateLimitChallengeRespondsPerHour > 0 {
		if !s.rateLimiter.Allow(acme.ActionChallengeRespond, challengeID, s.cfg.RateLimitChallengeRespondsPerHour) {
			s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
			return nil, ErrACMERateLimited
		}
	}

	ch, err := s.repo.GetChallengeByID(ctx, challengeID)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrACMEChallengeNotFound
		}
		return nil, fmt.Errorf("acme: lookup challenge: %w", err)
	}

	// Idempotent re-POST: already valid/invalid → just return.
	if ch.Status == domain.ACMEChallengeStatusValid || ch.Status == domain.ACMEChallengeStatusInvalid {
		s.metrics.bump(&s.metrics.ChallengeRespondTotal)
		return ch, nil
	}
	if ch.Status == domain.ACMEChallengeStatusProcessing {
		// In-flight. Return the row as-is.
		s.metrics.bump(&s.metrics.ChallengeRespondTotal)
		return ch, nil
	}

	// Confirm the requesting account owns the parent authz/order.
	authz, err := s.repo.GetAuthzByID(ctx, ch.AuthzID)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: lookup parent authz: %w", err)
	}
	order, err := s.repo.GetOrderByID(ctx, authz.OrderID)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: lookup parent order: %w", err)
	}
	if order.AccountID != accountID {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, ErrACMEOrderUnauthorized
	}

	// Compute the key authorization the validator needs.
	expected, err := acme.KeyAuthorization(ch.Token, accountJWK)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: key authorization: %w", err)
	}

	// Transition challenge → processing (atomic with audit row).
	ch.Status = domain.ACMEChallengeStatusProcessing
	if err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateChallengeWithTx(ctx, q, ch); err != nil {
			return err
		}
		return s.auditService.RecordEventWithTx(ctx, q,
			fmt.Sprintf("acme:%s", accountID), domain.ActorTypeUser,
			"acme_challenge_processing", "acme_challenge", ch.ChallengeID,
			map[string]interface{}{
				"authz_id":   ch.AuthzID,
				"type":       string(ch.Type),
				"identifier": authz.Identifier.Value,
			})
	}); err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, err
	}

	// Submit to the pool. The onComplete callback persists the final
	// challenge status + cascades the parent authz status. We detach
	// from the request context via context.WithoutCancel so the
	// callback's WithinTx survives the HTTP handler returning, while
	// preserving inherited values (logger, trace IDs, audit actor).
	bgctx := context.WithoutCancel(ctx)
	chSnapshot := *ch
	authzSnapshot := *authz
	identifier := authz.Identifier.Value
	s.validatorPool.Submit(bgctx, string(ch.Type), identifier, ch.Token, expected, func(verr error) {
		s.recordChallengeOutcome(bgctx, accountID, &chSnapshot, &authzSnapshot, verr)
	})

	s.metrics.bump(&s.metrics.ChallengeRespondTotal)
	return ch, nil
}

// recordChallengeOutcome is the validator-pool callback. Persists the
// challenge's final status + cascades the parent authz status.
//
// Authz cascade: if the challenge succeeded, the authz becomes valid
// (RFC 8555 §7.1.6: any one challenge passing makes the authz valid).
// If the challenge failed, the authz becomes invalid only if no other
// pending challenges remain (Phase 3 minimal-viable path: we mark the
// authz invalid on first failure since Phase 3 emits 1 challenge per
// authz; Phase 4+ extending to multi-challenge-per-authz revisits this).
func (s *ACMEService) recordChallengeOutcome(
	ctx context.Context,
	accountID string,
	ch *domain.ACMEChallenge,
	authz *domain.ACMEAuthorization,
	verr error,
) {
	now := time.Now().UTC()
	var newAuthzStatus domain.ACMEAuthzStatus
	if verr == nil {
		ch.Status = domain.ACMEChallengeStatusValid
		ch.ValidatedAt = &now
		ch.Error = nil
		newAuthzStatus = domain.ACMEAuthzStatusValid
		s.metrics.bump(&s.metrics.ChallengeValidateValid)
	} else {
		ch.Status = domain.ACMEChallengeStatusInvalid
		if p := acme.ChallengeProblemFromError(string(ch.Type), verr); p != nil {
			ch.Error = &domain.ACMEProblem{
				Type:   p.Type,
				Detail: p.Detail,
				Status: p.Status,
			}
		}
		newAuthzStatus = domain.ACMEAuthzStatusInvalid
		s.metrics.bump(&s.metrics.ChallengeValidateInvalid)
	}

	auditDetails := map[string]interface{}{
		"authz_id":   ch.AuthzID,
		"type":       string(ch.Type),
		"identifier": authz.Identifier.Value,
		"valid":      verr == nil,
	}
	if verr != nil {
		auditDetails["error"] = verr.Error()
	}

	_ = s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateChallengeWithTx(ctx, q, ch); err != nil {
			return err
		}
		if err := s.repo.UpdateAuthzStatusWithTx(ctx, q, ch.AuthzID, newAuthzStatus); err != nil {
			return err
		}
		// Cascade: if the authz turned valid, see whether the order's
		// authzs are now ALL valid; flip order to ready if so.
		// Read-after-write to confirm.
		authzs, err := s.repo.ListAuthzsByOrder(ctx, authz.OrderID)
		if err != nil {
			return err
		}
		allValid := len(authzs) > 0
		anyInvalid := false
		for _, a := range authzs {
			if a.AuthzID == ch.AuthzID {
				if newAuthzStatus != domain.ACMEAuthzStatusValid {
					allValid = false
				}
				if newAuthzStatus == domain.ACMEAuthzStatusInvalid {
					anyInvalid = true
				}
				continue
			}
			if a.Status != domain.ACMEAuthzStatusValid {
				allValid = false
			}
			if a.Status == domain.ACMEAuthzStatusInvalid {
				anyInvalid = true
			}
		}
		order, err := s.repo.GetOrderByID(ctx, authz.OrderID)
		if err != nil {
			return err
		}
		switch {
		case allValid && order.Status == domain.ACMEOrderStatusPending:
			order.Status = domain.ACMEOrderStatusReady
			if err := s.repo.UpdateOrderWithTx(ctx, q, order); err != nil {
				return err
			}
		case anyInvalid && order.Status == domain.ACMEOrderStatusPending:
			order.Status = domain.ACMEOrderStatusInvalid
			order.Error = &domain.ACMEProblem{
				Type:   "urn:ietf:params:acme:error:incorrectResponse",
				Detail: "one or more authorizations failed",
				Status: 403,
			}
			if err := s.repo.UpdateOrderWithTx(ctx, q, order); err != nil {
				return err
			}
		}
		return s.auditService.RecordEventWithTx(ctx, q,
			fmt.Sprintf("acme:%s", accountID), domain.ActorTypeUser,
			"acme_challenge_completed", "acme_challenge", ch.ChallengeID,
			auditDetails)
	})
}
