// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"fmt"

	"github.com/certctl-io/certctl/internal/api/acme"
)

// Phase 9 ARCH-M2 closure Sprint 9 (2026-05-14): extracted from
// internal/service/acme.go via the Option B sibling-file pattern
// (operator's choice post-Sprint-8). Package stays `service`; every
// external caller of `service.ACMEService.IssueNonce(...)` resolves
// the same way — pure mechanical relocation.
//
// This file holds the SERVER-issues-nonce concern: the IssueNonce
// method that generates + persists a fresh ACME nonce for the
// Replay-Nonce header per RFC 8555 §6.5. The nonceAdapter type
// (which wraps ACMERepo.ConsumeNonce for the JWS verifier) stays
// in acme.go alongside VerifyJWS — it's a verification-infrastructure
// helper, not a server-side nonce concern.

// IssueNonce generates a fresh ACME nonce, persists it with the
// configured TTL, and returns the encoded string for the
// Replay-Nonce header.
//
// RFC 8555 §6.5: every successful ACME response carries a
// Replay-Nonce. Phase 1a wires this via the directory + new-nonce
// handlers; Phase 1b extends with new-account + account/<id> POST
// responses (the JWS-authenticated paths).
func (s *ACMEService) IssueNonce(ctx context.Context) (string, error) {
	nonce, err := acme.GenerateNonce()
	if err != nil {
		s.metrics.bump(&s.metrics.NewNonceFailureTotal)
		return "", fmt.Errorf("acme: generate nonce: %w", err)
	}
	if err := s.repo.IssueNonce(ctx, nonce, s.cfg.NonceTTL); err != nil {
		s.metrics.bump(&s.metrics.NewNonceFailureTotal)
		return "", fmt.Errorf("acme: persist nonce: %w", err)
	}
	s.metrics.bump(&s.metrics.NewNonceTotal)
	return nonce, nil
}
