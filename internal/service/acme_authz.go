// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Phase 9 ARCH-M2 closure Sprint 9 (2026-05-14): extracted from
// internal/service/acme.go via the Option B sibling-file pattern.
// Package stays `service`; every external caller of
// `service.ACMEService.LookupAuthz(...)` / `ListAuthzsByOrder(...)`
// resolves the same way — pure mechanical relocation.
//
// This file holds the authz read-side concern. The authz write-side
// (status cascade after challenge validation) lives in
// acme_challenges.go alongside recordChallengeOutcome where it
// belongs operationally; the authz creation path stays inside
// CreateOrder in acme.go (orders own the per-order authz rows).

// LookupAuthz returns an authz by ID. Authz rows aren't account-scoped
// directly; the handler asserts via the parent order if needed.
func (s *ACMEService) LookupAuthz(ctx context.Context, authzID string) (*domain.ACMEAuthorization, error) {
	authz, err := s.repo.GetAuthzByID(ctx, authzID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrACMEAuthzNotFound
		}
		return nil, fmt.Errorf("acme: lookup authz: %w", err)
	}
	s.metrics.bump(&s.metrics.AuthzReadTotal)
	return authz, nil
}

// ListAuthzsByOrder returns the per-order authz rows. Used by
// MarshalOrder to compute the authorizations URL list.
func (s *ACMEService) ListAuthzsByOrder(ctx context.Context, orderID string) ([]*domain.ACMEAuthorization, error) {
	return s.repo.ListAuthzsByOrder(ctx, orderID)
}
