// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package repository

import (
	"context"
	"errors"
	"time"

	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
)

// Sentinel errors for the user repository.
var (
	// ErrUserNotFound: Get / GetByOIDCSubject returned no row. Phase
	// 3's HandleCallback treats this as "first login for this person;
	// create the row".
	ErrUserNotFound = errors.New("user: not found")

	// ErrUserDuplicateOIDCSubject: Create tripped the
	// (oidc_provider_id, oidc_subject) UNIQUE constraint. HTTP 409.
	ErrUserDuplicateOIDCSubject = errors.New("user: a user with this provider+subject already exists")
)

// UserRepository wraps the users table. Phase 3's HandleCallback
// uses GetByOIDCSubject + Create + Update on every login; the GUI's
// admin user-list surface uses ListAll + Get.
type UserRepository interface {
	// Get returns one user by id. ErrUserNotFound on miss.
	Get(ctx context.Context, id string) (*userdomain.User, error)

	// GetByOIDCSubject is the Phase 3 hot-path lookup at login time.
	// Returns the existing row if present, ErrUserNotFound otherwise.
	GetByOIDCSubject(ctx context.Context, providerID, subject string) (*userdomain.User, error)

	// Create persists a new user. Caller MUST have called u.Validate().
	// Returns ErrUserDuplicateOIDCSubject on UNIQUE constraint trip.
	Create(ctx context.Context, u *userdomain.User) error

	// Update writes the mutable field set back to the row. Immutable
	// fields (id, tenant_id, oidc_subject, oidc_provider_id,
	// created_at) are preserved. updated_at is set to NOW() by the
	// implementation.
	Update(ctx context.Context, u *userdomain.User) error

	// ListAll returns every user in the tenant. Order:
	// created_at ASC. Used by the GUI's admin surface.
	ListAll(ctx context.Context, tenantID string) ([]*userdomain.User, error)

	// ListDeactivatedBefore returns every user whose deactivated_at is
	// not NULL AND strictly before the supplied threshold. Sprint 6
	// COMP-002-RETENTION closure — the scheduler's userRetentionLoop
	// uses this to enumerate purge-eligible rows on each tick. Order:
	// deactivated_at ASC (oldest first, so a tick-budget cap is
	// deterministic about which rows it processes).
	ListDeactivatedBefore(ctx context.Context, threshold time.Time) ([]*userdomain.User, error)
}
