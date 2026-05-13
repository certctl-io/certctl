// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// ErrProfileEditPendingApproval (Bundle 1 Phase 9) is returned by
// UpdateProfile when the live profile (or the proposed update) carries
// RequiresApproval=true. The handler maps this to HTTP 202 Accepted +
// {pending_approval_id} so the operator knows to chase a second-admin
// approve. See docs/reference/profiles.md.
var ErrProfileEditPendingApproval = errors.New("profile edit gated by approval workflow")

// ProfileEditApprovalRequester is the slice of ApprovalService the
// ProfileService consumes when a profile edit triggers the gate.
// Pulled out as a small interface so unit tests can drive the gate
// without the full ApprovalService dependency tree.
type ProfileEditApprovalRequester interface {
	RequestProfileEditApproval(ctx context.Context, profileID, requestedBy string, payload []byte) (string, error)
}

// ProfileService provides business logic for certificate profile management.
type ProfileService struct {
	profileRepo     repository.CertificateProfileRepository
	auditService    *AuditService
	approvalService ProfileEditApprovalRequester // Bundle 1 Phase 9; nil disables the gate
}

// NewProfileService creates a new profile service.
func NewProfileService(
	profileRepo repository.CertificateProfileRepository,
	auditService *AuditService,
) *ProfileService {
	return &ProfileService{
		profileRepo:  profileRepo,
		auditService: auditService,
	}
}

// SetApprovalService wires the Bundle 1 Phase 9 gate. cmd/server/main.go
// calls this after both ProfileService and ApprovalService are
// constructed. nil disables the gate (preserving pre-Phase-9 behaviour
// for any test fixture or alternate boot path that doesn't wire it).
func (s *ProfileService) SetApprovalService(a ProfileEditApprovalRequester) {
	s.approvalService = a
}

// ListProfiles returns all profiles (handler interface method).
func (s *ProfileService) ListProfiles(ctx context.Context, page, perPage int) ([]domain.CertificateProfile, int64, error) {
	// Bundle E / Audit L-020: page/perPage are unused; the underlying repo
	// List() does not yet take pagination params. Marked explicitly so
	// ineffassign sees no dead store and future maintainers see the
	// vestigial params rather than a misleading default-applied clamp.
	_ = page
	_ = perPage

	profiles, err := s.profileRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list profiles: %w", err)
	}
	total := int64(len(profiles))

	var result []domain.CertificateProfile
	for _, p := range profiles {
		if p != nil {
			result = append(result, *p)
		}
	}

	return result, total, nil
}

// GetProfile returns a single profile (handler interface method).
func (s *ProfileService) GetProfile(ctx context.Context, id string) (*domain.CertificateProfile, error) {
	return s.profileRepo.Get(ctx, id)
}

// CreateProfile creates a new profile with validation (handler interface method).
func (s *ProfileService) CreateProfile(ctx context.Context, profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
	if err := validateProfile(&profile); err != nil {
		return nil, err
	}

	if profile.ID == "" {
		profile.ID = generateID("prof")
	}
	now := time.Now()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = now
	}

	// Apply defaults if not set
	if len(profile.AllowedKeyAlgorithms) == 0 {
		profile.AllowedKeyAlgorithms = domain.DefaultKeyAlgorithms()
	}
	if len(profile.AllowedEKUs) == 0 {
		profile.AllowedEKUs = domain.DefaultEKUs()
	}

	if err := s.profileRepo.Create(ctx, &profile); err != nil {
		return nil, fmt.Errorf("failed to create profile: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(context.WithoutCancel(ctx), "api", domain.ActorTypeUser,
			"create_profile", "certificate_profile", profile.ID, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return &profile, nil
}

// UpdateProfile modifies an existing profile (handler interface method).
//
// Bundle 1 Phase 9 (approval-bypass closure): if the LIVE profile has
// RequiresApproval=true OR the proposed update would set it true, the
// edit is NOT applied directly. Instead it is serialized to a pending
// ApprovalRequest with Kind=profile_edit and the caller receives
// ErrProfileEditPendingApproval. The handler maps this to HTTP 202 +
// the new approval ID. A non-requester admin then approves via the
// existing /v1/approvals/{id}/approve endpoint, which deserializes
// the payload and persists the diff via the profile-edit-apply
// callback registered in main.go. This closes the flip-flop loophole
// where an admin could disable RequiresApproval, mutate, re-enable.
//
// SetApprovalService(nil) disables the gate (test fixtures); the
// pre-Phase-9 direct-apply path is preserved.
func (s *ProfileService) UpdateProfile(ctx context.Context, id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
	if err := validateProfile(&profile); err != nil {
		return nil, err
	}
	profile.ID = id

	if s.approvalService != nil {
		live, err := s.profileRepo.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to load live profile: %w", err)
		}
		// Gate when the live profile is approval-tier OR the edit
		// would flip it on. Both arms close the loophole: a flip-
		// flop attacker can't set false→mutate→true because every
		// transition through an approval-tier profile triggers the
		// gate.
		if (live != nil && live.RequiresApproval) || profile.RequiresApproval {
			payload, perr := json.Marshal(profile)
			if perr != nil {
				return nil, fmt.Errorf("marshal profile for approval payload: %w", perr)
			}
			requester := actorFromContext(ctx)
			approvalID, gerr := s.approvalService.RequestProfileEditApproval(ctx, id, requester, payload)
			if gerr != nil {
				return nil, fmt.Errorf("approval gate: %w", gerr)
			}
			if s.auditService != nil {
				// Audit 2026-05-10 HIGH-6 partial closure — emit WARN on
				// audit-write failure so the silent row-miss is observable.
				if err := s.auditService.RecordEventWithCategory(
					context.WithoutCancel(ctx),
					requester, domain.ActorTypeUser,
					"profile.edit_request", domain.EventCategoryAuth,
					"certificate_profile", id,
					map[string]interface{}{"approval_id": approvalID},
				); err != nil {
					slog.WarnContext(ctx, "profile.edit_request audit write failed (approval requested; audit row may be missing)",
						"profile_id", id,
						"approval_id", approvalID,
						"requester", requester,
						"err", err)
				}
			}
			return nil, fmt.Errorf("%w: approval=%s", ErrProfileEditPendingApproval, approvalID)
		}
	}

	if err := s.profileRepo.Update(ctx, &profile); err != nil {
		return nil, fmt.Errorf("failed to update profile: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(context.WithoutCancel(ctx), "api", domain.ActorTypeUser,
			"update_profile", "certificate_profile", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return &profile, nil
}

// actorFromContext pulls the caller's actor ID from the
// auth-middleware ActorIDKey populated by NewAuthWithKeyStore /
// NewDemoModeAuth. Falls back to "api" so legacy test fixtures that
// don't wire the auth context still record meaningful audit rows.
func actorFromContext(ctx context.Context) string {
	if ctx == nil {
		return "api"
	}
	if id := auth.GetActorID(ctx); id != "" {
		return id
	}
	if id, ok := ctx.Value(auth.UserKey{}).(string); ok && id != "" {
		return id
	}
	return "api"
}

// DeleteProfile removes a profile (handler interface method).
func (s *ProfileService) DeleteProfile(ctx context.Context, id string) error {
	if err := s.profileRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete profile: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(context.WithoutCancel(ctx), "api", domain.ActorTypeUser,
			"delete_profile", "certificate_profile", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Get retrieves a profile by ID (used by other services like RenewalService).
func (s *ProfileService) Get(ctx context.Context, id string) (*domain.CertificateProfile, error) {
	return s.profileRepo.Get(ctx, id)
}

// validateProfile checks that a profile's configuration is valid.
func validateProfile(p *domain.CertificateProfile) error {
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	if len(p.Name) > 255 {
		return fmt.Errorf("profile name exceeds 255 characters")
	}

	// Validate key algorithms
	for _, alg := range p.AllowedKeyAlgorithms {
		if !domain.ValidKeyAlgorithms[alg.Algorithm] {
			return fmt.Errorf("invalid key algorithm: %s (allowed: RSA, ECDSA, Ed25519)", alg.Algorithm)
		}
		if alg.Algorithm == domain.KeyAlgorithmRSA && alg.MinSize < 2048 {
			return fmt.Errorf("RSA minimum key size must be at least 2048, got %d", alg.MinSize)
		}
		if alg.Algorithm == domain.KeyAlgorithmECDSA && alg.MinSize < 256 {
			return fmt.Errorf("ECDSA minimum key size must be at least 256, got %d", alg.MinSize)
		}
	}

	// Validate EKUs
	for _, eku := range p.AllowedEKUs {
		if !domain.ValidEKUs[eku] {
			return fmt.Errorf("invalid EKU: %s", eku)
		}
	}

	// Validate max TTL
	if p.MaxTTLSeconds < 0 {
		return fmt.Errorf("max_ttl_seconds cannot be negative")
	}

	// Validate short-lived consistency
	if p.AllowShortLived && p.MaxTTLSeconds >= 3600 {
		return fmt.Errorf("allow_short_lived is true but max_ttl_seconds (%d) is >= 3600; short-lived certs must have TTL under 1 hour", p.MaxTTLSeconds)
	}

	return nil
}
