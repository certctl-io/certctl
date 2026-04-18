package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// ProfileService provides business logic for certificate profile management.
type ProfileService struct {
	profileRepo  repository.CertificateProfileRepository
	auditService *AuditService
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

// ListProfiles returns all profiles (handler interface method).
func (s *ProfileService) ListProfiles(ctx context.Context, page, perPage int) ([]domain.CertificateProfile, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

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
func (s *ProfileService) UpdateProfile(ctx context.Context, id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
	if err := validateProfile(&profile); err != nil {
		return nil, err
	}

	profile.ID = id
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
