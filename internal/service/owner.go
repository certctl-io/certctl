package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// OwnerService provides business logic for certificate owner management.
type OwnerService struct {
	ownerRepo    repository.OwnerRepository
	auditService *AuditService
}

// NewOwnerService creates a new owner service.
func NewOwnerService(
	ownerRepo repository.OwnerRepository,
	auditService *AuditService,
) *OwnerService {
	return &OwnerService{
		ownerRepo:    ownerRepo,
		auditService: auditService,
	}
}

// List returns a paginated list of owners.
func (s *OwnerService) List(ctx context.Context, page, perPage int) ([]*domain.Owner, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	owners, err := s.ownerRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list owners: %w", err)
	}
	total := int64(len(owners))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}
	return owners[start:end], total, nil
}

// Get retrieves an owner by ID.
func (s *OwnerService) Get(ctx context.Context, id string) (*domain.Owner, error) {
	owner, err := s.ownerRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get owner %s: %w", id, err)
	}
	return owner, nil
}

// Create validates and stores a new owner.
func (s *OwnerService) Create(ctx context.Context, owner *domain.Owner, actor string) error {
	if owner.Name == "" {
		return fmt.Errorf("owner name is required")
	}

	if owner.ID == "" {
		owner.ID = generateID("owner")
	}
	now := time.Now()
	if owner.CreatedAt.IsZero() {
		owner.CreatedAt = now
	}
	if owner.UpdatedAt.IsZero() {
		owner.UpdatedAt = now
	}
	if err := s.ownerRepo.Create(ctx, owner); err != nil {
		return fmt.Errorf("failed to create owner: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "create_owner", "owner", owner.ID, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Update modifies an existing owner.
func (s *OwnerService) Update(ctx context.Context, id string, owner *domain.Owner, actor string) error {
	if owner.Name == "" {
		return fmt.Errorf("owner name is required")
	}

	owner.ID = id
	if err := s.ownerRepo.Update(ctx, owner); err != nil {
		return fmt.Errorf("failed to update owner %s: %w", id, err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "update_owner", "owner", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Delete removes an owner.
func (s *OwnerService) Delete(ctx context.Context, id string, actor string) error {
	if err := s.ownerRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete owner %s: %w", id, err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "delete_owner", "owner", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// ListOwners returns paginated owners (handler interface method).
func (s *OwnerService) ListOwners(ctx context.Context, page, perPage int) ([]domain.Owner, int64, error) {
	// Bundle E / Audit L-020: page/perPage are unused; the underlying repo
	// List() does not yet take pagination params. Marked explicitly so
	// ineffassign sees no dead store and future maintainers see the
	// vestigial params rather than a misleading default-applied clamp.
	_ = page
	_ = perPage

	owners, err := s.ownerRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list owners: %w", err)
	}
	total := int64(len(owners))

	var result []domain.Owner
	for _, o := range owners {
		if o != nil {
			result = append(result, *o)
		}
	}

	return result, total, nil
}

// GetOwner returns a single owner (handler interface method).
func (s *OwnerService) GetOwner(ctx context.Context, id string) (*domain.Owner, error) {
	return s.ownerRepo.Get(ctx, id)
}

// CreateOwner creates a new owner (handler interface method).
func (s *OwnerService) CreateOwner(ctx context.Context, owner domain.Owner) (*domain.Owner, error) {
	if owner.ID == "" {
		owner.ID = generateID("owner")
	}
	now := time.Now()
	if owner.CreatedAt.IsZero() {
		owner.CreatedAt = now
	}
	if owner.UpdatedAt.IsZero() {
		owner.UpdatedAt = now
	}
	if err := s.ownerRepo.Create(ctx, &owner); err != nil {
		return nil, fmt.Errorf("failed to create owner: %w", err)
	}
	return &owner, nil
}

// UpdateOwner modifies an owner (handler interface method).
func (s *OwnerService) UpdateOwner(ctx context.Context, id string, owner domain.Owner) (*domain.Owner, error) {
	owner.ID = id
	if err := s.ownerRepo.Update(ctx, &owner); err != nil {
		return nil, fmt.Errorf("failed to update owner: %w", err)
	}
	return &owner, nil
}

// DeleteOwner removes an owner (handler interface method).
func (s *OwnerService) DeleteOwner(ctx context.Context, id string) error {
	return s.ownerRepo.Delete(ctx, id)
}
