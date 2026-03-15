package service

import (
	"context"
	"fmt"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// TargetService provides business logic for deployment target management.
type TargetService struct {
	targetRepo   repository.TargetRepository
	auditService *AuditService
}

// NewTargetService creates a new target service.
func NewTargetService(
	targetRepo repository.TargetRepository,
	auditService *AuditService,
) *TargetService {
	return &TargetService{
		targetRepo:   targetRepo,
		auditService: auditService,
	}
}

// List returns a paginated list of deployment targets.
func (s *TargetService) List(ctx context.Context, page, perPage int) ([]*domain.DeploymentTarget, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	targets, err := s.targetRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list targets: %w", err)
	}
	total := int64(len(targets))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}
	return targets[start:end], total, nil
}

// Get retrieves a deployment target by ID.
func (s *TargetService) Get(ctx context.Context, id string) (*domain.DeploymentTarget, error) {
	target, err := s.targetRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get target %s: %w", id, err)
	}
	return target, nil
}

// Create validates and stores a new deployment target.
func (s *TargetService) Create(ctx context.Context, target *domain.DeploymentTarget, actor string) error {
	if target.Name == "" {
		return fmt.Errorf("target name is required")
	}

	if target.ID == "" {
		target.ID = generateID("target")
	}
	now := time.Now()
	if target.CreatedAt.IsZero() {
		target.CreatedAt = now
	}
	if target.UpdatedAt.IsZero() {
		target.UpdatedAt = now
	}
	if err := s.targetRepo.Create(ctx, target); err != nil {
		return fmt.Errorf("failed to create target: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "create_target", "target", target.ID, nil)
	}

	return nil
}

// Update modifies an existing deployment target.
func (s *TargetService) Update(ctx context.Context, id string, target *domain.DeploymentTarget, actor string) error {
	if target.Name == "" {
		return fmt.Errorf("target name is required")
	}

	target.ID = id
	if err := s.targetRepo.Update(ctx, target); err != nil {
		return fmt.Errorf("failed to update target %s: %w", id, err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "update_target", "target", id, nil)
	}

	return nil
}

// Delete removes a deployment target.
func (s *TargetService) Delete(ctx context.Context, id string, actor string) error {
	if err := s.targetRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete target %s: %w", id, err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "delete_target", "target", id, nil)
	}

	return nil
}

// ListTargets returns paginated targets (handler interface method).
func (s *TargetService) ListTargets(page, perPage int) ([]domain.DeploymentTarget, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	targets, err := s.targetRepo.List(context.Background())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list targets: %w", err)
	}
	total := int64(len(targets))

	var result []domain.DeploymentTarget
	for _, t := range targets {
		if t != nil {
			result = append(result, *t)
		}
	}

	return result, total, nil
}

// GetTarget returns a single target (handler interface method).
func (s *TargetService) GetTarget(id string) (*domain.DeploymentTarget, error) {
	return s.targetRepo.Get(context.Background(), id)
}

// CreateTarget creates a new target (handler interface method).
func (s *TargetService) CreateTarget(target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	if target.ID == "" {
		target.ID = generateID("target")
	}
	now := time.Now()
	if target.CreatedAt.IsZero() {
		target.CreatedAt = now
	}
	if target.UpdatedAt.IsZero() {
		target.UpdatedAt = now
	}
	if err := s.targetRepo.Create(context.Background(), &target); err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}
	return &target, nil
}

// UpdateTarget modifies a target (handler interface method).
func (s *TargetService) UpdateTarget(id string, target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	target.ID = id
	if err := s.targetRepo.Update(context.Background(), &target); err != nil {
		return nil, fmt.Errorf("failed to update target: %w", err)
	}
	return &target, nil
}

// DeleteTarget removes a target (handler interface method).
func (s *TargetService) DeleteTarget(id string) error {
	return s.targetRepo.Delete(context.Background(), id)
}
