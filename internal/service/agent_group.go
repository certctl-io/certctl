package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// AgentGroupService provides business logic for agent group management.
type AgentGroupService struct {
	groupRepo    repository.AgentGroupRepository
	auditService *AuditService
}

// NewAgentGroupService creates a new agent group service.
func NewAgentGroupService(
	groupRepo repository.AgentGroupRepository,
	auditService *AuditService,
) *AgentGroupService {
	return &AgentGroupService{
		groupRepo:    groupRepo,
		auditService: auditService,
	}
}

// ListAgentGroups returns paginated agent groups (handler interface method).
func (s *AgentGroupService) ListAgentGroups(ctx context.Context, page, perPage int) ([]domain.AgentGroup, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	groups, err := s.groupRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list agent groups: %w", err)
	}
	total := int64(len(groups))

	var result []domain.AgentGroup
	for _, g := range groups {
		if g != nil {
			result = append(result, *g)
		}
	}

	return result, total, nil
}

// GetAgentGroup returns a single agent group (handler interface method).
func (s *AgentGroupService) GetAgentGroup(ctx context.Context, id string) (*domain.AgentGroup, error) {
	return s.groupRepo.Get(ctx, id)
}

// CreateAgentGroup creates a new agent group with validation (handler interface method).
func (s *AgentGroupService) CreateAgentGroup(ctx context.Context, group domain.AgentGroup) (*domain.AgentGroup, error) {
	if err := validateAgentGroup(&group); err != nil {
		return nil, err
	}

	if group.ID == "" {
		group.ID = generateID("ag")
	}
	now := time.Now()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = now
	}

	if err := s.groupRepo.Create(ctx, &group); err != nil {
		return nil, fmt.Errorf("failed to create agent group: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			"create_agent_group", "agent_group", group.ID, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return &group, nil
}

// UpdateAgentGroup modifies an existing agent group (handler interface method).
func (s *AgentGroupService) UpdateAgentGroup(ctx context.Context, id string, group domain.AgentGroup) (*domain.AgentGroup, error) {
	if err := validateAgentGroup(&group); err != nil {
		return nil, err
	}

	group.ID = id
	if err := s.groupRepo.Update(ctx, &group); err != nil {
		return nil, fmt.Errorf("failed to update agent group: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			"update_agent_group", "agent_group", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return &group, nil
}

// DeleteAgentGroup removes an agent group (handler interface method).
func (s *AgentGroupService) DeleteAgentGroup(ctx context.Context, id string) error {
	if err := s.groupRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete agent group: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, "api", domain.ActorTypeUser,
			"delete_agent_group", "agent_group", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// ListMembers returns agents in a group.
func (s *AgentGroupService) ListMembers(ctx context.Context, id string) ([]domain.Agent, int64, error) {
	agents, err := s.groupRepo.ListMembers(ctx, id)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list group members: %w", err)
	}

	var result []domain.Agent
	for _, a := range agents {
		if a != nil {
			result = append(result, *a)
		}
	}

	return result, int64(len(result)), nil
}

// validateAgentGroup checks that an agent group's configuration is valid.
func validateAgentGroup(g *domain.AgentGroup) error {
	if g.Name == "" {
		return fmt.Errorf("agent group name is required")
	}
	if len(g.Name) > 255 {
		return fmt.Errorf("agent group name exceeds 255 characters")
	}
	return nil
}
