package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// TeamService provides business logic for team management.
type TeamService struct {
	teamRepo     repository.TeamRepository
	auditService *AuditService
}

// NewTeamService creates a new team service.
func NewTeamService(
	teamRepo repository.TeamRepository,
	auditService *AuditService,
) *TeamService {
	return &TeamService{
		teamRepo:     teamRepo,
		auditService: auditService,
	}
}

// List returns a paginated list of teams.
func (s *TeamService) List(ctx context.Context, page, perPage int) ([]*domain.Team, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	teams, err := s.teamRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list teams: %w", err)
	}
	total := int64(len(teams))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}
	return teams[start:end], total, nil
}

// Get retrieves a team by ID.
func (s *TeamService) Get(ctx context.Context, id string) (*domain.Team, error) {
	team, err := s.teamRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get team %s: %w", id, err)
	}
	return team, nil
}

// Create validates and stores a new team.
func (s *TeamService) Create(ctx context.Context, team *domain.Team, actor string) error {
	if team.Name == "" {
		return fmt.Errorf("team name is required")
	}

	if team.ID == "" {
		team.ID = generateID("team")
	}
	now := time.Now()
	if team.CreatedAt.IsZero() {
		team.CreatedAt = now
	}
	if team.UpdatedAt.IsZero() {
		team.UpdatedAt = now
	}
	if err := s.teamRepo.Create(ctx, team); err != nil {
		return fmt.Errorf("failed to create team: %w", err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "create_team", "team", team.ID, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Update modifies an existing team.
func (s *TeamService) Update(ctx context.Context, id string, team *domain.Team, actor string) error {
	if team.Name == "" {
		return fmt.Errorf("team name is required")
	}

	team.ID = id
	if err := s.teamRepo.Update(ctx, team); err != nil {
		return fmt.Errorf("failed to update team %s: %w", id, err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "update_team", "team", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// Delete removes a team.
func (s *TeamService) Delete(ctx context.Context, id string, actor string) error {
	if err := s.teamRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete team %s: %w", id, err)
	}

	if s.auditService != nil {
		if auditErr := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "delete_team", "team", id, nil); auditErr != nil {
			slog.Error("failed to record audit event", "error", auditErr)
		}
	}

	return nil
}

// ListTeams returns paginated teams (handler interface method).
func (s *TeamService) ListTeams(ctx context.Context, page, perPage int) ([]domain.Team, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	teams, err := s.teamRepo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list teams: %w", err)
	}
	total := int64(len(teams))

	var result []domain.Team
	for _, t := range teams {
		if t != nil {
			result = append(result, *t)
		}
	}

	return result, total, nil
}

// GetTeam returns a single team (handler interface method).
func (s *TeamService) GetTeam(ctx context.Context, id string) (*domain.Team, error) {
	return s.teamRepo.Get(ctx, id)
}

// CreateTeam creates a new team (handler interface method).
func (s *TeamService) CreateTeam(ctx context.Context, team domain.Team) (*domain.Team, error) {
	if team.ID == "" {
		team.ID = generateID("team")
	}
	now := time.Now()
	if team.CreatedAt.IsZero() {
		team.CreatedAt = now
	}
	if team.UpdatedAt.IsZero() {
		team.UpdatedAt = now
	}
	if err := s.teamRepo.Create(ctx, &team); err != nil {
		return nil, fmt.Errorf("failed to create team: %w", err)
	}
	return &team, nil
}

// UpdateTeam modifies a team (handler interface method).
func (s *TeamService) UpdateTeam(ctx context.Context, id string, team domain.Team) (*domain.Team, error) {
	team.ID = id
	if err := s.teamRepo.Update(ctx, &team); err != nil {
		return nil, fmt.Errorf("failed to update team: %w", err)
	}
	return &team, nil
}

// DeleteTeam removes a team (handler interface method).
func (s *TeamService) DeleteTeam(ctx context.Context, id string) error {
	return s.teamRepo.Delete(ctx, id)
}
