package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/certctl-io/certctl/internal/repository"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/google/uuid"
)

// TeamRepository implements repository.TeamRepository
type TeamRepository struct {
	db *sql.DB
}

// NewTeamRepository creates a new TeamRepository
func NewTeamRepository(db *sql.DB) *TeamRepository {
	return &TeamRepository{db: db}
}

// List returns all teams
func (r *TeamRepository) List(ctx context.Context) ([]*domain.Team, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, description, created_at, updated_at
		FROM teams
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query teams: %w", err)
	}
	defer rows.Close()

	var teams []*domain.Team
	for rows.Next() {
		var team domain.Team
		if err := rows.Scan(&team.ID, &team.Name, &team.Description,
			&team.CreatedAt, &team.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan team: %w", err)
		}
		teams = append(teams, &team)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating team rows: %w", err)
	}

	return teams, nil
}

// Get retrieves a team by ID
func (r *TeamRepository) Get(ctx context.Context, id string) (*domain.Team, error) {
	var team domain.Team
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, description, created_at, updated_at
		FROM teams
		WHERE id = $1
	`, id).Scan(&team.ID, &team.Name, &team.Description,
		&team.CreatedAt, &team.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("team not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query team: %w", err)
	}

	return &team, nil
}

// Create stores a new team
func (r *TeamRepository) Create(ctx context.Context, team *domain.Team) error {
	if team.ID == "" {
		team.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO teams (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, team.ID, team.Name, team.Description, team.CreatedAt, team.UpdatedAt).Scan(&team.ID)

	if err != nil {
		return fmt.Errorf("failed to create team: %w", err)
	}

	return nil
}

// Update modifies an existing team
func (r *TeamRepository) Update(ctx context.Context, team *domain.Team) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE teams SET
			name = $1,
			description = $2,
			updated_at = $3
		WHERE id = $4
	`, team.Name, team.Description, team.UpdatedAt, team.ID)

	if err != nil {
		return fmt.Errorf("failed to update team: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("team not found: %w", repository.ErrNotFound)
	}

	return nil
}

// Delete removes a team
func (r *TeamRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM teams WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete team: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("team not found: %w", repository.ErrNotFound)
	}

	return nil
}
