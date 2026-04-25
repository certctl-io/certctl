package postgres

import (
	"github.com/shankar0123/certctl/internal/repository"
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// OwnerRepository implements repository.OwnerRepository
type OwnerRepository struct {
	db *sql.DB
}

// NewOwnerRepository creates a new OwnerRepository
func NewOwnerRepository(db *sql.DB) *OwnerRepository {
	return &OwnerRepository{db: db}
}

// List returns all owners
func (r *OwnerRepository) List(ctx context.Context) ([]*domain.Owner, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, email, team_id, created_at, updated_at
		FROM owners
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query owners: %w", err)
	}
	defer rows.Close()

	var owners []*domain.Owner
	for rows.Next() {
		var owner domain.Owner
		if err := rows.Scan(&owner.ID, &owner.Name, &owner.Email, &owner.TeamID,
			&owner.CreatedAt, &owner.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan owner: %w", err)
		}
		owners = append(owners, &owner)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating owner rows: %w", err)
	}

	return owners, nil
}

// Get retrieves an owner by ID
func (r *OwnerRepository) Get(ctx context.Context, id string) (*domain.Owner, error) {
	var owner domain.Owner
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, email, team_id, created_at, updated_at
		FROM owners
		WHERE id = $1
	`, id).Scan(&owner.ID, &owner.Name, &owner.Email, &owner.TeamID,
		&owner.CreatedAt, &owner.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("owner not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query owner: %w", err)
	}

	return &owner, nil
}

// Create stores a new owner
func (r *OwnerRepository) Create(ctx context.Context, owner *domain.Owner) error {
	if owner.ID == "" {
		owner.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO owners (id, name, email, team_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, owner.ID, owner.Name, owner.Email, owner.TeamID,
		owner.CreatedAt, owner.UpdatedAt).Scan(&owner.ID)

	if err != nil {
		return fmt.Errorf("failed to create owner: %w", err)
	}

	return nil
}

// Update modifies an existing owner
func (r *OwnerRepository) Update(ctx context.Context, owner *domain.Owner) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE owners SET
			name = $1,
			email = $2,
			team_id = $3,
			updated_at = $4
		WHERE id = $5
	`, owner.Name, owner.Email, owner.TeamID, owner.UpdatedAt, owner.ID)

	if err != nil {
		return fmt.Errorf("failed to update owner: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("owner not found: %w", repository.ErrNotFound)
	}

	return nil
}

// Delete removes an owner
func (r *OwnerRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM owners WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete owner: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("owner not found: %w", repository.ErrNotFound)
	}

	return nil
}
