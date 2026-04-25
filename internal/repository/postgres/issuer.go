package postgres

import (
	"github.com/shankar0123/certctl/internal/repository"
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// IssuerRepository implements repository.IssuerRepository
type IssuerRepository struct {
	db *sql.DB
}

// NewIssuerRepository creates a new IssuerRepository
func NewIssuerRepository(db *sql.DB) *IssuerRepository {
	return &IssuerRepository{db: db}
}

// List returns all issuers
func (r *IssuerRepository) List(ctx context.Context) ([]*domain.Issuer, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, type, config, COALESCE(encrypted_config, NULL), enabled,
		       last_tested_at, COALESCE(test_status, 'untested'), COALESCE(source, 'database'),
		       created_at, updated_at
		FROM issuers
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query issuers: %w", err)
	}
	defer rows.Close()

	var issuers []*domain.Issuer
	for rows.Next() {
		var issuer domain.Issuer
		if err := rows.Scan(&issuer.ID, &issuer.Name, &issuer.Type, &issuer.Config,
			&issuer.EncryptedConfig, &issuer.Enabled,
			&issuer.LastTestedAt, &issuer.TestStatus, &issuer.Source,
			&issuer.CreatedAt, &issuer.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan issuer: %w", err)
		}
		issuers = append(issuers, &issuer)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating issuer rows: %w", err)
	}

	return issuers, nil
}

// Get retrieves an issuer by ID
func (r *IssuerRepository) Get(ctx context.Context, id string) (*domain.Issuer, error) {
	var issuer domain.Issuer
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, type, config, COALESCE(encrypted_config, NULL), enabled,
		       last_tested_at, COALESCE(test_status, 'untested'), COALESCE(source, 'database'),
		       created_at, updated_at
		FROM issuers
		WHERE id = $1
	`, id).Scan(&issuer.ID, &issuer.Name, &issuer.Type, &issuer.Config,
		&issuer.EncryptedConfig, &issuer.Enabled,
		&issuer.LastTestedAt, &issuer.TestStatus, &issuer.Source,
		&issuer.CreatedAt, &issuer.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("issuer not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query issuer: %w", err)
	}

	return &issuer, nil
}

// Create stores a new issuer
func (r *IssuerRepository) Create(ctx context.Context, issuer *domain.Issuer) error {
	if issuer.ID == "" {
		issuer.ID = uuid.New().String()
	}

	source := issuer.Source
	if source == "" {
		source = "database"
	}
	testStatus := issuer.TestStatus
	if testStatus == "" {
		testStatus = "untested"
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO issuers (id, name, type, config, encrypted_config, enabled,
		                     last_tested_at, test_status, source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`, issuer.ID, issuer.Name, issuer.Type, issuer.Config, issuer.EncryptedConfig,
		issuer.Enabled, issuer.LastTestedAt, testStatus, source,
		issuer.CreatedAt, issuer.UpdatedAt).Scan(&issuer.ID)

	if err != nil {
		return fmt.Errorf("failed to create issuer: %w", err)
	}

	return nil
}

// CreateIfNotExists creates an issuer only if the ID doesn't already exist.
// Used for env var seeding on first boot. Returns true if created, false if already existed.
func (r *IssuerRepository) CreateIfNotExists(ctx context.Context, issuer *domain.Issuer) (bool, error) {
	source := issuer.Source
	if source == "" {
		source = "env"
	}
	testStatus := issuer.TestStatus
	if testStatus == "" {
		testStatus = "untested"
	}

	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO issuers (id, name, type, config, encrypted_config, enabled,
		                     last_tested_at, test_status, source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO NOTHING
		RETURNING id
	`, issuer.ID, issuer.Name, issuer.Type, issuer.Config, issuer.EncryptedConfig,
		issuer.Enabled, issuer.LastTestedAt, testStatus, source,
		issuer.CreatedAt, issuer.UpdatedAt).Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			// ON CONFLICT DO NOTHING — row already existed
			return false, nil
		}
		return false, fmt.Errorf("failed to create issuer: %w", err)
	}

	return true, nil
}

// Update modifies an existing issuer
func (r *IssuerRepository) Update(ctx context.Context, issuer *domain.Issuer) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE issuers SET
			name = $1,
			type = $2,
			config = $3,
			encrypted_config = $4,
			enabled = $5,
			last_tested_at = $6,
			test_status = $7,
			updated_at = $8
		WHERE id = $9
	`, issuer.Name, issuer.Type, issuer.Config, issuer.EncryptedConfig,
		issuer.Enabled, issuer.LastTestedAt, issuer.TestStatus,
		issuer.UpdatedAt, issuer.ID)

	if err != nil {
		return fmt.Errorf("failed to update issuer: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("issuer not found: %w", repository.ErrNotFound)
	}

	return nil
}

// Delete removes an issuer
func (r *IssuerRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM issuers WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete issuer: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("issuer not found: %w", repository.ErrNotFound)
	}

	return nil
}
