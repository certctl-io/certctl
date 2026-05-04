package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/certctl-io/certctl/internal/repository"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/google/uuid"
)

// TargetRepository implements repository.TargetRepository
type TargetRepository struct {
	db *sql.DB
}

// NewTargetRepository creates a new TargetRepository
func NewTargetRepository(db *sql.DB) *TargetRepository {
	return &TargetRepository{db: db}
}

// scanTarget scans a target row including optional M35 columns (encrypted_config, last_tested_at, test_status, source).
func scanTarget(scanner interface {
	Scan(dest ...interface{}) error
}, target *domain.DeploymentTarget) error {
	var lastTestedAt sql.NullTime
	var testStatus sql.NullString
	var source sql.NullString
	if err := scanner.Scan(
		&target.ID, &target.Name, &target.Type, &target.AgentID,
		&target.Config, &target.EncryptedConfig, &target.Enabled,
		&lastTestedAt, &testStatus, &source,
		&target.CreatedAt, &target.UpdatedAt,
	); err != nil {
		return err
	}
	if lastTestedAt.Valid {
		target.LastTestedAt = &lastTestedAt.Time
	}
	if testStatus.Valid {
		target.TestStatus = testStatus.String
	}
	if source.Valid {
		target.Source = source.String
	}
	return nil
}

// targetSelectColumns is the standard column list for target queries.
const targetSelectColumns = `id, name, type, agent_id, config, COALESCE(encrypted_config, ''::bytea), enabled, last_tested_at, COALESCE(test_status, 'untested'), COALESCE(source, 'database'), created_at, updated_at`

// List returns all targets
func (r *TargetRepository) List(ctx context.Context) ([]*domain.DeploymentTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+targetSelectColumns+`
		FROM deployment_targets
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query targets: %w", err)
	}
	defer rows.Close()

	var targets []*domain.DeploymentTarget
	for rows.Next() {
		var target domain.DeploymentTarget
		if err := scanTarget(rows, &target); err != nil {
			return nil, fmt.Errorf("failed to scan target: %w", err)
		}
		targets = append(targets, &target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating target rows: %w", err)
	}

	return targets, nil
}

// Get retrieves a target by ID
func (r *TargetRepository) Get(ctx context.Context, id string) (*domain.DeploymentTarget, error) {
	var target domain.DeploymentTarget
	err := scanTarget(r.db.QueryRowContext(ctx, `
		SELECT `+targetSelectColumns+`
		FROM deployment_targets
		WHERE id = $1
	`, id), &target)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("target not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query target: %w", err)
	}

	return &target, nil
}

// Create stores a new target
func (r *TargetRepository) Create(ctx context.Context, target *domain.DeploymentTarget) error {
	if target.ID == "" {
		target.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO deployment_targets (id, name, type, agent_id, config, encrypted_config, enabled, last_tested_at, test_status, source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`, target.ID, target.Name, target.Type, target.AgentID, target.Config, target.EncryptedConfig,
		target.Enabled, target.LastTestedAt, target.TestStatus, target.Source,
		target.CreatedAt, target.UpdatedAt).Scan(&target.ID)

	if err != nil {
		return fmt.Errorf("failed to create target: %w", err)
	}

	return nil
}

// CreateIfNotExists creates a target only if the ID doesn't already exist (ON CONFLICT DO NOTHING).
// Returns true if created, false if already existed.
func (r *TargetRepository) CreateIfNotExists(ctx context.Context, target *domain.DeploymentTarget) (bool, error) {
	if target.ID == "" {
		target.ID = uuid.New().String()
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO deployment_targets (id, name, type, agent_id, config, encrypted_config, enabled, last_tested_at, test_status, source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO NOTHING
	`, target.ID, target.Name, target.Type, target.AgentID, target.Config, target.EncryptedConfig,
		target.Enabled, target.LastTestedAt, target.TestStatus, target.Source,
		target.CreatedAt, target.UpdatedAt)

	if err != nil {
		return false, fmt.Errorf("failed to create target: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rows > 0, nil
}

// Update modifies an existing target
func (r *TargetRepository) Update(ctx context.Context, target *domain.DeploymentTarget) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE deployment_targets SET
			name = $1,
			type = $2,
			agent_id = $3,
			config = $4,
			encrypted_config = $5,
			enabled = $6,
			last_tested_at = $7,
			test_status = $8,
			source = $9,
			updated_at = $10
		WHERE id = $11
	`, target.Name, target.Type, target.AgentID, target.Config, target.EncryptedConfig,
		target.Enabled, target.LastTestedAt, target.TestStatus, target.Source,
		target.UpdatedAt, target.ID)

	if err != nil {
		return fmt.Errorf("failed to update target: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("target not found: %w", repository.ErrNotFound)
	}

	return nil
}

// Delete removes a target
func (r *TargetRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM deployment_targets WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete target: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("target not found: %w", repository.ErrNotFound)
	}

	return nil
}

// ListByCertificate returns all targets for a given certificate
func (r *TargetRepository) ListByCertificate(ctx context.Context, certID string) ([]*domain.DeploymentTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT dt.id, dt.name, dt.type, dt.agent_id, dt.config, COALESCE(dt.encrypted_config, ''::bytea), dt.enabled, dt.last_tested_at, COALESCE(dt.test_status, 'untested'), COALESCE(dt.source, 'database'), dt.created_at, dt.updated_at
		FROM deployment_targets dt
		INNER JOIN certificate_target_mappings ctm ON dt.id = ctm.target_id
		WHERE ctm.certificate_id = $1
		ORDER BY dt.created_at DESC
	`, certID)

	if err != nil {
		return nil, fmt.Errorf("failed to query targets for certificate: %w", err)
	}
	defer rows.Close()

	var targets []*domain.DeploymentTarget
	for rows.Next() {
		var target domain.DeploymentTarget
		if err := scanTarget(rows, &target); err != nil {
			return nil, fmt.Errorf("failed to scan target: %w", err)
		}
		targets = append(targets, &target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating target rows: %w", err)
	}

	return targets, nil
}
