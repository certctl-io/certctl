package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/shankar0123/certctl/internal/repository"
	"time"

	"github.com/lib/pq"
	"github.com/shankar0123/certctl/internal/domain"
)

// NetworkScanRepository implements repository.NetworkScanRepository using PostgreSQL.
type NetworkScanRepository struct {
	db *sql.DB
}

// NewNetworkScanRepository creates a new PostgreSQL-backed network scan repository.
func NewNetworkScanRepository(db *sql.DB) *NetworkScanRepository {
	return &NetworkScanRepository{db: db}
}

// List returns all network scan targets.
func (r *NetworkScanRepository) List(ctx context.Context) ([]*domain.NetworkScanTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, cidrs, ports, enabled, scan_interval_hours, timeout_ms,
		       last_scan_at, last_scan_duration_ms, last_scan_certs_found,
		       created_at, updated_at
		FROM network_scan_targets
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list network scan targets: %w", err)
	}
	defer rows.Close()
	return r.scanRows(rows)
}

// ListEnabled returns only enabled scan targets.
func (r *NetworkScanRepository) ListEnabled(ctx context.Context) ([]*domain.NetworkScanTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, cidrs, ports, enabled, scan_interval_hours, timeout_ms,
		       last_scan_at, last_scan_duration_ms, last_scan_certs_found,
		       created_at, updated_at
		FROM network_scan_targets
		WHERE enabled = TRUE
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list enabled network scan targets: %w", err)
	}
	defer rows.Close()
	return r.scanRows(rows)
}

// Get retrieves a network scan target by ID.
func (r *NetworkScanRepository) Get(ctx context.Context, id string) (*domain.NetworkScanTarget, error) {
	target := &domain.NetworkScanTarget{}
	var lastScanAt sql.NullTime
	var lastScanDurationMs, lastScanCertsFound sql.NullInt64
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, cidrs, ports, enabled, scan_interval_hours, timeout_ms,
		       last_scan_at, last_scan_duration_ms, last_scan_certs_found,
		       created_at, updated_at
		FROM network_scan_targets
		WHERE id = $1`, id).Scan(
		&target.ID, &target.Name, pq.Array(&target.CIDRs), pq.Array(&target.Ports),
		&target.Enabled, &target.ScanIntervalHours, &target.TimeoutMs,
		&lastScanAt, &lastScanDurationMs, &lastScanCertsFound,
		&target.CreatedAt, &target.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("network scan target not found: %w", repository.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get network scan target: %w", err)
	}
	if lastScanAt.Valid {
		target.LastScanAt = &lastScanAt.Time
	}
	if lastScanDurationMs.Valid {
		v := int(lastScanDurationMs.Int64)
		target.LastScanDurationMs = &v
	}
	if lastScanCertsFound.Valid {
		v := int(lastScanCertsFound.Int64)
		target.LastScanCertsFound = &v
	}
	return target, nil
}

// Create stores a new network scan target.
func (r *NetworkScanRepository) Create(ctx context.Context, target *domain.NetworkScanTarget) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO network_scan_targets (id, name, cidrs, ports, enabled, scan_interval_hours, timeout_ms, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		target.ID, target.Name, pq.Array(target.CIDRs), pq.Array(target.Ports),
		target.Enabled, target.ScanIntervalHours, target.TimeoutMs,
		target.CreatedAt, target.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create network scan target: %w", err)
	}
	return nil
}

// Update modifies an existing network scan target.
func (r *NetworkScanRepository) Update(ctx context.Context, target *domain.NetworkScanTarget) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE network_scan_targets
		SET name = $1, cidrs = $2, ports = $3, enabled = $4, scan_interval_hours = $5, timeout_ms = $6, updated_at = $7
		WHERE id = $8`,
		target.Name, pq.Array(target.CIDRs), pq.Array(target.Ports),
		target.Enabled, target.ScanIntervalHours, target.TimeoutMs,
		time.Now(), target.ID,
	)
	if err != nil {
		return fmt.Errorf("update network scan target: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("network scan target not found: %w", repository.ErrNotFound)
	}
	return nil
}

// Delete removes a network scan target.
func (r *NetworkScanRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM network_scan_targets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete network scan target: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("network scan target not found: %w", repository.ErrNotFound)
	}
	return nil
}

// UpdateScanResults records the outcome of the last scan for a target.
func (r *NetworkScanRepository) UpdateScanResults(ctx context.Context, id string, scanAt time.Time, durationMs int, certsFound int) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE network_scan_targets
		SET last_scan_at = $1, last_scan_duration_ms = $2, last_scan_certs_found = $3, updated_at = $4
		WHERE id = $5`,
		scanAt, durationMs, certsFound, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("update scan results: %w", err)
	}
	return nil
}

// scanRows scans multiple rows from a query result.
func (r *NetworkScanRepository) scanRows(rows *sql.Rows) ([]*domain.NetworkScanTarget, error) {
	var targets []*domain.NetworkScanTarget
	for rows.Next() {
		target := &domain.NetworkScanTarget{}
		var lastScanAt sql.NullTime
		var lastScanDurationMs, lastScanCertsFound sql.NullInt64
		if err := rows.Scan(
			&target.ID, &target.Name, pq.Array(&target.CIDRs), pq.Array(&target.Ports),
			&target.Enabled, &target.ScanIntervalHours, &target.TimeoutMs,
			&lastScanAt, &lastScanDurationMs, &lastScanCertsFound,
			&target.CreatedAt, &target.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan network scan target row: %w", err)
		}
		if lastScanAt.Valid {
			target.LastScanAt = &lastScanAt.Time
		}
		if lastScanDurationMs.Valid {
			v := int(lastScanDurationMs.Int64)
			target.LastScanDurationMs = &v
		}
		if lastScanCertsFound.Valid {
			v := int(lastScanCertsFound.Int64)
			target.LastScanCertsFound = &v
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}
