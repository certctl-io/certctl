package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// HealthCheckRepository implements repository.HealthCheckRepository using PostgreSQL.
type HealthCheckRepository struct {
	db *sql.DB
}

// NewHealthCheckRepository creates a new PostgreSQL-backed health check repository.
func NewHealthCheckRepository(db *sql.DB) *HealthCheckRepository {
	return &HealthCheckRepository{db: db}
}

// Create stores a new health check.
func (r *HealthCheckRepository) Create(ctx context.Context, check *domain.EndpointHealthCheck) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO endpoint_health_checks (
			id, endpoint, certificate_id, network_scan_target_id,
			expected_fingerprint, observed_fingerprint, status,
			consecutive_failures, response_time_ms, tls_version, cipher_suite,
			cert_subject, cert_issuer, cert_expiry,
			last_checked_at, last_success_at, last_failure_at, last_transition_at,
			failure_reason, degraded_threshold, down_threshold, check_interval_seconds,
			enabled, acknowledged, acknowledged_by, acknowledged_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10, $11,
			$12, $13, $14,
			$15, $16, $17, $18,
			$19, $20, $21, $22,
			$23, $24, $25, $26,
			$27, $28
		)`,
		check.ID, check.Endpoint, check.CertificateID, check.NetworkScanTargetID,
		check.ExpectedFingerprint, check.ObservedFingerprint, string(check.Status),
		check.ConsecutiveFailures, check.ResponseTimeMs, check.TLSVersion, check.CipherSuite,
		check.CertSubject, check.CertIssuer, check.CertExpiry,
		check.LastCheckedAt, check.LastSuccessAt, check.LastFailureAt, check.LastTransitionAt,
		check.FailureReason, check.DegradedThreshold, check.DownThreshold, check.CheckIntervalSecs,
		check.Enabled, check.Acknowledged, check.AcknowledgedBy, check.AcknowledgedAt,
		check.CreatedAt, check.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create health check: %w", err)
	}
	return nil
}

// Update modifies an existing health check.
func (r *HealthCheckRepository) Update(ctx context.Context, check *domain.EndpointHealthCheck) error {
	check.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, `
		UPDATE endpoint_health_checks SET
			endpoint = $2, certificate_id = $3, network_scan_target_id = $4,
			expected_fingerprint = $5, observed_fingerprint = $6, status = $7,
			consecutive_failures = $8, response_time_ms = $9, tls_version = $10, cipher_suite = $11,
			cert_subject = $12, cert_issuer = $13, cert_expiry = $14,
			last_checked_at = $15, last_success_at = $16, last_failure_at = $17, last_transition_at = $18,
			failure_reason = $19, degraded_threshold = $20, down_threshold = $21, check_interval_seconds = $22,
			enabled = $23, acknowledged = $24, acknowledged_by = $25, acknowledged_at = $26,
			updated_at = $27
		WHERE id = $1`,
		check.ID,
		check.Endpoint, check.CertificateID, check.NetworkScanTargetID,
		check.ExpectedFingerprint, check.ObservedFingerprint, string(check.Status),
		check.ConsecutiveFailures, check.ResponseTimeMs, check.TLSVersion, check.CipherSuite,
		check.CertSubject, check.CertIssuer, check.CertExpiry,
		check.LastCheckedAt, check.LastSuccessAt, check.LastFailureAt, check.LastTransitionAt,
		check.FailureReason, check.DegradedThreshold, check.DownThreshold, check.CheckIntervalSecs,
		check.Enabled, check.Acknowledged, check.AcknowledgedBy, check.AcknowledgedAt,
		check.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update health check: %w", err)
	}
	return nil
}

// Get retrieves a health check by ID.
func (r *HealthCheckRepository) Get(ctx context.Context, id string) (*domain.EndpointHealthCheck, error) {
	check := &domain.EndpointHealthCheck{}
	var status string
	var certExpiry, lastCheckedAt, lastSuccessAt, lastFailureAt, lastTransitionAt, acknowledgedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT id, endpoint, certificate_id, network_scan_target_id,
			expected_fingerprint, observed_fingerprint, status,
			consecutive_failures, response_time_ms, tls_version, cipher_suite,
			cert_subject, cert_issuer, cert_expiry,
			last_checked_at, last_success_at, last_failure_at, last_transition_at,
			failure_reason, degraded_threshold, down_threshold, check_interval_seconds,
			enabled, acknowledged, acknowledged_by, acknowledged_at,
			created_at, updated_at
		FROM endpoint_health_checks
		WHERE id = $1`, id).Scan(
		&check.ID, &check.Endpoint, &check.CertificateID, &check.NetworkScanTargetID,
		&check.ExpectedFingerprint, &check.ObservedFingerprint, &status,
		&check.ConsecutiveFailures, &check.ResponseTimeMs, &check.TLSVersion, &check.CipherSuite,
		&check.CertSubject, &check.CertIssuer, &certExpiry,
		&lastCheckedAt, &lastSuccessAt, &lastFailureAt, &lastTransitionAt,
		&check.FailureReason, &check.DegradedThreshold, &check.DownThreshold, &check.CheckIntervalSecs,
		&check.Enabled, &check.Acknowledged, &check.AcknowledgedBy, &acknowledgedAt,
		&check.CreatedAt, &check.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("health check not found: %w", repository.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get health check: %w", err)
	}
	check.Status = domain.HealthStatus(status)
	if certExpiry.Valid {
		check.CertExpiry = &certExpiry.Time
	}
	if lastCheckedAt.Valid {
		check.LastCheckedAt = &lastCheckedAt.Time
	}
	if lastSuccessAt.Valid {
		check.LastSuccessAt = &lastSuccessAt.Time
	}
	if lastFailureAt.Valid {
		check.LastFailureAt = &lastFailureAt.Time
	}
	if lastTransitionAt.Valid {
		check.LastTransitionAt = &lastTransitionAt.Time
	}
	if acknowledgedAt.Valid {
		check.AcknowledgedAt = &acknowledgedAt.Time
	}
	return check, nil
}

// Delete removes a health check.
func (r *HealthCheckRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM endpoint_health_checks WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete health check: %w", err)
	}
	return nil
}

// List returns health checks matching the filter with pagination.
func (r *HealthCheckRepository) List(ctx context.Context, filter *repository.HealthCheckFilter) ([]*domain.EndpointHealthCheck, int, error) {
	query := `SELECT id, endpoint, certificate_id, network_scan_target_id,
		expected_fingerprint, observed_fingerprint, status,
		consecutive_failures, response_time_ms, tls_version, cipher_suite,
		cert_subject, cert_issuer, cert_expiry,
		last_checked_at, last_success_at, last_failure_at, last_transition_at,
		failure_reason, degraded_threshold, down_threshold, check_interval_seconds,
		enabled, acknowledged, acknowledged_by, acknowledged_at,
		created_at, updated_at
	FROM endpoint_health_checks`
	countQuery := `SELECT COUNT(*) FROM endpoint_health_checks`

	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter != nil {
		if filter.Status != "" {
			conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
			args = append(args, filter.Status)
			argIdx++
		}
		if filter.CertificateID != "" {
			conditions = append(conditions, fmt.Sprintf("certificate_id = $%d", argIdx))
			args = append(args, filter.CertificateID)
			argIdx++
		}
		if filter.NetworkScanTargetID != "" {
			conditions = append(conditions, fmt.Sprintf("network_scan_target_id = $%d", argIdx))
			args = append(args, filter.NetworkScanTargetID)
			argIdx++
		}
		if filter.Enabled != nil {
			conditions = append(conditions, fmt.Sprintf("enabled = $%d", argIdx))
			args = append(args, *filter.Enabled)
			argIdx++
		}
	}

	if len(conditions) > 0 {
		where := " WHERE " + conditions[0]
		for i := 1; i < len(conditions); i++ {
			where += " AND " + conditions[i]
		}
		query += where
		countQuery += where
	}

	// Get total count
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count health checks: %w", err)
	}

	// Apply pagination
	query += " ORDER BY created_at DESC"
	page := 1
	perPage := 50
	if filter != nil {
		if filter.Page > 0 {
			page = filter.Page
		}
		if filter.PerPage > 0 {
			perPage = filter.PerPage
		}
	}
	offset := (page - 1) * perPage
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, perPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list health checks: %w", err)
	}
	defer rows.Close()

	var checks []*domain.EndpointHealthCheck
	for rows.Next() {
		check, err := scanHealthCheck(rows)
		if err != nil {
			return nil, 0, err
		}
		checks = append(checks, check)
	}
	return checks, total, rows.Err()
}

// ListDueForCheck returns health checks where the check interval has been exceeded.
func (r *HealthCheckRepository) ListDueForCheck(ctx context.Context) ([]*domain.EndpointHealthCheck, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, endpoint, certificate_id, network_scan_target_id,
			expected_fingerprint, observed_fingerprint, status,
			consecutive_failures, response_time_ms, tls_version, cipher_suite,
			cert_subject, cert_issuer, cert_expiry,
			last_checked_at, last_success_at, last_failure_at, last_transition_at,
			failure_reason, degraded_threshold, down_threshold, check_interval_seconds,
			enabled, acknowledged, acknowledged_by, acknowledged_at,
			created_at, updated_at
		FROM endpoint_health_checks
		WHERE enabled = TRUE
		AND (
			last_checked_at IS NULL
			OR last_checked_at + (check_interval_seconds * INTERVAL '1 second') < NOW()
		)
		ORDER BY last_checked_at ASC NULLS FIRST`)
	if err != nil {
		return nil, fmt.Errorf("list due health checks: %w", err)
	}
	defer rows.Close()

	var checks []*domain.EndpointHealthCheck
	for rows.Next() {
		check, err := scanHealthCheck(rows)
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}
	return checks, rows.Err()
}

// GetByEndpoint retrieves a health check by endpoint address.
func (r *HealthCheckRepository) GetByEndpoint(ctx context.Context, endpoint string) (*domain.EndpointHealthCheck, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, endpoint, certificate_id, network_scan_target_id,
			expected_fingerprint, observed_fingerprint, status,
			consecutive_failures, response_time_ms, tls_version, cipher_suite,
			cert_subject, cert_issuer, cert_expiry,
			last_checked_at, last_success_at, last_failure_at, last_transition_at,
			failure_reason, degraded_threshold, down_threshold, check_interval_seconds,
			enabled, acknowledged, acknowledged_by, acknowledged_at,
			created_at, updated_at
		FROM endpoint_health_checks
		WHERE endpoint = $1`, endpoint)
	check := &domain.EndpointHealthCheck{}
	var status string
	var certExpiry, lastCheckedAt, lastSuccessAt, lastFailureAt, lastTransitionAt, acknowledgedAt sql.NullTime
	err := row.Scan(
		&check.ID, &check.Endpoint, &check.CertificateID, &check.NetworkScanTargetID,
		&check.ExpectedFingerprint, &check.ObservedFingerprint, &status,
		&check.ConsecutiveFailures, &check.ResponseTimeMs, &check.TLSVersion, &check.CipherSuite,
		&check.CertSubject, &check.CertIssuer, &certExpiry,
		&lastCheckedAt, &lastSuccessAt, &lastFailureAt, &lastTransitionAt,
		&check.FailureReason, &check.DegradedThreshold, &check.DownThreshold, &check.CheckIntervalSecs,
		&check.Enabled, &check.Acknowledged, &check.AcknowledgedBy, &acknowledgedAt,
		&check.CreatedAt, &check.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("health check not found for endpoint: %w", repository.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get health check by endpoint: %w", err)
	}
	check.Status = domain.HealthStatus(status)
	if certExpiry.Valid {
		check.CertExpiry = &certExpiry.Time
	}
	if lastCheckedAt.Valid {
		check.LastCheckedAt = &lastCheckedAt.Time
	}
	if lastSuccessAt.Valid {
		check.LastSuccessAt = &lastSuccessAt.Time
	}
	if lastFailureAt.Valid {
		check.LastFailureAt = &lastFailureAt.Time
	}
	if lastTransitionAt.Valid {
		check.LastTransitionAt = &lastTransitionAt.Time
	}
	if acknowledgedAt.Valid {
		check.AcknowledgedAt = &acknowledgedAt.Time
	}
	return check, nil
}

// RecordHistory records a single probe result in history.
func (r *HealthCheckRepository) RecordHistory(ctx context.Context, entry *domain.HealthHistoryEntry) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO endpoint_health_history (id, health_check_id, status, response_time_ms, fingerprint, failure_reason, checked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.ID, entry.HealthCheckID, entry.Status, entry.ResponseTimeMs, entry.Fingerprint, entry.FailureReason, entry.CheckedAt,
	)
	if err != nil {
		return fmt.Errorf("record health check history: %w", err)
	}
	return nil
}

// GetHistory retrieves recent probe history for a health check.
func (r *HealthCheckRepository) GetHistory(ctx context.Context, healthCheckID string, limit int) ([]*domain.HealthHistoryEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, health_check_id, status, response_time_ms, fingerprint, failure_reason, checked_at
		FROM endpoint_health_history
		WHERE health_check_id = $1
		ORDER BY checked_at DESC
		LIMIT $2`, healthCheckID, limit)
	if err != nil {
		return nil, fmt.Errorf("get health check history: %w", err)
	}
	defer rows.Close()

	var entries []*domain.HealthHistoryEntry
	for rows.Next() {
		entry := &domain.HealthHistoryEntry{}
		if err := rows.Scan(&entry.ID, &entry.HealthCheckID, &entry.Status, &entry.ResponseTimeMs, &entry.Fingerprint, &entry.FailureReason, &entry.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan health history entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// PurgeHistory deletes history entries older than the specified time.
func (r *HealthCheckRepository) PurgeHistory(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM endpoint_health_history WHERE checked_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("purge health check history: %w", err)
	}
	return result.RowsAffected()
}

// GetSummary returns aggregate counts by health status.
func (r *HealthCheckRepository) GetSummary(ctx context.Context) (*domain.HealthCheckSummary, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM endpoint_health_checks GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("get health check summary: %w", err)
	}
	defer rows.Close()

	summary := &domain.HealthCheckSummary{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scan health check summary: %w", err)
		}
		switch domain.HealthStatus(status) {
		case domain.HealthStatusHealthy:
			summary.Healthy = count
		case domain.HealthStatusDegraded:
			summary.Degraded = count
		case domain.HealthStatusDown:
			summary.Down = count
		case domain.HealthStatusCertMismatch:
			summary.CertMismatch = count
		case domain.HealthStatusUnknown:
			summary.Unknown = count
		}
		summary.Total += count
	}
	return summary, rows.Err()
}

// scannable is an interface satisfied by both *sql.Row and *sql.Rows.
type scannable interface {
	Scan(dest ...interface{}) error
}

// scanHealthCheck scans a health check from a row.
func scanHealthCheck(row scannable) (*domain.EndpointHealthCheck, error) {
	check := &domain.EndpointHealthCheck{}
	var status string
	var certExpiry, lastCheckedAt, lastSuccessAt, lastFailureAt, lastTransitionAt, acknowledgedAt sql.NullTime
	err := row.Scan(
		&check.ID, &check.Endpoint, &check.CertificateID, &check.NetworkScanTargetID,
		&check.ExpectedFingerprint, &check.ObservedFingerprint, &status,
		&check.ConsecutiveFailures, &check.ResponseTimeMs, &check.TLSVersion, &check.CipherSuite,
		&check.CertSubject, &check.CertIssuer, &certExpiry,
		&lastCheckedAt, &lastSuccessAt, &lastFailureAt, &lastTransitionAt,
		&check.FailureReason, &check.DegradedThreshold, &check.DownThreshold, &check.CheckIntervalSecs,
		&check.Enabled, &check.Acknowledged, &check.AcknowledgedBy, &acknowledgedAt,
		&check.CreatedAt, &check.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan health check: %w", err)
	}
	check.Status = domain.HealthStatus(status)
	if certExpiry.Valid {
		check.CertExpiry = &certExpiry.Time
	}
	if lastCheckedAt.Valid {
		check.LastCheckedAt = &lastCheckedAt.Time
	}
	if lastSuccessAt.Valid {
		check.LastSuccessAt = &lastSuccessAt.Time
	}
	if lastFailureAt.Valid {
		check.LastFailureAt = &lastFailureAt.Time
	}
	if lastTransitionAt.Valid {
		check.LastTransitionAt = &lastTransitionAt.Time
	}
	if acknowledgedAt.Valid {
		check.AcknowledgedAt = &acknowledgedAt.Time
	}
	return check, nil
}
