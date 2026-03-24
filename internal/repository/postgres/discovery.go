package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// DiscoveryRepository implements the repository.DiscoveryRepository interface.
type DiscoveryRepository struct {
	db *sql.DB
}

// NewDiscoveryRepository creates a new PostgreSQL-backed discovery repository.
func NewDiscoveryRepository(db *sql.DB) *DiscoveryRepository {
	return &DiscoveryRepository{db: db}
}

// --- Discovery Scans ---

// CreateScan stores a new discovery scan record.
func (r *DiscoveryRepository) CreateScan(ctx context.Context, scan *domain.DiscoveryScan) error {
	query := `
		INSERT INTO discovery_scans (id, agent_id, directories, certificates_found, certificates_new, errors_count, scan_duration_ms, started_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING`

	_, err := r.db.ExecContext(ctx, query,
		scan.ID,
		scan.AgentID,
		pq.Array(scan.Directories),
		scan.CertificatesFound,
		scan.CertificatesNew,
		scan.ErrorsCount,
		scan.ScanDurationMs,
		scan.StartedAt,
		scan.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create discovery scan: %w", err)
	}
	return nil
}

// GetScan retrieves a discovery scan by ID.
func (r *DiscoveryRepository) GetScan(ctx context.Context, id string) (*domain.DiscoveryScan, error) {
	query := `
		SELECT id, agent_id, directories, certificates_found, certificates_new, errors_count, scan_duration_ms, started_at, completed_at
		FROM discovery_scans WHERE id = $1`

	scan := &domain.DiscoveryScan{}
	var dirs []string
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&scan.ID, &scan.AgentID, pq.Array(&dirs),
		&scan.CertificatesFound, &scan.CertificatesNew, &scan.ErrorsCount,
		&scan.ScanDurationMs, &scan.StartedAt, &scan.CompletedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("discovery scan not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get discovery scan: %w", err)
	}
	scan.Directories = dirs
	return scan, nil
}

// ListScans returns discovery scans, optionally filtered by agent ID.
func (r *DiscoveryRepository) ListScans(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage <= 0 || perPage > 500 {
		perPage = 50
	}

	var whereConditions []string
	var args []interface{}
	argCount := 1

	if agentID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("agent_id = $%d", argCount))
		args = append(args, agentID)
		argCount++
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM discovery_scans %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count discovery scans: %w", err)
	}

	// List
	offset := (page - 1) * perPage
	listQuery := fmt.Sprintf(`
		SELECT id, agent_id, directories, certificates_found, certificates_new, errors_count, scan_duration_ms, started_at, completed_at
		FROM discovery_scans %s
		ORDER BY started_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argCount, argCount+1)

	args = append(args, perPage, offset)
	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list discovery scans: %w", err)
	}
	defer rows.Close()

	var scans []*domain.DiscoveryScan
	for rows.Next() {
		scan := &domain.DiscoveryScan{}
		var dirs []string
		if err := rows.Scan(
			&scan.ID, &scan.AgentID, pq.Array(&dirs),
			&scan.CertificatesFound, &scan.CertificatesNew, &scan.ErrorsCount,
			&scan.ScanDurationMs, &scan.StartedAt, &scan.CompletedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan discovery scan row: %w", err)
		}
		scan.Directories = dirs
		scans = append(scans, scan)
	}
	return scans, total, nil
}

// --- Discovered Certificates ---

// CreateDiscovered stores a new discovered certificate.
// Uses ON CONFLICT to update last_seen_at for existing fingerprint+agent+path combos.
func (r *DiscoveryRepository) CreateDiscovered(ctx context.Context, cert *domain.DiscoveredCertificate) (bool, error) {
	query := `
		INSERT INTO discovered_certificates (
			id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn, subject_dn,
			not_before, not_after, key_algorithm, key_size, is_ca, pem_data,
			source_path, source_format, agent_id, discovery_scan_id,
			status, first_seen_at, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
		ON CONFLICT (fingerprint_sha256, agent_id, source_path) DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			discovery_scan_id = EXCLUDED.discovery_scan_id,
			updated_at = NOW()
		RETURNING (xmax = 0) AS is_new`

	var isNew bool
	err := r.db.QueryRowContext(ctx, query,
		cert.ID, cert.FingerprintSHA256, cert.CommonName, pq.Array(cert.SANs),
		cert.SerialNumber, cert.IssuerDN, cert.SubjectDN,
		cert.NotBefore, cert.NotAfter, cert.KeyAlgorithm, cert.KeySize, cert.IsCA,
		cert.PEMData, cert.SourcePath, cert.SourceFormat,
		cert.AgentID, nullableString(cert.DiscoveryScanID),
		string(cert.Status), cert.FirstSeenAt, cert.LastSeenAt,
		cert.CreatedAt, cert.UpdatedAt,
	).Scan(&isNew)
	if err != nil {
		return false, fmt.Errorf("failed to upsert discovered certificate: %w", err)
	}
	return isNew, nil
}

// GetDiscovered retrieves a discovered certificate by ID.
func (r *DiscoveryRepository) GetDiscovered(ctx context.Context, id string) (*domain.DiscoveredCertificate, error) {
	query := `
		SELECT id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn, subject_dn,
			not_before, not_after, key_algorithm, key_size, is_ca, pem_data,
			source_path, source_format, agent_id, discovery_scan_id, managed_certificate_id,
			status, first_seen_at, last_seen_at, dismissed_at, created_at, updated_at
		FROM discovered_certificates WHERE id = $1`

	cert := &domain.DiscoveredCertificate{}
	var sans []string
	var scanID, managedID sql.NullString
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, pq.Array(&sans),
		&cert.SerialNumber, &cert.IssuerDN, &cert.SubjectDN,
		&cert.NotBefore, &cert.NotAfter, &cert.KeyAlgorithm, &cert.KeySize, &cert.IsCA,
		&cert.PEMData, &cert.SourcePath, &cert.SourceFormat,
		&cert.AgentID, &scanID, &managedID,
		&cert.Status, &cert.FirstSeenAt, &cert.LastSeenAt, &cert.DismissedAt,
		&cert.CreatedAt, &cert.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("discovered certificate not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get discovered certificate: %w", err)
	}
	cert.SANs = sans
	if scanID.Valid {
		cert.DiscoveryScanID = scanID.String
	}
	if managedID.Valid {
		cert.ManagedCertificateID = managedID.String
	}
	return cert, nil
}

// ListDiscovered returns discovered certificates matching the filter.
func (r *DiscoveryRepository) ListDiscovered(ctx context.Context, filter *repository.DiscoveryFilter) ([]*domain.DiscoveredCertificate, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage <= 0 || filter.PerPage > 500 {
		filter.PerPage = 50
	}

	var whereConditions []string
	var args []interface{}
	argCount := 1

	if filter.AgentID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("agent_id = $%d", argCount))
		args = append(args, filter.AgentID)
		argCount++
	}
	if filter.Status != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("status = $%d", argCount))
		args = append(args, filter.Status)
		argCount++
	}
	if filter.IsExpired {
		whereConditions = append(whereConditions, "not_after < NOW()")
	}
	if filter.IsCA {
		whereConditions = append(whereConditions, "is_ca = TRUE")
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM discovered_certificates %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count discovered certificates: %w", err)
	}

	// List
	offset := (filter.Page - 1) * filter.PerPage
	listQuery := fmt.Sprintf(`
		SELECT id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn, subject_dn,
			not_before, not_after, key_algorithm, key_size, is_ca, pem_data,
			source_path, source_format, agent_id, discovery_scan_id, managed_certificate_id,
			status, first_seen_at, last_seen_at, dismissed_at, created_at, updated_at
		FROM discovered_certificates %s
		ORDER BY last_seen_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argCount, argCount+1)

	args = append(args, filter.PerPage, offset)
	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list discovered certificates: %w", err)
	}
	defer rows.Close()

	var certs []*domain.DiscoveredCertificate
	for rows.Next() {
		cert := &domain.DiscoveredCertificate{}
		var sans []string
		var scanID, managedID sql.NullString
		if err := rows.Scan(
			&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, pq.Array(&sans),
			&cert.SerialNumber, &cert.IssuerDN, &cert.SubjectDN,
			&cert.NotBefore, &cert.NotAfter, &cert.KeyAlgorithm, &cert.KeySize, &cert.IsCA,
			&cert.PEMData, &cert.SourcePath, &cert.SourceFormat,
			&cert.AgentID, &scanID, &managedID,
			&cert.Status, &cert.FirstSeenAt, &cert.LastSeenAt, &cert.DismissedAt,
			&cert.CreatedAt, &cert.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan discovered certificate row: %w", err)
		}
		cert.SANs = sans
		if scanID.Valid {
			cert.DiscoveryScanID = scanID.String
		}
		if managedID.Valid {
			cert.ManagedCertificateID = managedID.String
		}
		certs = append(certs, cert)
	}
	return certs, total, nil
}

// UpdateDiscoveredStatus updates the status and optional managed certificate link.
func (r *DiscoveryRepository) UpdateDiscoveredStatus(ctx context.Context, id string, status domain.DiscoveryStatus, managedCertID string) error {
	var query string
	var args []interface{}

	now := time.Now()
	switch status {
	case domain.DiscoveryStatusManaged:
		query = `UPDATE discovered_certificates SET status = $1, managed_certificate_id = $2, updated_at = $3 WHERE id = $4`
		args = []interface{}{string(status), managedCertID, now, id}
	case domain.DiscoveryStatusDismissed:
		query = `UPDATE discovered_certificates SET status = $1, dismissed_at = $2, updated_at = $3 WHERE id = $4`
		args = []interface{}{string(status), now, now, id}
	default:
		query = `UPDATE discovered_certificates SET status = $1, managed_certificate_id = NULL, dismissed_at = NULL, updated_at = $2 WHERE id = $3`
		args = []interface{}{string(status), now, id}
	}

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update discovered certificate status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("discovered certificate not found: %s", id)
	}
	return nil
}

// GetByFingerprint retrieves discovered certificates by SHA-256 fingerprint.
func (r *DiscoveryRepository) GetByFingerprint(ctx context.Context, fingerprint string) ([]*domain.DiscoveredCertificate, error) {
	query := `
		SELECT id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn, subject_dn,
			not_before, not_after, key_algorithm, key_size, is_ca, '',
			source_path, source_format, agent_id, discovery_scan_id, managed_certificate_id,
			status, first_seen_at, last_seen_at, dismissed_at, created_at, updated_at
		FROM discovered_certificates WHERE fingerprint_sha256 = $1
		ORDER BY last_seen_at DESC`

	rows, err := r.db.QueryContext(ctx, query, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get by fingerprint: %w", err)
	}
	defer rows.Close()

	var certs []*domain.DiscoveredCertificate
	for rows.Next() {
		cert := &domain.DiscoveredCertificate{}
		var sans []string
		var scanID, managedID sql.NullString
		if err := rows.Scan(
			&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, pq.Array(&sans),
			&cert.SerialNumber, &cert.IssuerDN, &cert.SubjectDN,
			&cert.NotBefore, &cert.NotAfter, &cert.KeyAlgorithm, &cert.KeySize, &cert.IsCA,
			&cert.PEMData, &cert.SourcePath, &cert.SourceFormat,
			&cert.AgentID, &scanID, &managedID,
			&cert.Status, &cert.FirstSeenAt, &cert.LastSeenAt, &cert.DismissedAt,
			&cert.CreatedAt, &cert.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		cert.SANs = sans
		if scanID.Valid {
			cert.DiscoveryScanID = scanID.String
		}
		if managedID.Valid {
			cert.ManagedCertificateID = managedID.String
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// CountByStatus returns counts of discovered certificates grouped by status.
func (r *DiscoveryRepository) CountByStatus(ctx context.Context) (map[string]int, error) {
	query := `SELECT status, COUNT(*) FROM discovered_certificates GROUP BY status`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to count by status: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		counts[status] = count
	}
	return counts, nil
}

// nullableString returns a sql.NullString, null if the string is empty.
func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
