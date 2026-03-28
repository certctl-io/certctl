package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// CertificateRepository implements repository.CertificateRepository
type CertificateRepository struct {
	db *sql.DB
}

// NewCertificateRepository creates a new CertificateRepository
func NewCertificateRepository(db *sql.DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

// List returns a paginated list of certificates matching the filter criteria
func (r *CertificateRepository) List(ctx context.Context, filter *repository.CertificateFilter) ([]*domain.ManagedCertificate, int, error) {
	if filter == nil {
		filter = &repository.CertificateFilter{}
	}

	// Set defaults
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage == 0 || filter.PerPage > 500 {
		filter.PerPage = 50
	}

	// Build WHERE clause
	var whereConditions []string
	var args []interface{}
	argCount := 1

	if filter.Status != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("status = $%d", argCount))
		args = append(args, filter.Status)
		argCount++
	}
	if filter.Environment != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("environment = $%d", argCount))
		args = append(args, filter.Environment)
		argCount++
	}
	if filter.OwnerID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("owner_id = $%d", argCount))
		args = append(args, filter.OwnerID)
		argCount++
	}
	if filter.TeamID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("team_id = $%d", argCount))
		args = append(args, filter.TeamID)
		argCount++
	}
	if filter.IssuerID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("issuer_id = $%d", argCount))
		args = append(args, filter.IssuerID)
		argCount++
	}
	if filter.ProfileID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("certificate_profile_id = $%d", argCount))
		args = append(args, filter.ProfileID)
		argCount++
	}
	if filter.ExpiresBefore != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("expires_at < $%d", argCount))
		args = append(args, filter.ExpiresBefore)
		argCount++
	}
	if filter.ExpiresAfter != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("expires_at > $%d", argCount))
		args = append(args, filter.ExpiresAfter)
		argCount++
	}
	if filter.CreatedAfter != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("created_at > $%d", argCount))
		args = append(args, filter.CreatedAfter)
		argCount++
	}
	if filter.UpdatedAfter != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("updated_at > $%d", argCount))
		args = append(args, filter.UpdatedAfter)
		argCount++
	}
	if filter.AgentID != "" {
		// Filter by agent_id via deployment_targets and certificate_target_mappings
		whereConditions = append(whereConditions, fmt.Sprintf(`id IN (
			SELECT DISTINCT certificate_id FROM certificate_target_mappings ctm
			JOIN deployment_targets dt ON ctm.target_id = dt.id
			WHERE dt.agent_id = $%d
		)`, argCount))
		args = append(args, filter.AgentID)
		argCount++
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Handle cursor-based pagination
	if filter.Cursor != "" {
		createdAt, id, err := decodeCursor(filter.Cursor)
		if err == nil {
			// Add cursor condition: (created_at, id) < (cursor_time, cursor_id)
			whereConditions = append(whereConditions, fmt.Sprintf("(created_at, id) < ($%d, $%d)", argCount, argCount+1))
			args = append(args, createdAt, id)
			argCount += 2
			whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
		}
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM managed_certificates %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count certificates: %w", err)
	}

	// Determine sort field and direction
	sortField := "created_at"
	sortDir := "DESC"
	sortFieldMap := map[string]string{
		"notAfter":    "expires_at",
		"expiresAt":   "expires_at",
		"createdAt":   "created_at",
		"updatedAt":   "updated_at",
		"commonName":  "common_name",
		"name":        "name",
		"status":      "status",
		"environment": "environment",
	}
	if filter.Sort != "" {
		if mappedField, ok := sortFieldMap[filter.Sort]; ok {
			sortField = mappedField
		}
	}
	if filter.SortDesc {
		sortDir = "DESC"
	} else {
		sortDir = "ASC"
	}

	// Get paginated results
	pageSize := filter.PerPage
	if filter.PageSize > 0 && filter.PageSize <= 500 {
		pageSize = filter.PageSize
	}

	var limitClause string
	var offset int
	if filter.Cursor != "" {
		// Cursor-based pagination
		limitClause = fmt.Sprintf("LIMIT $%d", argCount)
		args = append(args, pageSize)
		argCount++
	} else {
		// Page-based pagination
		offset = (filter.Page - 1) * pageSize
		limitClause = fmt.Sprintf("LIMIT $%d OFFSET $%d", argCount, argCount+1)
		args = append(args, pageSize, offset)
		argCount += 2
	}

	query := fmt.Sprintf(`
		SELECT id, name, common_name, sans, environment, owner_id, team_id, issuer_id, renewal_policy_id,
		       certificate_profile_id, status, expires_at, tags, last_renewal_at, last_deployment_at, revoked_at, revocation_reason, created_at, updated_at
		FROM managed_certificates
		%s
		ORDER BY %s %s
		%s
	`, whereClause, sortField, sortDir, limitClause)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()

	var certs []*domain.ManagedCertificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, 0, err
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating certificate rows: %w", err)
	}

	return certs, total, nil
}

// Get retrieves a certificate by ID
func (r *CertificateRepository) Get(ctx context.Context, id string) (*domain.ManagedCertificate, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, common_name, sans, environment, owner_id, team_id, issuer_id, renewal_policy_id,
		       certificate_profile_id, status, expires_at, tags, last_renewal_at, last_deployment_at, revoked_at, revocation_reason, created_at, updated_at
		FROM managed_certificates
		WHERE id = $1
	`, id)

	cert, err := scanCertificate(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("failed to query certificate: %w", err)
	}

	return cert, nil
}

// Create stores a new certificate
func (r *CertificateRepository) Create(ctx context.Context, cert *domain.ManagedCertificate) error {
	if cert.ID == "" {
		cert.ID = uuid.New().String()
	}

	tagsJSON, err := json.Marshal(cert.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	var profileID *string
	if cert.CertificateProfileID != "" {
		profileID = &cert.CertificateProfileID
	}

	var revocationReason *string
	if cert.RevocationReason != "" {
		revocationReason = &cert.RevocationReason
	}

	err = r.db.QueryRowContext(ctx, `
		INSERT INTO managed_certificates (
			id, name, common_name, sans, environment, owner_id, team_id, issuer_id, renewal_policy_id,
			certificate_profile_id, status, expires_at, tags, last_renewal_at, last_deployment_at, revoked_at, revocation_reason, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING id
	`, cert.ID, cert.Name, cert.CommonName, pq.Array(cert.SANs), cert.Environment,
		cert.OwnerID, cert.TeamID, cert.IssuerID, cert.RenewalPolicyID, profileID,
		cert.Status, cert.ExpiresAt,
		tagsJSON, cert.LastRenewalAt, cert.LastDeploymentAt,
		cert.RevokedAt, revocationReason,
		cert.CreatedAt, cert.UpdatedAt).Scan(&cert.ID)

	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	return nil
}

// Update modifies an existing certificate
func (r *CertificateRepository) Update(ctx context.Context, cert *domain.ManagedCertificate) error {
	tagsJSON, err := json.Marshal(cert.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	var profileID *string
	if cert.CertificateProfileID != "" {
		profileID = &cert.CertificateProfileID
	}

	var revocationReason *string
	if cert.RevocationReason != "" {
		revocationReason = &cert.RevocationReason
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE managed_certificates SET
			name = $1,
			common_name = $2,
			sans = $3,
			environment = $4,
			owner_id = $5,
			team_id = $6,
			issuer_id = $7,
			certificate_profile_id = $8,
			status = $9,
			expires_at = $10,
			tags = $11,
			last_renewal_at = $12,
			last_deployment_at = $13,
			revoked_at = $14,
			revocation_reason = $15,
			updated_at = $16
		WHERE id = $17
	`, cert.Name, cert.CommonName, pq.Array(cert.SANs), cert.Environment,
		cert.OwnerID, cert.TeamID, cert.IssuerID, profileID, cert.Status, cert.ExpiresAt,
		tagsJSON, cert.LastRenewalAt, cert.LastDeploymentAt,
		cert.RevokedAt, revocationReason, cert.UpdatedAt, cert.ID)

	if err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("certificate not found")
	}

	return nil
}

// Archive marks a certificate as archived
func (r *CertificateRepository) Archive(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE managed_certificates SET status = $1, updated_at = $2 WHERE id = $3
	`, domain.CertificateStatusArchived, time.Now(), id)

	if err != nil {
		return fmt.Errorf("failed to archive certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("certificate not found")
	}

	return nil
}

// ListVersions returns all versions of a certificate
func (r *CertificateRepository) ListVersions(ctx context.Context, certID string) ([]*domain.CertificateVersion, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, certificate_id, serial_number, not_before, not_after,
		       fingerprint_sha256, pem_chain, csr_pem, key_algorithm, key_size, created_at
		FROM certificate_versions
		WHERE certificate_id = $1
		ORDER BY created_at DESC
	`, certID)

	if err != nil {
		return nil, fmt.Errorf("failed to query certificate versions: %w", err)
	}
	defer rows.Close()

	var versions []*domain.CertificateVersion
	for rows.Next() {
		var v domain.CertificateVersion
		if err := rows.Scan(&v.ID, &v.CertificateID, &v.SerialNumber, &v.NotBefore, &v.NotAfter,
			&v.FingerprintSHA256, &v.PEMChain, &v.CSRPEM, &v.KeyAlgorithm, &v.KeySize, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan certificate version: %w", err)
		}
		versions = append(versions, &v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating version rows: %w", err)
	}

	return versions, nil
}

// CreateVersion stores a new certificate version
func (r *CertificateRepository) CreateVersion(ctx context.Context, version *domain.CertificateVersion) error {
	if version.ID == "" {
		version.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO certificate_versions (
			id, certificate_id, serial_number, not_before, not_after,
			fingerprint_sha256, pem_chain, csr_pem, key_algorithm, key_size, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`, version.ID, version.CertificateID, version.SerialNumber, version.NotBefore, version.NotAfter,
		version.FingerprintSHA256, version.PEMChain, version.CSRPEM, version.KeyAlgorithm, version.KeySize, version.CreatedAt).Scan(&version.ID)

	if err != nil {
		return fmt.Errorf("failed to create certificate version: %w", err)
	}

	return nil
}

// GetExpiringCertificates returns certificates expiring before the given time
func (r *CertificateRepository) GetExpiringCertificates(ctx context.Context, before time.Time) ([]*domain.ManagedCertificate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, common_name, sans, environment, owner_id, team_id, issuer_id, renewal_policy_id,
		       certificate_profile_id, status, expires_at, tags, last_renewal_at, last_deployment_at, revoked_at, revocation_reason, created_at, updated_at
		FROM managed_certificates
		WHERE expires_at < $1 AND status != $2
		ORDER BY expires_at ASC
	`, before, domain.CertificateStatusArchived)

	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
	}
	defer rows.Close()

	var certs []*domain.ManagedCertificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating expiring certificate rows: %w", err)
	}

	return certs, nil
}

// GetLatestVersion returns the most recent certificate version for a certificate.
func (r *CertificateRepository) GetLatestVersion(ctx context.Context, certID string) (*domain.CertificateVersion, error) {
	var v domain.CertificateVersion
	err := r.db.QueryRowContext(ctx, `
		SELECT id, certificate_id, serial_number, not_before, not_after,
		       fingerprint_sha256, pem_chain, csr_pem, key_algorithm, key_size, created_at
		FROM certificate_versions
		WHERE certificate_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`, certID).Scan(&v.ID, &v.CertificateID, &v.SerialNumber, &v.NotBefore, &v.NotAfter,
		&v.FingerprintSHA256, &v.PEMChain, &v.CSRPEM, &v.KeyAlgorithm, &v.KeySize, &v.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to get latest certificate version: %w", err)
	}

	return &v, nil
}

// scanCertificate scans a certificate from a row or rows
func scanCertificate(scanner interface {
	Scan(...interface{}) error
}) (*domain.ManagedCertificate, error) {
	var cert domain.ManagedCertificate
	var tagsJSON []byte
	var sans pq.StringArray
	var profileID sql.NullString
	var revocationReason sql.NullString

	err := scanner.Scan(
		&cert.ID, &cert.Name, &cert.CommonName, &sans, &cert.Environment, &cert.OwnerID,
		&cert.TeamID, &cert.IssuerID, &cert.RenewalPolicyID, &profileID,
		&cert.Status, &cert.ExpiresAt, &tagsJSON,
		&cert.LastRenewalAt, &cert.LastDeploymentAt, &cert.RevokedAt, &revocationReason,
		&cert.CreatedAt, &cert.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to scan certificate: %w", err)
	}

	cert.SANs = []string(sans)
	if profileID.Valid {
		cert.CertificateProfileID = profileID.String
	}
	if revocationReason.Valid {
		cert.RevocationReason = revocationReason.String
	}

	// Unmarshal tags
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &cert.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
	} else {
		cert.Tags = make(map[string]string)
	}

	return &cert, nil
}

// decodeCursor extracts a timestamp and ID from a cursor token.
func decodeCursor(cursor string) (time.Time, string, error) {
	raw, err := base64.URLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid cursor format")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor timestamp: %w", err)
	}
	return t, parts[1], nil
}

// encodeCursor creates an opaque cursor token from a timestamp and ID.
// Reserved for future use in repository-level cursor pagination.
var _ = func(createdAt time.Time, id string) string {
	raw := createdAt.Format(time.RFC3339Nano) + ":" + id
	return base64.URLEncoding.EncodeToString([]byte(raw))
}
