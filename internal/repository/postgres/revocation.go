package postgres

import (
	"github.com/shankar0123/certctl/internal/repository"
	"context"
	"database/sql"
	"fmt"

	"github.com/shankar0123/certctl/internal/domain"
)

// RevocationRepository implements repository.RevocationRepository using PostgreSQL.
type RevocationRepository struct {
	db *sql.DB
}

// NewRevocationRepository creates a new RevocationRepository.
func NewRevocationRepository(db *sql.DB) *RevocationRepository {
	return &RevocationRepository{db: db}
}

// Create records a new certificate revocation.
//
// Uniqueness is scoped to (issuer_id, serial_number) per RFC 5280 §5.2.3.
// Serial numbers are only unique within an issuer, so certctl supports
// collisions across different issuer connectors. The composite ON CONFLICT
// target matches migration 000012's unique index.
func (r *RevocationRepository) Create(ctx context.Context, revocation *domain.CertificateRevocation) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificate_revocations (
			id, certificate_id, serial_number, reason, revoked_by, revoked_at,
			issuer_id, issuer_notified, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (issuer_id, serial_number) DO NOTHING
	`, revocation.ID, revocation.CertificateID, revocation.SerialNumber,
		revocation.Reason, revocation.RevokedBy, revocation.RevokedAt,
		revocation.IssuerID, revocation.IssuerNotified, revocation.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create revocation record: %w", err)
	}

	return nil
}

// GetByIssuerAndSerial retrieves a revocation by the (issuer_id, serial) pair.
//
// Per RFC 5280 §5.2.3, serial numbers are unique only within a single issuer.
// Callers (OCSP handlers, CRL generation) always know the issuer because the
// OCSP URL carries it as a path parameter and CRLs are generated per-issuer.
func (r *RevocationRepository) GetByIssuerAndSerial(ctx context.Context, issuerID, serial string) (*domain.CertificateRevocation, error) {
	var rev domain.CertificateRevocation
	err := r.db.QueryRowContext(ctx, `
		SELECT id, certificate_id, serial_number, reason, revoked_by, revoked_at,
		       issuer_id, issuer_notified, created_at
		FROM certificate_revocations
		WHERE issuer_id = $1 AND serial_number = $2
	`, issuerID, serial).Scan(&rev.ID, &rev.CertificateID, &rev.SerialNumber,
		&rev.Reason, &rev.RevokedBy, &rev.RevokedAt,
		&rev.IssuerID, &rev.IssuerNotified, &rev.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to get revocation by issuer and serial: %w", err)
	}

	return &rev, nil
}

// ListAll returns all revocations ordered by revocation time (for CRL generation).
func (r *RevocationRepository) ListAll(ctx context.Context) ([]*domain.CertificateRevocation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, certificate_id, serial_number, reason, revoked_by, revoked_at,
		       issuer_id, issuer_notified, created_at
		FROM certificate_revocations
		ORDER BY revoked_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list revocations: %w", err)
	}
	defer rows.Close()

	return scanRevocations(rows)
}

// ListByIssuer returns all revocations for a single issuer, ordered by revocation time.
//
// This is the hot path for CRL generation. Pushing the issuer filter into the
// SQL query lets the composite index `idx_certificate_revocations_issuer_serial`
// (migration 000012) drive a prefix scan on issuer_id rather than forcing
// callers to load every row in the table and discard the ones belonging to
// other issuers.
func (r *RevocationRepository) ListByIssuer(ctx context.Context, issuerID string) ([]*domain.CertificateRevocation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, certificate_id, serial_number, reason, revoked_by, revoked_at,
		       issuer_id, issuer_notified, created_at
		FROM certificate_revocations
		WHERE issuer_id = $1
		ORDER BY revoked_at ASC
	`, issuerID)
	if err != nil {
		return nil, fmt.Errorf("failed to list revocations by issuer: %w", err)
	}
	defer rows.Close()

	return scanRevocations(rows)
}

// ListByCertificate returns all revocations for a certificate.
func (r *RevocationRepository) ListByCertificate(ctx context.Context, certID string) ([]*domain.CertificateRevocation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, certificate_id, serial_number, reason, revoked_by, revoked_at,
		       issuer_id, issuer_notified, created_at
		FROM certificate_revocations
		WHERE certificate_id = $1
		ORDER BY revoked_at ASC
	`, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to list revocations by certificate: %w", err)
	}
	defer rows.Close()

	return scanRevocations(rows)
}

// MarkIssuerNotified updates the issuer_notified flag for a revocation.
func (r *RevocationRepository) MarkIssuerNotified(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE certificate_revocations SET issuer_notified = TRUE WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("failed to mark issuer notified: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("revocation not found: %w", repository.ErrNotFound)
	}

	return nil
}

func scanRevocations(rows *sql.Rows) ([]*domain.CertificateRevocation, error) {
	var revocations []*domain.CertificateRevocation
	for rows.Next() {
		var rev domain.CertificateRevocation
		if err := rows.Scan(&rev.ID, &rev.CertificateID, &rev.SerialNumber,
			&rev.Reason, &rev.RevokedBy, &rev.RevokedAt,
			&rev.IssuerID, &rev.IssuerNotified, &rev.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan revocation: %w", err)
		}
		revocations = append(revocations, &rev)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating revocation rows: %w", err)
	}

	return revocations, nil
}
