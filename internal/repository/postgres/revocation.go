package postgres

import (
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
func (r *RevocationRepository) Create(ctx context.Context, revocation *domain.CertificateRevocation) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificate_revocations (
			id, certificate_id, serial_number, reason, revoked_by, revoked_at,
			issuer_id, issuer_notified, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (serial_number) DO NOTHING
	`, revocation.ID, revocation.CertificateID, revocation.SerialNumber,
		revocation.Reason, revocation.RevokedBy, revocation.RevokedAt,
		revocation.IssuerID, revocation.IssuerNotified, revocation.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create revocation record: %w", err)
	}

	return nil
}

// GetBySerial retrieves a revocation by serial number.
func (r *RevocationRepository) GetBySerial(ctx context.Context, serial string) (*domain.CertificateRevocation, error) {
	var rev domain.CertificateRevocation
	err := r.db.QueryRowContext(ctx, `
		SELECT id, certificate_id, serial_number, reason, revoked_by, revoked_at,
		       issuer_id, issuer_notified, created_at
		FROM certificate_revocations
		WHERE serial_number = $1
	`, serial).Scan(&rev.ID, &rev.CertificateID, &rev.SerialNumber,
		&rev.Reason, &rev.RevokedBy, &rev.RevokedAt,
		&rev.IssuerID, &rev.IssuerNotified, &rev.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to get revocation by serial: %w", err)
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
		return fmt.Errorf("revocation not found")
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
