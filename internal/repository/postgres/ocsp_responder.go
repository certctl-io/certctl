package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// OCSPResponderRepository implements repository.OCSPResponderRepository.
//
// One row per issuer; rotation is an upsert (no historical rows kept —
// operators have the audit log + the previous CertSerial recorded in
// rotated_from for the most-recent rotation).
type OCSPResponderRepository struct {
	db *sql.DB
}

// NewOCSPResponderRepository creates a new repository.
func NewOCSPResponderRepository(db *sql.DB) *OCSPResponderRepository {
	return &OCSPResponderRepository{db: db}
}

// Compile-time interface check.
var _ repository.OCSPResponderRepository = (*OCSPResponderRepository)(nil)

// Get returns the current responder row, or (nil, nil) when missing.
func (r *OCSPResponderRepository) Get(ctx context.Context, issuerID string) (*domain.OCSPResponder, error) {
	const query = `
		SELECT issuer_id, cert_pem, cert_serial, key_path, key_alg,
		       not_before, not_after, COALESCE(rotated_from, ''),
		       created_at, updated_at
		FROM ocsp_responders
		WHERE issuer_id = $1
	`
	var resp domain.OCSPResponder
	err := r.db.QueryRowContext(ctx, query, issuerID).Scan(
		&resp.IssuerID,
		&resp.CertPEM,
		&resp.CertSerial,
		&resp.KeyPath,
		&resp.KeyAlg,
		&resp.NotBefore,
		&resp.NotAfter,
		&resp.RotatedFrom,
		&resp.CreatedAt,
		&resp.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ocsp_responders get %q: %w", issuerID, err)
	}
	return &resp, nil
}

// Put upserts the responder row. The DB sets created_at on first insert
// (default NOW()) and updated_at on every write (NOW() in the SET clause).
// Callers leave CreatedAt + UpdatedAt zero; the DB authoritative for both.
func (r *OCSPResponderRepository) Put(ctx context.Context, responder *domain.OCSPResponder) error {
	if responder == nil {
		return errors.New("ocsp_responders put: nil responder")
	}
	if responder.IssuerID == "" {
		return errors.New("ocsp_responders put: empty issuer_id")
	}
	const query = `
		INSERT INTO ocsp_responders (
			issuer_id, cert_pem, cert_serial, key_path, key_alg,
			not_before, not_after, rotated_from, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NOW())
		ON CONFLICT (issuer_id) DO UPDATE SET
			cert_pem     = EXCLUDED.cert_pem,
			cert_serial  = EXCLUDED.cert_serial,
			key_path     = EXCLUDED.key_path,
			key_alg      = EXCLUDED.key_alg,
			not_before   = EXCLUDED.not_before,
			not_after    = EXCLUDED.not_after,
			rotated_from = EXCLUDED.rotated_from,
			updated_at   = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		responder.IssuerID,
		responder.CertPEM,
		responder.CertSerial,
		responder.KeyPath,
		responder.KeyAlg,
		responder.NotBefore,
		responder.NotAfter,
		responder.RotatedFrom,
	)
	if err != nil {
		return fmt.Errorf("ocsp_responders put %q: %w", responder.IssuerID, err)
	}
	return nil
}

// ListExpiring returns responders whose not_after is at or before
// (now + grace). Used by the rotation scheduler to find responders due
// for rotation. Ordered by not_after ASC so earliest-expiring is first.
func (r *OCSPResponderRepository) ListExpiring(ctx context.Context, grace time.Duration, now time.Time) ([]*domain.OCSPResponder, error) {
	threshold := now.Add(grace)
	const query = `
		SELECT issuer_id, cert_pem, cert_serial, key_path, key_alg,
		       not_before, not_after, COALESCE(rotated_from, ''),
		       created_at, updated_at
		FROM ocsp_responders
		WHERE not_after <= $1
		ORDER BY not_after ASC
	`
	rows, err := r.db.QueryContext(ctx, query, threshold)
	if err != nil {
		return nil, fmt.Errorf("ocsp_responders list_expiring: %w", err)
	}
	defer rows.Close()

	var out []*domain.OCSPResponder
	for rows.Next() {
		var resp domain.OCSPResponder
		if err := rows.Scan(
			&resp.IssuerID,
			&resp.CertPEM,
			&resp.CertSerial,
			&resp.KeyPath,
			&resp.KeyAlg,
			&resp.NotBefore,
			&resp.NotAfter,
			&resp.RotatedFrom,
			&resp.CreatedAt,
			&resp.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("ocsp_responders list_expiring scan: %w", err)
		}
		out = append(out, &resp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ocsp_responders list_expiring iterate: %w", err)
	}
	return out, nil
}
