package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// OCSPResponseCacheRepository implements repository.OCSPResponseCacheRepository
// using PostgreSQL.
//
// Schema: see migrations/000024_ocsp_response_cache.up.sql. The cache
// stores one row per (issuer_id, serial_hex) — the composite primary
// key collapses upserts to ON CONFLICT DO UPDATE. The response DER
// blob lives in BYTEA — typical sizes are a few hundred bytes for a
// single-cert response (one OCSP response wraps one cert; a request
// for cert+chain typically issues separate responses).
//
// Production hardening II Phase 2.
type OCSPResponseCacheRepository struct {
	db *sql.DB
}

// NewOCSPResponseCacheRepository creates a new repository.
func NewOCSPResponseCacheRepository(db *sql.DB) *OCSPResponseCacheRepository {
	return &OCSPResponseCacheRepository{db: db}
}

// Compile-time interface check.
var _ repository.OCSPResponseCacheRepository = (*OCSPResponseCacheRepository)(nil)

// Get returns the cached OCSP response for (issuer, serial). Returns
// (nil, nil) on miss so the caller can fall through to live signing
// + a write-back via Put (read-through pattern).
func (r *OCSPResponseCacheRepository) Get(ctx context.Context, issuerID, serialHex string) (*domain.OCSPResponseCacheEntry, error) {
	const query = `
		SELECT issuer_id, serial_hex, response_der, cert_status,
		       COALESCE(revocation_reason, 0), COALESCE(revoked_at, '0001-01-01 00:00:00 UTC'::timestamptz),
		       this_update, next_update, generated_at
		FROM ocsp_response_cache
		WHERE issuer_id = $1 AND serial_hex = $2`
	var e domain.OCSPResponseCacheEntry
	err := r.db.QueryRowContext(ctx, query, issuerID, serialHex).Scan(
		&e.IssuerID, &e.SerialHex, &e.ResponseDER, &e.CertStatus,
		&e.RevocationReason, &e.RevokedAt,
		&e.ThisUpdate, &e.NextUpdate, &e.GeneratedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("OCSPResponseCacheRepository.Get: %w", err)
	}
	return &e, nil
}

// Put upserts the cache row for (issuer, serial). The composite PK
// collapses repeat-writes to ON CONFLICT DO UPDATE (matches the
// crl_cache pattern in 000019).
func (r *OCSPResponseCacheRepository) Put(ctx context.Context, e *domain.OCSPResponseCacheEntry) error {
	const stmt = `
		INSERT INTO ocsp_response_cache (
			issuer_id, serial_hex, response_der, cert_status,
			revocation_reason, revoked_at,
			this_update, next_update, generated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (issuer_id, serial_hex) DO UPDATE SET
			response_der      = EXCLUDED.response_der,
			cert_status       = EXCLUDED.cert_status,
			revocation_reason = EXCLUDED.revocation_reason,
			revoked_at        = EXCLUDED.revoked_at,
			this_update       = EXCLUDED.this_update,
			next_update       = EXCLUDED.next_update,
			generated_at      = EXCLUDED.generated_at`

	// Convert the domain's zero-time RevokedAt to nullable for the SQL
	// row when CertStatus != "revoked" — the cert_status discriminator
	// is the source of truth, but keeping the nullable columns nullable
	// in storage is friendlier for ad-hoc queries.
	var revokedAt interface{}
	var revocationReason interface{}
	if e.CertStatus == "revoked" {
		revokedAt = e.RevokedAt
		revocationReason = e.RevocationReason
	}

	_, err := r.db.ExecContext(ctx, stmt,
		e.IssuerID, e.SerialHex, e.ResponseDER, e.CertStatus,
		revocationReason, revokedAt,
		e.ThisUpdate, e.NextUpdate, e.GeneratedAt)
	if err != nil {
		return fmt.Errorf("OCSPResponseCacheRepository.Put: %w", err)
	}
	return nil
}

// Delete removes a single (issuer, serial) entry. Used by
// InvalidateOnRevoke when the revocation service wants the cache to
// re-sign on the next request rather than carry stale data.
func (r *OCSPResponseCacheRepository) Delete(ctx context.Context, issuerID, serialHex string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM ocsp_response_cache WHERE issuer_id = $1 AND serial_hex = $2`,
		issuerID, serialHex)
	if err != nil {
		return fmt.Errorf("OCSPResponseCacheRepository.Delete: %w", err)
	}
	return nil
}

// CountByIssuer returns the count of cached entries per issuer.
// Backs the admin observability endpoint at /api/v1/admin/ocsp/cache.
func (r *OCSPResponseCacheRepository) CountByIssuer(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT issuer_id, COUNT(*) FROM ocsp_response_cache GROUP BY issuer_id`)
	if err != nil {
		return nil, fmt.Errorf("OCSPResponseCacheRepository.CountByIssuer: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var issuerID string
		var n int
		if err := rows.Scan(&issuerID, &n); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out[issuerID] = n
	}
	return out, rows.Err()
}
