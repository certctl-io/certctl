package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/lib/pq"
)

// SCEPProbeResultRepository is the PostgreSQL-backed implementation of
// repository.SCEPProbeResultRepository.
//
// SCEP RFC 8894 + Intune master bundle Phase 11.5. Each row is one
// completed probe run; the table accumulates history (no in-place
// updates) so the GUI can show "recent probes" without losing the prior
// snapshot's CA cert metadata.
type SCEPProbeResultRepository struct {
	db *sql.DB
}

// NewSCEPProbeResultRepository creates a new Postgres-backed repo.
func NewSCEPProbeResultRepository(db *sql.DB) *SCEPProbeResultRepository {
	return &SCEPProbeResultRepository{db: db}
}

// Insert persists a single probe result.
func (r *SCEPProbeResultRepository) Insert(ctx context.Context, result *domain.SCEPProbeResult) error {
	if result == nil {
		return fmt.Errorf("scep probe result: nil")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scep_probe_results (
			id, target_url, reachable,
			advertised_caps, supports_rfc8894, supports_aes,
			supports_post_operation, supports_renewal,
			supports_sha256, supports_sha512,
			ca_cert_subject, ca_cert_issuer,
			ca_cert_not_before, ca_cert_not_after, ca_cert_expired,
			ca_cert_algorithm, ca_cert_chain_length,
			probed_at, probe_duration_ms, error
		) VALUES (
			$1, $2, $3,
			$4, $5, $6,
			$7, $8,
			$9, $10,
			$11, $12,
			$13, $14, $15,
			$16, $17,
			$18, $19, $20
		)`,
		result.ID, result.TargetURL, result.Reachable,
		pq.Array(result.AdvertisedCaps), result.SupportsRFC8894, result.SupportsAES,
		result.SupportsPOSTOperation, result.SupportsRenewal,
		result.SupportsSHA256, result.SupportsSHA512,
		nullString(result.CACertSubject), nullString(result.CACertIssuer),
		nullTime(result.CACertNotBefore), nullTime(result.CACertNotAfter), result.CACertExpired,
		nullString(result.CACertAlgorithm), result.CACertChainLength,
		result.ProbedAt, result.ProbeDurationMs, nullString(result.Error),
	)
	if err != nil {
		return fmt.Errorf("insert scep probe result: %w", err)
	}
	return nil
}

// ListRecent returns the most recent N probe results across any URL,
// ordered by probed_at descending. limit is clamped to [1, 200] to bound
// the response size — the GUI defaults to 50.
func (r *SCEPProbeResultRepository) ListRecent(ctx context.Context, limit int) ([]*domain.SCEPProbeResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, target_url, reachable,
		       advertised_caps, supports_rfc8894, supports_aes,
		       supports_post_operation, supports_renewal,
		       supports_sha256, supports_sha512,
		       ca_cert_subject, ca_cert_issuer,
		       ca_cert_not_before, ca_cert_not_after, ca_cert_expired,
		       ca_cert_algorithm, ca_cert_chain_length,
		       probed_at, probe_duration_ms, error,
		       created_at
		FROM scep_probe_results
		ORDER BY probed_at DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list recent scep probe results: %w", err)
	}
	defer rows.Close()

	var out []*domain.SCEPProbeResult
	for rows.Next() {
		var (
			row       domain.SCEPProbeResult
			subject   sql.NullString
			issuer    sql.NullString
			notBefore sql.NullTime
			notAfter  sql.NullTime
			algorithm sql.NullString
			errString sql.NullString
		)
		err := rows.Scan(
			&row.ID, &row.TargetURL, &row.Reachable,
			pq.Array(&row.AdvertisedCaps), &row.SupportsRFC8894, &row.SupportsAES,
			&row.SupportsPOSTOperation, &row.SupportsRenewal,
			&row.SupportsSHA256, &row.SupportsSHA512,
			&subject, &issuer,
			&notBefore, &notAfter, &row.CACertExpired,
			&algorithm, &row.CACertChainLength,
			&row.ProbedAt, &row.ProbeDurationMs, &errString,
			&row.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan scep probe result row: %w", err)
		}
		if subject.Valid {
			row.CACertSubject = subject.String
		}
		if issuer.Valid {
			row.CACertIssuer = issuer.String
		}
		if notBefore.Valid {
			row.CACertNotBefore = notBefore.Time
		}
		if notAfter.Valid {
			row.CACertNotAfter = notAfter.Time
			if !row.CACertExpired {
				// Re-derive days_to_expiry on read so it reflects the
				// query-time wall clock rather than the persisted
				// snapshot's wall clock — operators care about how
				// fresh "30d remaining" is.
				hours := time.Until(notAfter.Time).Hours()
				row.CACertDaysToExpiry = int(hours / 24)
			}
		}
		if algorithm.Valid {
			row.CACertAlgorithm = algorithm.String
		}
		if errString.Valid {
			row.Error = errString.String
		}
		out = append(out, &row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scep probe results: %w", err)
	}
	return out, nil
}

// nullString returns sql.NullString — empty becomes NULL.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullTime returns sql.NullTime — zero time becomes NULL.
func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t, Valid: true}
}

// Compile-time interface check.
var _ repository.SCEPProbeResultRepository = (*SCEPProbeResultRepository)(nil)
