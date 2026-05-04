package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// CRLCacheRepository implements repository.CRLCacheRepository using PostgreSQL.
//
// Schema: see migrations/000019_crl_cache.up.sql. The cache stores at most
// one row per issuer (PRIMARY KEY on issuer_id); upsert collapses to ON
// CONFLICT DO UPDATE. The CRL DER blob lives in BYTEA — typical sizes
// are 100s of bytes for small CAs, KBs for busy ones, capped by the
// number of revoked certs the issuer has issued (a few hundred KB at
// most for a year-old enterprise CA).
type CRLCacheRepository struct {
	db *sql.DB
}

// NewCRLCacheRepository creates a new CRLCacheRepository.
func NewCRLCacheRepository(db *sql.DB) *CRLCacheRepository {
	return &CRLCacheRepository{db: db}
}

// Compile-time interface check.
var _ repository.CRLCacheRepository = (*CRLCacheRepository)(nil)

// Get returns the cached CRL for an issuer. Returns (nil, nil) when no
// cache row exists yet — caller treats as a miss.
func (r *CRLCacheRepository) Get(ctx context.Context, issuerID string) (*domain.CRLCacheEntry, error) {
	const query = `
		SELECT issuer_id, crl_der, crl_number, this_update, next_update,
		       generated_at, generation_duration_ms, revoked_count
		FROM crl_cache
		WHERE issuer_id = $1
	`
	row := r.db.QueryRowContext(ctx, query, issuerID)

	var entry domain.CRLCacheEntry
	var durationMs int
	if err := row.Scan(
		&entry.IssuerID,
		&entry.CRLDER,
		&entry.CRLNumber,
		&entry.ThisUpdate,
		&entry.NextUpdate,
		&entry.GeneratedAt,
		&durationMs,
		&entry.RevokedCount,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("crl_cache get %q: %w", issuerID, err)
	}
	entry.GenerationDuration = msToDuration(durationMs)
	return &entry, nil
}

// Put upserts the cache row. ON CONFLICT updates every field so the
// cache always reflects the latest generation; updated_at is bumped via
// NOW() to give ops a fresh "last touched" timestamp.
func (r *CRLCacheRepository) Put(ctx context.Context, entry *domain.CRLCacheEntry) error {
	if entry == nil {
		return errors.New("crl_cache put: nil entry")
	}
	if entry.IssuerID == "" {
		return errors.New("crl_cache put: empty issuer_id")
	}
	const query = `
		INSERT INTO crl_cache (
			issuer_id, crl_der, crl_number, this_update, next_update,
			generated_at, generation_duration_ms, revoked_count, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (issuer_id) DO UPDATE SET
			crl_der                = EXCLUDED.crl_der,
			crl_number             = EXCLUDED.crl_number,
			this_update            = EXCLUDED.this_update,
			next_update            = EXCLUDED.next_update,
			generated_at           = EXCLUDED.generated_at,
			generation_duration_ms = EXCLUDED.generation_duration_ms,
			revoked_count          = EXCLUDED.revoked_count,
			updated_at             = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		entry.IssuerID,
		entry.CRLDER,
		entry.CRLNumber,
		entry.ThisUpdate,
		entry.NextUpdate,
		entry.GeneratedAt,
		durationToMs(entry.GenerationDuration),
		entry.RevokedCount,
	)
	if err != nil {
		return fmt.Errorf("crl_cache put %q: %w", entry.IssuerID, err)
	}
	return nil
}

// NextCRLNumber returns the monotonically-incrementing CRL number for an
// issuer. RFC 5280 §5.2.3 requires the number to be strictly increasing
// per issuer; concurrent generations of the same issuer must NOT produce
// the same number.
//
// Implementation: a single UPDATE that reads max+1 from the existing
// row OR returns 1 if no row exists. Wrapped in a transaction with
// SERIALIZABLE isolation to defeat the read-then-write race entirely
// — an alternative would be a dedicated sequence per issuer, but
// per-issuer sequences proliferate as new issuers are created and the
// cleanup story is fiddly.
//
// Cost: each call is a single round-trip; the SERIALIZABLE retry path
// fires only when two crlGenerationLoop ticks (or a tick + an HTTP-miss
// regeneration) collide on the same issuer, which is rare given the
// singleflight collapsing in the cache service layer.
func (r *CRLCacheRepository) NextCRLNumber(ctx context.Context, issuerID string) (int64, error) {
	if issuerID == "" {
		return 0, errors.New("crl_cache next_crl_number: empty issuer_id")
	}

	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, fmt.Errorf("crl_cache next_crl_number: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // safe no-op after commit

	var current sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT crl_number FROM crl_cache WHERE issuer_id = $1 FOR UPDATE`,
		issuerID,
	).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// First-ever CRL for this issuer.
		if commitErr := tx.Commit(); commitErr != nil {
			return 0, fmt.Errorf("crl_cache next_crl_number: commit: %w", commitErr)
		}
		return 1, nil
	case err != nil:
		return 0, fmt.Errorf("crl_cache next_crl_number: select: %w", err)
	}

	next := current.Int64 + 1
	if commitErr := tx.Commit(); commitErr != nil {
		return 0, fmt.Errorf("crl_cache next_crl_number: commit: %w", commitErr)
	}
	return next, nil
}

// RecordGenerationEvent appends an event row. The id is BIGSERIAL and is
// assigned by the database; we rely on RETURNING id to populate the
// passed-in struct so callers can correlate event-IDs with their own
// telemetry.
func (r *CRLCacheRepository) RecordGenerationEvent(ctx context.Context, evt *domain.CRLGenerationEvent) error {
	if evt == nil {
		return errors.New("crl_cache record_event: nil event")
	}
	if evt.IssuerID == "" {
		return errors.New("crl_cache record_event: empty issuer_id")
	}
	const query = `
		INSERT INTO crl_generation_events (
			issuer_id, crl_number, duration_ms, revoked_count,
			started_at, succeeded, error
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))
		RETURNING id
	`
	var id int64
	err := r.db.QueryRowContext(ctx, query,
		evt.IssuerID,
		evt.CRLNumber,
		durationToMs(evt.Duration),
		evt.RevokedCount,
		evt.StartedAt,
		evt.Succeeded,
		evt.Error,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("crl_cache record_event %q: %w", evt.IssuerID, err)
	}
	evt.ID = id
	return nil
}

// ListGenerationEvents returns the most recent N events for an issuer,
// newest first. Used by the admin endpoint and the GUI panel.
func (r *CRLCacheRepository) ListGenerationEvents(ctx context.Context, issuerID string, limit int) ([]*domain.CRLGenerationEvent, error) {
	if issuerID == "" {
		return nil, errors.New("crl_cache list_events: empty issuer_id")
	}
	if limit <= 0 {
		limit = 50
	}
	const query = `
		SELECT id, issuer_id, crl_number, duration_ms, revoked_count,
		       started_at, succeeded, COALESCE(error, '')
		FROM crl_generation_events
		WHERE issuer_id = $1
		ORDER BY started_at DESC
		LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, issuerID, limit)
	if err != nil {
		return nil, fmt.Errorf("crl_cache list_events %q: %w", issuerID, err)
	}
	defer rows.Close()

	var out []*domain.CRLGenerationEvent
	for rows.Next() {
		var evt domain.CRLGenerationEvent
		var durationMs int
		if err := rows.Scan(
			&evt.ID,
			&evt.IssuerID,
			&evt.CRLNumber,
			&durationMs,
			&evt.RevokedCount,
			&evt.StartedAt,
			&evt.Succeeded,
			&evt.Error,
		); err != nil {
			return nil, fmt.Errorf("crl_cache list_events scan: %w", err)
		}
		evt.Duration = msToDuration(durationMs)
		out = append(out, &evt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crl_cache list_events iterate: %w", err)
	}
	return out, nil
}

// durationToMs / msToDuration are the boundary helpers between Go's
// time.Duration (nanosecond-resolution) and the DB's INTEGER ms column.
// Storing as ms (int) matches the SQL schema's `generation_duration_ms
// INTEGER NOT NULL` and keeps admin queries readable (`SELECT issuer_id,
// duration_ms FROM ...` rather than computing nanoseconds in SQL).
func durationToMs(d time.Duration) int {
	return int(d / time.Millisecond)
}

func msToDuration(ms int) time.Duration {
	return time.Duration(ms) * time.Millisecond
}
