package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// IntermediateCARepository is the postgres implementation of
// repository.IntermediateCARepository. Rank 8 first-class CA
// hierarchy.
type IntermediateCARepository struct {
	db *sql.DB
}

// NewIntermediateCARepository constructs an IntermediateCARepository
// against the given *sql.DB. Schema defined by migration
// 000028_intermediate_ca_hierarchy.up.sql.
func NewIntermediateCARepository(db *sql.DB) *IntermediateCARepository {
	return &IntermediateCARepository{db: db}
}

// Create inserts a new IntermediateCA row.
func (r *IntermediateCARepository) Create(ctx context.Context, ca *domain.IntermediateCA) error {
	if ca.ID == "" {
		ca.ID = "ica-" + uuid.NewString()
	}
	if ca.State == "" {
		ca.State = domain.IntermediateCAStateActive
	}
	if !domain.IsValidIntermediateCAState(ca.State) {
		return fmt.Errorf("invalid intermediate CA state %q", ca.State)
	}
	now := time.Now().UTC()
	if ca.CreatedAt.IsZero() {
		ca.CreatedAt = now
	}
	if ca.UpdatedAt.IsZero() {
		ca.UpdatedAt = now
	}

	nameConstraintsJSON, err := json.Marshal(ca.NameConstraints)
	if err != nil {
		return fmt.Errorf("marshal name_constraints: %w", err)
	}
	if len(nameConstraintsJSON) == 0 || string(nameConstraintsJSON) == "null" {
		nameConstraintsJSON = []byte("[]")
	}
	metadataJSON, err := json.Marshal(ca.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if len(metadataJSON) == 0 || string(metadataJSON) == "null" {
		metadataJSON = []byte("{}")
	}

	const q = `
		INSERT INTO intermediate_cas
			(id, owning_issuer_id, parent_ca_id, name, subject, state,
			 cert_pem, key_driver_id, not_before, not_after,
			 path_len_constraint, name_constraints, ocsp_responder_url,
			 metadata, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`
	_, err = r.db.ExecContext(ctx, q,
		ca.ID, ca.OwningIssuerID, ca.ParentCAID, ca.Name, ca.Subject, string(ca.State),
		ca.CertPEM, ca.KeyDriverID, ca.NotBefore, ca.NotAfter,
		ca.PathLenConstraint, nameConstraintsJSON, nullIfEmpty(ca.OCSPResponderURL),
		metadataJSON, ca.CreatedAt, ca.UpdatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // unique_violation
			return repository.ErrAlreadyExists
		}
		return fmt.Errorf("insert intermediate CA: %w", err)
	}
	return nil
}

// Get returns the row by ID or repository.ErrNotFound.
func (r *IntermediateCARepository) Get(ctx context.Context, id string) (*domain.IntermediateCA, error) {
	const q = `
		SELECT id, owning_issuer_id, parent_ca_id, name, subject, state,
		       cert_pem, key_driver_id, not_before, not_after,
		       path_len_constraint, name_constraints, ocsp_responder_url,
		       metadata, created_at, updated_at
		FROM   intermediate_cas
		WHERE  id = $1
	`
	row := r.db.QueryRowContext(ctx, q, id)
	return scanIntermediateCARow(row)
}

// ListByIssuer returns every CA row for an issuer.
func (r *IntermediateCARepository) ListByIssuer(ctx context.Context, issuerID string) ([]*domain.IntermediateCA, error) {
	const q = `
		SELECT id, owning_issuer_id, parent_ca_id, name, subject, state,
		       cert_pem, key_driver_id, not_before, not_after,
		       path_len_constraint, name_constraints, ocsp_responder_url,
		       metadata, created_at, updated_at
		FROM   intermediate_cas
		WHERE  owning_issuer_id = $1
		ORDER  BY created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, q, issuerID)
	if err != nil {
		return nil, fmt.Errorf("list intermediate CAs: %w", err)
	}
	defer rows.Close()
	return scanIntermediateCARows(rows)
}

// ListChildren returns direct children of the given CA.
func (r *IntermediateCARepository) ListChildren(ctx context.Context, parentCAID string) ([]*domain.IntermediateCA, error) {
	const q = `
		SELECT id, owning_issuer_id, parent_ca_id, name, subject, state,
		       cert_pem, key_driver_id, not_before, not_after,
		       path_len_constraint, name_constraints, ocsp_responder_url,
		       metadata, created_at, updated_at
		FROM   intermediate_cas
		WHERE  parent_ca_id = $1
		ORDER  BY created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, q, parentCAID)
	if err != nil {
		return nil, fmt.Errorf("list children: %w", err)
	}
	defer rows.Close()
	return scanIntermediateCARows(rows)
}

// UpdateState transitions a row's lifecycle state.
func (r *IntermediateCARepository) UpdateState(ctx context.Context, id string, state domain.IntermediateCAState) error {
	if !domain.IsValidIntermediateCAState(state) {
		return fmt.Errorf("invalid state %q", state)
	}
	const q = `
		UPDATE intermediate_cas
		SET    state = $2, updated_at = NOW()
		WHERE  id = $1
	`
	res, err := r.db.ExecContext(ctx, q, id, string(state))
	if err != nil {
		return fmt.Errorf("update state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// GetActiveRoot returns the active root CA for an issuer.
func (r *IntermediateCARepository) GetActiveRoot(ctx context.Context, issuerID string) (*domain.IntermediateCA, error) {
	const q = `
		SELECT id, owning_issuer_id, parent_ca_id, name, subject, state,
		       cert_pem, key_driver_id, not_before, not_after,
		       path_len_constraint, name_constraints, ocsp_responder_url,
		       metadata, created_at, updated_at
		FROM   intermediate_cas
		WHERE  owning_issuer_id = $1
		  AND  parent_ca_id IS NULL
		  AND  state = 'active'
		LIMIT  1
	`
	row := r.db.QueryRowContext(ctx, q, issuerID)
	return scanIntermediateCARow(row)
}

// WalkAncestry returns leaf-to-root chain via recursive CTE. Single
// SQL round-trip, O(depth) rows.
func (r *IntermediateCARepository) WalkAncestry(ctx context.Context, leafID string) ([]*domain.IntermediateCA, error) {
	const q = `
		WITH RECURSIVE ancestry AS (
			SELECT id, owning_issuer_id, parent_ca_id, name, subject, state,
			       cert_pem, key_driver_id, not_before, not_after,
			       path_len_constraint, name_constraints, ocsp_responder_url,
			       metadata, created_at, updated_at, 0 AS depth
			FROM   intermediate_cas
			WHERE  id = $1

			UNION ALL

			SELECT i.id, i.owning_issuer_id, i.parent_ca_id, i.name, i.subject, i.state,
			       i.cert_pem, i.key_driver_id, i.not_before, i.not_after,
			       i.path_len_constraint, i.name_constraints, i.ocsp_responder_url,
			       i.metadata, i.created_at, i.updated_at, a.depth + 1
			FROM   intermediate_cas i
			JOIN   ancestry a ON i.id = a.parent_ca_id
		)
		SELECT id, owning_issuer_id, parent_ca_id, name, subject, state,
		       cert_pem, key_driver_id, not_before, not_after,
		       path_len_constraint, name_constraints, ocsp_responder_url,
		       metadata, created_at, updated_at
		FROM   ancestry
		ORDER  BY depth ASC
	`
	rows, err := r.db.QueryContext(ctx, q, leafID)
	if err != nil {
		return nil, fmt.Errorf("walk ancestry: %w", err)
	}
	defer rows.Close()
	out, err := scanIntermediateCARows(rows)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, repository.ErrNotFound
	}
	return out, nil
}

// scanIntermediateCARow scans a single row.
func scanIntermediateCARow(row rowScanner) (*domain.IntermediateCA, error) {
	var (
		ca                  domain.IntermediateCA
		stateStr            string
		parentCAID          sql.NullString
		pathLenConstraint   sql.NullInt64
		ocspResponderURL    sql.NullString
		nameConstraintsJSON []byte
		metadataJSON        []byte
	)
	err := row.Scan(
		&ca.ID, &ca.OwningIssuerID, &parentCAID, &ca.Name, &ca.Subject, &stateStr,
		&ca.CertPEM, &ca.KeyDriverID, &ca.NotBefore, &ca.NotAfter,
		&pathLenConstraint, &nameConstraintsJSON, &ocspResponderURL,
		&metadataJSON, &ca.CreatedAt, &ca.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan intermediate CA: %w", err)
	}
	ca.State = domain.IntermediateCAState(stateStr)
	if parentCAID.Valid {
		s := parentCAID.String
		ca.ParentCAID = &s
	}
	if pathLenConstraint.Valid {
		v := int(pathLenConstraint.Int64)
		ca.PathLenConstraint = &v
	}
	if ocspResponderURL.Valid {
		ca.OCSPResponderURL = ocspResponderURL.String
	}
	if len(nameConstraintsJSON) > 0 {
		if err := json.Unmarshal(nameConstraintsJSON, &ca.NameConstraints); err != nil {
			return nil, fmt.Errorf("unmarshal name_constraints: %w", err)
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &ca.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &ca, nil
}

func scanIntermediateCARows(rows *sql.Rows) ([]*domain.IntermediateCA, error) {
	var out []*domain.IntermediateCA
	for rows.Next() {
		ca, err := scanIntermediateCARow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ca)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	return out, nil
}

// nullIfEmpty returns sql.NullString — Valid=false when s is empty so
// the column is written as SQL NULL rather than empty string.
func nullIfEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
