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

// ApprovalRepository is the postgres implementation of
// repository.ApprovalRepository. Rank 7 of the 2026-05-03 deep-research
// deep-research deliverable.
type ApprovalRepository struct {
	db *sql.DB
}

// NewApprovalRepository constructs an ApprovalRepository against the
// given *sql.DB. The schema is defined by migration
// 000027_approval_workflow.up.sql.
func NewApprovalRepository(db *sql.DB) *ApprovalRepository {
	return &ApprovalRepository{db: db}
}

// Create inserts a new ApprovalRequest at state=pending. Generates the
// ar-<slug> ID if req.ID is empty. Returns
// repository.ErrAlreadyExists if the partial-unique index
// (idx_approval_pending_per_job) trips — i.e., a pending request
// already exists for the given job_id.
func (r *ApprovalRepository) Create(ctx context.Context, req *domain.ApprovalRequest) error {
	if req.ID == "" {
		req.ID = "ar-" + uuid.NewString()
	}
	if req.State == "" {
		req.State = domain.ApprovalStatePending
	}
	if !domain.IsValidApprovalState(req.State) {
		return fmt.Errorf("invalid approval state %q", req.State)
	}
	now := time.Now().UTC()
	if req.CreatedAt.IsZero() {
		req.CreatedAt = now
	}
	if req.UpdatedAt.IsZero() {
		req.UpdatedAt = now
	}

	metadataJSON, err := json.Marshal(req.Metadata)
	if err != nil {
		return fmt.Errorf("marshal approval metadata: %w", err)
	}
	if len(metadataJSON) == 0 || string(metadataJSON) == "null" {
		metadataJSON = []byte("{}")
	}

	const q = `
		INSERT INTO issuance_approval_requests
			(id, certificate_id, job_id, profile_id, requested_by,
			 state, decided_by, decided_at, decision_note, metadata,
			 created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = r.db.ExecContext(ctx, q,
		req.ID, req.CertificateID, req.JobID, req.ProfileID, req.RequestedBy,
		string(req.State), req.DecidedBy, req.DecidedAt, req.DecisionNote, metadataJSON,
		req.CreatedAt, req.UpdatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // unique_violation
			return repository.ErrAlreadyExists
		}
		return fmt.Errorf("insert approval request: %w", err)
	}
	return nil
}

// Get returns the request by ID or repository.ErrNotFound.
func (r *ApprovalRepository) Get(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	const q = `
		SELECT id, certificate_id, job_id, profile_id, requested_by,
		       state, decided_by, decided_at, decision_note, metadata,
		       created_at, updated_at
		FROM   issuance_approval_requests
		WHERE  id = $1
	`
	row := r.db.QueryRowContext(ctx, q, id)
	return scanApprovalRow(row)
}

// GetByJobID returns the most-recently-created request for the given
// job_id, regardless of state.
func (r *ApprovalRepository) GetByJobID(ctx context.Context, jobID string) (*domain.ApprovalRequest, error) {
	const q = `
		SELECT id, certificate_id, job_id, profile_id, requested_by,
		       state, decided_by, decided_at, decision_note, metadata,
		       created_at, updated_at
		FROM   issuance_approval_requests
		WHERE  job_id = $1
		ORDER  BY created_at DESC
		LIMIT  1
	`
	row := r.db.QueryRowContext(ctx, q, jobID)
	return scanApprovalRow(row)
}

// List returns approval requests filtered by repository.ApprovalFilter.
// Supports paginated dashboard queries.
func (r *ApprovalRepository) List(ctx context.Context, filter *repository.ApprovalFilter) ([]*domain.ApprovalRequest, error) {
	if filter == nil {
		filter = &repository.ApprovalFilter{}
	}
	page := filter.Page
	if page < 1 {
		page = 1
	}
	perPage := filter.PerPage
	if perPage < 1 || perPage > 500 {
		perPage = 50
	}

	q := `
		SELECT id, certificate_id, job_id, profile_id, requested_by,
		       state, decided_by, decided_at, decision_note, metadata,
		       created_at, updated_at
		FROM   issuance_approval_requests
		WHERE  1 = 1
	`
	args := []interface{}{}
	idx := 1
	if filter.State != "" {
		q += fmt.Sprintf(" AND state = $%d", idx)
		args = append(args, filter.State)
		idx++
	}
	if filter.CertificateID != "" {
		q += fmt.Sprintf(" AND certificate_id = $%d", idx)
		args = append(args, filter.CertificateID)
		idx++
	}
	if filter.RequestedBy != "" {
		q += fmt.Sprintf(" AND requested_by = $%d", idx)
		args = append(args, filter.RequestedBy)
		idx++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, perPage, (page-1)*perPage)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list approval requests: %w", err)
	}
	defer rows.Close()

	var out []*domain.ApprovalRequest
	for rows.Next() {
		req, err := scanApprovalRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approval rows: %w", err)
	}
	return out, nil
}

// UpdateState transitions a row from state=pending to a terminal state.
// Returns repository.ErrNotFound if the ID does not exist.
//
// The schema's approval_decision_consistency CHECK constraint enforces
// that decided_by + decided_at MUST be non-null for terminal states,
// so a same-state update on an already-decided row returns a
// constraint-violation error from postgres.
func (r *ApprovalRepository) UpdateState(ctx context.Context, id string, state domain.ApprovalState,
	decidedBy string, decidedAt time.Time, note string) error {
	if !domain.IsValidApprovalState(state) {
		return fmt.Errorf("invalid approval state %q", state)
	}
	if !state.IsTerminal() {
		return fmt.Errorf("UpdateState only accepts terminal states; got %q", state)
	}

	var notePtr *string
	if note != "" {
		notePtr = &note
	}

	const q = `
		UPDATE issuance_approval_requests
		SET    state         = $2,
		       decided_by    = $3,
		       decided_at    = $4,
		       decision_note = $5,
		       updated_at    = NOW()
		WHERE  id = $1
		  AND  state = 'pending'
	`
	res, err := r.db.ExecContext(ctx, q, id, string(state), decidedBy, decidedAt, notePtr)
	if err != nil {
		return fmt.Errorf("update approval state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update approval rows affected: %w", err)
	}
	if n == 0 {
		// Either the ID does not exist, or the row is already terminal.
		// Disambiguate via a follow-up Get.
		existing, getErr := r.Get(ctx, id)
		if getErr != nil {
			return getErr // ErrNotFound or scan error
		}
		if existing.State.IsTerminal() {
			return repository.ErrAlreadyExists // signals "already decided"
		}
		return repository.ErrNotFound
	}
	return nil
}

// ExpireStale transitions every row with state=pending and created_at <=
// before to state=expired. Returns the number of rows transitioned.
//
// The decided_at is stamped with time.Now() rather than `before` so
// audit dashboards see the actual reaper-firing wall-clock, not the
// reaper's deadline-cutoff input. The decided_by is set to a sentinel
// "system-reaper" so SELECT FROM audit_events WHERE actor matches both
// human-decided and reaper-decided rows for compliance review.
func (r *ApprovalRepository) ExpireStale(ctx context.Context, before time.Time) (int, error) {
	const q = `
		UPDATE issuance_approval_requests
		SET    state         = 'expired',
		       decided_by    = 'system-reaper',
		       decided_at    = NOW(),
		       decision_note = 'auto-expired by scheduler reaper at CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT',
		       updated_at    = NOW()
		WHERE  state = 'pending'
		  AND  created_at <= $1
	`
	res, err := r.db.ExecContext(ctx, q, before)
	if err != nil {
		return 0, fmt.Errorf("expire stale approvals: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("expire stale rows affected: %w", err)
	}
	return int(n), nil
}

// scanApprovalRow scans a single row into a *domain.ApprovalRequest.
// Used by Get / GetByJobID (sql.Row) + List (*sql.Rows) — accepts the
// rowScanner interface. JSONB metadata is unmarshaled defensively.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanApprovalRow(row rowScanner) (*domain.ApprovalRequest, error) {
	var (
		req          domain.ApprovalRequest
		stateStr     string
		decidedBy    sql.NullString
		decidedAt    sql.NullTime
		decisionNote sql.NullString
		metadataJSON []byte
	)
	err := row.Scan(
		&req.ID, &req.CertificateID, &req.JobID, &req.ProfileID, &req.RequestedBy,
		&stateStr, &decidedBy, &decidedAt, &decisionNote, &metadataJSON,
		&req.CreatedAt, &req.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan approval row: %w", err)
	}

	req.State = domain.ApprovalState(stateStr)
	if decidedBy.Valid {
		s := decidedBy.String
		req.DecidedBy = &s
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		req.DecidedAt = &t
	}
	if decisionNote.Valid {
		s := decisionNote.String
		req.DecisionNote = &s
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &req.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal approval metadata: %w", err)
		}
	}
	return &req, nil
}
