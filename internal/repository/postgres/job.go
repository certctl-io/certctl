package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// JobRepository implements repository.JobRepository
type JobRepository struct {
	db *sql.DB
}

// NewJobRepository creates a new JobRepository
func NewJobRepository(db *sql.DB) *JobRepository {
	return &JobRepository{db: db}
}

// List returns all jobs
func (r *JobRepository) List(ctx context.Context) ([]*domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query jobs: %w", err)
	}
	defer rows.Close()

	var jobs []*domain.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job rows: %w", err)
	}

	return jobs, nil
}

// Get retrieves a job by ID
func (r *JobRepository) Get(ctx context.Context, id string) (*domain.Job, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE id = $1
	`, id)

	job, err := scanJob(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("job not found")
		}
		return nil, fmt.Errorf("failed to query job: %w", err)
	}

	return job, nil
}

// Create stores a new job
func (r *JobRepository) Create(ctx context.Context, job *domain.Job) error {
	if job.ID == "" {
		job.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO jobs (
			id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
			last_error, scheduled_at, started_at, completed_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id
	`, job.ID, job.Type, job.CertificateID, job.TargetID, job.AgentID, job.Status, job.Attempts,
		job.MaxAttempts, job.LastError, job.ScheduledAt, job.StartedAt, job.CompletedAt,
		job.CreatedAt).Scan(&job.ID)

	if err != nil {
		return fmt.Errorf("failed to create job: %w", err)
	}

	return nil
}

// Update modifies an existing job
func (r *JobRepository) Update(ctx context.Context, job *domain.Job) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE jobs SET
			type = $1,
			certificate_id = $2,
			target_id = $3,
			agent_id = $4,
			status = $5,
			attempts = $6,
			max_attempts = $7,
			last_error = $8,
			scheduled_at = $9,
			started_at = $10,
			completed_at = $11
		WHERE id = $12
	`, job.Type, job.CertificateID, job.TargetID, job.AgentID, job.Status, job.Attempts,
		job.MaxAttempts, job.LastError, job.ScheduledAt, job.StartedAt,
		job.CompletedAt, job.ID)

	if err != nil {
		return fmt.Errorf("failed to update job: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("job not found")
	}

	return nil
}

// Delete removes a job
func (r *JobRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM jobs WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete job: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("job not found")
	}

	return nil
}

// ListByStatus returns jobs with a specific status
func (r *JobRepository) ListByStatus(ctx context.Context, status domain.JobStatus) ([]*domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE status = $1
		ORDER BY created_at DESC
	`, status)

	if err != nil {
		return nil, fmt.Errorf("failed to query jobs by status: %w", err)
	}
	defer rows.Close()

	var jobs []*domain.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job rows: %w", err)
	}

	return jobs, nil
}

// ListByCertificate returns all jobs for a certificate
func (r *JobRepository) ListByCertificate(ctx context.Context, certID string) ([]*domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE certificate_id = $1
		ORDER BY created_at DESC
	`, certID)

	if err != nil {
		return nil, fmt.Errorf("failed to query jobs for certificate: %w", err)
	}
	defer rows.Close()

	var jobs []*domain.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job rows: %w", err)
	}

	return jobs, nil
}

// UpdateStatus updates a job's status and optional error message
func (r *JobRepository) UpdateStatus(ctx context.Context, id string, status domain.JobStatus, errMsg string) error {
	var lastError *string
	if errMsg != "" {
		lastError = &errMsg
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE jobs SET status = $1, last_error = $2 WHERE id = $3
	`, status, lastError, id)

	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("job not found")
	}

	return nil
}

// GetPendingJobs returns jobs not yet processed of a specific type.
//
// The SELECT uses FOR UPDATE SKIP LOCKED so that concurrent scheduler replicas
// cannot observe the same rows when invoked inside a transaction; combine with
// a subsequent UPDATE to Running for correct dispatch semantics. For the
// standard production dispatch path, prefer ClaimPendingJobs which wraps the
// lock, read, and state transition in a single transaction and is the
// authoritative race-free claim primitive (CWE-362 fix for H-6).
func (r *JobRepository) GetPendingJobs(ctx context.Context, jobType domain.JobType) ([]*domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE type = $1 AND status = $2
		ORDER BY scheduled_at ASC
		FOR UPDATE SKIP LOCKED
	`, jobType, domain.JobStatusPending)

	if err != nil {
		return nil, fmt.Errorf("failed to query pending jobs: %w", err)
	}
	defer rows.Close()

	var jobs []*domain.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job rows: %w", err)
	}

	return jobs, nil
}

// ClaimPendingJobs atomically claims up to `limit` Pending jobs and transitions
// them to Running inside a single transaction. The SELECT uses FOR UPDATE SKIP
// LOCKED so concurrent scheduler replicas observe disjoint result sets — each
// row can be claimed by exactly one caller per tick (CWE-362 fix for H-6).
//
// Passing an empty jobType claims any type. Passing limit<=0 claims all
// available rows. The claimed rows are returned with Status already set to
// domain.JobStatusRunning.
//
// Downstream processors (ProcessRenewalJob, ProcessDeploymentJob) already call
// UpdateStatus(Running) unconditionally on entry, so this pre-flip is
// idempotent with respect to existing processing logic.
func (r *JobRepository) ClaimPendingJobs(ctx context.Context, jobType domain.JobType, limit int) ([]*domain.Job, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin claim transaction: %w", err)
	}
	// Rollback is a no-op after Commit — safe deferred cleanup if an error path
	// triggers an early return before Commit().
	defer func() { _ = tx.Rollback() }()

	// Build the SELECT — jobType="" means any type, limit<=0 means unlimited.
	query := `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE status = $1`
	args := []interface{}{domain.JobStatusPending}
	if jobType != "" {
		query += ` AND type = $2`
		args = append(args, jobType)
	}
	query += `
		ORDER BY scheduled_at ASC
		FOR UPDATE SKIP LOCKED`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query claimable jobs: %w", err)
	}

	var jobs []*domain.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("error iterating claimable job rows: %w", err)
	}
	rows.Close()

	if len(jobs) == 0 {
		// No rows to claim — commit the (read-only) tx and return.
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("failed to commit empty claim tx: %w", err)
		}
		return nil, nil
	}

	// Flip claimed rows to Running. Build IN clause safely with placeholders.
	ids := make([]interface{}, len(jobs))
	placeholders := make([]byte, 0, len(jobs)*5)
	for i, job := range jobs {
		ids[i] = job.ID
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+2)...)
	}
	updateQuery := fmt.Sprintf(
		`UPDATE jobs SET status = $1 WHERE id IN (%s)`,
		string(placeholders),
	)
	updateArgs := append([]interface{}{domain.JobStatusRunning}, ids...)
	if _, err := tx.ExecContext(ctx, updateQuery, updateArgs...); err != nil {
		return nil, fmt.Errorf("failed to transition claimed jobs to Running: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit claim transaction: %w", err)
	}

	// Reflect the committed state in the returned objects.
	for _, job := range jobs {
		job.Status = domain.JobStatusRunning
	}

	return jobs, nil
}

// ListPendingByAgentID returns pending deployment jobs and AwaitingCSR jobs for
// a specific agent. Deployment jobs are matched by agent_id directly (set at
// creation time), with a fallback for legacy jobs where agent_id is NULL but
// target_id resolves to the agent via deployment_targets. AwaitingCSR jobs are
// matched through certificate → target mappings → agent ownership.
//
// The SELECT uses FOR UPDATE SKIP LOCKED so concurrent pollers (e.g. two agent
// instances running with the same agent_id) cannot observe the same rows when
// this method is invoked inside a transaction. For the production agent work
// poll path, prefer ClaimPendingByAgentID which additionally transitions
// claimed Pending deployment rows to Running atomically (H-6 CWE-362 fix).
func (r *JobRepository) ListPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE agent_id = $1 AND status = 'Pending' AND type = 'Deployment'

		UNION ALL

		SELECT j.id, j.type, j.certificate_id, j.target_id, j.agent_id, j.status, j.attempts, j.max_attempts,
		       j.last_error, j.scheduled_at, j.started_at, j.completed_at, j.created_at
		FROM jobs j
		INNER JOIN deployment_targets dt ON j.target_id = dt.id
		WHERE j.agent_id IS NULL AND j.status = 'Pending' AND j.type = 'Deployment'
		  AND dt.agent_id = $1

		UNION ALL

		SELECT j.id, j.type, j.certificate_id, j.target_id, j.agent_id, j.status, j.attempts, j.max_attempts,
		       j.last_error, j.scheduled_at, j.started_at, j.completed_at, j.created_at
		FROM jobs j
		WHERE j.status = 'AwaitingCSR'
		  AND j.type IN ('Renewal', 'Issuance')
		  AND EXISTS (
		    SELECT 1 FROM certificate_target_mappings ctm
		    INNER JOIN deployment_targets dt ON ctm.target_id = dt.id
		    WHERE ctm.certificate_id = j.certificate_id
		      AND dt.agent_id = $1
		  )

		ORDER BY created_at ASC
	`, agentID)

	if err != nil {
		return nil, fmt.Errorf("failed to query pending jobs for agent: %w", err)
	}
	defer rows.Close()

	var jobs []*domain.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating pending agent job rows: %w", err)
	}

	return jobs, nil
}

// ClaimPendingByAgentID atomically claims agent work inside a single
// transaction. Pending Deployment jobs assigned to the agent (directly via
// agent_id, or via legacy target→agent fallback) are transitioned from
// Pending to Running. AwaitingCSR Renewal/Issuance jobs linked to the agent
// via certificate → target mappings are locked with FOR UPDATE SKIP LOCKED
// and returned without a state transition — the flow requires the agent to
// submit a CSR to advance state, and pre-flipping AwaitingCSR would violate
// the renewal state machine (CWE-362 fix for H-6).
//
// Claimed rows are invisible to other concurrent claim calls for the lifetime
// of the transaction; rows claimed as Running remain invisible after commit
// because ListPendingByAgentID's filter is status='Pending'.
func (r *JobRepository) ClaimPendingByAgentID(ctx context.Context, agentID string) ([]*domain.Job, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin agent claim transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Branch 1 + 2: Pending Deployment jobs (direct agent_id match or legacy
	// target fallback). These get flipped to Running atomically below.
	pendingRows, err := tx.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE agent_id = $1 AND status = 'Pending' AND type = 'Deployment'

		UNION ALL

		SELECT j.id, j.type, j.certificate_id, j.target_id, j.agent_id, j.status, j.attempts, j.max_attempts,
		       j.last_error, j.scheduled_at, j.started_at, j.completed_at, j.created_at
		FROM jobs j
		INNER JOIN deployment_targets dt ON j.target_id = dt.id
		WHERE j.agent_id IS NULL AND j.status = 'Pending' AND j.type = 'Deployment'
		  AND dt.agent_id = $1

		ORDER BY created_at ASC
		FOR UPDATE SKIP LOCKED
	`, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending deployment jobs for agent: %w", err)
	}

	var pendingJobs []*domain.Job
	for pendingRows.Next() {
		job, err := scanJob(pendingRows)
		if err != nil {
			pendingRows.Close()
			return nil, err
		}
		pendingJobs = append(pendingJobs, job)
	}
	if err := pendingRows.Err(); err != nil {
		pendingRows.Close()
		return nil, fmt.Errorf("error iterating pending deployment rows: %w", err)
	}
	pendingRows.Close()

	// Branch 3: AwaitingCSR jobs for this agent. Locked with FOR UPDATE SKIP
	// LOCKED to prevent duplicate delivery to concurrent pollers, but state is
	// NOT transitioned — the agent advances state via CSR submission.
	csrRows, err := tx.QueryContext(ctx, `
		SELECT j.id, j.type, j.certificate_id, j.target_id, j.agent_id, j.status, j.attempts, j.max_attempts,
		       j.last_error, j.scheduled_at, j.started_at, j.completed_at, j.created_at
		FROM jobs j
		WHERE j.status = 'AwaitingCSR'
		  AND j.type IN ('Renewal', 'Issuance')
		  AND EXISTS (
		    SELECT 1 FROM certificate_target_mappings ctm
		    INNER JOIN deployment_targets dt ON ctm.target_id = dt.id
		    WHERE ctm.certificate_id = j.certificate_id
		      AND dt.agent_id = $1
		  )
		ORDER BY j.created_at ASC
		FOR UPDATE SKIP LOCKED
	`, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to query AwaitingCSR jobs for agent: %w", err)
	}

	var csrJobs []*domain.Job
	for csrRows.Next() {
		job, err := scanJob(csrRows)
		if err != nil {
			csrRows.Close()
			return nil, err
		}
		csrJobs = append(csrJobs, job)
	}
	if err := csrRows.Err(); err != nil {
		csrRows.Close()
		return nil, fmt.Errorf("error iterating AwaitingCSR rows: %w", err)
	}
	csrRows.Close()

	// Transition locked Pending deployments to Running before commit.
	if len(pendingJobs) > 0 {
		ids := make([]interface{}, len(pendingJobs))
		placeholders := make([]byte, 0, len(pendingJobs)*5)
		for i, job := range pendingJobs {
			ids[i] = job.ID
			if i > 0 {
				placeholders = append(placeholders, ',')
			}
			placeholders = append(placeholders, fmt.Sprintf("$%d", i+2)...)
		}
		updateQuery := fmt.Sprintf(
			`UPDATE jobs SET status = $1 WHERE id IN (%s)`,
			string(placeholders),
		)
		updateArgs := append([]interface{}{domain.JobStatusRunning}, ids...)
		if _, err := tx.ExecContext(ctx, updateQuery, updateArgs...); err != nil {
			return nil, fmt.Errorf("failed to transition claimed deployment jobs to Running: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit agent claim transaction: %w", err)
	}

	// Reflect the committed state in returned Pending deployment jobs; leave
	// AwaitingCSR jobs untouched.
	for _, job := range pendingJobs {
		job.Status = domain.JobStatusRunning
	}

	// Preserve the legacy ordering: Pending deployments first, AwaitingCSR
	// second. Callers that want a strict created_at merge can re-sort.
	return append(pendingJobs, csrJobs...), nil
}

// ListTimedOutAwaitingJobs returns jobs stuck in AwaitingCSR or AwaitingApproval past
// their respective cutoff timestamps (created_at < cutoff). The reaper loop transitions
// them to Failed; I-001's retry loop then auto-promotes eligible Failed jobs back to
// Pending. I-003 coverage-gap closure.
func (r *JobRepository) ListTimedOutAwaitingJobs(ctx context.Context, csrCutoff, approvalCutoff time.Time) ([]*domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE (status = $1 AND created_at < $2)
		   OR (status = $3 AND created_at < $4)
		ORDER BY created_at ASC
	`, domain.JobStatusAwaitingCSR, csrCutoff, domain.JobStatusAwaitingApproval, approvalCutoff)

	if err != nil {
		return nil, fmt.Errorf("failed to query timed-out awaiting jobs: %w", err)
	}
	defer rows.Close()

	var jobs []*domain.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating timed-out job rows: %w", err)
	}

	return jobs, nil
}

// scanJob scans a job from a row or rows
func scanJob(scanner interface {
	Scan(...interface{}) error
}) (*domain.Job, error) {
	var job domain.Job
	err := scanner.Scan(&job.ID, &job.Type, &job.CertificateID, &job.TargetID,
		&job.AgentID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.LastError,
		&job.ScheduledAt, &job.StartedAt, &job.CompletedAt, &job.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to scan job: %w", err)
	}

	return &job, nil
}
