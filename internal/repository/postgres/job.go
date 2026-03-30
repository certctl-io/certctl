package postgres

import (
	"context"
	"database/sql"
	"fmt"

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

// GetPendingJobs returns jobs not yet processed of a specific type
func (r *JobRepository) GetPendingJobs(ctx context.Context, jobType domain.JobType) ([]*domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, type, certificate_id, target_id, agent_id, status, attempts, max_attempts,
		       last_error, scheduled_at, started_at, completed_at, created_at
		FROM jobs
		WHERE type = $1 AND status = $2
		ORDER BY scheduled_at ASC
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

// ListPendingByAgentID returns pending deployment jobs and AwaitingCSR jobs for a specific agent.
// Deployment jobs are matched by agent_id directly (set at creation time), with a fallback
// for legacy jobs where agent_id is NULL but target_id resolves to the agent via deployment_targets.
// AwaitingCSR jobs are matched through certificate → target mappings → agent ownership.
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
