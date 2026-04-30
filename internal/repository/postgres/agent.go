package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/shankar0123/certctl/internal/repository"
	"time"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// AgentRepository implements repository.AgentRepository
type AgentRepository struct {
	db *sql.DB
}

// NewAgentRepository creates a new AgentRepository
func NewAgentRepository(db *sql.DB) *AgentRepository {
	return &AgentRepository{db: db}
}

// List returns all ACTIVE agents — rows with retired_at IS NULL. I-004:
// the default listing path feeds the handler-facing ListAgents call, the
// stats dashboard, and the stale-offline sweeper; every caller wants active
// hardware, not decommissioned rows. Operators who need retired rows reach
// for ListRetired instead. The partial index idx_agents_retired_at
// (migration 000015) lets the planner skip the retired segment cheaply.
func (r *AgentRepository) List(ctx context.Context) ([]*domain.Agent, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		       os, architecture, ip_address, version, retired_at, retired_reason
		FROM agents
		WHERE retired_at IS NULL
		ORDER BY registered_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query agents: %w", err)
	}
	defer rows.Close()

	var agents []*domain.Agent
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating agent rows: %w", err)
	}

	return agents, nil
}

// Get retrieves an agent by ID. I-004: retired rows ARE surfaced here —
// callers that need to check "has this agent been retired?" (heartbeat
// handler returning 410 Gone, retirement service's idempotent-retire branch,
// detail page rendering a retirement banner) must see retired_at /
// retired_reason. Only the List path default-excludes retired rows; Get is
// by-ID and returns whatever row exists.
func (r *AgentRepository) Get(ctx context.Context, id string) (*domain.Agent, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		       os, architecture, ip_address, version, retired_at, retired_reason
		FROM agents
		WHERE id = $1
	`, id)

	agent, err := scanAgent(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("agent not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}

	return agent, nil
}

// Create stores a new agent. Duplicate-key errors surface to the caller —
// real-agent registration paths rely on this to detect collisions. Use
// CreateIfNotExists for sentinel/bootstrap paths where re-inserts are expected.
func (r *AgentRepository) Create(ctx context.Context, agent *domain.Agent) error {
	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO agents (id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		                    os, architecture, ip_address, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`, agent.ID, agent.Name, agent.Hostname, agent.Status, agent.LastHeartbeatAt,
		agent.RegisteredAt, agent.APIKeyHash,
		agent.OS, agent.Architecture, agent.IPAddress, agent.Version).Scan(&agent.ID)

	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	return nil
}

// CreateIfNotExists creates an agent only if the ID doesn't already exist.
// Used for sentinel agents (server-scanner, cloud-aws-sm, cloud-azure-kv,
// cloud-gcp-sm) on first boot AND on every subsequent restart/upgrade — the
// pre-M-6 code used plain INSERT, swallowed the duplicate-key error, and so
// silently swallowed every other database failure too (CWE-662 /
// CWE-209-adjacent). ON CONFLICT (id) DO NOTHING + RETURNING id +
// sql.ErrNoRows distinguishes "row already existed" (created=false, err=nil)
// from genuine errors (connectivity, permission, constraint violations
// other than the id primary key) which still surface. Returns true if the
// row was newly inserted, false if a row with the same ID already existed.
func (r *AgentRepository) CreateIfNotExists(ctx context.Context, agent *domain.Agent) (bool, error) {
	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}

	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO agents (id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		                    os, architecture, ip_address, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO NOTHING
		RETURNING id
	`, agent.ID, agent.Name, agent.Hostname, agent.Status, agent.LastHeartbeatAt,
		agent.RegisteredAt, agent.APIKeyHash,
		agent.OS, agent.Architecture, agent.IPAddress, agent.Version).Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			// ON CONFLICT DO NOTHING — a row with this ID already existed.
			return false, nil
		}
		return false, fmt.Errorf("failed to create agent: %w", err)
	}

	agent.ID = id
	return true, nil
}

// Update modifies an existing agent
func (r *AgentRepository) Update(ctx context.Context, agent *domain.Agent) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE agents SET
			name = $1,
			hostname = $2,
			status = $3,
			last_heartbeat_at = $4,
			api_key_hash = $5,
			os = $6,
			architecture = $7,
			ip_address = $8,
			version = $9
		WHERE id = $10
	`, agent.Name, agent.Hostname, agent.Status, agent.LastHeartbeatAt, agent.APIKeyHash,
		agent.OS, agent.Architecture, agent.IPAddress, agent.Version, agent.ID)

	if err != nil {
		return fmt.Errorf("failed to update agent: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("agent not found: %w", repository.ErrNotFound)
	}

	return nil
}

// Delete removes an agent
func (r *AgentRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM agents WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete agent: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("agent not found: %w", repository.ErrNotFound)
	}

	return nil
}

// UpdateHeartbeat updates the agent's last heartbeat timestamp and metadata.
//
// I-004: both branches include `AND retired_at IS NULL` in the WHERE clause,
// making the UPDATE a no-op on retired rows. The service layer already
// short-circuits with ErrAgentRetired before calling this method (see
// AgentService.Heartbeat), but the WHERE filter is belt-and-braces for any
// path that skips the service — a stale agent process that keeps polling
// after retirement cannot resurrect its heartbeat at the DB layer. A zero
// RowsAffected here returns the same "agent not found" error as before; the
// service layer distinguishes retired from missing by calling Get first.
func (r *AgentRepository) UpdateHeartbeat(ctx context.Context, id string, metadata *domain.AgentMetadata) error {
	var result sql.Result
	var err error

	if metadata != nil {
		result, err = r.db.ExecContext(ctx, `
			UPDATE agents SET
				last_heartbeat_at = $1,
				hostname = CASE WHEN $3 = '' THEN hostname ELSE $3 END,
				os = CASE WHEN $4 = '' THEN os ELSE $4 END,
				architecture = CASE WHEN $5 = '' THEN architecture ELSE $5 END,
				ip_address = CASE WHEN $6 = '' THEN ip_address ELSE $6 END,
				version = CASE WHEN $7 = '' THEN version ELSE $7 END
			WHERE id = $2 AND retired_at IS NULL
		`, time.Now(), id, metadata.Hostname, metadata.OS, metadata.Architecture, metadata.IPAddress, metadata.Version)
	} else {
		result, err = r.db.ExecContext(ctx, `
			UPDATE agents SET last_heartbeat_at = $1 WHERE id = $2 AND retired_at IS NULL
		`, time.Now(), id)
	}

	if err != nil {
		return fmt.Errorf("failed to update heartbeat: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("agent not found: %w", repository.ErrNotFound)
	}

	return nil
}

// GetByAPIKey retrieves an agent by hashed API key. I-004: retired rows ARE
// surfaced here so the auth middleware can detect "this API key belongs to a
// retired agent" and fail the request with 410 Gone instead of 401. If the
// filter hid retired rows, auth would return a plain 401 and leak no signal
// that the agent process needs cleaning up.
func (r *AgentRepository) GetByAPIKey(ctx context.Context, keyHash string) (*domain.Agent, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		       os, architecture, ip_address, version, retired_at, retired_reason
		FROM agents
		WHERE api_key_hash = $1
	`, keyHash)

	agent, err := scanAgent(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("agent not found: %w", repository.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}

	return agent, nil
}

// ─── I-004 agent retirement surface ──────────────────────────────────────
//
// The methods below implement the I-004 coverage-gap closure. They follow the
// interface contracts in internal/repository/interfaces.go:94-210 (which is the
// spec — keep godoc there in sync if behavior changes).

// ListRetired returns a paginated slice of retired agents ordered by
// retired_at DESC so the most recent retirements appear first. Used by the
// GUI's Retired tab and the audit export path. Returns the rows plus the
// total count (for pagination UI). page<1 or perPage<1 is clamped to
// sensible defaults in-repo rather than erroring, matching the ListAgents
// pagination behavior at the service layer. I-004, migration 000015.
func (r *AgentRepository) ListRetired(ctx context.Context, page, perPage int) ([]*domain.Agent, int, error) {
	// Clamp pagination to safe defaults. Keep in lockstep with the service
	// layer's pagination shape — negative / zero values on either axis should
	// degrade to "first page, default size" instead of returning an error.
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	// Total count first — separate query so pagination math stays correct
	// even when the page of rows is empty. Uses the partial
	// idx_agents_retired_at index so this is effectively a count of the
	// partial-index tuple count, not a full table scan.
	var total int
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM agents WHERE retired_at IS NOT NULL
	`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count retired agents: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		       os, architecture, ip_address, version, retired_at, retired_reason
		FROM agents
		WHERE retired_at IS NOT NULL
		ORDER BY retired_at DESC
		LIMIT $1 OFFSET $2
	`, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query retired agents: %w", err)
	}
	defer rows.Close()

	var agents []*domain.Agent
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, 0, err
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating retired agent rows: %w", err)
	}
	return agents, total, nil
}

// SoftRetire stamps retired_at + retired_reason on the agent row with no
// cascade. Scoped to `WHERE id=$1 AND retired_at IS NULL` so re-retiring an
// already-retired row is a silent no-op (zero RowsAffected). The service
// layer has its own idempotent-retire branch that detects already-retired
// rows via Get before calling SoftRetire; a zero here just means a racy
// caller got there first. I-004.
func (r *AgentRepository) SoftRetire(ctx context.Context, id string, retiredAt time.Time, reason string) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE agents
		SET retired_at = $2, retired_reason = $3
		WHERE id = $1 AND retired_at IS NULL
	`, id, retiredAt, reason); err != nil {
		return fmt.Errorf("failed to soft-retire agent: %w", err)
	}
	return nil
}

// RetireAgentWithCascade performs a transactional retire-and-cascade. In one
// transaction it (1) stamps retired_at + retired_reason on the agent row if
// it is still active, and (2) stamps the SAME retired_at + retired_reason on
// every active (retired_at IS NULL) deployment_targets row whose agent_id
// matches. Already-retired targets keep their original retirement metadata;
// only active targets are touched. If the agent is already retired, the
// whole transaction is a no-op — the caller's idempotent-retire branch
// already handled it before we got here. I-004, migration 000015.
//
// The two UPDATEs share a single (retiredAt, reason) pair so forensic
// analysis can trace "every row stamped at T1 with reason R was part of the
// same operator action" back to one cascade. Using BeginTx keeps the agent
// row and its targets' retirement metadata consistent even if something
// crashes mid-cascade.
func (r *AgentRepository) RetireAgentWithCascade(ctx context.Context, id string, retiredAt time.Time, reason string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin retire-cascade transaction: %w", err)
	}
	// Rollback is a no-op if Commit has already run — safe to always defer.
	defer func() { _ = tx.Rollback() }()

	// Agent row: flip to retired only if it was still active. If zero rows
	// match, the agent was already retired — the whole cascade becomes a
	// no-op (we deliberately do NOT stamp the targets against a retirement
	// we didn't perform).
	if _, err := tx.ExecContext(ctx, `
		UPDATE agents
		SET retired_at = $2, retired_reason = $3
		WHERE id = $1 AND retired_at IS NULL
	`, id, retiredAt, reason); err != nil {
		return fmt.Errorf("failed to retire agent in cascade: %w", err)
	}

	// Cascade: copy the same retired_at / retired_reason onto every active
	// deployment_target belonging to this agent. Skips targets that are
	// already retired so their original retirement metadata is preserved.
	if _, err := tx.ExecContext(ctx, `
		UPDATE deployment_targets
		SET retired_at = $2, retired_reason = $3
		WHERE agent_id = $1 AND retired_at IS NULL
	`, id, retiredAt, reason); err != nil {
		return fmt.Errorf("failed to cascade-retire deployment targets: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit retire-cascade transaction: %w", err)
	}
	return nil
}

// CountActiveTargets returns the number of deployment_targets with
// agent_id=agentID AND retired_at IS NULL. Used by the retirement preflight
// to decide 200 (soft-retire) vs 409 (blocked-by-deps). Hits the existing
// idx_deployment_targets_agent_id index (migration 000001 line 111); the
// retired_at IS NULL predicate is cheap because the partial
// idx_deployment_targets_retired_at index (migration 000015) lets the
// planner skip the retired-row segment. I-004.
func (r *AgentRepository) CountActiveTargets(ctx context.Context, agentID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM deployment_targets
		WHERE agent_id = $1 AND retired_at IS NULL
	`, agentID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active targets for agent: %w", err)
	}
	return count, nil
}

// CountActiveCertificates returns the count of distinct managed_certificates
// currently deployed through one of this agent's ACTIVE deployment_targets.
// Joins certificate_target_mappings (migration 000001 line 116) →
// deployment_targets filtering on deployment_targets.agent_id=$1 AND
// deployment_targets.retired_at IS NULL. COUNT(DISTINCT certificate_id) so
// the same cert deployed to multiple targets on one agent counts once.
// Used purely for the preflight 409 body. I-004.
func (r *AgentRepository) CountActiveCertificates(ctx context.Context, agentID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT ctm.certificate_id)
		FROM certificate_target_mappings ctm
		JOIN deployment_targets dt ON dt.id = ctm.target_id
		WHERE dt.agent_id = $1 AND dt.retired_at IS NULL
	`, agentID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active certificates for agent: %w", err)
	}
	return count, nil
}

// CountPendingJobs returns the number of jobs belonging to this agent whose
// status is in (Pending, AwaitingCSR, AwaitingApproval, Running) — the four
// statuses that represent work the agent would still be expected to pick up
// or complete. Completed / Failed / Cancelled jobs do not count toward the
// preflight gate. Status strings match domain.JobStatus* constants in
// internal/domain/job.go:43-49. Hits idx_jobs_agent_id (migration 000001
// line 161). I-004.
func (r *AgentRepository) CountPendingJobs(ctx context.Context, agentID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM jobs
		WHERE agent_id = $1
		  AND status IN ('Pending', 'AwaitingCSR', 'AwaitingApproval', 'Running')
	`, agentID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count pending jobs for agent: %w", err)
	}
	return count, nil
}

// scanAgent scans an agent from a row or rows.
//
// I-004: the column list here is the authoritative 13-field post-M15 order —
// retired_at and retired_reason are appended at the tail as nullable
// *time.Time / *string scan targets matching the `json:"...,omitempty"` domain
// fields. Every SELECT in this file that feeds scanAgent must emit columns in
// this same order, otherwise Scan will silently place values into the wrong
// fields (lib/pq does positional binding, not named).
func scanAgent(scanner interface {
	Scan(...interface{}) error
}) (*domain.Agent, error) {
	var agent domain.Agent
	err := scanner.Scan(&agent.ID, &agent.Name, &agent.Hostname, &agent.Status,
		&agent.LastHeartbeatAt, &agent.RegisteredAt, &agent.APIKeyHash,
		&agent.OS, &agent.Architecture, &agent.IPAddress, &agent.Version,
		&agent.RetiredAt, &agent.RetiredReason)

	if err != nil {
		return nil, fmt.Errorf("failed to scan agent: %w", err)
	}

	return &agent, nil
}
