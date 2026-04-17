package postgres

import (
	"context"
	"database/sql"
	"fmt"
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

// List returns all agents
func (r *AgentRepository) List(ctx context.Context) ([]*domain.Agent, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		       os, architecture, ip_address, version
		FROM agents
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

// Get retrieves an agent by ID
func (r *AgentRepository) Get(ctx context.Context, id string) (*domain.Agent, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		       os, architecture, ip_address, version
		FROM agents
		WHERE id = $1
	`, id)

	agent, err := scanAgent(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("agent not found")
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
		return fmt.Errorf("agent not found")
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
		return fmt.Errorf("agent not found")
	}

	return nil
}

// UpdateHeartbeat updates the agent's last heartbeat timestamp and metadata
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
			WHERE id = $2
		`, time.Now(), id, metadata.Hostname, metadata.OS, metadata.Architecture, metadata.IPAddress, metadata.Version)
	} else {
		result, err = r.db.ExecContext(ctx, `
			UPDATE agents SET last_heartbeat_at = $1 WHERE id = $2
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
		return fmt.Errorf("agent not found")
	}

	return nil
}

// GetByAPIKey retrieves an agent by hashed API key
func (r *AgentRepository) GetByAPIKey(ctx context.Context, keyHash string) (*domain.Agent, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash,
		       os, architecture, ip_address, version
		FROM agents
		WHERE api_key_hash = $1
	`, keyHash)

	agent, err := scanAgent(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("agent not found")
		}
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}

	return agent, nil
}

// scanAgent scans an agent from a row or rows
func scanAgent(scanner interface {
	Scan(...interface{}) error
}) (*domain.Agent, error) {
	var agent domain.Agent
	err := scanner.Scan(&agent.ID, &agent.Name, &agent.Hostname, &agent.Status,
		&agent.LastHeartbeatAt, &agent.RegisteredAt, &agent.APIKeyHash,
		&agent.OS, &agent.Architecture, &agent.IPAddress, &agent.Version)

	if err != nil {
		return nil, fmt.Errorf("failed to scan agent: %w", err)
	}

	return &agent, nil
}
