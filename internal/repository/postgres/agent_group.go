package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/certctl-io/certctl/internal/repository"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// AgentGroupRepository implements agent group CRUD with PostgreSQL.
type AgentGroupRepository struct {
	db *sql.DB
}

// NewAgentGroupRepository creates a new PostgreSQL-backed agent group repository.
func NewAgentGroupRepository(db *sql.DB) *AgentGroupRepository {
	return &AgentGroupRepository{db: db}
}

// List returns all agent groups.
func (r *AgentGroupRepository) List(ctx context.Context) ([]*domain.AgentGroup, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, description, match_os, match_architecture, match_ip_cidr, match_version, enabled, created_at, updated_at
		 FROM agent_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query agent groups: %w", err)
	}
	defer rows.Close()

	var groups []*domain.AgentGroup
	for rows.Next() {
		g, err := scanAgentGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// Get retrieves an agent group by ID.
func (r *AgentGroupRepository) Get(ctx context.Context, id string) (*domain.AgentGroup, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, description, match_os, match_architecture, match_ip_cidr, match_version, enabled, created_at, updated_at
		 FROM agent_groups WHERE id = $1`, id)

	g := &domain.AgentGroup{}
	err := row.Scan(&g.ID, &g.Name, &g.Description, &g.MatchOS, &g.MatchArchitecture,
		&g.MatchIPCIDR, &g.MatchVersion, &g.Enabled, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("agent group not found: %w", repository.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get agent group: %w", err)
	}
	return g, nil
}

// Create stores a new agent group.
func (r *AgentGroupRepository) Create(ctx context.Context, group *domain.AgentGroup) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO agent_groups (id, name, description, match_os, match_architecture, match_ip_cidr, match_version, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		group.ID, group.Name, group.Description, group.MatchOS, group.MatchArchitecture,
		group.MatchIPCIDR, group.MatchVersion, group.Enabled, group.CreatedAt, group.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create agent group: %w", err)
	}
	return nil
}

// Update modifies an existing agent group.
func (r *AgentGroupRepository) Update(ctx context.Context, group *domain.AgentGroup) error {
	group.UpdatedAt = time.Now()
	result, err := r.db.ExecContext(ctx,
		`UPDATE agent_groups SET name=$1, description=$2, match_os=$3, match_architecture=$4, match_ip_cidr=$5, match_version=$6, enabled=$7, updated_at=$8
		 WHERE id=$9`,
		group.Name, group.Description, group.MatchOS, group.MatchArchitecture,
		group.MatchIPCIDR, group.MatchVersion, group.Enabled, group.UpdatedAt, group.ID)
	if err != nil {
		return fmt.Errorf("failed to update agent group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("agent group not found: %w", repository.ErrNotFound)
	}
	return nil
}

// Delete removes an agent group.
func (r *AgentGroupRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM agent_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete agent group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("agent group not found: %w", repository.ErrNotFound)
	}
	return nil
}

// ListMembers returns agents that belong to a group (manual includes only for now).
func (r *AgentGroupRepository) ListMembers(ctx context.Context, groupID string) ([]*domain.Agent, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT a.id, a.name, a.hostname, a.status, a.last_heartbeat_at, a.registered_at, a.api_key_hash, a.os, a.architecture, a.ip_address, a.version
		 FROM agents a
		 INNER JOIN agent_group_members m ON a.id = m.agent_id
		 WHERE m.agent_group_id = $1 AND m.membership_type = 'include'
		 ORDER BY a.name`, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list group members: %w", err)
	}
	defer rows.Close()

	var agents []*domain.Agent
	for rows.Next() {
		a := &domain.Agent{}
		var lastHeartbeat sql.NullTime
		err := rows.Scan(&a.ID, &a.Name, &a.Hostname, &a.Status, &lastHeartbeat,
			&a.RegisteredAt, &a.APIKeyHash, &a.OS, &a.Architecture, &a.IPAddress, &a.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to scan agent: %w", err)
		}
		if lastHeartbeat.Valid {
			a.LastHeartbeatAt = &lastHeartbeat.Time
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// AddMember adds a manual membership.
func (r *AgentGroupRepository) AddMember(ctx context.Context, groupID, agentID, membershipType string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO agent_group_members (agent_group_id, agent_id, membership_type, created_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (agent_group_id, agent_id) DO UPDATE SET membership_type = $3`,
		groupID, agentID, membershipType, time.Now())
	if err != nil {
		return fmt.Errorf("failed to add group member: %w", err)
	}
	return nil
}

// RemoveMember removes a manual membership.
func (r *AgentGroupRepository) RemoveMember(ctx context.Context, groupID, agentID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM agent_group_members WHERE agent_group_id = $1 AND agent_id = $2`,
		groupID, agentID)
	if err != nil {
		return fmt.Errorf("failed to remove group member: %w", err)
	}
	return nil
}

// scanAgentGroup scans a single agent group row.
func scanAgentGroup(rows *sql.Rows) (*domain.AgentGroup, error) {
	g := &domain.AgentGroup{}
	err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.MatchOS, &g.MatchArchitecture,
		&g.MatchIPCIDR, &g.MatchVersion, &g.Enabled, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to scan agent group: %w", err)
	}
	return g, nil
}
