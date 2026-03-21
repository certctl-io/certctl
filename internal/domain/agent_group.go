package domain

import (
	"time"
)

// AgentGroup defines a logical grouping of agents based on metadata criteria
// and/or manual membership. Used for policy scoping and fleet management.
type AgentGroup struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	MatchOS           string    `json:"match_os"`
	MatchArchitecture string    `json:"match_architecture"`
	MatchIPCIDR       string    `json:"match_ip_cidr"`
	MatchVersion      string    `json:"match_version"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// AgentGroupMembership represents an explicit (manual) agent-to-group mapping.
type AgentGroupMembership struct {
	AgentGroupID   string    `json:"agent_group_id"`
	AgentID        string    `json:"agent_id"`
	MembershipType string    `json:"membership_type"` // "include" or "exclude"
	CreatedAt      time.Time `json:"created_at"`
}

// HasDynamicCriteria returns true if this group defines at least one metadata match rule.
func (g *AgentGroup) HasDynamicCriteria() bool {
	return g.MatchOS != "" || g.MatchArchitecture != "" || g.MatchIPCIDR != "" || g.MatchVersion != ""
}

// MatchesAgent checks whether an agent's metadata matches all non-empty criteria.
// Empty criteria fields are treated as wildcards (match anything).
func (g *AgentGroup) MatchesAgent(agent *Agent) bool {
	if g.MatchOS != "" && agent.OS != g.MatchOS {
		return false
	}
	if g.MatchArchitecture != "" && agent.Architecture != g.MatchArchitecture {
		return false
	}
	if g.MatchVersion != "" && agent.Version != g.MatchVersion {
		return false
	}
	// IP CIDR matching is more complex — for now, do exact match on the field.
	// Full CIDR parsing (net.ParseCIDR + Contains) deferred to when we have real use cases.
	if g.MatchIPCIDR != "" && agent.IPAddress != g.MatchIPCIDR {
		return false
	}
	return true
}
