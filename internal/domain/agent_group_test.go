package domain

import "testing"

func TestAgentGroup_HasDynamicCriteria_True(t *testing.T) {
	tests := []AgentGroup{
		{MatchOS: "linux"},
		{MatchArchitecture: "amd64"},
		{MatchIPCIDR: "192.168.1.0/24"},
		{MatchVersion: "1.0.0"},
		{MatchOS: "linux", MatchArchitecture: "amd64"},
	}
	for i, g := range tests {
		if !g.HasDynamicCriteria() {
			t.Errorf("test %d: expected HasDynamicCriteria=true, got false", i)
		}
	}
}

func TestAgentGroup_HasDynamicCriteria_False(t *testing.T) {
	tests := []AgentGroup{
		{},
		{Name: "test-group"},
		{Description: "some description"},
		{Name: "test-group", Description: "description", Enabled: true},
	}
	for i, g := range tests {
		if g.HasDynamicCriteria() {
			t.Errorf("test %d: expected HasDynamicCriteria=false, got true", i)
		}
	}
}

func TestAgentGroup_MatchesAgent_AllCriteriaMatch(t *testing.T) {
	group := &AgentGroup{
		MatchOS:           "linux",
		MatchArchitecture: "amd64",
		MatchVersion:      "1.0.0",
		MatchIPCIDR:       "192.168.1.1",
	}

	agent := &Agent{
		OS:           "linux",
		Architecture: "amd64",
		Version:      "1.0.0",
		IPAddress:    "192.168.1.1",
	}

	if !group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=true, got false")
	}
}

func TestAgentGroup_MatchesAgent_OSMismatch(t *testing.T) {
	group := &AgentGroup{
		MatchOS: "linux",
	}

	agent := &Agent{
		OS: "darwin",
	}

	if group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=false (OS mismatch), got true")
	}
}

func TestAgentGroup_MatchesAgent_ArchMismatch(t *testing.T) {
	group := &AgentGroup{
		MatchArchitecture: "amd64",
	}

	agent := &Agent{
		Architecture: "arm64",
	}

	if group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=false (architecture mismatch), got true")
	}
}

func TestAgentGroup_MatchesAgent_VersionMismatch(t *testing.T) {
	group := &AgentGroup{
		MatchVersion: "1.0.0",
	}

	agent := &Agent{
		Version: "2.0.0",
	}

	if group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=false (version mismatch), got true")
	}
}

func TestAgentGroup_MatchesAgent_IPMismatch(t *testing.T) {
	group := &AgentGroup{
		MatchIPCIDR: "192.168.1.1",
	}

	agent := &Agent{
		IPAddress: "192.168.1.2",
	}

	if group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=false (IP mismatch), got true")
	}
}

func TestAgentGroup_MatchesAgent_EmptyCriteriaMatchesAll(t *testing.T) {
	group := &AgentGroup{}

	agent := &Agent{
		OS:           "linux",
		Architecture: "amd64",
		Version:      "1.0.0",
		IPAddress:    "192.168.1.1",
	}

	if !group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=true (empty criteria matches all), got false")
	}
}

func TestAgentGroup_MatchesAgent_PartialCriteria(t *testing.T) {
	group := &AgentGroup{
		MatchOS:           "linux",
		MatchArchitecture: "amd64",
	}

	agent := &Agent{
		OS:           "linux",
		Architecture: "amd64",
		Version:      "1.0.0",
		IPAddress:    "192.168.1.1",
	}

	if !group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=true (partial criteria), got false")
	}
}

func TestAgentGroup_MatchesAgent_MultipleMatches(t *testing.T) {
	group := &AgentGroup{
		MatchOS:           "linux",
		MatchArchitecture: "amd64",
		MatchVersion:      "1.0.0",
	}

	// Matching agent
	agent := &Agent{
		OS:           "linux",
		Architecture: "amd64",
		Version:      "1.0.0",
	}

	if !group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=true for matching agent, got false")
	}

	// Non-matching agent (version mismatch)
	agent.Version = "0.9.0"
	if group.MatchesAgent(agent) {
		t.Errorf("expected MatchesAgent=false for non-matching agent, got true")
	}
}
