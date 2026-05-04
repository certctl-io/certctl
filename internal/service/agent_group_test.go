package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// mockAgentGroupRepo is a test implementation of AgentGroupRepository
type mockAgentGroupRepo struct {
	groups          map[string]*domain.AgentGroup
	members         map[string][]*domain.Agent
	CreateErr       error
	UpdateErr       error
	DeleteErr       error
	GetErr          error
	ListErr         error
	ListMembersErr  error
	AddMemberErr    error
	RemoveMemberErr error
}

func newMockAgentGroupRepository() *mockAgentGroupRepo {
	return &mockAgentGroupRepo{
		groups:  make(map[string]*domain.AgentGroup),
		members: make(map[string][]*domain.Agent),
	}
}

func (m *mockAgentGroupRepo) List(ctx context.Context) ([]*domain.AgentGroup, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var groups []*domain.AgentGroup
	for _, g := range m.groups {
		groups = append(groups, g)
	}
	return groups, nil
}

func (m *mockAgentGroupRepo) Get(ctx context.Context, id string) (*domain.AgentGroup, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	group, ok := m.groups[id]
	if !ok {
		return nil, errNotFound
	}
	return group, nil
}

func (m *mockAgentGroupRepo) Create(ctx context.Context, group *domain.AgentGroup) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.groups[group.ID] = group
	return nil
}

func (m *mockAgentGroupRepo) Update(ctx context.Context, group *domain.AgentGroup) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.groups[group.ID] = group
	return nil
}

func (m *mockAgentGroupRepo) Delete(ctx context.Context, id string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.groups, id)
	delete(m.members, id)
	return nil
}

func (m *mockAgentGroupRepo) ListMembers(ctx context.Context, groupID string) ([]*domain.Agent, error) {
	if m.ListMembersErr != nil {
		return nil, m.ListMembersErr
	}
	members := m.members[groupID]
	if members == nil {
		return make([]*domain.Agent, 0), nil
	}
	return members, nil
}

func (m *mockAgentGroupRepo) AddMember(ctx context.Context, groupID, agentID, membershipType string) error {
	if m.AddMemberErr != nil {
		return m.AddMemberErr
	}
	// For testing purposes, we'll assume a simple mock agent
	agent := &domain.Agent{
		ID:   agentID,
		Name: "test-agent-" + agentID,
	}
	m.members[groupID] = append(m.members[groupID], agent)
	return nil
}

func (m *mockAgentGroupRepo) RemoveMember(ctx context.Context, groupID, agentID string) error {
	if m.RemoveMemberErr != nil {
		return m.RemoveMemberErr
	}
	members := m.members[groupID]
	var filtered []*domain.Agent
	for _, m := range members {
		if m.ID != agentID {
			filtered = append(filtered, m)
		}
	}
	m.members[groupID] = filtered
	return nil
}

func (m *mockAgentGroupRepo) AddGroup(group *domain.AgentGroup) {
	m.groups[group.ID] = group
}

func (m *mockAgentGroupRepo) AddGroupMembers(groupID string, agents []*domain.Agent) {
	m.members[groupID] = agents
}

// Test: ListAgentGroups returns groups
func TestAgentGroupService_ListAgentGroups(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group1 := &domain.AgentGroup{
		ID:   "ag-test-1",
		Name: "Linux Servers",
	}
	group2 := &domain.AgentGroup{
		ID:   "ag-test-2",
		Name: "Windows Servers",
	}
	repo.AddGroup(group1)
	repo.AddGroup(group2)

	groups, total, err := svc.ListAgentGroups(context.Background(), 1, 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
}

// Test: ListAgentGroups with default pagination
func TestAgentGroupService_ListAgentGroups_DefaultPagination(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := &domain.AgentGroup{
		ID:   "ag-test-1",
		Name: "Test Group",
	}
	repo.AddGroup(group)

	// page < 1 should default to 1, perPage < 1 should default to 50
	groups, total, err := svc.ListAgentGroups(context.Background(), -1, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}
}

// Test: ListAgentGroups with repository error
func TestAgentGroupService_ListAgentGroups_RepositoryError(t *testing.T) {
	repo := newMockAgentGroupRepository()
	repo.ListErr = errors.New("database error")
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	_, _, err := svc.ListAgentGroups(context.Background(), 1, 50)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to list agent groups") {
		t.Errorf("expected 'failed to list agent groups' in error, got %v", err)
	}
}

// Test: ListAgentGroups with empty result
func TestAgentGroupService_ListAgentGroups_EmptyResult(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	groups, total, err := svc.ListAgentGroups(context.Background(), 1, 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if total != 0 {
		t.Errorf("expected total=0, got %d", total)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}

// Test: GetAgentGroup success
func TestAgentGroupService_GetAgentGroup(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := &domain.AgentGroup{
		ID:   "ag-test-1",
		Name: "Test Group",
	}
	repo.AddGroup(group)

	retrieved, err := svc.GetAgentGroup(context.Background(), "ag-test-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected group, got nil")
	}
	if retrieved.ID != "ag-test-1" {
		t.Errorf("expected ID 'ag-test-1', got %s", retrieved.ID)
	}
	if retrieved.Name != "Test Group" {
		t.Errorf("expected name 'Test Group', got %s", retrieved.Name)
	}
}

// Test: GetAgentGroup not found
func TestAgentGroupService_GetAgentGroup_NotFound(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	_, err := svc.GetAgentGroup(context.Background(), "ag-nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errNotFound) {
		t.Errorf("expected errNotFound, got %v", err)
	}
}

// Test: CreateAgentGroup success with ID generated and timestamps
func TestAgentGroupService_CreateAgentGroup(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := domain.AgentGroup{
		Name: "Test Group",
	}
	before := time.Now()

	created, err := svc.CreateAgentGroup(context.Background(), group)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if created == nil {
		t.Fatal("expected group, got nil")
	}

	// ID should be generated
	if created.ID == "" {
		t.Fatal("expected ID to be generated, got empty string")
	}
	if !strings.HasPrefix(created.ID, "ag-") {
		t.Errorf("expected ID to start with 'ag-', got %s", created.ID)
	}

	// Timestamps should be set
	if created.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}
	if created.UpdatedAt.IsZero() {
		t.Fatal("expected UpdatedAt to be set")
	}
	if created.CreatedAt.Before(before) {
		t.Errorf("expected CreatedAt >= before, got %v < %v", created.CreatedAt, before)
	}

	// Should be in repository
	retrieved, err := repo.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if retrieved.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, retrieved.ID)
	}

	// Audit event should be recorded
	if len(auditRepo.Events) == 0 {
		t.Fatal("expected audit event to be recorded")
	}
	if auditRepo.Events[0].Action != "create_agent_group" {
		t.Errorf("expected action 'create_agent_group', got %s", auditRepo.Events[0].Action)
	}
}

// Test: CreateAgentGroup with empty name
func TestAgentGroupService_CreateAgentGroup_EmptyName(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := domain.AgentGroup{
		Name: "",
	}

	_, err := svc.CreateAgentGroup(context.Background(), group)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "agent group name is required") {
		t.Errorf("expected 'agent group name is required' in error, got %v", err)
	}
}

// Test: CreateAgentGroup with name too long
func TestAgentGroupService_CreateAgentGroup_NameTooLong(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := domain.AgentGroup{
		Name: strings.Repeat("a", 256),
	}

	_, err := svc.CreateAgentGroup(context.Background(), group)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds 255 characters") {
		t.Errorf("expected 'exceeds 255 characters' in error, got %v", err)
	}
}

// Test: CreateAgentGroup with existing ID preserves ID
func TestAgentGroupService_CreateAgentGroup_WithExistingID(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := domain.AgentGroup{
		ID:   "ag-custom-id",
		Name: "Test Group",
	}

	created, err := svc.CreateAgentGroup(context.Background(), group)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if created.ID != "ag-custom-id" {
		t.Errorf("expected ID 'ag-custom-id', got %s", created.ID)
	}
}

// Test: CreateAgentGroup with dynamic criteria
func TestAgentGroupService_CreateAgentGroup_WithDynamicCriteria(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := domain.AgentGroup{
		Name:              "Linux x86_64 Servers",
		MatchOS:           "linux",
		MatchArchitecture: "amd64",
	}

	created, err := svc.CreateAgentGroup(context.Background(), group)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if created.MatchOS != "linux" {
		t.Errorf("expected MatchOS 'linux', got %s", created.MatchOS)
	}
	if created.MatchArchitecture != "amd64" {
		t.Errorf("expected MatchArchitecture 'amd64', got %s", created.MatchArchitecture)
	}
}

// Test: CreateAgentGroup with repository error
func TestAgentGroupService_CreateAgentGroup_RepositoryError(t *testing.T) {
	repo := newMockAgentGroupRepository()
	repo.CreateErr = errors.New("database error")
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := domain.AgentGroup{
		Name: "Test Group",
	}

	_, err := svc.CreateAgentGroup(context.Background(), group)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to create agent group") {
		t.Errorf("expected 'failed to create agent group' in error, got %v", err)
	}
}

// Test: UpdateAgentGroup success
func TestAgentGroupService_UpdateAgentGroup(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	existing := &domain.AgentGroup{
		ID:   "ag-test-1",
		Name: "Old Name",
	}
	repo.AddGroup(existing)

	updated := domain.AgentGroup{
		Name: "New Name",
	}

	result, err := svc.UpdateAgentGroup(context.Background(), "ag-test-1", updated)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID != "ag-test-1" {
		t.Errorf("expected ID 'ag-test-1', got %s", result.ID)
	}
	if result.Name != "New Name" {
		t.Errorf("expected name 'New Name', got %s", result.Name)
	}

	// Audit event should be recorded
	if len(auditRepo.Events) == 0 {
		t.Fatal("expected audit event to be recorded")
	}
	if auditRepo.Events[0].Action != "update_agent_group" {
		t.Errorf("expected action 'update_agent_group', got %s", auditRepo.Events[0].Action)
	}
}

// Test: UpdateAgentGroup with empty name validation error
func TestAgentGroupService_UpdateAgentGroup_EmptyName(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	updated := domain.AgentGroup{
		Name: "",
	}

	_, err := svc.UpdateAgentGroup(context.Background(), "ag-test-1", updated)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "agent group name is required") {
		t.Errorf("expected 'agent group name is required' in error, got %v", err)
	}
}

// Test: UpdateAgentGroup with repository error
func TestAgentGroupService_UpdateAgentGroup_RepositoryError(t *testing.T) {
	repo := newMockAgentGroupRepository()
	repo.UpdateErr = errors.New("database error")
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	updated := domain.AgentGroup{
		Name: "Valid Name",
	}

	_, err := svc.UpdateAgentGroup(context.Background(), "ag-test-1", updated)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to update agent group") {
		t.Errorf("expected 'failed to update agent group' in error, got %v", err)
	}
}

// Test: DeleteAgentGroup success with audit
func TestAgentGroupService_DeleteAgentGroup(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	group := &domain.AgentGroup{
		ID:   "ag-test-1",
		Name: "Test Group",
	}
	repo.AddGroup(group)

	err := svc.DeleteAgentGroup(context.Background(), "ag-test-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Group should be deleted from repository
	_, err = repo.Get(context.Background(), "ag-test-1")
	if !errors.Is(err, errNotFound) {
		t.Errorf("expected errNotFound after delete, got %v", err)
	}

	// Audit event should be recorded
	if len(auditRepo.Events) == 0 {
		t.Fatal("expected audit event to be recorded")
	}
	if auditRepo.Events[0].Action != "delete_agent_group" {
		t.Errorf("expected action 'delete_agent_group', got %s", auditRepo.Events[0].Action)
	}
}

// Test: DeleteAgentGroup with repository error
func TestAgentGroupService_DeleteAgentGroup_RepositoryError(t *testing.T) {
	repo := newMockAgentGroupRepository()
	repo.DeleteErr = errors.New("database error")
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	err := svc.DeleteAgentGroup(context.Background(), "ag-test-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to delete agent group") {
		t.Errorf("expected 'failed to delete agent group' in error, got %v", err)
	}
}

// Test: ListMembers returns agents
func TestAgentGroupService_ListMembers(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	agents := []*domain.Agent{
		{
			ID:   "agent-1",
			Name: "Agent 1",
		},
		{
			ID:   "agent-2",
			Name: "Agent 2",
		},
	}
	repo.AddGroupMembers("ag-test-1", agents)

	result, total, err := svc.ListMembers(context.Background(), "ag-test-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 agents, got %d", len(result))
	}
	if result[0].ID != "agent-1" {
		t.Errorf("expected first agent ID 'agent-1', got %s", result[0].ID)
	}
}

// Test: ListMembers returns empty when no agents
func TestAgentGroupService_ListMembers_Empty(t *testing.T) {
	repo := newMockAgentGroupRepository()
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	result, total, err := svc.ListMembers(context.Background(), "ag-test-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if total != 0 {
		t.Errorf("expected total=0, got %d", total)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 agents, got %d", len(result))
	}
}

// Test: ListMembers with repository error
func TestAgentGroupService_ListMembers_RepositoryError(t *testing.T) {
	repo := newMockAgentGroupRepository()
	repo.ListMembersErr = errors.New("database error")
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	svc := NewAgentGroupService(repo, auditSvc)

	_, _, err := svc.ListMembers(context.Background(), "ag-test-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to list group members") {
		t.Errorf("expected 'failed to list group members' in error, got %v", err)
	}
}

// Test: AgentGroup.MatchesAgent with all criteria matching
func TestAgentGroup_MatchesAgent(t *testing.T) {
	group := &domain.AgentGroup{
		MatchOS:           "linux",
		MatchArchitecture: "amd64",
		MatchVersion:      "1.0.0",
	}
	agent := &domain.Agent{
		OS:           "linux",
		Architecture: "amd64",
		Version:      "1.0.0",
	}

	matches := group.MatchesAgent(agent)
	if !matches {
		t.Fatal("expected agent to match all criteria")
	}
}

// Test: AgentGroup.MatchesAgent with OS mismatch
func TestAgentGroup_MatchesAgent_OSMismatch(t *testing.T) {
	group := &domain.AgentGroup{
		MatchOS:           "linux",
		MatchArchitecture: "amd64",
	}
	agent := &domain.Agent{
		OS:           "windows",
		Architecture: "amd64",
	}

	matches := group.MatchesAgent(agent)
	if matches {
		t.Fatal("expected agent NOT to match due to OS mismatch")
	}
}

// Test: AgentGroup.MatchesAgent with empty criteria matches any agent
func TestAgentGroup_MatchesAgent_EmptyCriteria(t *testing.T) {
	group := &domain.AgentGroup{
		// All criteria empty (wildcards)
	}
	agent := &domain.Agent{
		OS:           "linux",
		Architecture: "arm64",
		Version:      "2.0.0",
	}

	matches := group.MatchesAgent(agent)
	if !matches {
		t.Fatal("expected agent to match empty criteria (wildcard)")
	}
}

// Test: AgentGroup.HasDynamicCriteria returns true when criteria set
func TestAgentGroup_HasDynamicCriteria(t *testing.T) {
	group := &domain.AgentGroup{
		MatchOS: "linux",
	}

	if !group.HasDynamicCriteria() {
		t.Fatal("expected HasDynamicCriteria to return true")
	}
}

// Test: AgentGroup.HasDynamicCriteria returns false when empty
func TestAgentGroup_HasDynamicCriteria_Empty(t *testing.T) {
	group := &domain.AgentGroup{
		// All criteria empty
	}

	if group.HasDynamicCriteria() {
		t.Fatal("expected HasDynamicCriteria to return false")
	}
}
