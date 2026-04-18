package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// newTestTargetService creates a TargetService with mock repositories for testing.
func newTestTargetService() (*TargetService, *mockTargetRepo, *mockAuditRepo, *mockAgentRepo) {
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
	auditRepo := newMockAuditRepository()
	auditSvc := NewAuditService(auditRepo)
	agentRepo := &mockAgentRepo{Agents: make(map[string]*domain.Agent), HeartbeatUpdates: make(map[string]time.Time)}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewTargetService(targetRepo, auditSvc, agentRepo, testEncryptionKey, logger), targetRepo, auditRepo, agentRepo
}

func TestTargetService_List_Success(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()
	ctx := context.Background()

	// Add 3 targets
	target1 := &domain.DeploymentTarget{ID: "t-1", Name: "Target 1", Type: domain.TargetTypeNGINX}
	target2 := &domain.DeploymentTarget{ID: "t-2", Name: "Target 2", Type: domain.TargetTypeApache}
	target3 := &domain.DeploymentTarget{ID: "t-3", Name: "Target 3", Type: domain.TargetTypeHAProxy}
	targetRepo.AddTarget(target1)
	targetRepo.AddTarget(target2)
	targetRepo.AddTarget(target3)

	// Request page 1, perPage 2
	targets, total, err := svc.List(ctx, 1, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(targets))
	}

	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
}

func TestTargetService_List_DefaultPagination(t *testing.T) {
	svc, _, _, _ := newTestTargetService()
	ctx := context.Background()

	// Call with invalid pagination (page=0, perPage=0)
	targets, total, err := svc.List(ctx, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic; should use defaults (page=1, perPage=50)
	if targets != nil || total != 0 {
		t.Errorf("expected empty list with defaults, got %d targets", len(targets))
	}
}

func TestTargetService_List_EmptyPage(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()
	ctx := context.Background()

	// Add 3 targets
	target1 := &domain.DeploymentTarget{ID: "t-1", Name: "Target 1", Type: domain.TargetTypeNGINX}
	target2 := &domain.DeploymentTarget{ID: "t-2", Name: "Target 2", Type: domain.TargetTypeApache}
	target3 := &domain.DeploymentTarget{ID: "t-3", Name: "Target 3", Type: domain.TargetTypeHAProxy}
	targetRepo.AddTarget(target1)
	targetRepo.AddTarget(target2)
	targetRepo.AddTarget(target3)

	// Request page 2 with perPage 10 (beyond available data)
	targets, total, err := svc.List(ctx, 2, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}

	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
}

func TestTargetService_List_RepoError(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()
	ctx := context.Background()

	// Set repo to return error
	targetRepo.ListErr = errNotFound

	targets, total, err := svc.List(ctx, 1, 50)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if targets != nil || total != 0 {
		t.Errorf("expected nil targets and zero total, got %d targets and %d total", len(targets), total)
	}
}

func TestTargetService_Get_Success(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()
	ctx := context.Background()

	target := &domain.DeploymentTarget{ID: "t-1", Name: "Target 1", Type: domain.TargetTypeNGINX}
	targetRepo.AddTarget(target)

	result, err := svc.Get(ctx, "t-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "t-1" || result.Name != "Target 1" {
		t.Errorf("expected target t-1/Target 1, got %s/%s", result.ID, result.Name)
	}
}

func TestTargetService_Get_NotFound(t *testing.T) {
	svc, _, _, _ := newTestTargetService()
	ctx := context.Background()

	result, err := svc.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatalf("expected error for nonexistent target, got nil")
	}

	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

func TestTargetService_Create_Success(t *testing.T) {
	svc, targetRepo, auditRepo, _ := newTestTargetService()
	ctx := context.Background()

	target := &domain.DeploymentTarget{
		Name:   "New Target",
		Type:   domain.TargetTypeNGINX,
		Config: json.RawMessage(`{"path": "/etc/nginx/certs"}`),
	}

	err := svc.Create(ctx, target, "test-actor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify target was stored
	if target.ID == "" || len(target.ID) < 7 || target.ID[:6] != "target" {
		t.Errorf("expected ID to start with 'target', got %s", target.ID)
	}

	stored, ok := targetRepo.Targets[target.ID]
	if !ok {
		t.Fatalf("target not stored in repo")
	}

	if stored.Name != "New Target" {
		t.Errorf("expected name 'New Target', got %s", stored.Name)
	}

	// Verify timestamps are set
	if target.CreatedAt.IsZero() || target.UpdatedAt.IsZero() {
		t.Errorf("expected timestamps to be set, CreatedAt=%v, UpdatedAt=%v", target.CreatedAt, target.UpdatedAt)
	}

	// Verify test status and source defaults
	if target.TestStatus != "untested" {
		t.Errorf("expected test_status 'untested', got %s", target.TestStatus)
	}
	if target.Source != "database" {
		t.Errorf("expected source 'database', got %s", target.Source)
	}

	// Verify audit event
	if len(auditRepo.Events) == 0 {
		t.Fatalf("expected audit event, got none")
	}

	lastEvent := auditRepo.Events[len(auditRepo.Events)-1]
	if lastEvent.Action != "create_target" {
		t.Errorf("expected action 'create_target', got %s", lastEvent.Action)
	}

	if lastEvent.Actor != "test-actor" {
		t.Errorf("expected actor 'test-actor', got %s", lastEvent.Actor)
	}
}

func TestTargetService_Create_MissingName(t *testing.T) {
	svc, _, _, _ := newTestTargetService()
	ctx := context.Background()

	target := &domain.DeploymentTarget{
		Type: domain.TargetTypeNGINX,
	}

	err := svc.Create(ctx, target, "test-actor")
	if err == nil {
		t.Fatalf("expected error for missing name, got nil")
	}
}

func TestTargetService_Create_InvalidType(t *testing.T) {
	svc, _, _, _ := newTestTargetService()
	ctx := context.Background()

	target := &domain.DeploymentTarget{
		Name: "Bad Target",
		Type: domain.TargetType("InvalidType"),
	}

	err := svc.Create(ctx, target, "test-actor")
	if err == nil {
		t.Fatalf("expected error for invalid type, got nil")
	}
}

func TestTargetService_Create_RepoError(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()
	ctx := context.Background()

	targetRepo.CreateErr = errNotFound

	target := &domain.DeploymentTarget{
		Name: "New Target",
		Type: domain.TargetTypeNGINX,
	}

	err := svc.Create(ctx, target, "test-actor")
	if err == nil {
		t.Fatalf("expected error from repo, got nil")
	}
}

func TestTargetService_Update_Success(t *testing.T) {
	svc, targetRepo, auditRepo, _ := newTestTargetService()
	ctx := context.Background()

	// Create initial target
	existing := &domain.DeploymentTarget{ID: "t-1", Name: "Old Name", Type: domain.TargetTypeNGINX}
	targetRepo.AddTarget(existing)

	// Update it
	updated := &domain.DeploymentTarget{
		Name: "New Name",
		Type: domain.TargetTypeApache,
	}

	err := svc.Update(ctx, "t-1", updated, "test-actor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify update
	stored := targetRepo.Targets["t-1"]
	if stored.Name != "New Name" {
		t.Errorf("expected name 'New Name', got %s", stored.Name)
	}

	// Verify audit event
	if len(auditRepo.Events) == 0 {
		t.Fatalf("expected audit event, got none")
	}

	lastEvent := auditRepo.Events[len(auditRepo.Events)-1]
	if lastEvent.Action != "update_target" {
		t.Errorf("expected action 'update_target', got %s", lastEvent.Action)
	}
}

func TestTargetService_Update_MissingName(t *testing.T) {
	svc, _, _, _ := newTestTargetService()
	ctx := context.Background()

	target := &domain.DeploymentTarget{
		Type: domain.TargetTypeNGINX,
	}

	err := svc.Update(ctx, "t-1", target, "test-actor")
	if err == nil {
		t.Fatalf("expected error for missing name, got nil")
	}
}

func TestTargetService_Delete_Success(t *testing.T) {
	svc, targetRepo, auditRepo, _ := newTestTargetService()
	ctx := context.Background()

	// Create initial target
	target := &domain.DeploymentTarget{ID: "t-1", Name: "Target To Delete", Type: domain.TargetTypeNGINX}
	targetRepo.AddTarget(target)

	// Delete it
	err := svc.Delete(ctx, "t-1", "test-actor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deletion
	if _, ok := targetRepo.Targets["t-1"]; ok {
		t.Errorf("target should be deleted from repo")
	}

	// Verify audit event
	if len(auditRepo.Events) == 0 {
		t.Fatalf("expected audit event, got none")
	}

	lastEvent := auditRepo.Events[len(auditRepo.Events)-1]
	if lastEvent.Action != "delete_target" {
		t.Errorf("expected action 'delete_target', got %s", lastEvent.Action)
	}
}

func TestTargetService_Delete_RepoError(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()
	ctx := context.Background()

	targetRepo.DeleteErr = errNotFound

	err := svc.Delete(ctx, "t-1", "test-actor")
	if err == nil {
		t.Fatalf("expected error from repo, got nil")
	}
}

func TestTargetService_ListTargets_Success(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()

	// Add targets
	target1 := &domain.DeploymentTarget{ID: "t-1", Name: "Target 1", Type: domain.TargetTypeNGINX}
	target2 := &domain.DeploymentTarget{ID: "t-2", Name: "Target 2", Type: domain.TargetTypeApache}
	targetRepo.AddTarget(target1)
	targetRepo.AddTarget(target2)

	// Call handler-interface method
	ctx := context.Background()
	targets, total, err := svc.ListTargets(ctx, 1, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(targets))
	}

	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}
}

func TestTargetService_GetTarget_Success(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()

	target := &domain.DeploymentTarget{ID: "t-1", Name: "Target 1", Type: domain.TargetTypeNGINX}
	targetRepo.AddTarget(target)

	ctx := context.Background()
	result, err := svc.GetTarget(ctx, "t-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "t-1" || result.Name != "Target 1" {
		t.Errorf("expected target t-1/Target 1, got %s/%s", result.ID, result.Name)
	}
}

func TestTargetService_CreateTarget_Success(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()

	target := domain.DeploymentTarget{
		Name: "New Target",
		Type: domain.TargetTypeNGINX,
	}

	ctx := context.Background()
	result, err := svc.CreateTarget(ctx, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID == "" || len(result.ID) < 7 || result.ID[:6] != "target" {
		t.Errorf("expected ID to start with 'target', got %s", result.ID)
	}

	// Verify it was stored
	if _, ok := targetRepo.Targets[result.ID]; !ok {
		t.Fatalf("target not stored in repo")
	}
}

func TestTargetService_CreateTarget_InvalidType(t *testing.T) {
	svc, _, _, _ := newTestTargetService()

	target := domain.DeploymentTarget{
		Name: "Bad Target",
		Type: domain.TargetType("Unknown"),
	}

	ctx := context.Background()
	_, err := svc.CreateTarget(ctx, target)
	if err == nil {
		t.Fatalf("expected error for invalid type, got nil")
	}
}

func TestTargetService_UpdateTarget_Success(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()

	// Create initial target
	target := &domain.DeploymentTarget{ID: "t-1", Name: "Old Name", Type: domain.TargetTypeNGINX}
	targetRepo.AddTarget(target)

	// Update it
	updated := domain.DeploymentTarget{
		Name: "New Name",
		Type: domain.TargetTypeApache,
	}

	ctx := context.Background()
	result, err := svc.UpdateTarget(ctx, "t-1", updated)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Name != "New Name" {
		t.Errorf("expected name 'New Name', got %s", result.Name)
	}
}

func TestTargetService_DeleteTarget_Success(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()

	// Create initial target
	target := &domain.DeploymentTarget{ID: "t-1", Name: "Target To Delete", Type: domain.TargetTypeNGINX}
	targetRepo.AddTarget(target)

	// Delete it
	ctx := context.Background()
	err := svc.DeleteTarget(ctx, "t-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deletion
	if _, ok := targetRepo.Targets["t-1"]; ok {
		t.Errorf("target should be deleted from repo")
	}
}

func TestTargetService_TestConnection_AgentOnline(t *testing.T) {
	svc, targetRepo, _, agentRepo := newTestTargetService()
	ctx := context.Background()

	// Set up agent
	heartbeat := time.Now()
	agent := &domain.Agent{
		ID:              "agent-1",
		Name:            "Test Agent",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &heartbeat,
	}
	agentRepo.Create(ctx, agent)

	// Set up target assigned to agent
	target := &domain.DeploymentTarget{
		ID:      "t-1",
		Name:    "Test Target",
		Type:    domain.TargetTypeNGINX,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	// Test connection should succeed
	err := svc.TestConnection(ctx, "t-1")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	// Verify test status was updated
	stored := targetRepo.Targets["t-1"]
	if stored.TestStatus != "success" {
		t.Errorf("expected test_status 'success', got %s", stored.TestStatus)
	}
	if stored.LastTestedAt == nil {
		t.Error("expected last_tested_at to be set")
	}
}

func TestTargetService_TestConnection_AgentOffline(t *testing.T) {
	svc, targetRepo, _, agentRepo := newTestTargetService()
	ctx := context.Background()

	// Set up offline agent
	agent := &domain.Agent{
		ID:     "agent-1",
		Name:   "Offline Agent",
		Status: domain.AgentStatusOffline,
	}
	agentRepo.Create(ctx, agent)

	// Set up target
	target := &domain.DeploymentTarget{
		ID:      "t-1",
		Name:    "Test Target",
		Type:    domain.TargetTypeNGINX,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	err := svc.TestConnection(ctx, "t-1")
	if err == nil {
		t.Fatal("expected error for offline agent, got nil")
	}

	stored := targetRepo.Targets["t-1"]
	if stored.TestStatus != "failed" {
		t.Errorf("expected test_status 'failed', got %s", stored.TestStatus)
	}
}

func TestTargetService_TestConnection_NoAgent(t *testing.T) {
	svc, targetRepo, _, _ := newTestTargetService()
	ctx := context.Background()

	target := &domain.DeploymentTarget{
		ID:      "t-1",
		Name:    "Test Target",
		Type:    domain.TargetTypeNGINX,
		AgentID: "",
	}
	targetRepo.AddTarget(target)

	err := svc.TestConnection(ctx, "t-1")
	if err == nil {
		t.Fatal("expected error for missing agent, got nil")
	}
}

func TestTargetService_TestConnection_TargetNotFound(t *testing.T) {
	svc, _, _, _ := newTestTargetService()
	ctx := context.Background()

	err := svc.TestConnection(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent target, got nil")
	}
}

func TestTargetService_TestConnection_StaleHeartbeat(t *testing.T) {
	svc, targetRepo, _, agentRepo := newTestTargetService()
	ctx := context.Background()

	// Set up agent with stale heartbeat (10 minutes ago)
	staleTime := time.Now().Add(-10 * time.Minute)
	agent := &domain.Agent{
		ID:              "agent-1",
		Name:            "Stale Agent",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &staleTime,
	}
	agentRepo.Create(ctx, agent)

	target := &domain.DeploymentTarget{
		ID:      "t-1",
		Name:    "Test Target",
		Type:    domain.TargetTypeNGINX,
		AgentID: "agent-1",
	}
	targetRepo.AddTarget(target)

	err := svc.TestConnection(ctx, "t-1")
	if err == nil {
		t.Fatal("expected error for stale heartbeat, got nil")
	}
}
