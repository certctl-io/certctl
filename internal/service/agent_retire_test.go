package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// setupRetireTest wires up an AgentService with a single registered agent and
// returns (service, agentRepo, auditRepo) so tests can seed state and assert
// audit events. Kept minimal — tests that need targets/jobs/certs extend the
// returned repos directly.
func setupRetireTest(t *testing.T, agentID string) (*AgentService, *mockAgentRepo, *mockAuditRepo) {
	t.Helper()
	now := time.Now()
	agent := &domain.Agent{
		ID:              agentID,
		Name:            "prod-agent",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash-" + agentID,
	}
	agentRepo := newMockAgentRepository()
	agentRepo.AddAgent(agent)
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{
		Jobs:          make(map[string]*domain.Job),
		StatusUpdates: make(map[string]domain.JobStatus),
	}
	targetRepo := &mockTargetRepo{
		Targets: make(map[string]*domain.DeploymentTarget),
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	svc := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)
	return svc, agentRepo, auditRepo
}

// TestRetireAgent_Sentinel_Rejected covers I-004's sentinel guard. The four
// well-known sentinel agent IDs back discovery sources and the network scanner
// — retiring them would orphan those subsystems. Contract: reject with
// ErrAgentIsSentinel regardless of force/reason.
func TestRetireAgent_Sentinel_Rejected(t *testing.T) {
	sentinels := []string{"server-scanner", "cloud-aws-sm", "cloud-azure-kv", "cloud-gcp-sm"}
	for _, id := range sentinels {
		t.Run(id, func(t *testing.T) {
			svc, _, _ := setupRetireTest(t, id)
			_, err := svc.RetireAgent(context.Background(), id, "alice", false, "")
			if !errors.Is(err, ErrAgentIsSentinel) {
				t.Fatalf("retire(sentinel %q) err=%v want ErrAgentIsSentinel", id, err)
			}
			// Sentinel rejection must be deterministic even under force=true.
			_, err = svc.RetireAgent(context.Background(), id, "alice", true, "forced by operator")
			if !errors.Is(err, ErrAgentIsSentinel) {
				t.Fatalf("retire(sentinel %q force=true) err=%v want ErrAgentIsSentinel", id, err)
			}
		})
	}
}

// TestRetireAgent_NotFound covers the 404 preflight path. The handler maps
// ErrAgentNotFound-equivalent sentinel to 404; the service must surface it
// cleanly without partial state mutation.
func TestRetireAgent_NotFound(t *testing.T) {
	svc, _, _ := setupRetireTest(t, "agent-001")
	_, err := svc.RetireAgent(context.Background(), "agent-does-not-exist", "alice", false, "")
	if err == nil {
		t.Fatalf("retire(missing id) err=nil want not-found error")
	}
}

// TestRetireAgent_AlreadyRetired_Idempotent covers the 204 No Content path.
// Retiring an already-retired agent must succeed without error and without
// emitting a new audit event (the first retirement already recorded one).
// Idempotency matters because the handler is the escape hatch for operators
// re-issuing a failed retire after a partial failure mid-cascade.
func TestRetireAgent_AlreadyRetired_Idempotent(t *testing.T) {
	svc, agentRepo, auditRepo := setupRetireTest(t, "agent-001")
	past := time.Now().Add(-24 * time.Hour)
	reason := "operator decommissioned"
	agent := agentRepo.Agents["agent-001"]
	agent.RetiredAt = &past
	agent.RetiredReason = &reason

	result, err := svc.RetireAgent(context.Background(), "agent-001", "alice", false, "")
	if err != nil {
		t.Fatalf("retire(already retired) err=%v want nil (idempotent)", err)
	}
	if result == nil || !result.AlreadyRetired {
		t.Fatalf("retire(already retired) result=%+v want AlreadyRetired=true", result)
	}
	// Retire-on-retired must not emit a duplicate audit event.
	for _, e := range auditRepo.Events {
		if e.Action == "agent_retired" && e.ResourceID == "agent-001" {
			t.Fatalf("retire(already retired) emitted duplicate agent_retired audit event")
		}
	}
}

// TestRetireAgent_NoDeps_SoftSucceeds covers the happy 200 path: no active
// targets, certs, or jobs referencing the agent. Soft-retire stamps
// RetiredAt + RetiredReason and emits agent_retired audit event.
func TestRetireAgent_NoDeps_SoftSucceeds(t *testing.T) {
	svc, agentRepo, auditRepo := setupRetireTest(t, "agent-001")

	before := time.Now().Add(-time.Second)
	result, err := svc.RetireAgent(context.Background(), "agent-001", "alice", false, "")
	if err != nil {
		t.Fatalf("retire(clean) err=%v want nil", err)
	}
	if result == nil {
		t.Fatal("retire(clean) result=nil want non-nil")
	}
	if result.AlreadyRetired {
		t.Fatalf("retire(clean) result.AlreadyRetired=true want false")
	}
	if result.Cascade {
		t.Fatalf("retire(clean) result.Cascade=true want false (no deps to cascade)")
	}
	if !result.RetiredAt.After(before) {
		t.Fatalf("retire(clean) RetiredAt=%v not after test start %v", result.RetiredAt, before)
	}

	agent := agentRepo.Agents["agent-001"]
	if agent.RetiredAt == nil {
		t.Fatalf("retire(clean) agent.RetiredAt=nil want stamped")
	}

	// Audit event must be emitted with action=agent_retired, actor=alice.
	found := false
	for _, e := range auditRepo.Events {
		if e.Action == "agent_retired" && e.ResourceID == "agent-001" && e.Actor == "alice" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("retire(clean) missing agent_retired audit event for alice, events=%+v", auditRepo.Events)
	}
}

// TestRetireAgent_WithDeps_NoForce_Blocked covers the 409 preflight path. When
// the agent has any of: active non-retired targets, certs deployed via those
// targets, or pending jobs — a default retire must block with
// ErrBlockedByDependencies and the counts must be reachable via errors.As so
// the handler can build the 409 body.
func TestRetireAgent_WithDeps_NoForce_Blocked(t *testing.T) {
	svc, agentRepo, _ := setupRetireTest(t, "agent-001")
	// Seed dependency counts directly on the mock — the production repo
	// implements CountActive* queries; the mock exposes them as fields.
	agentRepo.ActiveTargetCounts["agent-001"] = 3
	agentRepo.ActiveCertCounts["agent-001"] = 7
	agentRepo.PendingJobCounts["agent-001"] = 2

	_, err := svc.RetireAgent(context.Background(), "agent-001", "alice", false, "")
	if !errors.Is(err, ErrBlockedByDependencies) {
		t.Fatalf("retire(with deps, no force) err=%v want ErrBlockedByDependencies", err)
	}
	var blocked *BlockedByDependenciesError
	if !errors.As(err, &blocked) {
		t.Fatalf("retire(with deps) err=%v want wrapped *BlockedByDependenciesError", err)
	}
	if blocked.Counts.ActiveTargets != 3 {
		t.Errorf("blocked.Counts.ActiveTargets=%d want 3", blocked.Counts.ActiveTargets)
	}
	if blocked.Counts.ActiveCertificates != 7 {
		t.Errorf("blocked.Counts.ActiveCertificates=%d want 7", blocked.Counts.ActiveCertificates)
	}
	if blocked.Counts.PendingJobs != 2 {
		t.Errorf("blocked.Counts.PendingJobs=%d want 2", blocked.Counts.PendingJobs)
	}
	// Agent must still be un-retired after preflight block.
	if agentRepo.Agents["agent-001"].RetiredAt != nil {
		t.Fatalf("retire(blocked) left RetiredAt stamped; preflight must be transactionally safe")
	}
}

// TestRetireAgent_WithDeps_Force_NoReason_Rejected covers the 400 guard on the
// force escape hatch. Operators using force=true must supply a justifying
// reason; empty reason is rejected before any DB mutation.
func TestRetireAgent_WithDeps_Force_NoReason_Rejected(t *testing.T) {
	svc, agentRepo, _ := setupRetireTest(t, "agent-001")
	agentRepo.ActiveTargetCounts["agent-001"] = 1

	_, err := svc.RetireAgent(context.Background(), "agent-001", "alice", true, "")
	if !errors.Is(err, ErrForceReasonRequired) {
		t.Fatalf("retire(force, no reason) err=%v want ErrForceReasonRequired", err)
	}
	if agentRepo.Agents["agent-001"].RetiredAt != nil {
		t.Fatalf("retire(force, no reason) left RetiredAt stamped; guard must fire before mutation")
	}
}

// TestRetireAgent_WithDeps_Force_Cascades covers the force=true transactional
// path: agent retires, downstream targets also soft-retire with the supplied
// reason, and the result surface indicates cascade happened. Reason
// propagates to every cascaded row so post-mortem forensics can trace the
// cascade to a single operator action.
func TestRetireAgent_WithDeps_Force_Cascades(t *testing.T) {
	svc, agentRepo, auditRepo := setupRetireTest(t, "agent-001")
	agentRepo.ActiveTargetCounts["agent-001"] = 2
	agentRepo.ActiveCertCounts["agent-001"] = 5
	agentRepo.PendingJobCounts["agent-001"] = 1

	reason := "decommissioning rack 7"
	result, err := svc.RetireAgent(context.Background(), "agent-001", "alice", true, reason)
	if err != nil {
		t.Fatalf("retire(force, reason) err=%v want nil", err)
	}
	if result == nil {
		t.Fatal("retire(force) result=nil want non-nil")
	}
	if !result.Cascade {
		t.Fatalf("retire(force) result.Cascade=false want true")
	}
	if result.Counts.ActiveTargets != 2 {
		t.Errorf("result.Counts.ActiveTargets=%d want 2 (pre-cascade snapshot)", result.Counts.ActiveTargets)
	}

	agent := agentRepo.Agents["agent-001"]
	if agent.RetiredAt == nil {
		t.Fatalf("retire(force) agent.RetiredAt=nil want stamped")
	}
	if agent.RetiredReason == nil || *agent.RetiredReason != reason {
		t.Fatalf("retire(force) RetiredReason=%v want %q", agent.RetiredReason, reason)
	}

	// Two audit events required: agent_retired + agent_retirement_cascaded.
	// The cascaded event captures which downstream resources were affected.
	var haveRetired, haveCascaded bool
	for _, e := range auditRepo.Events {
		if e.ResourceID == "agent-001" {
			switch e.Action {
			case "agent_retired":
				haveRetired = true
			case "agent_retirement_cascaded":
				haveCascaded = true
			}
		}
	}
	if !haveRetired {
		t.Errorf("retire(force) missing agent_retired audit event")
	}
	if !haveCascaded {
		t.Errorf("retire(force) missing agent_retirement_cascaded audit event")
	}
}

// TestRetireAgent_EmitsAuditEvent pins the audit contract for I-004:
// every retire path that mutates DB state emits at least one audit event with
// the operator's actor identity, so post-hoc compliance/forensics can
// reconstruct who retired what and when.
func TestRetireAgent_EmitsAuditEvent(t *testing.T) {
	svc, _, auditRepo := setupRetireTest(t, "agent-007")

	_, err := svc.RetireAgent(context.Background(), "agent-007", "compliance-bot", false, "")
	if err != nil {
		t.Fatalf("retire err=%v want nil", err)
	}
	for _, e := range auditRepo.Events {
		if e.Action == "agent_retired" && e.ResourceID == "agent-007" {
			if e.Actor != "compliance-bot" {
				t.Errorf("audit event Actor=%q want compliance-bot", e.Actor)
			}
			return
		}
	}
	t.Fatalf("no agent_retired audit event emitted, events=%+v", auditRepo.Events)
}

// TestHeartbeat_RetiredAgent_ReturnsErrAgentRetired covers the 410 Gone
// contract. A retired agent that is still polling must be told its identity
// is no longer accepted — the agent process should detect this and shut
// down rather than continue heartbeating indefinitely.
func TestHeartbeat_RetiredAgent_ReturnsErrAgentRetired(t *testing.T) {
	svc, agentRepo, _ := setupRetireTest(t, "agent-001")
	past := time.Now().Add(-time.Hour)
	reason := "decommissioned"
	agentRepo.Agents["agent-001"].RetiredAt = &past
	agentRepo.Agents["agent-001"].RetiredReason = &reason

	err := svc.Heartbeat(context.Background(), "agent-001", &domain.AgentMetadata{
		OS:           "linux",
		Architecture: "amd64",
		Hostname:     "server-01",
	})
	if !errors.Is(err, ErrAgentRetired) {
		t.Fatalf("heartbeat(retired) err=%v want ErrAgentRetired", err)
	}
	// Retired heartbeat must NOT bump LastHeartbeatAt — otherwise the retired
	// agent could ressurrect itself in stats/observability dashboards.
	if _, bumped := agentRepo.HeartbeatUpdates["agent-001"]; bumped {
		t.Fatalf("heartbeat(retired) updated LastHeartbeatAt; retired agents must be frozen")
	}
}

// TestListAgents_DefaultExcludesRetired covers the contract that the
// handler-facing ListAgents call hides retired rows by default. Otherwise
// every dashboard that paginates agents would surface retired stragglers.
// An explicit "list retired" endpoint (ListRetiredAgents) covers the audit
// use case.
func TestListAgents_DefaultExcludesRetired(t *testing.T) {
	svc, agentRepo, _ := setupRetireTest(t, "agent-active")
	// Seed one retired agent alongside the active one.
	past := time.Now().Add(-24 * time.Hour)
	reason := "old hardware"
	agentRepo.AddAgent(&domain.Agent{
		ID:            "agent-retired",
		Name:          "retired-agent",
		Hostname:      "server-old",
		Status:        domain.AgentStatusOffline,
		RegisteredAt:  past,
		APIKeyHash:    "hash-retired",
		RetiredAt:     &past,
		RetiredReason: &reason,
	})

	agents, total, err := svc.ListAgents(context.Background(), 1, 50)
	if err != nil {
		t.Fatalf("ListAgents err=%v want nil", err)
	}
	for _, a := range agents {
		if a.ID == "agent-retired" {
			t.Fatalf("ListAgents returned retired agent %q in default listing", a.ID)
		}
	}
	if total != 1 {
		t.Errorf("ListAgents total=%d want 1 (only active)", total)
	}

	// ListRetiredAgents must surface retired-only, with count=1.
	retired, retiredTotal, err := svc.ListRetiredAgents(context.Background(), 1, 50)
	if err != nil {
		t.Fatalf("ListRetiredAgents err=%v want nil", err)
	}
	if retiredTotal != 1 {
		t.Errorf("ListRetiredAgents total=%d want 1", retiredTotal)
	}
	if len(retired) != 1 || retired[0].ID != "agent-retired" {
		t.Fatalf("ListRetiredAgents got=%+v want [agent-retired]", retired)
	}
}

// TestMarkStaleAgentsOffline_SkipsRetired covers the stale-offline sweeper
// interaction with retirement. A retired agent must not be re-surfaced as
// a state transition ("Online → Offline") by the scheduler, because its
// Status column is preserved as the last-known operational state at
// retirement time and RetiredAt is the source of truth for filtering.
func TestMarkStaleAgentsOffline_SkipsRetired(t *testing.T) {
	svc, agentRepo, _ := setupRetireTest(t, "agent-live")
	// Active agent is currently stale (no heartbeat for 10 minutes) — eligible
	// for Online→Offline transition.
	stale := time.Now().Add(-10 * time.Minute)
	agentRepo.Agents["agent-live"].LastHeartbeatAt = &stale

	// Retired agent was also stale at retirement time, but must NOT be
	// touched by the sweeper.
	past := time.Now().Add(-24 * time.Hour)
	reason := "hw failure"
	agentRepo.AddAgent(&domain.Agent{
		ID:              "agent-retired",
		Name:            "dead-agent",
		Hostname:        "server-old",
		Status:          domain.AgentStatusOnline, // preserved last-seen status
		RegisteredAt:    past,
		LastHeartbeatAt: &past,
		APIKeyHash:      "hash-dead",
		RetiredAt:       &past,
		RetiredReason:   &reason,
	})

	if err := svc.MarkStaleAgentsOffline(context.Background(), 5*time.Minute); err != nil {
		t.Fatalf("MarkStaleAgentsOffline err=%v want nil", err)
	}

	// Active-stale agent should flip Online → Offline.
	if got := agentRepo.Agents["agent-live"].Status; got != domain.AgentStatusOffline {
		t.Errorf("agent-live Status=%s want Offline", got)
	}
	// Retired agent's Status column must be frozen at Online (its preserved
	// last-seen state); the sweeper must skip it.
	if got := agentRepo.Agents["agent-retired"].Status; got != domain.AgentStatusOnline {
		t.Errorf("agent-retired Status=%s want Online (frozen); sweeper touched retired row", got)
	}
}
