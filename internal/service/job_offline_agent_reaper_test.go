package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// Bundle C / Audit M-016 (CWE-754): regression suite for the new
// ReapJobsWithOfflineAgents path. Pre-bundle the reaper only handled
// AwaitingCSR / AwaitingApproval timeouts; jobs claimed by an agent
// that subsequently dies sat in Running indefinitely. These tests pin
// the new behavior end-to-end through the JobService → mockJobRepo
// boundary.

func newOfflineReaperService(t *testing.T) (*JobService, *mockJobRepo, *mockAuditRepo) {
	t.Helper()
	jobRepo := &mockJobRepo{
		Jobs:   map[string]*domain.Job{},
		Agents: map[string]*domain.Agent{},
	}
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)
	svc := NewJobService(jobRepo, nil, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.SetAuditService(auditService)
	return svc, jobRepo, auditRepo
}

func mkRunningJob(id, agentID string) *domain.Job {
	a := agentID
	now := time.Now()
	return &domain.Job{
		ID:       id,
		AgentID:  &a,
		Status:   domain.JobStatusRunning,
		CreatedAt: now.Add(-2 * time.Hour),
	}
}

func mkAgentWithHeartbeat(id string, hbAge time.Duration) *domain.Agent {
	hb := time.Now().Add(-hbAge)
	return &domain.Agent{
		ID:              id,
		Name:            id,
		LastHeartbeatAt: &hb,
	}
}

func TestReapJobsWithOfflineAgents_FlipsRunningToFailed(t *testing.T) {
	svc, repo, _ := newOfflineReaperService(t)

	repo.Agents["agt-stale"] = mkAgentWithHeartbeat("agt-stale", 30*time.Minute)
	repo.Agents["agt-fresh"] = mkAgentWithHeartbeat("agt-fresh", 1*time.Minute)
	repo.Jobs["j-stale"] = mkRunningJob("j-stale", "agt-stale")
	repo.Jobs["j-fresh"] = mkRunningJob("j-fresh", "agt-fresh")

	if err := svc.ReapJobsWithOfflineAgents(context.Background(), 10*time.Minute); err != nil {
		t.Fatalf("reaper returned error: %v", err)
	}

	if got := repo.Jobs["j-stale"].Status; got != domain.JobStatusFailed {
		t.Errorf("stale-agent job status = %s, want Failed", got)
	}
	if got := repo.Jobs["j-fresh"].Status; got != domain.JobStatusRunning {
		t.Errorf("fresh-agent job status = %s, want Running (must NOT be reaped)", got)
	}

	stale := repo.Jobs["j-stale"]
	if stale.LastError == nil || !strings.Contains(*stale.LastError, "agent offline") {
		t.Errorf("stale job LastError must cite agent offline; got: %v", stale.LastError)
	}
}

func TestReapJobsWithOfflineAgents_SkipsServerKeygenJobs(t *testing.T) {
	// Jobs without an agent_id (server-side keygen) must NOT be reaped
	// by this path — they have no agent to be "offline".
	svc, repo, _ := newOfflineReaperService(t)
	noAgent := &domain.Job{
		ID:        "j-server",
		Status:    domain.JobStatusRunning,
		CreatedAt: time.Now().Add(-time.Hour),
	}
	repo.Jobs["j-server"] = noAgent

	if err := svc.ReapJobsWithOfflineAgents(context.Background(), 1*time.Minute); err != nil {
		t.Fatalf("reaper returned error: %v", err)
	}
	if got := repo.Jobs["j-server"].Status; got != domain.JobStatusRunning {
		t.Errorf("server-keygen job (no agent_id) status = %s, want Running", got)
	}
}

func TestReapJobsWithOfflineAgents_SkipsNonRunningJobs(t *testing.T) {
	// Pending / AwaitingCSR / AwaitingApproval jobs are NOT in scope —
	// they're handled by ReapTimedOutJobs (I-003) or ClaimPendingJobs.
	svc, repo, _ := newOfflineReaperService(t)
	repo.Agents["agt-stale"] = mkAgentWithHeartbeat("agt-stale", 1*time.Hour)
	repo.Jobs["j-pending"] = func() *domain.Job {
		j := mkRunningJob("j-pending", "agt-stale")
		j.Status = domain.JobStatusPending
		return j
	}()

	if err := svc.ReapJobsWithOfflineAgents(context.Background(), 1*time.Minute); err != nil {
		t.Fatalf("reaper returned error: %v", err)
	}
	if got := repo.Jobs["j-pending"].Status; got != domain.JobStatusPending {
		t.Errorf("Pending job status = %s, want Pending (out of scope for offline-agent reaper)", got)
	}
}

func TestReapJobsWithOfflineAgents_RejectsNonPositiveTTL(t *testing.T) {
	svc, _, _ := newOfflineReaperService(t)
	if err := svc.ReapJobsWithOfflineAgents(context.Background(), 0); err == nil {
		t.Error("expected error for zero TTL — fail-loud guard against misconfig")
	}
	if err := svc.ReapJobsWithOfflineAgents(context.Background(), -time.Hour); err == nil {
		t.Error("expected error for negative TTL — fail-loud guard against misconfig")
	}
}

func TestReapJobsWithOfflineAgents_PropagatesRepoError(t *testing.T) {
	svc, repo, _ := newOfflineReaperService(t)
	repo.ListOfflineAgentJobsErr = errors.New("simulated db down")

	err := svc.ReapJobsWithOfflineAgents(context.Background(), 5*time.Minute)
	if err == nil {
		t.Fatal("expected error to propagate from repo")
	}
	if !strings.Contains(err.Error(), "simulated db down") {
		t.Errorf("expected wrapped repo error, got: %v", err)
	}
}

func TestReapJobsWithOfflineAgents_RecordsAuditEvent(t *testing.T) {
	svc, repo, audit := newOfflineReaperService(t)
	repo.Agents["agt-stale"] = mkAgentWithHeartbeat("agt-stale", 30*time.Minute)
	repo.Jobs["j-stale"] = mkRunningJob("j-stale", "agt-stale")

	if err := svc.ReapJobsWithOfflineAgents(context.Background(), 5*time.Minute); err != nil {
		t.Fatalf("reaper: %v", err)
	}

	audit.mu.Lock()
	events := append([]*domain.AuditEvent(nil), audit.Events...)
	audit.mu.Unlock()
	var found *domain.AuditEvent
	for i := range events {
		if events[i].Action == "job_offline_agent_reap" {
			found = events[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected job_offline_agent_reap audit event, got none")
	}
	if found.Actor != "system" {
		t.Errorf("audit Actor = %q, want system", found.Actor)
	}
	if found.ResourceType != "job" || found.ResourceID != "j-stale" {
		t.Errorf("audit resource binding wrong: %s/%s", found.ResourceType, found.ResourceID)
	}
}
