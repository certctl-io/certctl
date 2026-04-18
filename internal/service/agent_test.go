package service

import (
	"context"
	"encoding/base64"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)


func TestRegisterAgent(t *testing.T) {
	ctx := context.Background()
	agentRepo := &mockAgentRepo{
		Agents:           make(map[string]*domain.Agent),
		HeartbeatUpdates: make(map[string]time.Time),
	}
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

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	agent, apiKey, err := agentService.Register(ctx, "prod-agent-1", "server-01.example.com")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if agent.Name != "prod-agent-1" {
		t.Errorf("expected name prod-agent-1, got %s", agent.Name)
	}
	if agent.Hostname != "server-01.example.com" {
		t.Errorf("expected hostname server-01.example.com, got %s", agent.Hostname)
	}
	if agent.Status != domain.AgentStatusOnline {
		t.Errorf("expected status Online, got %s", agent.Status)
	}
	if apiKey == "" {
		t.Fatal("expected non-empty API key")
	}

	if len(agentRepo.Agents) != 1 {
		t.Errorf("expected 1 agent in repo, got %d", len(agentRepo.Agents))
	}
}

func TestHeartbeat(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agent := &domain.Agent{
		ID:              "agent-001",
		Name:            "prod-agent",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash123",
	}

	agentRepo := &mockAgentRepo{
		Agents:           map[string]*domain.Agent{"agent-001": agent},
		HeartbeatUpdates: make(map[string]time.Time),
	}
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
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	err := agentService.Heartbeat(ctx, "agent-001", nil)
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}

	if _, ok := agentRepo.HeartbeatUpdates["agent-001"]; !ok {
		t.Fatal("heartbeat not recorded")
	}
}

func TestHeartbeat_NotFound(t *testing.T) {
	ctx := context.Background()
	agentRepo := &mockAgentRepo{
		Agents:           make(map[string]*domain.Agent),
		HeartbeatUpdates: make(map[string]time.Time),
	}
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
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	err := agentService.Heartbeat(ctx, "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestGetPendingWork(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agentID := "agent-001"
	agent := &domain.Agent{
		ID:              agentID,
		Name:            "prod-agent",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash123",
	}

	job1 := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusPending,
		AgentID:       &agentID,
		CreatedAt:     now,
	}
	job2 := &domain.Job{
		ID:            "job-002",
		Type:          domain.JobTypeRenewal,
		CertificateID: "cert-002",
		Status:        domain.JobStatusPending,
		CreatedAt:     now,
	}

	agentRepo := &mockAgentRepo{
		Agents:           map[string]*domain.Agent{agentID: agent},
		HeartbeatUpdates: make(map[string]time.Time),
	}
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job1, "job-002": job2},
		StatusUpdates: make(map[string]domain.JobStatus),
	}
	targetRepo := &mockTargetRepo{
		Targets: make(map[string]*domain.DeploymentTarget),
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	jobs, err := agentService.GetPendingWork(ctx, agentID)
	if err != nil {
		t.Fatalf("GetPendingWork failed: %v", err)
	}

	if len(jobs) != 1 {
		t.Errorf("expected 1 deployment job, got %d", len(jobs))
	}
	if len(jobs) > 0 && jobs[0].Type != domain.JobTypeDeployment {
		t.Errorf("expected JobTypeDeployment, got %s", jobs[0].Type)
	}
}

func TestGetPendingWork_OnlyReturnsAgentJobs(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agentA := "agent-A"
	agentB := "agent-B"

	agentRepo := &mockAgentRepo{
		Agents: map[string]*domain.Agent{
			agentA: {ID: agentA, Name: "agent-A", Hostname: "host-a", Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "hashA"},
			agentB: {ID: agentB, Name: "agent-B", Hostname: "host-b", Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "hashB"},
		},
		HeartbeatUpdates: make(map[string]time.Time),
	}

	jobA := &domain.Job{ID: "job-A", Type: domain.JobTypeDeployment, CertificateID: "cert-001", Status: domain.JobStatusPending, AgentID: &agentA, CreatedAt: now}
	jobB := &domain.Job{ID: "job-B", Type: domain.JobTypeDeployment, CertificateID: "cert-002", Status: domain.JobStatusPending, AgentID: &agentB, CreatedAt: now}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-A": jobA, "job-B": jobB},
		StatusUpdates: make(map[string]domain.JobStatus),
	}
	certRepo := &mockCertRepo{Certs: make(map[string]*domain.ManagedCertificate), Versions: make(map[string][]*domain.CertificateVersion)}
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
	auditService := NewAuditService(&mockAuditRepo{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	// Agent A should only see its job
	jobsA, err := agentService.GetPendingWork(ctx, agentA)
	if err != nil {
		t.Fatalf("GetPendingWork for agent-A failed: %v", err)
	}
	if len(jobsA) != 1 {
		t.Fatalf("expected 1 job for agent-A, got %d", len(jobsA))
	}
	if jobsA[0].ID != "job-A" {
		t.Errorf("expected job-A, got %s", jobsA[0].ID)
	}

	// Agent B should only see its job
	jobsB, err := agentService.GetPendingWork(ctx, agentB)
	if err != nil {
		t.Fatalf("GetPendingWork for agent-B failed: %v", err)
	}
	if len(jobsB) != 1 {
		t.Fatalf("expected 1 job for agent-B, got %d", len(jobsB))
	}
	if jobsB[0].ID != "job-B" {
		t.Errorf("expected job-B, got %s", jobsB[0].ID)
	}
}

func TestGetPendingWork_EmptyWhenNoJobsForAgent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agentA := "agent-A"
	agentB := "agent-B"

	agentRepo := &mockAgentRepo{
		Agents: map[string]*domain.Agent{
			agentA: {ID: agentA, Name: "agent-A", Hostname: "host-a", Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "hashA"},
		},
		HeartbeatUpdates: make(map[string]time.Time),
	}

	// All jobs belong to agent-B
	jobB := &domain.Job{ID: "job-B", Type: domain.JobTypeDeployment, CertificateID: "cert-001", Status: domain.JobStatusPending, AgentID: &agentB, CreatedAt: now}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-B": jobB},
		StatusUpdates: make(map[string]domain.JobStatus),
	}
	certRepo := &mockCertRepo{Certs: make(map[string]*domain.ManagedCertificate), Versions: make(map[string][]*domain.CertificateVersion)}
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
	auditService := NewAuditService(&mockAuditRepo{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	jobs, err := agentService.GetPendingWork(ctx, agentA)
	if err != nil {
		t.Fatalf("GetPendingWork failed: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("expected 0 jobs for agent-A (all jobs are for agent-B), got %d", len(jobs))
	}
}

func TestGetPendingWork_DeploymentAndCSR_Scoped(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agentA := "agent-A"

	agentRepo := &mockAgentRepo{
		Agents: map[string]*domain.Agent{
			agentA: {ID: agentA, Name: "agent-A", Hostname: "host-a", Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "hashA"},
		},
		HeartbeatUpdates: make(map[string]time.Time),
	}

	deployJob := &domain.Job{ID: "job-deploy", Type: domain.JobTypeDeployment, CertificateID: "cert-001", Status: domain.JobStatusPending, AgentID: &agentA, CreatedAt: now}
	csrJob := &domain.Job{ID: "job-csr", Type: domain.JobTypeRenewal, CertificateID: "cert-002", Status: domain.JobStatusAwaitingCSR, AgentID: &agentA, CreatedAt: now}

	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-deploy": deployJob, "job-csr": csrJob},
		StatusUpdates: make(map[string]domain.JobStatus),
	}
	certRepo := &mockCertRepo{Certs: make(map[string]*domain.ManagedCertificate), Versions: make(map[string][]*domain.CertificateVersion)}
	targetRepo := &mockTargetRepo{Targets: make(map[string]*domain.DeploymentTarget)}
	auditService := NewAuditService(&mockAuditRepo{})

	issuerRegistry := NewIssuerRegistry(slog.Default())
	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	jobs, err := agentService.GetPendingWork(ctx, agentA)
	if err != nil {
		t.Fatalf("GetPendingWork failed: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs (deployment + AwaitingCSR), got %d", len(jobs))
	}
}

func TestReportJobStatus(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agent := &domain.Agent{
		ID:              "agent-001",
		Name:            "prod-agent",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash123",
	}
	job := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusRunning,
		CreatedAt:     now,
	}

	agentRepo := &mockAgentRepo{
		Agents:           map[string]*domain.Agent{"agent-001": agent},
		HeartbeatUpdates: make(map[string]time.Time),
	}
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	jobRepo := &mockJobRepo{
		Jobs:          map[string]*domain.Job{"job-001": job},
		StatusUpdates: make(map[string]domain.JobStatus),
	}
	targetRepo := &mockTargetRepo{
		Targets: make(map[string]*domain.DeploymentTarget),
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	err := agentService.ReportJobStatus(ctx, "agent-001", "job-001", domain.JobStatusCompleted, "")
	if err != nil {
		t.Fatalf("ReportJobStatus failed: %v", err)
	}

	if jobRepo.StatusUpdates["job-001"] != domain.JobStatusCompleted {
		t.Errorf("expected status Completed, got %s", jobRepo.StatusUpdates["job-001"])
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestMarkStaleAgentsOffline(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	staleTime := now.Add(-3 * time.Hour)

	agent1 := &domain.Agent{
		ID:              "agent-001",
		Name:            "online-agent",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash1",
	}
	agent2 := &domain.Agent{
		ID:              "agent-002",
		Name:            "stale-agent",
		Hostname:        "server-02",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now.Add(-24 * time.Hour),
		LastHeartbeatAt: &staleTime,
		APIKeyHash:      "hash2",
	}

	agentRepo := &mockAgentRepo{
		Agents:           map[string]*domain.Agent{"agent-001": agent1, "agent-002": agent2},
		HeartbeatUpdates: make(map[string]time.Time),
	}
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
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	err := agentService.MarkStaleAgentsOffline(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("MarkStaleAgentsOffline failed: %v", err)
	}

	if agentRepo.Agents["agent-001"].Status != domain.AgentStatusOnline {
		t.Errorf("expected agent-001 to be Online, got %s", agentRepo.Agents["agent-001"].Status)
	}
	if agentRepo.Agents["agent-002"].Status != domain.AgentStatusOffline {
		t.Errorf("expected agent-002 to be Offline, got %s", agentRepo.Agents["agent-002"].Status)
	}
}

func TestSubmitCSR(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agent := &domain.Agent{
		ID:              "agent-001",
		Name:            "prod-agent",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash123",
	}
	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "iss-local",
		Status:     domain.CertificateStatusPending,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	agentRepo := &mockAgentRepo{
		Agents:           map[string]*domain.Agent{"agent-001": agent},
		HeartbeatUpdates: make(map[string]time.Time),
	}
	certRepo := &mockCertRepo{
		Certs:    map[string]*domain.ManagedCertificate{"cert-001": cert},
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

	issuerConnector := &mockIssuerConnector{
		Result: &IssuanceResult{
			Serial:    "serial-123",
			CertPEM:   "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			ChainPEM:  "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
			NotBefore: now,
			NotAfter:  now.AddDate(1, 0, 0),
		},
	}
	issuerRegistry := NewIssuerRegistry(slog.Default())
	issuerRegistry.Set("iss-local", issuerConnector)

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	csrPEM := generateTestCSR(t, "ECDSA", 256)
	err := agentService.SubmitCSR(ctx, "agent-001", "cert-001", []byte(csrPEM))
	if err != nil {
		t.Fatalf("SubmitCSR failed: %v", err)
	}

	if len(certRepo.Versions["cert-001"]) != 1 {
		t.Errorf("expected 1 certificate version, got %d", len(certRepo.Versions["cert-001"]))
	}

	if cert.Status != domain.CertificateStatusActive {
		t.Errorf("expected certificate status Active, got %s", cert.Status)
	}
}

func TestSubmitCSR_EmptyCSR(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	agent := &domain.Agent{
		ID:              "agent-001",
		Name:            "prod-agent",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash123",
	}

	agentRepo := &mockAgentRepo{
		Agents:           map[string]*domain.Agent{"agent-001": agent},
		HeartbeatUpdates: make(map[string]time.Time),
	}
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
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	err := agentService.SubmitCSR(ctx, "agent-001", "", []byte{})
	if err == nil {
		t.Fatal("expected error for empty CSR")
	}
}

func TestListAgents(t *testing.T) {
	now := time.Now()
	agent1 := &domain.Agent{
		ID:              "agent-001",
		Name:            "agent1",
		Hostname:        "server-01",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash1",
	}
	agent2 := &domain.Agent{
		ID:              "agent-002",
		Name:            "agent2",
		Hostname:        "server-02",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "hash2",
	}

	agentRepo := &mockAgentRepo{
		Agents:           map[string]*domain.Agent{"agent-001": agent1, "agent-002": agent2},
		HeartbeatUpdates: make(map[string]time.Time),
	}
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
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	issuerRegistry := NewIssuerRegistry(slog.Default())

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	agents, total, err := agentService.ListAgents(context.Background(), 1, 50)
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}

	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
}

// TestGenerateAPIKey_Properties is the core regression test for C-1 (CWE-338).
// It verifies that generateAPIKey produces cryptographically random,
// unpadded base64url-encoded, 32-byte (256-bit) keys that never collide
// across consecutive calls. Exact length and alphabet are verified against
// base64.RawURLEncoding so any silent change to entropy or encoding fails
// fast.
//
// Note on the error branch: since Go 1.24 (issue #66821) crypto/rand.Read
// treats entropy-source failures as fatal — the process is terminated
// rather than returning an error. The defensive `if err != nil` branch
// in generateAPIKey is therefore unreachable from tests on modern Go.
// It is kept to preserve the documented (string, error) contract and
// to remain correct on older Go toolchains or future changes.
func TestGenerateAPIKey_Properties(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		k, err := generateAPIKey()
		if err != nil {
			t.Fatalf("generateAPIKey failed: %v", err)
		}
		if k == "" {
			t.Fatal("expected non-empty API key")
		}
		// base64.RawURLEncoding of 32 bytes yields exactly 43 chars.
		if got, want := len(k), 43; got != want {
			t.Fatalf("expected key length %d, got %d (%q)", want, got, k)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil {
			t.Fatalf("key %q not valid base64url: %v", k, err)
		}
		if len(decoded) != 32 {
			t.Fatalf("expected 32 decoded bytes (256 bits entropy), got %d", len(decoded))
		}
		if _, dup := seen[k]; dup {
			t.Fatalf("collision detected after %d calls; weak PRNG?", i+1)
		}
		seen[k] = struct{}{}
	}
}
