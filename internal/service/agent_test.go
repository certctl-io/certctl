package service

import (
	"context"
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

	issuerRegistry := make(map[string]IssuerConnector)

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
	issuerRegistry := make(map[string]IssuerConnector)

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	err := agentService.HeartbeatWithContext(ctx, "agent-001", nil)
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
	issuerRegistry := make(map[string]IssuerConnector)

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	err := agentService.HeartbeatWithContext(ctx, "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestGetPendingWork(t *testing.T) {
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

	job1 := &domain.Job{
		ID:            "job-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "cert-001",
		Status:        domain.JobStatusPending,
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
		Agents:           map[string]*domain.Agent{"agent-001": agent},
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
	issuerRegistry := make(map[string]IssuerConnector)

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	jobs, err := agentService.GetPendingWork(ctx, "agent-001")
	if err != nil {
		t.Fatalf("GetPendingWork failed: %v", err)
	}

	if len(jobs) != 1 {
		t.Errorf("expected 1 deployment job, got %d", len(jobs))
	}
	if jobs[0].Type != domain.JobTypeDeployment {
		t.Errorf("expected JobTypeDeployment, got %s", jobs[0].Type)
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
	issuerRegistry := make(map[string]IssuerConnector)

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
	issuerRegistry := make(map[string]IssuerConnector)

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
	issuerRegistry := map[string]IssuerConnector{"iss-local": issuerConnector}

	agentService := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)

	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\ntest-csr\n-----END CERTIFICATE REQUEST-----"
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
	issuerRegistry := make(map[string]IssuerConnector)

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
	issuerRegistry := make(map[string]IssuerConnector)

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
