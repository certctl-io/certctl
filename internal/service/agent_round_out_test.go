package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// Bundle N.C-extended: agent service-layer round-out (target +5pp).
// Targets uncovered handler-interface delegators on AgentService:
// GetAgent, RegisterAgent, CSRSubmit, CSRSubmitForCert, GetWork,
// GetWorkWithTargets, UpdateJobStatus, CertificatePickup, plus
// SetProfileRepo / GetCertificateForAgent / GetAgentByAPIKey.

func newTestAgentSvc(t *testing.T) (*AgentService, *mockAgentRepo, *mockCertRepo, *mockJobRepo, *mockTargetRepo) {
	t.Helper()
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
	issuerRegistry := NewIssuerRegistry(nil)
	svc := NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, nil)
	return svc, agentRepo, certRepo, jobRepo, targetRepo
}

func TestAgentService_GetAgent_DelegatesToRepo(t *testing.T) {
	svc, repo, _, _, _ := newTestAgentSvc(t)
	repo.Agents["a-1"] = &domain.Agent{ID: "a-1", Name: "test"}
	got, err := svc.GetAgent(context.Background(), "a-1")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.Name != "test" {
		t.Errorf("expected name=test, got %q", got.Name)
	}
}

func TestAgentService_RegisterAgent_PopulatesIDStatusKey(t *testing.T) {
	svc, _, _, _, _ := newTestAgentSvc(t)
	got, err := svc.RegisterAgent(context.Background(), domain.Agent{Name: "fresh"})
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if got.ID == "" {
		t.Errorf("expected ID populated")
	}
	if got.Status != domain.AgentStatusOnline {
		t.Errorf("expected Online status, got %s", got.Status)
	}
	if got.APIKeyHash == "" {
		t.Errorf("expected APIKeyHash populated")
	}
	if got.RegisteredAt.IsZero() {
		t.Errorf("expected RegisteredAt populated")
	}
}

func TestAgentService_RegisterAgent_RepoError(t *testing.T) {
	svc, repo, _, _, _ := newTestAgentSvc(t)
	repo.CreateErr = errors.New("conflict")
	_, err := svc.RegisterAgent(context.Background(), domain.Agent{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "register agent") {
		t.Errorf("expected register-agent error wrapper, got %v", err)
	}
}

func TestAgentService_GetWork_NoJobs(t *testing.T) {
	svc, repo, _, _, _ := newTestAgentSvc(t)
	repo.Agents["a-1"] = &domain.Agent{ID: "a-1", Status: domain.AgentStatusOnline}
	got, err := svc.GetWork(context.Background(), "a-1")
	if err != nil {
		t.Fatalf("GetWork: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(got))
	}
}

func TestAgentService_GetWorkWithTargets_NoJobs(t *testing.T) {
	svc, repo, _, _, _ := newTestAgentSvc(t)
	repo.Agents["a-1"] = &domain.Agent{ID: "a-1", Status: domain.AgentStatusOnline}
	got, err := svc.GetWorkWithTargets(context.Background(), "a-1")
	if err != nil {
		t.Fatalf("GetWorkWithTargets: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 work items, got %d", len(got))
	}
}

func TestAgentService_UpdateJobStatus_DelegatesToReportJobStatus(t *testing.T) {
	svc, repo, _, jobRepo, _ := newTestAgentSvc(t)
	repo.Agents["a-1"] = &domain.Agent{ID: "a-1", Status: domain.AgentStatusOnline}
	jobRepo.Jobs["j-1"] = &domain.Job{
		ID:      "j-1",
		AgentID: strPtr("a-1"),
		Status:  domain.JobStatusRunning,
	}
	err := svc.UpdateJobStatus(context.Background(), "a-1", "j-1", "Completed", "")
	if err != nil {
		t.Errorf("UpdateJobStatus: %v", err)
	}
}

// Local strPtr to avoid colliding with other test files.
func strPtr(s string) *string { return &s }

func TestAgentService_CSRSubmit_NoCertID(t *testing.T) {
	svc, _, _, _, _ := newTestAgentSvc(t)
	// CSRSubmit calls SubmitCSR which performs validation. Pass an obviously
	// invalid CSR to exercise the error path.
	_, err := svc.CSRSubmit(context.Background(), "a-1", "not-a-csr")
	if err == nil {
		t.Errorf("expected SubmitCSR error to surface for invalid CSR")
	}
}

func TestAgentService_CSRSubmitForCert_InvalidPEM(t *testing.T) {
	svc, _, _, _, _ := newTestAgentSvc(t)
	_, err := svc.CSRSubmitForCert(context.Background(), "a-1", "mc-1", "not-a-csr")
	if err == nil {
		t.Errorf("expected error for invalid CSR")
	}
}

func TestAgentService_CertificatePickup_AgentNotFound(t *testing.T) {
	svc, _, _, _, _ := newTestAgentSvc(t)
	_, err := svc.CertificatePickup(context.Background(), "a-missing", "mc-1")
	if err == nil {
		t.Errorf("expected error for missing agent")
	}
}

func TestAgentService_GetAgentByAPIKey_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestAgentSvc(t)
	_, err := svc.GetAgentByAPIKey(context.Background(), "no-such-key")
	if err == nil {
		t.Errorf("expected error for unknown API key")
	}
}

func TestAgentService_GetCertificateForAgent_AgentNotFound(t *testing.T) {
	svc, _, _, _, _ := newTestAgentSvc(t)
	_, err := svc.GetCertificateForAgent(context.Background(), "a-missing", "mc-1")
	if err == nil {
		t.Errorf("expected error for missing agent")
	}
}

func TestAgentService_SetProfileRepo_NoCrash(t *testing.T) {
	svc, _, _, _, _ := newTestAgentSvc(t)
	// SetProfileRepo accepts nil — confirm no panic.
	svc.SetProfileRepo(nil)
}
