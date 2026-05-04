package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/service"
)

// MockAgentService is a mock implementation of AgentService interface.
type MockAgentService struct {
	ListAgentsFn         func(page, perPage int) ([]domain.Agent, int64, error)
	GetAgentFn           func(id string) (*domain.Agent, error)
	RegisterAgentFn      func(agent domain.Agent) (*domain.Agent, error)
	HeartbeatFn          func(agentID string, metadata *domain.AgentMetadata) error
	CSRSubmitFn          func(agentID string, csrPEM string) (string, error)
	CSRSubmitForCertFn   func(agentID string, certID string, csrPEM string) (string, error)
	CertificatePickupFn  func(agentID, certID string) (string, error)
	GetWorkFn            func(agentID string) ([]domain.Job, error)
	GetWorkWithTargetsFn func(agentID string) ([]domain.WorkItem, error)
	UpdateJobStatusFn    func(agentID string, jobID string, status string, errMsg string) error
	// I-004: soft-retirement hooks. Tests that don't set these receive nil
	// results and nil errors, which mirrors the safest default (no-op) for
	// unrelated suites that mock only the legacy surface.
	RetireAgentFn       func(agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error)
	ListRetiredAgentsFn func(page, perPage int) ([]domain.Agent, int64, error)
}

func (m *MockAgentService) ListAgents(_ context.Context, page, perPage int) ([]domain.Agent, int64, error) {
	if m.ListAgentsFn != nil {
		return m.ListAgentsFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *MockAgentService) GetAgent(_ context.Context, id string) (*domain.Agent, error) {
	if m.GetAgentFn != nil {
		return m.GetAgentFn(id)
	}
	return nil, nil
}

func (m *MockAgentService) RegisterAgent(_ context.Context, agent domain.Agent) (*domain.Agent, error) {
	if m.RegisterAgentFn != nil {
		return m.RegisterAgentFn(agent)
	}
	return nil, nil
}

func (m *MockAgentService) Heartbeat(_ context.Context, agentID string, metadata *domain.AgentMetadata) error {
	if m.HeartbeatFn != nil {
		return m.HeartbeatFn(agentID, metadata)
	}
	return nil
}

func (m *MockAgentService) CSRSubmit(_ context.Context, agentID string, csrPEM string) (string, error) {
	if m.CSRSubmitFn != nil {
		return m.CSRSubmitFn(agentID, csrPEM)
	}
	return "", nil
}

func (m *MockAgentService) CSRSubmitForCert(_ context.Context, agentID string, certID string, csrPEM string) (string, error) {
	if m.CSRSubmitForCertFn != nil {
		return m.CSRSubmitForCertFn(agentID, certID, csrPEM)
	}
	return "", nil
}

func (m *MockAgentService) CertificatePickup(_ context.Context, agentID, certID string) (string, error) {
	if m.CertificatePickupFn != nil {
		return m.CertificatePickupFn(agentID, certID)
	}
	return "", nil
}

func (m *MockAgentService) GetWork(_ context.Context, agentID string) ([]domain.Job, error) {
	if m.GetWorkFn != nil {
		return m.GetWorkFn(agentID)
	}
	return nil, nil
}

func (m *MockAgentService) GetWorkWithTargets(_ context.Context, agentID string) ([]domain.WorkItem, error) {
	if m.GetWorkWithTargetsFn != nil {
		return m.GetWorkWithTargetsFn(agentID)
	}
	return nil, nil
}

func (m *MockAgentService) UpdateJobStatus(_ context.Context, agentID string, jobID string, status string, errMsg string) error {
	if m.UpdateJobStatusFn != nil {
		return m.UpdateJobStatusFn(agentID, jobID, status, errMsg)
	}
	return nil
}

// RetireAgent is the I-004 soft-retirement entrypoint. Tests that don't set
// RetireAgentFn get a nil result + nil error, which is a no-op response that
// lets unrelated suites compile without caring about the retirement surface.
func (m *MockAgentService) RetireAgent(_ context.Context, agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error) {
	if m.RetireAgentFn != nil {
		return m.RetireAgentFn(agentID, actor, force, reason)
	}
	return nil, nil
}

// ListRetiredAgents returns retired rows for the retired-agents tab / audit
// views. Same zero-value default as RetireAgent for unrelated tests.
func (m *MockAgentService) ListRetiredAgents(_ context.Context, page, perPage int) ([]domain.Agent, int64, error) {
	if m.ListRetiredAgentsFn != nil {
		return m.ListRetiredAgentsFn(page, perPage)
	}
	return nil, 0, nil
}

// Test ListAgents - success case
func TestListAgents_Success(t *testing.T) {
	now := time.Now()
	agent1 := domain.Agent{
		ID:              "a-prod-001",
		Name:            "Production Agent",
		Hostname:        "prod-server-01",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &now,
		RegisteredAt:    now,
	}
	agent2 := domain.Agent{
		ID:              "a-prod-002",
		Name:            "API Agent",
		Hostname:        "api-server-01",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &now,
		RegisteredAt:    now,
	}

	mock := &MockAgentService{
		ListAgentsFn: func(page, perPage int) ([]domain.Agent, int64, error) {
			if page == 1 && perPage == 50 {
				return []domain.Agent{agent1, agent2}, 2, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?page=1&per_page=50", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response PagedResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Total != 2 {
		t.Errorf("expected total 2, got %d", response.Total)
	}
}

// Test ListAgents - method not allowed
func TestListAgents_MethodNotAllowed(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// Test ListAgents - service error
func TestListAgents_ServiceError(t *testing.T) {
	mock := &MockAgentService{
		ListAgentsFn: func(page, perPage int) ([]domain.Agent, int64, error) {
			return nil, 0, ErrMockServiceFailed
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListAgents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test GetAgent - success case
func TestGetAgent_Success(t *testing.T) {
	now := time.Now()
	agent := &domain.Agent{
		ID:              "a-prod-001",
		Name:            "Production Agent",
		Hostname:        "prod-server-01",
		Status:          domain.AgentStatusOnline,
		LastHeartbeatAt: &now,
		RegisteredAt:    now,
	}

	mock := &MockAgentService{
		GetAgentFn: func(id string) (*domain.Agent, error) {
			if id == "a-prod-001" {
				return agent, nil
			}
			return nil, ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/a-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetAgent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response domain.Agent
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.ID != "a-prod-001" {
		t.Errorf("expected ID a-prod-001, got %s", response.ID)
	}
}

// Test GetAgent - not found
func TestGetAgent_NotFound(t *testing.T) {
	mock := &MockAgentService{
		GetAgentFn: func(id string) (*domain.Agent, error) {
			return nil, ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/nonexistent", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetAgent(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// Test RegisterAgent - success case
func TestRegisterAgent_Success(t *testing.T) {
	now := time.Now()
	registered := &domain.Agent{
		ID:           "a-prod-001",
		Name:         "Production Agent",
		Hostname:     "prod-server-01",
		Status:       domain.AgentStatusOnline,
		RegisteredAt: now,
	}

	mock := &MockAgentService{
		RegisterAgentFn: func(agent domain.Agent) (*domain.Agent, error) {
			return registered, nil
		},
	}

	handler := NewAgentHandler(mock, "")

	agentBody := domain.Agent{
		Name:     "Production Agent",
		Hostname: "prod-server-01",
	}
	body, _ := json.Marshal(agentBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RegisterAgent(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var response domain.Agent
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.ID != "a-prod-001" {
		t.Errorf("expected ID a-prod-001, got %s", response.ID)
	}
}

// Test RegisterAgent - invalid body
func TestRegisterAgent_InvalidBody(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader([]byte("invalid json")))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RegisterAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test Heartbeat - success case
func TestHeartbeat_Success(t *testing.T) {
	mock := &MockAgentService{
		HeartbeatFn: func(agentID string, metadata *domain.AgentMetadata) error {
			if agentID == "a-prod-001" {
				return nil
			}
			return ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/heartbeat", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "heartbeat_recorded" {
		t.Errorf("expected status 'heartbeat_recorded', got %s", response["status"])
	}
}

// Test Heartbeat - service error
func TestHeartbeat_ServiceError(t *testing.T) {
	mock := &MockAgentService{
		HeartbeatFn: func(agentID string, metadata *domain.AgentMetadata) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/heartbeat", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test AgentCSRSubmit - with certificate_id
func TestAgentCSRSubmit_WithCertificateID(t *testing.T) {
	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

	mock := &MockAgentService{
		CSRSubmitForCertFn: func(agentID string, certID string, csrPEM string) (string, error) {
			if agentID == "a-prod-001" && certID == "mc-prod-001" {
				return "csr_submitted", nil
			}
			return "", ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")

	reqBody := map[string]string{
		"csr_pem":        csrPEM,
		"certificate_id": "mc-prod-001",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/csr", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentCSRSubmit(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "csr_submitted" {
		t.Errorf("expected status 'csr_submitted', got %s", response["status"])
	}
}

// Test AgentCSRSubmit - without certificate_id
func TestAgentCSRSubmit_WithoutCertificateID(t *testing.T) {
	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

	mock := &MockAgentService{
		CSRSubmitFn: func(agentID string, csrPEM string) (string, error) {
			if agentID == "a-prod-001" {
				return "csr_submitted", nil
			}
			return "", ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")

	reqBody := map[string]string{
		"csr_pem": csrPEM,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/csr", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentCSRSubmit(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}
}

// Test AgentCSRSubmit - missing CSR PEM
func TestAgentCSRSubmit_MissingCSRPEM(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	reqBody := map[string]string{
		"certificate_id": "mc-prod-001",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/csr", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentCSRSubmit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test AgentCSRSubmit - invalid body
func TestAgentCSRSubmit_InvalidBody(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/csr", bytes.NewReader([]byte("invalid")))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentCSRSubmit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test AgentCertificatePickup - success case
func TestAgentCertificatePickup_Success(t *testing.T) {
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

	mock := &MockAgentService{
		CertificatePickupFn: func(agentID, certID string) (string, error) {
			if agentID == "a-prod-001" && certID == "mc-prod-001" {
				return certPEM, nil
			}
			return "", ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")
	// Path structure: /api/v1/agents/{agent_id}/certificates/{cert_id}
	// After trim and split: parts[0]="agent_id", parts[1]="certificates", parts[2]="cert_id", parts[3]=""
	// Note: handler checks len(parts) < 4, so we need the trailing slash
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/a-prod-001/certificates/mc-prod-001/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.AgentCertificatePickup(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d (body: %s)", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["certificate_pem"] != certPEM {
		t.Errorf("expected cert PEM %s, got %s", certPEM, response["certificate_pem"])
	}
}

// Test AgentCertificatePickup - not found
func TestAgentCertificatePickup_NotFound(t *testing.T) {
	mock := &MockAgentService{
		CertificatePickupFn: func(agentID, certID string) (string, error) {
			return "", ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/a-prod-001/certificates/nonexistent/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.AgentCertificatePickup(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d (body: %s)", http.StatusNotFound, w.Code, w.Body.String())
	}
}

// Test AgentGetWork - success with items
func TestAgentGetWork_Success(t *testing.T) {
	workItem := domain.WorkItem{
		ID:            "j-deploy-001",
		Type:          domain.JobTypeDeployment,
		CertificateID: "mc-prod-001",
		TargetID:      stringPtr("t-nginx-001"),
		TargetType:    "NGINX",
		Status:        domain.JobStatusPending,
	}

	mock := &MockAgentService{
		GetWorkWithTargetsFn: func(agentID string) ([]domain.WorkItem, error) {
			if agentID == "a-prod-001" {
				return []domain.WorkItem{workItem}, nil
			}
			return nil, ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/a-prod-001/work", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.AgentGetWork(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["count"] != float64(1) {
		t.Errorf("expected count 1, got %v", response["count"])
	}
}

// Test AgentGetWork - no work items
func TestAgentGetWork_NoItems(t *testing.T) {
	mock := &MockAgentService{
		GetWorkWithTargetsFn: func(agentID string) ([]domain.WorkItem, error) {
			return nil, nil
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/a-prod-001/work", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.AgentGetWork(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["count"] != float64(0) {
		t.Errorf("expected count 0, got %v", response["count"])
	}
}

// Test AgentGetWork - service error
func TestAgentGetWork_ServiceError(t *testing.T) {
	mock := &MockAgentService{
		GetWorkWithTargetsFn: func(agentID string) ([]domain.WorkItem, error) {
			return nil, ErrMockServiceFailed
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/a-prod-001/work", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.AgentGetWork(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test AgentReportJobStatus - success case
func TestAgentReportJobStatus_Success(t *testing.T) {
	mock := &MockAgentService{
		UpdateJobStatusFn: func(agentID string, jobID string, status string, errMsg string) error {
			if agentID == "a-prod-001" && jobID == "j-deploy-001" && status == "Completed" {
				return nil
			}
			return ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")

	statusReq := map[string]string{
		"status": "Completed",
	}
	body, _ := json.Marshal(statusReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/jobs/j-deploy-001/status", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentReportJobStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "updated" {
		t.Errorf("expected status 'updated', got %s", response["status"])
	}
}

// Test AgentReportJobStatus - with error message
func TestAgentReportJobStatus_WithError(t *testing.T) {
	mock := &MockAgentService{
		UpdateJobStatusFn: func(agentID string, jobID string, status string, errMsg string) error {
			if agentID == "a-prod-001" && jobID == "j-deploy-001" && status == "Failed" && errMsg == "timeout" {
				return nil
			}
			return ErrMockNotFound
		},
	}

	handler := NewAgentHandler(mock, "")

	statusReq := map[string]string{
		"status": "Failed",
		"error":  "timeout",
	}
	body, _ := json.Marshal(statusReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/jobs/j-deploy-001/status", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentReportJobStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Test AgentReportJobStatus - missing status
func TestAgentReportJobStatus_MissingStatus(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	statusReq := map[string]string{}
	body, _ := json.Marshal(statusReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/jobs/j-deploy-001/status", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentReportJobStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test AgentReportJobStatus - invalid body
func TestAgentReportJobStatus_InvalidBody(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/jobs/j-deploy-001/status", bytes.NewReader([]byte("invalid")))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentReportJobStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test ListAgents - invalid pagination parameters
func TestListAgents_InvalidPagination(t *testing.T) {
	mock := &MockAgentService{
		ListAgentsFn: func(page, perPage int) ([]domain.Agent, int64, error) {
			// Should default to page=1, perPage=50 if invalid
			if page == 1 && perPage == 50 {
				return []domain.Agent{}, 0, nil
			}
			return nil, 0, nil
		},
	}

	handler := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?page=invalid&per_page=invalid", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.ListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Test GetAgent - empty ID
func TestGetAgent_EmptyID(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.GetAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test RegisterAgent - service error
func TestRegisterAgent_ServiceError(t *testing.T) {
	mock := &MockAgentService{
		RegisterAgentFn: func(agent domain.Agent) (*domain.Agent, error) {
			return nil, ErrMockServiceFailed
		},
	}

	handler := NewAgentHandler(mock, "")

	agentBody := domain.Agent{
		Name:     "Production Agent",
		Hostname: "prod-server-01",
	}
	body, _ := json.Marshal(agentBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RegisterAgent(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test Heartbeat - empty agent ID
func TestHeartbeat_EmptyAgentID(t *testing.T) {
	mock := &MockAgentService{}
	handler := NewAgentHandler(mock, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents//heartbeat", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test AgentCSRSubmit - service error
func TestAgentCSRSubmit_ServiceError(t *testing.T) {
	mock := &MockAgentService{
		CSRSubmitFn: func(agentID string, csrPEM string) (string, error) {
			return "", ErrMockServiceFailed
		},
	}

	handler := NewAgentHandler(mock, "")

	reqBody := map[string]string{
		"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/csr", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentCSRSubmit(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test AgentReportJobStatus - service error
func TestAgentReportJobStatus_ServiceError(t *testing.T) {
	mock := &MockAgentService{
		UpdateJobStatusFn: func(agentID string, jobID string, status string, errMsg string) error {
			return ErrMockServiceFailed
		},
	}

	handler := NewAgentHandler(mock, "")

	statusReq := map[string]string{
		"status": "Completed",
	}
	body, _ := json.Marshal(statusReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-prod-001/jobs/j-deploy-001/status", bytes.NewReader(body))
	req = req.WithContext(contextWithRequestID())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AgentReportJobStatus(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}

// G-2 (P1): cat-s5-apikey_leak audit closure tests. Pre-G-2,
// Agent.APIKeyHash was tagged `json:"api_key_hash"` and shipped on
// every wire surface that returned domain.Agent. Post-G-2 the tag is
// "-" and Agent.MarshalJSON enforces redaction via a marshal-time copy
// (see internal/domain/connector_test.go for the type-level pin). These
// four tests are the wire-shape contract — they capture the actual HTTP
// response body via httptest and assert the credential-derivative hash
// is absent.
//
// One sentinel value (g2HandlerLeakSentinel) flows through every fixture
// so a single grep over a failing test's output identifies the leak
// surface immediately.
const g2HandlerLeakSentinel = "sha256:LEAKED-CREDENTIAL-DERIVATIVE-HANDLER-SENTINEL"

func TestListAgents_DoesNotLeakAPIKeyHash(t *testing.T) {
	now := time.Now()
	mock := &MockAgentService{
		ListAgentsFn: func(page, perPage int) ([]domain.Agent, int64, error) {
			return []domain.Agent{
				{ID: "a-1", Name: "agent-one", Hostname: "host-1",
					Status: domain.AgentStatusOnline, RegisteredAt: now,
					APIKeyHash: g2HandlerLeakSentinel + "-1"},
				{ID: "a-2", Name: "agent-two", Hostname: "host-2",
					Status: domain.AgentStatusOnline, RegisteredAt: now,
					APIKeyHash: g2HandlerLeakSentinel + "-2"},
			}, 2, nil
		},
	}
	h := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?page=1&per_page=50", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	h.ListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListAgents status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if bytes.Contains([]byte(body), []byte("api_key_hash")) {
		t.Errorf("ListAgents response leaked \"api_key_hash\" key (G-2 regressed):\n%s", body)
	}
	if bytes.Contains([]byte(body), []byte(g2HandlerLeakSentinel)) {
		t.Errorf("ListAgents response leaked sentinel %q:\n%s", g2HandlerLeakSentinel, body)
	}
	// Sanity: the non-leaked fields ARE present (handler did serve real data).
	for _, want := range []string{"a-1", "a-2", "agent-one", "agent-two"} {
		if !bytes.Contains([]byte(body), []byte(want)) {
			t.Errorf("ListAgents response missing expected field %q (handler may not be serving data):\n%s", want, body)
		}
	}
}

func TestGetAgent_DoesNotLeakAPIKeyHash(t *testing.T) {
	now := time.Now()
	mock := &MockAgentService{
		GetAgentFn: func(id string) (*domain.Agent, error) {
			return &domain.Agent{
				ID: id, Name: "single-agent", Hostname: "single.host",
				Status: domain.AgentStatusOnline, RegisteredAt: now,
				APIKeyHash: g2HandlerLeakSentinel,
			}, nil
		},
	}
	h := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/a-prod-001", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	h.GetAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetAgent status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if bytes.Contains([]byte(body), []byte("api_key_hash")) {
		t.Errorf("GetAgent response leaked \"api_key_hash\" key:\n%s", body)
	}
	if bytes.Contains([]byte(body), []byte(g2HandlerLeakSentinel)) {
		t.Errorf("GetAgent response leaked sentinel:\n%s", body)
	}
	if !bytes.Contains([]byte(body), []byte("single-agent")) {
		t.Errorf("GetAgent response missing the agent name (handler may not be serving data):\n%s", body)
	}
}

func TestRegisterAgent_DoesNotLeakAPIKeyHash(t *testing.T) {
	// Registration is the most likely path for a freshly-hashed key to
	// leak: the service mints a new APIKeyHash inside RegisterAgent
	// (service/agent.go:405) and the handler returns the agent struct
	// verbatim. Pin that the redaction holds even on a "freshly created"
	// agent payload.
	now := time.Now()
	mock := &MockAgentService{
		RegisterAgentFn: func(in domain.Agent) (*domain.Agent, error) {
			return &domain.Agent{
				ID: "agent-new", Name: in.Name, Hostname: in.Hostname,
				Status: domain.AgentStatusOnline, RegisteredAt: now,
				APIKeyHash: g2HandlerLeakSentinel,
			}, nil
		},
	}
	h := NewAgentHandler(mock, "")
	body := bytes.NewBufferString(`{"name":"freshly-registered","hostname":"new.host"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", body)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	h.RegisterAgent(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("RegisterAgent status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	respBody := w.Body.String()
	if bytes.Contains([]byte(respBody), []byte("api_key_hash")) {
		t.Errorf("RegisterAgent response leaked \"api_key_hash\" key:\n%s", respBody)
	}
	if bytes.Contains([]byte(respBody), []byte(g2HandlerLeakSentinel)) {
		t.Errorf("RegisterAgent response leaked sentinel:\n%s", respBody)
	}
	if !bytes.Contains([]byte(respBody), []byte("agent-new")) {
		t.Errorf("RegisterAgent response missing the new agent ID (handler may not be serving data):\n%s", respBody)
	}
}

func TestListRetiredAgents_DoesNotLeakAPIKeyHash(t *testing.T) {
	// I-004 surface — separate handler from ListAgents; same leak risk.
	now := time.Now()
	retiredAt := now.Add(-1 * time.Hour)
	reason := "test cascade"
	mock := &MockAgentService{
		ListRetiredAgentsFn: func(page, perPage int) ([]domain.Agent, int64, error) {
			return []domain.Agent{
				{ID: "ret-1", Name: "retired-one", Hostname: "host-r1",
					Status: domain.AgentStatusOffline, RegisteredAt: now,
					RetiredAt: &retiredAt, RetiredReason: &reason,
					APIKeyHash: g2HandlerLeakSentinel},
			}, 1, nil
		},
	}
	h := NewAgentHandler(mock, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/retired?page=1&per_page=50", nil)
	req = req.WithContext(contextWithRequestID())
	w := httptest.NewRecorder()
	h.ListRetiredAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListRetiredAgents status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if bytes.Contains([]byte(body), []byte("api_key_hash")) {
		t.Errorf("ListRetiredAgents response leaked \"api_key_hash\" key:\n%s", body)
	}
	if bytes.Contains([]byte(body), []byte(g2HandlerLeakSentinel)) {
		t.Errorf("ListRetiredAgents response leaked sentinel:\n%s", body)
	}
	if !bytes.Contains([]byte(body), []byte("ret-1")) {
		t.Errorf("ListRetiredAgents response missing the retired agent ID:\n%s", body)
	}
}
