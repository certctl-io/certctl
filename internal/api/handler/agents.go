package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
)

// AgentService defines the service interface for agent operations.
type AgentService interface {
	ListAgents(ctx context.Context, page, perPage int) ([]domain.Agent, int64, error)
	GetAgent(ctx context.Context, id string) (*domain.Agent, error)
	RegisterAgent(ctx context.Context, agent domain.Agent) (*domain.Agent, error)
	Heartbeat(ctx context.Context, agentID string, metadata *domain.AgentMetadata) error
	CSRSubmit(ctx context.Context, agentID string, csrPEM string) (string, error)
	CSRSubmitForCert(ctx context.Context, agentID string, certID string, csrPEM string) (string, error)
	CertificatePickup(ctx context.Context, agentID, certID string) (string, error)
	GetWork(ctx context.Context, agentID string) ([]domain.Job, error)
	GetWorkWithTargets(ctx context.Context, agentID string) ([]domain.WorkItem, error)
	UpdateJobStatus(ctx context.Context, agentID string, jobID string, status string, errMsg string) error
}

// AgentHandler handles HTTP requests for agent operations.
type AgentHandler struct {
	svc AgentService
}

// NewAgentHandler creates a new AgentHandler with a service dependency.
func NewAgentHandler(svc AgentService) AgentHandler {
	return AgentHandler{svc: svc}
}

// ListAgents lists all registered agents.
// GET /api/v1/agents?page=1&per_page=50
func (h AgentHandler) ListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	page := 1
	perPage := 50
	query := r.URL.Query()
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 && parsed <= 500 {
			perPage = parsed
		}
	}

	agents, total, err := h.svc.ListAgents(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list agents", requestID)
		return
	}

	response := PagedResponse{
		Data:    agents,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetAgent retrieves a single agent by ID.
// GET /api/v1/agents/{id}
func (h AgentHandler) GetAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent ID is required", requestID)
		return
	}
	id = parts[0]

	agent, err := h.svc.GetAgent(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Agent not found", requestID)
		return
	}

	JSON(w, http.StatusOK, agent)
}

// RegisterAgent registers a new agent.
// POST /api/v1/agents
func (h AgentHandler) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	var agent domain.Agent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate required fields
	if err := ValidateRequired("name", agent.Name); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateStringLength("name", agent.Name, 128); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}
	if err := ValidateRequired("hostname", agent.Hostname); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	created, err := h.svc.RegisterAgent(r.Context(), agent)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to register agent", requestID)
		return
	}

	JSON(w, http.StatusCreated, created)
}

// Heartbeat records a heartbeat from an agent.
// POST /api/v1/agents/{id}/heartbeat
func (h AgentHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract agent ID from path /api/v1/agents/{id}/heartbeat
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent ID is required", requestID)
		return
	}
	agentID := parts[0]

	// Parse optional metadata from request body
	var metadata *domain.AgentMetadata
	if r.Body != nil {
		var body struct {
			Version      string `json:"version"`
			Hostname     string `json:"hostname"`
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			IPAddress    string `json:"ip_address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			if body.Version != "" || body.Hostname != "" || body.OS != "" || body.Architecture != "" || body.IPAddress != "" {
				metadata = &domain.AgentMetadata{
					Version:      body.Version,
					Hostname:     body.Hostname,
					OS:           body.OS,
					Architecture: body.Architecture,
					IPAddress:    body.IPAddress,
				}
			}
		}
	}

	if err := h.svc.Heartbeat(r.Context(), agentID, metadata); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to record heartbeat", requestID)
		return
	}

	response := map[string]string{
		"status": "heartbeat_recorded",
	}

	JSON(w, http.StatusOK, response)
}

// AgentCSRSubmit receives a Certificate Signing Request from an agent.
// POST /api/v1/agents/{id}/csr
// Optionally accepts a certificate_id to sign the CSR for a specific certificate.
func (h AgentHandler) AgentCSRSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract agent ID from path /api/v1/agents/{id}/csr
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent ID is required", requestID)
		return
	}
	agentID := parts[0]

	var req struct {
		CSRPEM        string `json:"csr_pem"`
		CertificateID string `json:"certificate_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	// Validate CSR PEM
	if err := ValidateCSRPEM(req.CSRPEM); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		return
	}

	var status string
	var err error

	// If certificate_id is provided, sign the CSR for that specific certificate
	if req.CertificateID != "" {
		status, err = h.svc.CSRSubmitForCert(r.Context(), agentID, req.CertificateID, req.CSRPEM)
	} else {
		status, err = h.svc.CSRSubmit(r.Context(), agentID, req.CSRPEM)
	}

	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to submit CSR", requestID)
		return
	}

	response := map[string]string{
		"status": status,
	}

	JSON(w, http.StatusAccepted, response)
}

// AgentCertificatePickup allows an agent to retrieve an issued certificate.
// GET /api/v1/agents/{id}/certificates/{cert_id}
func (h AgentHandler) AgentCertificatePickup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract agent ID and certificate ID from path /api/v1/agents/{id}/certificates/{cert_id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[0] == "" || parts[2] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent ID and Certificate ID are required", requestID)
		return
	}
	agentID := parts[0]
	certID := parts[2]

	certPEM, err := h.svc.CertificatePickup(r.Context(), agentID, certID)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Certificate not found or not ready", requestID)
		return
	}

	response := map[string]string{
		"certificate_pem": certPEM,
	}

	JSON(w, http.StatusOK, response)
}

// AgentGetWork returns pending deployment jobs for an agent.
// GET /api/v1/agents/{id}/work
func (h AgentHandler) AgentGetWork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract agent ID from path /api/v1/agents/{id}/work
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent ID is required", requestID)
		return
	}
	agentID := parts[0]

	workItems, err := h.svc.GetWorkWithTargets(r.Context(), agentID)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to get pending work", requestID)
		return
	}

	if workItems == nil {
		workItems = []domain.WorkItem{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"jobs":  workItems,
		"count": len(workItems),
	})
}

// AgentReportJobStatus receives a job status report from an agent.
// POST /api/v1/agents/{id}/jobs/{job_id}/status
func (h AgentHandler) AgentReportJobStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract agent ID and job ID from path /api/v1/agents/{id}/jobs/{job_id}/status
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[0] == "" || parts[2] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent ID and Job ID are required", requestID)
		return
	}
	agentID := parts[0]
	jobID := parts[2]

	var req struct {
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "Invalid request body", requestID)
		return
	}

	if req.Status == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Status is required", requestID)
		return
	}

	if err := h.svc.UpdateJobStatus(r.Context(), agentID, jobID, req.Status, req.Error); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to update job status", requestID)
		return
	}

	JSON(w, http.StatusOK, map[string]string{
		"status": "updated",
	})
}
