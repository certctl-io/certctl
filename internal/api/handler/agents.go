package handler

import (
	"github.com/shankar0123/certctl/internal/repository"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// AgentService defines the service interface for agent operations.
//
// I-004 expansion: RetireAgent + ListRetiredAgents back the soft-retirement
// surface. The handler depends on the service-package's AgentRetirementResult
// and BlockedByDependenciesError types for result shape + errors.As unwrap,
// which is why this file imports internal/service.
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
	// I-004 soft-retirement API. Both default to no-op (nil result / nil error)
	// in mocks that don't override them — handler tests opt in per suite.
	RetireAgent(ctx context.Context, agentID, actor string, force bool, reason string) (*service.AgentRetirementResult, error)
	ListRetiredAgents(ctx context.Context, page, perPage int) ([]domain.Agent, int64, error)
}

// AgentHandler handles HTTP requests for agent operations.
//
// Bundle-5 / Audit H-007: BootstrapToken is the pre-shared secret enforced
// on RegisterAgent. Empty = warn-mode pass-through; non-empty triggers the
// constant-time compare in verifyBootstrapToken. See agent_bootstrap.go.
type AgentHandler struct {
	svc            AgentService
	BootstrapToken string
}

// NewAgentHandler creates a new AgentHandler with a service dependency.
//
// Bundle-5 / Audit H-007: bootstrapToken (may be empty for warn-mode) gates
// the registration endpoint. main.go reads cfg.Auth.AgentBootstrapToken and
// passes it here.
func NewAgentHandler(svc AgentService, bootstrapToken string) AgentHandler {
	return AgentHandler{svc: svc, BootstrapToken: bootstrapToken}
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
//
// Bundle-5 / Audit H-007 / CWE-306 + CWE-288: bootstrap-token gate runs
// BEFORE body parse so an unauthenticated probe can't even cause a JSON
// allocation. When CERTCTL_AGENT_BOOTSTRAP_TOKEN is set on the server,
// callers must include `Authorization: Bearer <token>`. See
// agent_bootstrap.go for the verification helper.
func (h AgentHandler) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Bundle-5 / H-007: bootstrap-token gate. Returns 401 with a fixed
	// error string on miss so a token spray can't infer credential shape.
	if err := verifyBootstrapToken(r, h.BootstrapToken); err != nil {
		ErrorWithRequestID(w, http.StatusUnauthorized, "invalid_or_missing_bootstrap_token", requestID)
		return
	}

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
		errMsg := err.Error()
		if strings.Contains(errMsg, "unique") || strings.Contains(errMsg, "duplicate") || strings.Contains(errMsg, "already exists") {
			ErrorWithRequestID(w, http.StatusConflict, "Agent with this name already exists", requestID)
			return
		}
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
		// I-004: a retired agent still polling must receive 410 Gone so
		// cmd/agent detects the terminal signal and shuts down cleanly
		// instead of looping forever against a decommissioned identity.
		// Check this FIRST — before "not found" string matching — so the
		// retired-path is never masked by a sibling error branch.
		if errors.Is(err, service.ErrAgentRetired) {
			ErrorWithRequestID(w, http.StatusGone, "Agent has been retired", requestID)
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Agent not found", requestID)
			return
		}
		slog.Error("Heartbeat failed", "agent_id", agentID, "error", err.Error())
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
		slog.Error("CSR submission failed", "agent_id", agentID, "certificate_id", req.CertificateID, "error", err.Error())
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
	// After TrimPrefix, path is "{id}/certificates/{cert_id}" → split gives [id, "certificates", cert_id]
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 || parts[0] == "" || parts[2] == "" {
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

// RetireAgent executes the I-004 soft-retirement surface.
// DELETE /api/v1/agents/{id}[?force=true&reason=...]
//
// Contract (pinned by agent_retire_handler_test.go):
//
//	405  any method other than DELETE
//	200  clean retire (body: retired_at, already_retired=false, cascade=false, counts=0s)
//	200  force-cascade retire (body: cascade=true, counts=pre-cascade snapshot)
//	204  idempotent retire of an already-retired agent (NO body — downstream
//	     clients that tee responses into dashboards break on spurious bodies)
//	400  force=true without a non-empty reason (ErrForceReasonRequired)
//	403  one of the four reserved sentinel IDs (ErrAgentIsSentinel)
//	404  agent does not exist ("not found" string match, kept for compat with
//	     repo error strings; sentinel checks run first so they never mask)
//	409  blocked by preflight counts (*BlockedByDependenciesError) — body
//	     carries the per-bucket counts so the operator UI can tell the
//	     human which downstream dependency is holding up the retirement,
//	     rather than forcing them to re-run the DELETE with ?force=true
//	     and guess
//	500  anything else
//
// The 409 body intentionally does NOT go through ErrorWithRequestID because
// that helper's ErrorResponse shape has no `counts` field — we inline-marshal
// a custom body instead. Keeping this shape stable is important: the GUI
// pattern is "show the 409 dialog, list the N targets / M certs / K jobs
// blocking, let the operator retire them first or tick the force checkbox."
func (h AgentHandler) RetireAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	// Extract {id} from /api/v1/agents/{id}. Mirror GetAgent's pattern so
	// the path parser is identical across the agent handler surface and a
	// future refactor can extract it once without introducing drift.
	rawID := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(rawID, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Agent ID is required", requestID)
		return
	}
	id := parts[0]

	// Parse optional force + reason. A missing `force` param is treated as
	// force=false (the default, safe path); anything strconv.ParseBool rejects
	// is also force=false so a malformed query can never silently enable the
	// cascade. The reason string is passed through verbatim — the service
	// owns the "force=true requires reason" rule.
	query := r.URL.Query()
	force := false
	if fv := query.Get("force"); fv != "" {
		if parsed, err := strconv.ParseBool(fv); err == nil {
			force = parsed
		}
	}
	reason := query.Get("reason")

	actor := resolveActor(r.Context())

	result, err := h.svc.RetireAgent(r.Context(), id, actor, force, reason)
	if err != nil {
		// Sentinel + typed-error checks run BEFORE string matching on "not
		// found" so a repo error that happens to contain those words can
		// never mask a structural refusal (403/400/409). Order matters.
		if errors.Is(err, service.ErrAgentIsSentinel) {
			ErrorWithRequestID(w, http.StatusForbidden, "Agent is a reserved sentinel and cannot be retired", requestID)
			return
		}
		if errors.Is(err, service.ErrForceReasonRequired) {
			ErrorWithRequestID(w, http.StatusBadRequest, "force=true requires a non-empty reason", requestID)
			return
		}
		var blocked *service.BlockedByDependenciesError
		if errors.As(err, &blocked) {
			// Custom 409 body with per-bucket counts. ErrorResponse has no
			// `counts` field, so we marshal a bespoke struct instead.
			// Keep `error`/`message`/`counts` as the stable shape — any
			// dashboard parsing this relies on those three keys.
			body := struct {
				Error   string                       `json:"error"`
				Message string                       `json:"message"`
				Counts  domain.AgentDependencyCounts `json:"counts"`
			}{
				Error: "blocked_by_dependencies",
				Message: "Agent has active downstream dependencies. Retire or reassign them " +
					"first, or re-run with ?force=true&reason=... to cascade.",
				Counts: blocked.Counts,
			}
			JSON(w, http.StatusConflict, body)
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, "Agent not found", requestID)
			return
		}
		slog.Error("RetireAgent failed", "agent_id", id, "error", err.Error())
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to retire agent", requestID)
		return
	}

	// Idempotent retire: the agent was already retired, so we return 204 No
	// Content with a ZERO-length body. The Red contract (test line 106) fails
	// if even a trailing newline leaks into the response. WriteHeader alone
	// emits the status without invoking the JSON encoder.
	if result.AlreadyRetired {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Clean retire (force=false) or successful cascade (force=true). Body
	// shape pinned by Red contract: retired_at, already_retired, cascade,
	// counts. Omitempty is deliberately NOT used — operators parsing the
	// response expect every field to always be present.
	JSON(w, http.StatusOK, struct {
		RetiredAt      time.Time                    `json:"retired_at"`
		AlreadyRetired bool                         `json:"already_retired"`
		Cascade        bool                         `json:"cascade"`
		Counts         domain.AgentDependencyCounts `json:"counts"`
	}{
		RetiredAt:      result.RetiredAt,
		AlreadyRetired: result.AlreadyRetired,
		Cascade:        result.Cascade,
		Counts:         result.Counts,
	})
}

// ListRetiredAgents returns the opt-in listing of retired agents for the
// operator UI's "Retired" tab and for audit/forensics workflows.
// GET /api/v1/agents/retired?page=1&per_page=50
//
// The default ListAgents handler hides retired rows; this is the dedicated
// surface for reading them back. Pagination defaults match ListAgents so
// the GUI can reuse the same query hook (page=1, per_page=50, cap 500).
//
// Go 1.22's enhanced ServeMux routes `/agents/retired` to this handler via
// the literal-beats-pattern-var precedence rule (literal `retired` wins over
// `{id}` in the sibling GET /api/v1/agents/{id} route), so both entries can
// coexist without conflict. If that precedence ever regresses, the failure
// mode is TestListRetiredAgentsHandler_Success blowing up with a 404 — which
// is the fast signal we want.
func (h AgentHandler) ListRetiredAgents(w http.ResponseWriter, r *http.Request) {
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

	agents, total, err := h.svc.ListRetiredAgents(r.Context(), page, perPage)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list retired agents", requestID)
		return
	}

	JSON(w, http.StatusOK, PagedResponse{
		Data:    agents,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}
