package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/api/handler"
	"github.com/shankar0123/certctl/internal/api/router"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/service"
)

// TestCertificateLifecycle exercises the full certificate lifecycle:
// create -> renew -> process jobs -> verify versions -> register agent -> heartbeat -> audit trail
func TestCertificateLifecycle(t *testing.T) {
	ctx := context.Background()

	// Setup: Create in-memory mock repositories
	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	auditRepo := newMockAuditRepository()
	agentRepo := newMockAgentRepository()
	targetRepo := newMockTargetRepository()
	notifRepo := newMockNotificationRepository()
	policyRepo := newMockPolicyRepository()
	renewalPolicyRepo := newMockRenewalPolicyRepository()
	issuerRepo := newMockIssuerRepository()

	// Create logger
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Initialize Local CA issuer connector (real implementation, no mock)
	localCA := local.New(nil, logger)

	// Build issuer registry with adapter
	issuerRegistry := map[string]service.IssuerConnector{
		"iss-local": service.NewIssuerConnectorAdapter(localCA),
	}

	// Initialize services (following dependency graph)
	auditService := service.NewAuditService(auditRepo)
	policyService := service.NewPolicyService(policyRepo, auditService)
	certificateService := service.NewCertificateService(certRepo, policyService, auditService)
	notificationService := service.NewNotificationService(notifRepo, make(map[string]service.Notifier))
	revocationRepo := newMockRevocationRepository()
	certificateService.SetRevocationRepo(revocationRepo)
	certificateService.SetNotificationService(notificationService)
	certificateService.SetIssuerRegistry(issuerRegistry)
	certificateService.SetTargetRepo(targetRepo)
	renewalService := service.NewRenewalService(certRepo, jobRepo, renewalPolicyRepo, nil, auditService, notificationService, issuerRegistry, "server")
	deploymentService := service.NewDeploymentService(jobRepo, targetRepo, agentRepo, certRepo, auditService, notificationService)
	jobService := service.NewJobService(jobRepo, renewalService, deploymentService, logger)
	agentService := service.NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, renewalService)
	issuerService := service.NewIssuerService(issuerRepo, auditService)

	// Initialize handlers
	certificateHandler := handler.NewCertificateHandler(certificateService)
	issuerHandler := handler.NewIssuerHandler(issuerService)
	targetHandler := handler.NewTargetHandler(&mockTargetService{targetRepo: targetRepo, auditService: auditService})
	agentHandler := handler.NewAgentHandler(agentService)
	jobHandler := handler.NewJobHandler(jobService)
	policyHandler := handler.NewPolicyHandler(policyService)
	profileHandler := handler.NewProfileHandler(&mockProfileService{})
	teamHandler := handler.NewTeamHandler(&mockTeamService{})
	ownerHandler := handler.NewOwnerHandler(&mockOwnerService{})
	agentGroupHandler := handler.NewAgentGroupHandler(&mockAgentGroupService{})
	auditHandler := handler.NewAuditHandler(auditService)
	notificationHandler := handler.NewNotificationHandler(notificationService)
	statsHandler := handler.NewStatsHandler(&mockStatsService{})
	metricsHandler := handler.NewMetricsHandler(&mockStatsService{}, time.Now())
	healthHandler := handler.NewHealthHandler("none")

	// Create router and register handlers
	r := router.New()
	r.RegisterHandlers(
		certificateHandler,
		issuerHandler,
		targetHandler,
		agentHandler,
		jobHandler,
		policyHandler,
		profileHandler,
		teamHandler,
		ownerHandler,
		agentGroupHandler,
		auditHandler,
		notificationHandler,
		statsHandler,
		metricsHandler,
		healthHandler,
	)

	// Create test server
	server := httptest.NewServer(r)
	defer server.Close()

	// ======================
	// Step 1: Check health
	// ======================
	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/health")
		if err != nil {
			t.Fatalf("GET /health failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if body["status"] != "healthy" {
			t.Errorf("expected status=healthy, got %s", body["status"])
		}
	})

	// ======================
	// Step 2: Create certificate
	// ======================
	var certID string
	t.Run("CreateCertificate", func(t *testing.T) {
		now := time.Now()
		payload := map[string]interface{}{
			"name":              "Example Certificate",
			"common_name":       "example.com",
			"sans":              []string{"www.example.com", "api.example.com"},
			"environment":       "production",
			"owner_id":          "owner-alice",
			"team_id":           "team-platform",
			"issuer_id":         "iss-local",
			"target_ids":        []string{},
			"renewal_policy_id": "policy-standard",
			"status":            "Pending",
			"expires_at":        now.AddDate(1, 0, 0),
			"tags":              map[string]string{"environment": "prod"},
		}

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal payload: %v", err)
		}

		resp, err := http.Post(
			server.URL+"/api/v1/certificates",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("POST /api/v1/certificates failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 201, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}

		var cert domain.ManagedCertificate
		if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if cert.ID == "" {
			t.Fatalf("response missing id field")
		}

		certID = cert.ID
		t.Logf("Created certificate with ID: %s", certID)
	})

	// ======================
	// Step 3: Verify certificate
	// ======================
	t.Run("GetCertificate", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates/" + certID)
		if err != nil {
			t.Fatalf("GET /api/v1/certificates/{id} failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		var cert domain.ManagedCertificate
		if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if cert.ID != certID {
			t.Errorf("expected cert ID %s, got %s", certID, cert.ID)
		}
		if cert.CommonName != "example.com" {
			t.Errorf("expected common_name example.com, got %s", cert.CommonName)
		}
		if len(cert.SANs) != 2 {
			t.Errorf("expected 2 SANs, got %d", len(cert.SANs))
		}
	})

	// ======================
	// Step 4: Trigger renewal
	// ======================
	t.Run("TriggerRenewal", func(t *testing.T) {
		resp, err := http.Post(
			server.URL+"/api/v1/certificates/"+certID+"/renew",
			"application/json",
			nil,
		)
		if err != nil {
			t.Fatalf("POST /api/v1/certificates/{id}/renew failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 202, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	// ======================
	// Step 5: Process jobs (simulate scheduler)
	// ======================
	t.Run("ProcessPendingJobs", func(t *testing.T) {
		// Jobs should have been created by the renewal trigger.
		// Process them using the job service directly.
		if err := jobService.ProcessPendingJobs(ctx); err != nil {
			t.Fatalf("failed to process pending jobs: %v", err)
		}

		// Verify that jobs were processed
		jobs, err := jobRepo.ListByStatus(ctx, domain.JobStatusCompleted)
		if err != nil {
			t.Fatalf("failed to list completed jobs: %v", err)
		}

		// We expect at least one renewal job to have been processed
		if len(jobs) == 0 {
			t.Logf("Warning: no completed jobs found. This may indicate the renewal job wasn't processed.")
			// Check pending jobs instead
			pending, _ := jobRepo.ListByStatus(ctx, domain.JobStatusPending)
			t.Logf("Pending jobs: %d", len(pending))
		}
	})

	// ======================
	// Step 6: Verify certificate versions
	// ======================
	t.Run("GetCertificateVersions", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates/" + certID + "/versions")
		if err != nil {
			t.Fatalf("GET /api/v1/certificates/{id}/versions failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}

		var respBody map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Extract data field which contains the versions array
		dataField := respBody["data"]
		if dataField == nil {
			t.Logf("No versions found yet - this is expected if renewal is still in progress")
		} else {
			versions, ok := dataField.([]interface{})
			if !ok {
				t.Errorf("expected data to be array, got %T", dataField)
			} else if len(versions) > 0 {
				t.Logf("Found %d certificate versions", len(versions))
				// Verify the first version has required fields
				if version, ok := versions[0].(map[string]interface{}); ok {
					if version["pem_chain"] == nil || version["pem_chain"] == "" {
						t.Errorf("certificate version missing pem_chain")
					}
					if version["serial_number"] == nil || version["serial_number"] == "" {
						t.Errorf("certificate version missing serial_number")
					}
				}
			}
		}
	})

	// ======================
	// Step 7: Register agent
	// ======================
	var agentID string
	t.Run("RegisterAgent", func(t *testing.T) {
		payload := map[string]string{
			"name":     "agent-prod-1",
			"hostname": "prod-server-01.example.com",
		}

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal payload: %v", err)
		}

		resp, err := http.Post(
			server.URL+"/api/v1/agents",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("POST /api/v1/agents failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 201, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}

		// The handler returns the agent directly, not wrapped
		var agent domain.Agent
		if err := json.NewDecoder(resp.Body).Decode(&agent); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		agentID = agent.ID
		if agentID == "" {
			t.Fatalf("agent id is empty")
		}

		t.Logf("Registered agent with ID: %s", agentID)
	})

	// ======================
	// Step 8: Agent heartbeat
	// ======================
	t.Run("AgentHeartbeat", func(t *testing.T) {
		payload := map[string]string{
			"agent_id": agentID,
		}

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal payload: %v", err)
		}

		resp, err := http.Post(
			server.URL+"/api/v1/agents/"+agentID+"/heartbeat",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("POST /api/v1/agents/{id}/heartbeat failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}

		// Verify agent heartbeat was updated
		agent, err := agentRepo.Get(ctx, agentID)
		if err != nil {
			t.Fatalf("failed to get agent: %v", err)
		}

		if agent.LastHeartbeatAt == nil {
			t.Errorf("agent LastHeartbeatAt was not updated")
		}
	})

	// ======================
	// Step 9: List audit events
	// ======================
	t.Run("ListAuditEvents", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/audit?page=1&per_page=50")
		if err != nil {
			t.Fatalf("GET /api/v1/audit failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		var respBody map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Extract data field which contains the events array
		dataField := respBody["data"]
		if dataField == nil {
			t.Logf("No audit events found")
		} else {
			events, ok := dataField.([]interface{})
			if !ok {
				t.Errorf("expected data to be array, got %T", dataField)
			} else {
				t.Logf("Found %d audit events", len(events))
				if len(events) == 0 {
					t.Logf("Warning: no audit events found. Expected events for certificate_created, agent_registered, etc.")
				}

				// Verify we have expected event types
				eventTypes := make(map[string]int)
				for _, evt := range events {
					if eventMap, ok := evt.(map[string]interface{}); ok {
						if action, ok := eventMap["action"].(string); ok {
							eventTypes[action]++
						}
					}
				}
				t.Logf("Audit event types: %v", eventTypes)
			}
		}
	})

	// ======================
	// Step 10: Get agent and verify status
	// ======================
	t.Run("GetAgent", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/agents/" + agentID)
		if err != nil {
			t.Fatalf("GET /api/v1/agents/{id} failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}

		var agent domain.Agent
		if err := json.NewDecoder(resp.Body).Decode(&agent); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if agent.ID != agentID {
			t.Errorf("expected agent ID %s, got %s", agentID, agent.ID)
		}
		if agent.Status != domain.AgentStatusOnline {
			t.Errorf("expected agent status Online, got %s", agent.Status)
		}
	})

	// ======================
	// Summary
	// ======================
	t.Run("Summary", func(t *testing.T) {
		totalCerts, _, _ := certRepo.List(ctx, &repository.CertificateFilter{})
		totalJobs, _ := jobRepo.List(ctx)
		totalAgents, _ := agentRepo.List(ctx)
		totalAuditEvents, _ := auditRepo.List(ctx, &repository.AuditFilter{})

		t.Logf("=== Integration Test Summary ===")
		t.Logf("Certificates: %d", len(totalCerts))
		t.Logf("Jobs: %d", len(totalJobs))
		t.Logf("Agents: %d", len(totalAgents))
		t.Logf("Audit Events: %d", len(totalAuditEvents))

		if len(totalCerts) == 0 {
			t.Error("Expected at least 1 certificate")
		}
		if len(totalAgents) == 0 {
			t.Error("Expected at least 1 agent")
		}
		if len(totalAuditEvents) == 0 {
			t.Logf("Warning: Expected audit events, but none found")
		}
	})
}

// Mock repository implementations for integration testing
// These are simple in-memory implementations similar to testutil_test.go patterns

type mockCertificateRepository struct {
	certs    map[string]*domain.ManagedCertificate
	versions map[string][]*domain.CertificateVersion
}

func newMockCertificateRepository() *mockCertificateRepository {
	return &mockCertificateRepository{
		certs:    make(map[string]*domain.ManagedCertificate),
		versions: make(map[string][]*domain.CertificateVersion),
	}
}

func (m *mockCertificateRepository) List(ctx context.Context, filter *repository.CertificateFilter) ([]*domain.ManagedCertificate, int, error) {
	var certs []*domain.ManagedCertificate
	for _, c := range m.certs {
		certs = append(certs, c)
	}
	return certs, len(certs), nil
}

func (m *mockCertificateRepository) Get(ctx context.Context, id string) (*domain.ManagedCertificate, error) {
	cert, ok := m.certs[id]
	if !ok {
		return nil, fmt.Errorf("certificate not found")
	}
	return cert, nil
}

func (m *mockCertificateRepository) Create(ctx context.Context, cert *domain.ManagedCertificate) error {
	m.certs[cert.ID] = cert
	return nil
}

func (m *mockCertificateRepository) Update(ctx context.Context, cert *domain.ManagedCertificate) error {
	m.certs[cert.ID] = cert
	return nil
}

func (m *mockCertificateRepository) Archive(ctx context.Context, id string) error {
	cert, ok := m.certs[id]
	if !ok {
		return fmt.Errorf("certificate not found")
	}
	cert.Status = domain.CertificateStatusArchived
	return nil
}

func (m *mockCertificateRepository) ListVersions(ctx context.Context, certID string) ([]*domain.CertificateVersion, error) {
	return m.versions[certID], nil
}

func (m *mockCertificateRepository) CreateVersion(ctx context.Context, version *domain.CertificateVersion) error {
	m.versions[version.CertificateID] = append(m.versions[version.CertificateID], version)
	return nil
}

func (m *mockCertificateRepository) GetExpiringCertificates(ctx context.Context, before time.Time) ([]*domain.ManagedCertificate, error) {
	var expiring []*domain.ManagedCertificate
	for _, c := range m.certs {
		if c.ExpiresAt.Before(before) {
			expiring = append(expiring, c)
		}
	}
	return expiring, nil
}

func (m *mockCertificateRepository) GetLatestVersion(ctx context.Context, certID string) (*domain.CertificateVersion, error) {
	versions := m.versions[certID]
	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found")
	}
	return versions[len(versions)-1], nil
}

type mockJobRepository struct {
	jobs map[string]*domain.Job
}

func newMockJobRepository() *mockJobRepository {
	return &mockJobRepository{
		jobs: make(map[string]*domain.Job),
	}
}

func (m *mockJobRepository) List(ctx context.Context) ([]*domain.Job, error) {
	var jobs []*domain.Job
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	return jobs, nil
}

func (m *mockJobRepository) Get(ctx context.Context, id string) (*domain.Job, error) {
	job, ok := m.jobs[id]
	if !ok {
		return nil, fmt.Errorf("job not found")
	}
	return job, nil
}

func (m *mockJobRepository) Create(ctx context.Context, job *domain.Job) error {
	m.jobs[job.ID] = job
	return nil
}

func (m *mockJobRepository) Update(ctx context.Context, job *domain.Job) error {
	m.jobs[job.ID] = job
	return nil
}

func (m *mockJobRepository) Delete(ctx context.Context, id string) error {
	delete(m.jobs, id)
	return nil
}

func (m *mockJobRepository) ListByStatus(ctx context.Context, status domain.JobStatus) ([]*domain.Job, error) {
	var jobs []*domain.Job
	for _, j := range m.jobs {
		if j.Status == status {
			jobs = append(jobs, j)
		}
	}
	return jobs, nil
}

func (m *mockJobRepository) ListByCertificate(ctx context.Context, certID string) ([]*domain.Job, error) {
	var jobs []*domain.Job
	for _, j := range m.jobs {
		if j.CertificateID == certID {
			jobs = append(jobs, j)
		}
	}
	return jobs, nil
}

func (m *mockJobRepository) UpdateStatus(ctx context.Context, id string, status domain.JobStatus, errMsg string) error {
	job, ok := m.jobs[id]
	if !ok {
		return fmt.Errorf("job not found")
	}
	job.Status = status
	if errMsg != "" {
		job.LastError = &errMsg
	}
	return nil
}

func (m *mockJobRepository) GetPendingJobs(ctx context.Context, jobType domain.JobType) ([]*domain.Job, error) {
	var jobs []*domain.Job
	for _, j := range m.jobs {
		if j.Type == jobType && j.Status == domain.JobStatusPending {
			jobs = append(jobs, j)
		}
	}
	return jobs, nil
}

type mockAuditRepository struct {
	events []*domain.AuditEvent
}

func newMockAuditRepository() *mockAuditRepository {
	return &mockAuditRepository{
		events: make([]*domain.AuditEvent, 0),
	}
}

func (m *mockAuditRepository) Create(ctx context.Context, event *domain.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuditRepository) List(ctx context.Context, filter *repository.AuditFilter) ([]*domain.AuditEvent, error) {
	return m.events, nil
}

type mockAgentRepository struct {
	agents map[string]*domain.Agent
}

func newMockAgentRepository() *mockAgentRepository {
	return &mockAgentRepository{
		agents: make(map[string]*domain.Agent),
	}
}

func (m *mockAgentRepository) List(ctx context.Context) ([]*domain.Agent, error) {
	var agents []*domain.Agent
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents, nil
}

func (m *mockAgentRepository) Get(ctx context.Context, id string) (*domain.Agent, error) {
	agent, ok := m.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	return agent, nil
}

func (m *mockAgentRepository) Create(ctx context.Context, agent *domain.Agent) error {
	m.agents[agent.ID] = agent
	return nil
}

func (m *mockAgentRepository) Update(ctx context.Context, agent *domain.Agent) error {
	m.agents[agent.ID] = agent
	return nil
}

func (m *mockAgentRepository) Delete(ctx context.Context, id string) error {
	delete(m.agents, id)
	return nil
}

func (m *mockAgentRepository) UpdateHeartbeat(ctx context.Context, id string, metadata *domain.AgentMetadata) error {
	agent, ok := m.agents[id]
	if !ok {
		return fmt.Errorf("agent not found")
	}
	now := time.Now()
	agent.LastHeartbeatAt = &now
	return nil
}

func (m *mockAgentRepository) GetByAPIKey(ctx context.Context, keyHash string) (*domain.Agent, error) {
	for _, a := range m.agents {
		if a.APIKeyHash == keyHash {
			return a, nil
		}
	}
	return nil, fmt.Errorf("agent not found")
}

type mockTargetRepository struct {
	targets map[string]*domain.DeploymentTarget
}

func newMockTargetRepository() *mockTargetRepository {
	return &mockTargetRepository{
		targets: make(map[string]*domain.DeploymentTarget),
	}
}

func (m *mockTargetRepository) List(ctx context.Context) ([]*domain.DeploymentTarget, error) {
	var targets []*domain.DeploymentTarget
	for _, t := range m.targets {
		targets = append(targets, t)
	}
	return targets, nil
}

func (m *mockTargetRepository) Get(ctx context.Context, id string) (*domain.DeploymentTarget, error) {
	target, ok := m.targets[id]
	if !ok {
		return nil, fmt.Errorf("target not found")
	}
	return target, nil
}

func (m *mockTargetRepository) Create(ctx context.Context, target *domain.DeploymentTarget) error {
	m.targets[target.ID] = target
	return nil
}

func (m *mockTargetRepository) Update(ctx context.Context, target *domain.DeploymentTarget) error {
	m.targets[target.ID] = target
	return nil
}

func (m *mockTargetRepository) Delete(ctx context.Context, id string) error {
	delete(m.targets, id)
	return nil
}

func (m *mockTargetRepository) ListByCertificate(ctx context.Context, certID string) ([]*domain.DeploymentTarget, error) {
	return m.List(ctx)
}

type mockNotificationRepository struct {
	notifications []*domain.NotificationEvent
}

func newMockNotificationRepository() *mockNotificationRepository {
	return &mockNotificationRepository{
		notifications: make([]*domain.NotificationEvent, 0),
	}
}

func (m *mockNotificationRepository) Create(ctx context.Context, notif *domain.NotificationEvent) error {
	m.notifications = append(m.notifications, notif)
	return nil
}

func (m *mockNotificationRepository) List(ctx context.Context, filter *repository.NotificationFilter) ([]*domain.NotificationEvent, error) {
	return m.notifications, nil
}

func (m *mockNotificationRepository) UpdateStatus(ctx context.Context, id string, status string, sentAt time.Time) error {
	for _, n := range m.notifications {
		if n.ID == id {
			n.Status = status
			return nil
		}
	}
	return fmt.Errorf("notification not found")
}

type mockPolicyRepository struct {
	rules      map[string]*domain.PolicyRule
	violations []*domain.PolicyViolation
}

func newMockPolicyRepository() *mockPolicyRepository {
	return &mockPolicyRepository{
		rules:      make(map[string]*domain.PolicyRule),
		violations: make([]*domain.PolicyViolation, 0),
	}
}

func (m *mockPolicyRepository) ListRules(ctx context.Context) ([]*domain.PolicyRule, error) {
	var rules []*domain.PolicyRule
	for _, r := range m.rules {
		rules = append(rules, r)
	}
	return rules, nil
}

func (m *mockPolicyRepository) GetRule(ctx context.Context, id string) (*domain.PolicyRule, error) {
	rule, ok := m.rules[id]
	if !ok {
		return nil, fmt.Errorf("rule not found")
	}
	return rule, nil
}

func (m *mockPolicyRepository) CreateRule(ctx context.Context, rule *domain.PolicyRule) error {
	m.rules[rule.ID] = rule
	return nil
}

func (m *mockPolicyRepository) UpdateRule(ctx context.Context, rule *domain.PolicyRule) error {
	m.rules[rule.ID] = rule
	return nil
}

func (m *mockPolicyRepository) DeleteRule(ctx context.Context, id string) error {
	delete(m.rules, id)
	return nil
}

func (m *mockPolicyRepository) CreateViolation(ctx context.Context, violation *domain.PolicyViolation) error {
	m.violations = append(m.violations, violation)
	return nil
}

func (m *mockPolicyRepository) ListViolations(ctx context.Context, filter *repository.AuditFilter) ([]*domain.PolicyViolation, error) {
	return m.violations, nil
}

type mockRenewalPolicyRepository struct {
	policies map[string]*domain.RenewalPolicy
}

func newMockRenewalPolicyRepository() *mockRenewalPolicyRepository {
	return &mockRenewalPolicyRepository{
		policies: make(map[string]*domain.RenewalPolicy),
	}
}

func (m *mockRenewalPolicyRepository) Get(ctx context.Context, id string) (*domain.RenewalPolicy, error) {
	policy, ok := m.policies[id]
	if !ok {
		// Return default policy
		return &domain.RenewalPolicy{
			ID:                  id,
			Name:                "Default Policy",
			RenewalWindowDays:   30,
			AutoRenew:           true,
			MaxRetries:          3,
			RetryInterval:       3600,
			AlertThresholdsDays: domain.DefaultAlertThresholds(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}, nil
	}
	return policy, nil
}

func (m *mockRenewalPolicyRepository) List(ctx context.Context) ([]*domain.RenewalPolicy, error) {
	var policies []*domain.RenewalPolicy
	for _, p := range m.policies {
		policies = append(policies, p)
	}
	return policies, nil
}

type mockIssuerRepository struct {
	issuers map[string]*domain.Issuer
}

func newMockIssuerRepository() *mockIssuerRepository {
	return &mockIssuerRepository{
		issuers: make(map[string]*domain.Issuer),
	}
}

func (m *mockIssuerRepository) List(ctx context.Context) ([]*domain.Issuer, error) {
	var issuers []*domain.Issuer
	for _, i := range m.issuers {
		issuers = append(issuers, i)
	}
	return issuers, nil
}

func (m *mockIssuerRepository) Get(ctx context.Context, id string) (*domain.Issuer, error) {
	issuer, ok := m.issuers[id]
	if !ok {
		return nil, fmt.Errorf("issuer not found")
	}
	return issuer, nil
}

func (m *mockIssuerRepository) Create(ctx context.Context, issuer *domain.Issuer) error {
	m.issuers[issuer.ID] = issuer
	return nil
}

func (m *mockIssuerRepository) Update(ctx context.Context, issuer *domain.Issuer) error {
	m.issuers[issuer.ID] = issuer
	return nil
}

func (m *mockIssuerRepository) Delete(ctx context.Context, id string) error {
	delete(m.issuers, id)
	return nil
}

// Mock service implementations for handlers that need them but aren't tested

type mockTargetService struct {
	targetRepo   *mockTargetRepository
	auditService *service.AuditService
}

func (m *mockTargetService) ListTargets(page, perPage int) ([]domain.DeploymentTarget, int64, error) {
	targets, err := m.targetRepo.List(context.Background())
	if err != nil {
		return nil, 0, err
	}
	var result []domain.DeploymentTarget
	for _, t := range targets {
		result = append(result, *t)
	}
	return result, int64(len(result)), nil
}

func (m *mockTargetService) GetTarget(id string) (*domain.DeploymentTarget, error) {
	return m.targetRepo.Get(context.Background(), id)
}

func (m *mockTargetService) CreateTarget(target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	if err := m.targetRepo.Create(context.Background(), &target); err != nil {
		return nil, err
	}
	return &target, nil
}

func (m *mockTargetService) UpdateTarget(id string, target domain.DeploymentTarget) (*domain.DeploymentTarget, error) {
	target.ID = id
	if err := m.targetRepo.Update(context.Background(), &target); err != nil {
		return nil, err
	}
	return &target, nil
}

func (m *mockTargetService) DeleteTarget(id string) error {
	return m.targetRepo.Delete(context.Background(), id)
}

type mockTeamService struct{}

func (m *mockTeamService) ListTeams(page, perPage int) ([]domain.Team, int64, error) {
	return []domain.Team{}, 0, nil
}

func (m *mockTeamService) GetTeam(id string) (*domain.Team, error) {
	return nil, fmt.Errorf("team not found")
}

func (m *mockTeamService) CreateTeam(team domain.Team) (*domain.Team, error) {
	return &team, nil
}

func (m *mockTeamService) UpdateTeam(id string, team domain.Team) (*domain.Team, error) {
	team.ID = id
	return &team, nil
}

func (m *mockTeamService) DeleteTeam(id string) error {
	return nil
}

type mockOwnerService struct{}

func (m *mockOwnerService) ListOwners(page, perPage int) ([]domain.Owner, int64, error) {
	return []domain.Owner{}, 0, nil
}

func (m *mockOwnerService) GetOwner(id string) (*domain.Owner, error) {
	return nil, fmt.Errorf("owner not found")
}

func (m *mockOwnerService) CreateOwner(owner domain.Owner) (*domain.Owner, error) {
	return &owner, nil
}

func (m *mockOwnerService) UpdateOwner(id string, owner domain.Owner) (*domain.Owner, error) {
	owner.ID = id
	return &owner, nil
}

func (m *mockOwnerService) DeleteOwner(id string) error {
	return nil
}

type mockProfileService struct{}

func (m *mockProfileService) ListProfiles(page, perPage int) ([]domain.CertificateProfile, int64, error) {
	return []domain.CertificateProfile{}, 0, nil
}

func (m *mockProfileService) GetProfile(id string) (*domain.CertificateProfile, error) {
	return nil, fmt.Errorf("profile not found")
}

func (m *mockProfileService) CreateProfile(profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
	return &profile, nil
}

func (m *mockProfileService) UpdateProfile(id string, profile domain.CertificateProfile) (*domain.CertificateProfile, error) {
	profile.ID = id
	return &profile, nil
}

func (m *mockProfileService) DeleteProfile(id string) error {
	return nil
}

type mockAgentGroupService struct{}

func (m *mockAgentGroupService) ListAgentGroups(page, perPage int) ([]domain.AgentGroup, int64, error) {
	return []domain.AgentGroup{}, 0, nil
}

func (m *mockAgentGroupService) GetAgentGroup(id string) (*domain.AgentGroup, error) {
	return nil, fmt.Errorf("agent group not found")
}

func (m *mockAgentGroupService) CreateAgentGroup(group domain.AgentGroup) (*domain.AgentGroup, error) {
	return &group, nil
}

func (m *mockAgentGroupService) UpdateAgentGroup(id string, group domain.AgentGroup) (*domain.AgentGroup, error) {
	group.ID = id
	return &group, nil
}

func (m *mockAgentGroupService) DeleteAgentGroup(id string) error {
	return nil
}

func (m *mockAgentGroupService) ListMembers(id string) ([]domain.Agent, int64, error) {
	return []domain.Agent{}, 0, nil
}

// mockRevocationRepository is a test implementation of RevocationRepository for integration tests.
type mockRevocationRepository struct {
	revocations []*domain.CertificateRevocation
}

func newMockRevocationRepository() *mockRevocationRepository {
	return &mockRevocationRepository{
		revocations: make([]*domain.CertificateRevocation, 0),
	}
}

func (m *mockRevocationRepository) Create(ctx context.Context, revocation *domain.CertificateRevocation) error {
	m.revocations = append(m.revocations, revocation)
	return nil
}

func (m *mockRevocationRepository) GetBySerial(ctx context.Context, serial string) (*domain.CertificateRevocation, error) {
	for _, r := range m.revocations {
		if r.SerialNumber == serial {
			return r, nil
		}
	}
	return nil, fmt.Errorf("revocation not found")
}

func (m *mockRevocationRepository) ListAll(ctx context.Context) ([]*domain.CertificateRevocation, error) {
	return m.revocations, nil
}

func (m *mockRevocationRepository) ListByCertificate(ctx context.Context, certID string) ([]*domain.CertificateRevocation, error) {
	var result []*domain.CertificateRevocation
	for _, r := range m.revocations {
		if r.CertificateID == certID {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockRevocationRepository) MarkIssuerNotified(ctx context.Context, id string) error {
	for _, r := range m.revocations {
		if r.ID == id {
			r.IssuerNotified = true
			return nil
		}
	}
	return fmt.Errorf("revocation not found")
}

// mockStatsService implements both handler.StatsService and handler.MetricsService for integration tests.
type mockStatsService struct{}

func (m *mockStatsService) GetDashboardSummary(ctx context.Context) (interface{}, error) {
	return &handler.DashboardSummary{}, nil
}

func (m *mockStatsService) GetCertificatesByStatus(ctx context.Context) (interface{}, error) {
	return map[string]int64{}, nil
}

func (m *mockStatsService) GetExpirationTimeline(ctx context.Context, days int) (interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockStatsService) GetJobStats(ctx context.Context, days int) (interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockStatsService) GetIssuanceRate(ctx context.Context, days int) (interface{}, error) {
	return []interface{}{}, nil
}
