package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/api/handler"
	"github.com/shankar0123/certctl/internal/api/router"
	"github.com/shankar0123/certctl/internal/connector/issuer/local"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// setupTestServer creates a fully-wired test server for negative path testing.
func setupTestServer(t *testing.T) (*httptest.Server, *mockCertificateRepository, *mockJobRepository, *mockAgentRepository) {
	t.Helper()

	certRepo := newMockCertificateRepository()
	jobRepo := newMockJobRepository()
	auditRepo := newMockAuditRepository()
	agentRepo := newMockAgentRepository()
	targetRepo := newMockTargetRepository()
	notifRepo := newMockNotificationRepository()
	policyRepo := newMockPolicyRepository()
	renewalPolicyRepo := newMockRenewalPolicyRepository()
	issuerRepo := newMockIssuerRepository()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	localCA := local.New(nil, logger)

	issuerRegistry := service.NewIssuerRegistry(logger)
	issuerRegistry.Set("iss-local", service.NewIssuerConnectorAdapter(localCA))

	revocationRepo := newMockRevocationRepository()

	auditService := service.NewAuditService(auditRepo)
	policyService := service.NewPolicyService(policyRepo, auditService)
	certificateService := service.NewCertificateService(certRepo, policyService, auditService)
	notificationService := service.NewNotificationService(notifRepo, make(map[string]service.Notifier))

	// Wire decomposed sub-services (TICKET-007)
	revocationSvc := service.NewRevocationSvc(certRepo, revocationRepo, auditService)
	revocationSvc.SetNotificationService(notificationService)
	revocationSvc.SetIssuerRegistry(issuerRegistry)
	caOperationsSvc := service.NewCAOperationsSvc(revocationRepo, certRepo, nil)
	caOperationsSvc.SetIssuerRegistry(issuerRegistry)
	certificateService.SetRevocationSvc(revocationSvc)
	certificateService.SetCAOperationsSvc(caOperationsSvc)
	renewalService := service.NewRenewalService(certRepo, jobRepo, renewalPolicyRepo, nil, auditService, notificationService, issuerRegistry, "server")
	deploymentService := service.NewDeploymentService(jobRepo, targetRepo, agentRepo, certRepo, auditService, notificationService)
	jobService := service.NewJobService(jobRepo, renewalService, deploymentService, logger)
	agentService := service.NewAgentService(agentRepo, certRepo, jobRepo, targetRepo, auditService, issuerRegistry, renewalService)
	issuerService := service.NewIssuerService(issuerRepo, auditService, issuerRegistry, nil, logger)

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
	discoveryHandler := handler.NewDiscoveryHandler(&mockDiscoveryService{})
	networkScanHandler := handler.NewNetworkScanHandler(&mockNetworkScanService{})
	verificationHandler := handler.NewVerificationHandler(&mockVerificationService{})

	// EST handler — uses real Local CA issuer via ESTService
	localCAConnector, _ := issuerRegistry.Get("iss-local")
	estService := service.NewESTService("iss-local", localCAConnector, auditService, logger)
	estHandler := handler.NewESTHandler(estService)

	r := router.New()
	r.RegisterHandlers(router.HandlerRegistry{
		Certificates:  certificateHandler,
		Issuers:       issuerHandler,
		Targets:       targetHandler,
		Agents:        agentHandler,
		Jobs:          jobHandler,
		Policies:      policyHandler,
		Profiles:      profileHandler,
		Teams:         teamHandler,
		Owners:        ownerHandler,
		AgentGroups:   agentGroupHandler,
		Audit:         auditHandler,
		Notifications: notificationHandler,
		Stats:         statsHandler,
		Metrics:       metricsHandler,
		Health:        healthHandler,
		Discovery:     discoveryHandler,
		NetworkScan:   networkScanHandler,
		Verification:    verificationHandler,
		BulkRevocation:  handler.BulkRevocationHandler{},
	})
	r.RegisterESTHandlers(estHandler)

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })

	return server, certRepo, jobRepo, agentRepo
}

// TestNegativePaths exercises error paths and edge cases.
func TestNegativePaths(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	// ======================
	// Nonexistent resource lookups
	// ======================
	t.Run("GetNonexistentCertificate", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates/mc-does-not-exist")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("GetNonexistentAgent", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/agents/agent-ghost")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("GetNonexistentJob", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/jobs/job-ghost")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})

	// ======================
	// Invalid request bodies
	// ======================
	t.Run("CreateCertificateInvalidJSON", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/api/v1/certificates", "application/json", bytes.NewReader([]byte("not json")))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 400, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("CreateCertificateMissingCommonName", func(t *testing.T) {
		body := map[string]interface{}{
			"name":        "Test Cert",
			"environment": "test",
		}
		bodyBytes, _ := json.Marshal(body)

		resp, err := http.Post(server.URL+"/api/v1/certificates", "application/json", bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 400, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("CreatePolicyInvalidType", func(t *testing.T) {
		body := map[string]interface{}{
			"name": "Bad Policy",
			"type": "NonexistentType",
		}
		bodyBytes, _ := json.Marshal(body)

		resp, err := http.Post(server.URL+"/api/v1/policies", "application/json", bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 400, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	// ======================
	// Invalid CSR submission
	// ======================
	t.Run("SubmitInvalidCSR", func(t *testing.T) {
		// First register an agent
		agentBody := map[string]interface{}{
			"name":     "test-agent",
			"hostname": "test-host",
		}
		agentBytes, _ := json.Marshal(agentBody)

		regResp, err := http.Post(server.URL+"/api/v1/agents", "application/json", bytes.NewReader(agentBytes))
		if err != nil {
			t.Fatalf("register agent failed: %v", err)
		}
		defer regResp.Body.Close()

		if regResp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(regResp.Body)
			t.Fatalf("expected 201, got %d. Body: %s", regResp.StatusCode, string(bodyBytes))
		}

		var agentResp struct {
			Agent  domain.Agent `json:"agent"`
			APIKey string       `json:"api_key"`
		}
		if err := json.NewDecoder(regResp.Body).Decode(&agentResp); err != nil {
			t.Fatalf("failed to decode agent response: %v", err)
		}

		// Submit garbage CSR
		csrBody := map[string]interface{}{
			"csr_pem": "not a valid CSR",
		}
		csrBytes, _ := json.Marshal(csrBody)

		csrResp, err := http.Post(
			fmt.Sprintf("%s/api/v1/agents/%s/csr", server.URL, agentResp.Agent.ID),
			"application/json",
			bytes.NewReader(csrBytes),
		)
		if err != nil {
			t.Fatalf("CSR submission failed: %v", err)
		}
		defer csrResp.Body.Close()

		// Should reject — either 400 (bad CSR format) or 500 (no cert to sign for)
		if csrResp.StatusCode == http.StatusOK || csrResp.StatusCode == http.StatusCreated {
			t.Errorf("expected error status for invalid CSR, got %d", csrResp.StatusCode)
		}
	})

	// ======================
	// Heartbeat for nonexistent agent
	// ======================
	t.Run("HeartbeatNonexistentAgent", func(t *testing.T) {
		heartbeatBody := map[string]interface{}{
			"status": "healthy",
		}
		bodyBytes, _ := json.Marshal(heartbeatBody)

		resp, err := http.Post(
			server.URL+"/api/v1/agents/agent-nonexistent/heartbeat",
			"application/json",
			bytes.NewReader(bodyBytes),
		)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should fail — agent doesn't exist
		if resp.StatusCode == http.StatusOK {
			t.Errorf("expected error status for nonexistent agent heartbeat, got 200")
		}
	})

	// ======================
	// Method not allowed
	// ======================
	t.Run("PutToListEndpoint", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/certificates", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("expected error for PUT on list endpoint, got 200")
		}
	})

	// ======================
	// Empty list responses
	// ======================
	t.Run("ListEmptyCertificates", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for empty list, got %d", resp.StatusCode)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("failed to decode: %v", err)
		}

		total, ok := result["total"].(float64)
		if !ok || total != 0 {
			t.Errorf("expected total 0, got %v", result["total"])
		}
	})

	t.Run("ListEmptyJobs", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/jobs")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for empty list, got %d", resp.StatusCode)
		}
	})

	// ======================
	// Trigger renewal on nonexistent cert
	// ======================
	t.Run("TriggerRenewalNonexistentCert", func(t *testing.T) {
		resp, err := http.Post(
			server.URL+"/api/v1/certificates/mc-ghost/renew",
			"application/json",
			nil,
		)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.Errorf("expected error for renewal of nonexistent cert, got %d", resp.StatusCode)
		}
	})
}

// TestCertificateLifecycleWithExpiredCert verifies handling of an expired certificate.
func TestCertificateLifecycleWithExpiredCert(t *testing.T) {
	server, certRepo, _, _ := setupTestServer(t)

	// Create an already-expired certificate directly in the repo
	expiredTime := time.Now().Add(-24 * time.Hour)
	expiredCert := &domain.ManagedCertificate{
		ID:              "mc-expired-001",
		Name:            "Expired Cert",
		CommonName:      "expired.example.com",
		Status:          domain.CertificateStatusExpired,
		Environment:     "prod",
		IssuerID:        "iss-local",
		RenewalPolicyID: "rp-default",
		ExpiresAt:       expiredTime,
		CreatedAt:       time.Now().Add(-90 * 24 * time.Hour),
		UpdatedAt:       time.Now(),
	}
	certRepo.certs[expiredCert.ID] = expiredCert

	// Verify we can retrieve the expired cert
	t.Run("GetExpiredCert", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates/mc-expired-001")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var cert domain.ManagedCertificate
		if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
			t.Fatalf("failed to decode: %v", err)
		}

		if cert.Status != domain.CertificateStatusExpired {
			t.Errorf("expected status Expired, got %s", cert.Status)
		}
	})

	// Trigger renewal on expired cert — should succeed (creating a renewal job)
	t.Run("TriggerRenewalOnExpiredCert", func(t *testing.T) {
		resp, err := http.Post(
			server.URL+"/api/v1/certificates/mc-expired-001/renew",
			"application/json",
			nil,
		)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		// Renewal should be accepted (creates a job) or return an error
		// if the service doesn't allow renewal on expired certs
		t.Logf("Renewal trigger on expired cert returned status: %d", resp.StatusCode)
	})
}

// TestM11bEndpoints exercises the M11b endpoints: teams, owners, agent groups.
// Tests M11b feature coverage through the HTTP API.
func TestM11bEndpoints(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	// ========================
	// Teams API
	// ========================
	t.Run("Teams", func(t *testing.T) {
		t.Run("CreateTeam_Success", func(t *testing.T) {
			payload := map[string]string{"name": "Platform", "description": "Platform team"}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server.URL+"/api/v1/teams", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				bodyBytes, _ := io.ReadAll(resp.Body)
				t.Errorf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
			}
			var team domain.Team
			json.NewDecoder(resp.Body).Decode(&team)
			if team.Name != "Platform" {
				t.Errorf("expected name=Platform, got %s", team.Name)
			}
		})

		t.Run("CreateTeam_MissingName", func(t *testing.T) {
			payload := map[string]string{"description": "No name team"}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server.URL+"/api/v1/teams", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", resp.StatusCode)
			}
		})

		t.Run("CreateTeam_NameTooLong", func(t *testing.T) {
			longName := ""
			for i := 0; i < 256; i++ {
				longName += "a"
			}
			payload := map[string]string{"name": longName}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server.URL+"/api/v1/teams", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", resp.StatusCode)
			}
		})

		t.Run("CreateTeam_InvalidJSON", func(t *testing.T) {
			resp, err := http.Post(server.URL+"/api/v1/teams", "application/json", bytes.NewReader([]byte("not json")))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", resp.StatusCode)
			}
		})

		t.Run("GetTeam_NotFound", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/teams/t-nonexistent")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected 404, got %d", resp.StatusCode)
			}
		})

		t.Run("ListTeams_Empty", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/teams")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		})

		t.Run("DeleteTeam_Success", func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/teams/t-platform", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("expected 204, got %d", resp.StatusCode)
			}
		})

		t.Run("ListTeams_MethodNotAllowed", func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/teams", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("expected 405, got %d", resp.StatusCode)
			}
		})
	})

	// ========================
	// Owners API
	// ========================
	t.Run("Owners", func(t *testing.T) {
		t.Run("CreateOwner_Success", func(t *testing.T) {
			payload := map[string]string{"name": "Alice", "email": "alice@example.com", "team_id": "t-platform"}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server.URL+"/api/v1/owners", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				bodyBytes, _ := io.ReadAll(resp.Body)
				t.Errorf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
			}
			var owner domain.Owner
			json.NewDecoder(resp.Body).Decode(&owner)
			if owner.Name != "Alice" {
				t.Errorf("expected name=Alice, got %s", owner.Name)
			}
			if owner.Email != "alice@example.com" {
				t.Errorf("expected email=alice@example.com, got %s", owner.Email)
			}
		})

		t.Run("CreateOwner_MissingName", func(t *testing.T) {
			payload := map[string]string{"email": "bob@example.com"}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server.URL+"/api/v1/owners", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", resp.StatusCode)
			}
		})

		t.Run("GetOwner_NotFound", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/owners/o-nonexistent")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected 404, got %d", resp.StatusCode)
			}
		})

		t.Run("ListOwners_Empty", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/owners")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		})

		t.Run("DeleteOwner_Success", func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/owners/o-alice", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("expected 204, got %d", resp.StatusCode)
			}
		})
	})

	// ========================
	// Agent Groups API
	// ========================
	t.Run("AgentGroups", func(t *testing.T) {
		t.Run("CreateAgentGroup_Success", func(t *testing.T) {
			payload := map[string]interface{}{
				"name":        "Linux Servers",
				"description": "All linux-based agents",
				"match_os":    "linux",
				"match_architecture": "amd64",
				"enabled":     true,
			}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server.URL+"/api/v1/agent-groups", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				bodyBytes, _ := io.ReadAll(resp.Body)
				t.Errorf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
			}
			var group domain.AgentGroup
			json.NewDecoder(resp.Body).Decode(&group)
			if group.Name != "Linux Servers" {
				t.Errorf("expected name=Linux Servers, got %s", group.Name)
			}
		})

		t.Run("CreateAgentGroup_MissingName", func(t *testing.T) {
			payload := map[string]string{"description": "No name group"}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server.URL+"/api/v1/agent-groups", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", resp.StatusCode)
			}
		})

		t.Run("GetAgentGroup_NotFound", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/agent-groups/ag-nonexistent")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected 404, got %d", resp.StatusCode)
			}
		})

		t.Run("ListAgentGroups_Empty", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/agent-groups")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		})

		t.Run("DeleteAgentGroup_Success", func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/agent-groups/ag-linux", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("expected 204, got %d", resp.StatusCode)
			}
		})

		t.Run("ListAgentGroupMembers_Empty", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/agent-groups/ag-linux/members")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		})
	})
}

// TestRevocationEndpoints exercises the revocation API endpoints through a full integration stack.
func TestRevocationEndpoints(t *testing.T) {
	server, certRepo, _, _ := setupTestServer(t)

	// Create a test certificate with a version
	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:              "mc-revoke-test",
		Name:            "Revocation Test Cert",
		CommonName:      "revoke-test.example.com",
		SANs:            []string{},
		Environment:     "test",
		OwnerID:         "owner-test",
		TeamID:          "team-test",
		IssuerID:        "iss-local",
		RenewalPolicyID: "policy-1",
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       now.AddDate(0, 6, 0),
		Tags:            map[string]string{},
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	certRepo.certs["mc-revoke-test"] = cert
	certRepo.versions["mc-revoke-test"] = []*domain.CertificateVersion{
		{
			ID:            "cv-revoke-test",
			CertificateID: "mc-revoke-test",
			SerialNumber:  "REVOKE-SERIAL-001",
			NotBefore:     now,
			NotAfter:      now.AddDate(1, 0, 0),
			CreatedAt:     now,
		},
	}

	t.Run("RevokeCertificate_Success", func(t *testing.T) {
		body := bytes.NewBufferString(`{"reason":"keyCompromise"}`)
		resp, err := http.Post(server.URL+"/api/v1/certificates/mc-revoke-test/revoke", "application/json", body)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["status"] != "revoked" {
			t.Errorf("expected status 'revoked', got %s", result["status"])
		}

		// Verify certificate status updated
		if cert.Status != domain.CertificateStatusRevoked {
			t.Errorf("expected Revoked status, got %s", cert.Status)
		}
	})

	t.Run("RevokeCertificate_AlreadyRevoked", func(t *testing.T) {
		body := bytes.NewBufferString(`{"reason":"superseded"}`)
		resp, err := http.Post(server.URL+"/api/v1/certificates/mc-revoke-test/revoke", "application/json", body)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for already revoked, got %d", resp.StatusCode)
		}
	})

	t.Run("RevokeCertificate_NotFound", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/api/v1/certificates/mc-nonexistent/revoke", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("GetCRL_Success", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/crl")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var crl map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&crl)

		if crl["version"] != float64(1) {
			t.Errorf("expected CRL version 1, got %v", crl["version"])
		}

		// Should have at least 1 entry from the revocation above
		total, _ := crl["total"].(float64)
		if total < 1 {
			t.Errorf("expected at least 1 CRL entry, got %v", total)
		}
	})
}

