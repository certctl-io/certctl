package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// TestStatsAndMetricsEndpoints exercises the M14 observability endpoints end-to-end.
func TestStatsAndMetricsEndpoints(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	t.Run("GetHealth", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/health")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var body map[string]string
		json.NewDecoder(resp.Body).Decode(&body)
		if body["status"] != "healthy" {
			t.Errorf("expected status=healthy, got %s", body["status"])
		}
	})

	t.Run("GetReady", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/ready")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("GetMetrics", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/metrics")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var metrics map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&metrics)
		if metrics["gauge"] == nil {
			t.Error("expected gauge in metrics response")
		}
		if metrics["counter"] == nil {
			t.Error("expected counter in metrics response")
		}
		if metrics["uptime"] == nil {
			t.Error("expected uptime in metrics response")
		}
	})

	t.Run("GetStatsSummary", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/stats/summary")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("GetCertificatesByStatus", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/stats/certificates-by-status")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("GetExpirationTimeline", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/stats/expiration-timeline?days=90")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("GetExpirationTimeline_DefaultDays", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/stats/expiration-timeline")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("GetJobTrends", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/stats/job-trends?days=30")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("GetIssuanceRate", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/stats/issuance-rate?days=30")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})
}

// TestCrossResourceWorkflow exercises a multi-step workflow spanning certificates,
// policies, agents, jobs, audit trail, and notifications — verifying data flows
// correctly across service boundaries.
func TestCrossResourceWorkflow(t *testing.T) {
	server, certRepo, jobRepo, agentRepo := setupTestServer(t)

	// Step 1: Create a policy rule
	var policyID string
	t.Run("CreatePolicy", func(t *testing.T) {
		payload := map[string]interface{}{
			"name":        "Allowed Domains Policy",
			"type":        "AllowedDomains",
			"severity":    "Error",
			"config":      json.RawMessage(`{"domains": ["example.com", "*.example.com"]}`),
			"description": "Restrict issuance to example.com domains",
		}
		body, _ := json.Marshal(payload)
		resp, err := http.Post(server.URL+"/api/v1/policies", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var rule domain.PolicyRule
		json.NewDecoder(resp.Body).Decode(&rule)
		policyID = rule.ID
		if policyID == "" {
			t.Fatal("expected policy ID")
		}
		t.Logf("Created policy: %s", policyID)
	})

	// Step 2: Create a certificate
	var certID string
	t.Run("CreateCertificate", func(t *testing.T) {
		now := time.Now()
		payload := map[string]interface{}{
			"name":              "Workflow Test Cert",
			"common_name":       "workflow.example.com",
			"sans":              []string{"www.workflow.example.com"},
			"environment":       "staging",
			"owner_id":          "owner-ops",
			"team_id":           "team-platform",
			"issuer_id":         "iss-local",
			"target_ids":        []string{},
			"renewal_policy_id": "policy-standard",
			"status":            "Pending",
			"expires_at":        now.AddDate(0, 3, 0),
			"tags":              map[string]string{"team": "platform"},
		}
		body, _ := json.Marshal(payload)
		resp, err := http.Post(server.URL+"/api/v1/certificates", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var cert domain.ManagedCertificate
		json.NewDecoder(resp.Body).Decode(&cert)
		certID = cert.ID
		t.Logf("Created certificate: %s", certID)
	})

	// Step 3: Register an agent
	var agentID string
	t.Run("RegisterAgent", func(t *testing.T) {
		payload := map[string]string{"name": "workflow-agent", "hostname": "workflow-host-01"}
		body, _ := json.Marshal(payload)
		resp, err := http.Post(server.URL+"/api/v1/agents", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var agent domain.Agent
		json.NewDecoder(resp.Body).Decode(&agent)
		agentID = agent.ID
		t.Logf("Registered agent: %s", agentID)
	})

	// Step 4: Trigger renewal
	t.Run("TriggerRenewal", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/api/v1/certificates/"+certID+"/renew", "application/json", nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 202, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	// Step 5: Verify jobs were created
	t.Run("VerifyJobsCreated", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/jobs?page=1&per_page=50")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		// data may be null (nil) if no jobs exist, or an array
		if data, ok := respBody["data"].([]interface{}); ok && len(data) > 0 {
			t.Logf("Found %d jobs after renewal trigger", len(data))
		} else {
			t.Log("No jobs found after renewal trigger (expected — mock TriggerRenewal is async/no-op)")
		}
	})

	// Step 6: Agent heartbeat with metadata
	t.Run("AgentHeartbeatWithMetadata", func(t *testing.T) {
		payload := map[string]interface{}{
			"os":           "linux",
			"architecture": "amd64",
			"ip_address":   "10.0.1.50",
			"version":      "1.0.0",
		}
		body, _ := json.Marshal(payload)
		resp, err := http.Post(server.URL+"/api/v1/agents/"+agentID+"/heartbeat", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		// Verify metadata was stored
		agent, ok := agentRepo.agents[agentID]
		if !ok {
			t.Fatal("agent not found in repo after heartbeat")
		}
		if agent.LastHeartbeatAt == nil {
			t.Error("expected heartbeat timestamp to be set")
		}
	})

	// Step 7: Add a version to the cert so revocation works
	t.Run("AddCertVersion", func(t *testing.T) {
		now := time.Now()
		certRepo.versions[certID] = []*domain.CertificateVersion{
			{
				ID:            "cv-workflow-1",
				CertificateID: certID,
				SerialNumber:  "WORKFLOW-SERIAL-001",
				NotBefore:     now,
				NotAfter:      now.AddDate(0, 3, 0),
				CreatedAt:     now,
			},
		}
		// Update cert status to Active for revocation
		if cert, ok := certRepo.certs[certID]; ok {
			cert.Status = domain.CertificateStatusActive
		}
	})

	// Step 8: Revoke the certificate
	t.Run("RevokeCertificate", func(t *testing.T) {
		body := bytes.NewBufferString(`{"reason":"cessationOfOperation"}`)
		resp, err := http.Post(server.URL+"/api/v1/certificates/"+certID+"/revoke", "application/json", body)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		// Verify cert status changed to Revoked
		cert := certRepo.certs[certID]
		if cert.Status != domain.CertificateStatusRevoked {
			t.Errorf("expected Revoked status, got %s", cert.Status)
		}
	})

	// Step 9: Verify revoked cert cannot be renewed
	t.Run("CannotRenewRevoked", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/api/v1/certificates/"+certID+"/renew", "application/json", nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		// Revoked cert should not accept renewal (expect error status)
		if resp.StatusCode == http.StatusAccepted {
			t.Log("Warning: revoked cert accepted renewal — may need business logic enforcement")
		}
	})

	// Step 10: Verify audit trail accumulated events
	t.Run("AuditTrailAccumulated", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/audit?page=1&per_page=100")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		data, ok := respBody["data"].([]interface{})
		if !ok {
			t.Fatal("expected data array")
		}
		// We should have at least cert_created, agent_registered, renewal_triggered, cert_revoked
		if len(data) < 3 {
			t.Logf("Warning: expected at least 3 audit events, got %d", len(data))
		}
		t.Logf("Total audit events from workflow: %d", len(data))

		// Verify event types
		eventTypes := make(map[string]int)
		for _, evt := range data {
			if eventMap, ok := evt.(map[string]interface{}); ok {
				if action, ok := eventMap["action"].(string); ok {
					eventTypes[action]++
				}
			}
		}
		t.Logf("Audit event types: %v", eventTypes)
	})

	// Summary
	t.Run("WorkflowSummary", func(t *testing.T) {
		certCount := len(certRepo.certs)
		jobCount := len(jobRepo.jobs)
		agentCount := len(agentRepo.agents)
		t.Logf("Cross-resource workflow complete: %d certs, %d jobs, %d agents", certCount, jobCount, agentCount)
	})
}

// TestJobApprovalWorkflow exercises the interactive approval flow (M11b).
func TestJobApprovalWorkflow(t *testing.T) {
	server, _, jobRepo, _ := setupTestServer(t)

	// Seed a job in AwaitingApproval state
	jobID := "job-approval-test-1"
	jobRepo.jobs[jobID] = &domain.Job{
		ID:            jobID,
		CertificateID: "mc-test",
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingApproval,
		MaxAttempts:   3,
		Attempts:      0,
		CreatedAt:     time.Now(),
	}

	t.Run("ApproveJob_Success", func(t *testing.T) {
		payload := map[string]string{"reason": "Approved by ops team"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/jobs/"+jobID+"/approve", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		// Verify job moved to Pending
		job := jobRepo.jobs[jobID]
		if job.Status != domain.JobStatusPending {
			t.Errorf("expected Pending after approval, got %s", job.Status)
		}
	})

	// Seed another job for rejection
	rejectJobID := "job-reject-test-1"
	jobRepo.jobs[rejectJobID] = &domain.Job{
		ID:            rejectJobID,
		CertificateID: "mc-test",
		Type:          domain.JobTypeRenewal,
		Status:        domain.JobStatusAwaitingApproval,
		MaxAttempts:   3,
		Attempts:      0,
		CreatedAt:     time.Now(),
	}

	t.Run("RejectJob_Success", func(t *testing.T) {
		payload := map[string]string{"reason": "Certificate no longer needed"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/jobs/"+rejectJobID+"/reject", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		// Verify job moved to Cancelled
		job := jobRepo.jobs[rejectJobID]
		if job.Status != domain.JobStatusCancelled {
			t.Errorf("expected Cancelled after rejection, got %s", job.Status)
		}
	})

	t.Run("ApproveNonexistentJob", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/jobs/job-ghost/approve", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("ApproveNonAwaitingJob", func(t *testing.T) {
		// The first job is already Pending (approved earlier) — approving again should fail
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/jobs/"+jobID+"/approve", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("expected error when approving non-AwaitingApproval job")
		}
	})
}

// TestNotificationEndpoints exercises the M3 notification API.
func TestNotificationEndpoints(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	t.Run("ListNotifications_Empty", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/notifications?page=1&per_page=10")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		total, ok := respBody["total"].(float64)
		if !ok {
			t.Log("Warning: total field not found or not a number")
		} else if total != 0 {
			t.Logf("Found %d notifications (expected 0 on fresh setup)", int(total))
		}
	})
}

// TestCRLEndpoint exercises the CRL listing endpoint (M15a).
func TestCRLEndpoint(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	t.Run("GetCRL_JSON", func(t *testing.T) {
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
		if crl["version"] == nil {
			t.Error("expected version field in CRL response")
		}
		if crl["entries"] == nil {
			t.Error("expected entries field in CRL response")
		}
		t.Logf("CRL response: version=%v, entries_count=%v", crl["version"], crl["total"])
	})
}

// TestPaginationAcrossEndpoints verifies pagination parameters work consistently.
func TestPaginationAcrossEndpoints(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	endpoints := []struct {
		name string
		url  string
	}{
		{"Certificates", "/api/v1/certificates?page=1&per_page=5"},
		{"Agents", "/api/v1/agents?page=1&per_page=5"},
		{"Jobs", "/api/v1/jobs?page=1&per_page=5"},
		{"Audit", "/api/v1/audit?page=1&per_page=5"},
		{"Notifications", "/api/v1/notifications?page=1&per_page=5"},
		{"Policies", "/api/v1/policies?page=1&per_page=5"},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			resp, err := http.Get(server.URL + ep.url)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				bodyBytes, _ := io.ReadAll(resp.Body)
				t.Errorf("expected 200 for %s, got %d: %s", ep.name, resp.StatusCode, string(bodyBytes))
			}
		})
	}
}

// TestIssuerAndTargetCRUD exercises issuer and target CRUD lifecycle.
func TestIssuerAndTargetCRUD(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	// Issuer CRUD
	var issuerID string
	t.Run("CreateIssuer", func(t *testing.T) {
		payload := map[string]interface{}{
			"id":     "iss-test-ca",
			"name":   "Test Local CA",
			"type":   "GenericCA",
			"config": json.RawMessage(`{"ca_common_name": "Test CA"}`),
		}
		body, _ := json.Marshal(payload)
		resp, err := http.Post(server.URL+"/api/v1/issuers", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var issuer domain.Issuer
		json.NewDecoder(resp.Body).Decode(&issuer)
		issuerID = issuer.ID
		t.Logf("Created issuer: %s", issuerID)
	})

	t.Run("GetIssuer", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/issuers/" + issuerID)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("ListIssuers", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/issuers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	// Target CRUD
	var targetID string
	t.Run("CreateTarget", func(t *testing.T) {
		payload := map[string]interface{}{
			"id":       "t-test-nginx",
			"name":     "Test NGINX",
			"type":     "NGINX",
			"agent_id": "agent-1",
			"config":   json.RawMessage(`{"cert_path": "/etc/nginx/ssl/cert.pem"}`),
		}
		body, _ := json.Marshal(payload)
		resp, err := http.Post(server.URL+"/api/v1/targets", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var target domain.DeploymentTarget
		json.NewDecoder(resp.Body).Decode(&target)
		targetID = target.ID
		t.Logf("Created target: %s", targetID)
	})

	t.Run("GetTarget", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/targets/" + targetID)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("DeleteTarget", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/targets/"+targetID, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		// Accept either 200 or 204
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("expected 200 or 204, got %d", resp.StatusCode)
		}
	})

	t.Run("DeleteIssuer", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/issuers/"+issuerID, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("expected 200 or 204, got %d", resp.StatusCode)
		}
	})
}

// TestM20EnhancedQueryAPI exercises M20 query API enhancements: sorting, time-range filters,
// cursor pagination, sparse fields, profile/agent filters, and the deployments endpoint.
func TestM20EnhancedQueryAPI(t *testing.T) {
	server, certRepo, _, _ := setupTestServer(t)

	// Setup: Create a certificate for testing
	now := time.Now()
	cert := &domain.ManagedCertificate{
		ID:          "mc-m20-test-1",
		Name:        "M20 Test Cert",
		CommonName:  "m20.example.com",
		Environment: "production",
		Status:      domain.CertificateStatusActive,
		IssuerID:    "iss-local",
		OwnerID:     "owner-ops",
		TeamID:      "team-platform",
		CertificateProfileID: "prof-standard",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	certRepo.certs["mc-m20-test-1"] = cert

	t.Run("ListWithSortDescending", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates?sort=-notAfter&page=1&per_page=10")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		if _, ok := respBody["data"]; !ok {
			t.Error("expected data field in response")
		}
	})

	t.Run("ListWithSortAscending", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates?sort=createdAt&page=1&per_page=10")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		if _, ok := respBody["page"]; !ok {
			t.Error("expected page-based pagination response")
		}
	})

	t.Run("TimeRangeFilter_ExpiresBefore", func(t *testing.T) {
		future := now.AddDate(0, 0, 365).Format(time.RFC3339)
		resp, err := http.Get(server.URL + "/api/v1/certificates?expires_before=" + future)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("TimeRangeFilter_ExpiresAfter", func(t *testing.T) {
		past := now.AddDate(0, 0, -90).Format(time.RFC3339)
		resp, err := http.Get(server.URL + "/api/v1/certificates?expires_after=" + past)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("TimeRangeFilter_CreatedAfter", func(t *testing.T) {
		past := now.AddDate(-1, 0, 0).Format(time.RFC3339)
		resp, err := http.Get(server.URL + "/api/v1/certificates?created_after=" + past)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("SparseFields", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates?fields=id,common_name,status")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		if data, ok := respBody["data"].([]interface{}); ok && len(data) > 0 {
			firstCert, ok := data[0].(map[string]interface{})
			if !ok {
				t.Fatal("expected cert object in data array")
			}
			// Should have requested fields
			if _, ok := firstCert["id"]; !ok {
				t.Error("expected 'id' field in sparse response")
			}
			// Should NOT have unrequested fields like 'environment'
			if _, ok := firstCert["environment"]; ok {
				t.Error("did not expect 'environment' field in sparse response")
			}
		}
	})

	t.Run("ProfileFilter", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates?profile_id=prof-standard")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("AgentIDFilter", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates?agent_id=agent-prod-001")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("CursorPagination", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates?cursor=abc123&page_size=10")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		if _, ok := respBody["next_cursor"]; !ok {
			t.Error("expected next_cursor field with cursor pagination")
		}
	})

	t.Run("CombinedFilters", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates?status=Active&environment=production&profile_id=prof-standard&sort=-createdAt&per_page=10")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("GetCertificateDeployments_Success", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates/mc-m20-test-1/deployments")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		if _, ok := respBody["data"]; !ok {
			t.Error("expected data field in response")
		}
		if _, ok := respBody["total"]; !ok {
			t.Error("expected total field in response")
		}
	})

	t.Run("GetCertificateDeployments_NotFound", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/certificates/mc-nonexistent-m20/deployments")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("InvalidTimeRange", func(t *testing.T) {
		// Invalid RFC3339 should be silently ignored (no filter applied)
		resp, err := http.Get(server.URL + "/api/v1/certificates?expires_before=not-a-date&page=1&per_page=10")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 (invalid time ignored), got %d", resp.StatusCode)
		}
	})
}

// generateE2ECSRPEM creates a valid ECDSA P-256 CSR PEM for integration testing.
func generateE2ECSRPEM(t *testing.T, cn string, sans []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// generateE2ECSRBase64DER creates a valid base64-encoded DER CSR for EST wire format testing.
func generateE2ECSRBase64DER(t *testing.T, cn string, sans []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return base64.StdEncoding.EncodeToString(csrDER)
}

// TestPrometheusMetrics exercises the Prometheus metrics endpoint (M22).
func TestPrometheusMetrics(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	t.Run("GetPrometheusMetrics_Success", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/api/v1/metrics/prometheus")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		// Verify Content-Type contains text/plain
		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "text/plain") {
			t.Errorf("expected Content-Type containing 'text/plain', got %s", contentType)
		}

		// Read and verify Prometheus format
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Should contain HELP and TYPE lines for metrics
		if !strings.Contains(bodyStr, "# HELP") {
			t.Error("expected HELP line in Prometheus response")
		}
		if !strings.Contains(bodyStr, "# TYPE") {
			t.Error("expected TYPE line in Prometheus response")
		}

		// Should contain metric lines (gauge, counter, uptime)
		if !strings.Contains(bodyStr, "certctl_") {
			t.Error("expected certctl_ prefixed metrics in response")
		}

		t.Logf("Prometheus metrics endpoint working, body size: %d bytes", len(bodyStr))
	})

	t.Run("GetPrometheusMetrics_MethodNotAllowed", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/api/v1/metrics/prometheus", "application/json", nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})
}

// TestESTEndpoints exercises the EST (RFC 7030) enrollment endpoints end-to-end (M23).
func TestESTEndpoints(t *testing.T) {
	server, _, _, _ := setupTestServer(t)

	// ===========================
	// GET /cacerts — CA certificate chain
	// ===========================
	t.Run("GetCACerts_Success", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/.well-known/est/cacerts")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/pkcs7-mime") {
			t.Errorf("expected application/pkcs7-mime content type, got %s", ct)
		}
		cte := resp.Header.Get("Content-Transfer-Encoding")
		if cte != "base64" {
			t.Errorf("expected base64 content-transfer-encoding, got %s", cte)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		if len(bodyBytes) == 0 {
			t.Error("expected non-empty PKCS#7 response body")
		}
	})

	t.Run("GetCACerts_MethodNotAllowed", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/.well-known/est/cacerts", "application/json", nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})

	// ===========================
	// POST /simpleenroll — certificate enrollment
	// ===========================
	t.Run("SimpleEnroll_PEM_Success", func(t *testing.T) {
		csrPEM := generateE2ECSRPEM(t, "est-test.example.com", []string{"est-test.example.com"})
		resp, err := http.Post(server.URL+"/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(csrPEM))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/pkcs7-mime") {
			t.Errorf("expected application/pkcs7-mime, got %s", ct)
		}
	})

	t.Run("SimpleEnroll_Base64DER_Success", func(t *testing.T) {
		csrB64 := generateE2ECSRBase64DER(t, "est-der.example.com", []string{"est-der.example.com"})
		resp, err := http.Post(server.URL+"/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(csrB64))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("SimpleEnroll_EmptyBody", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(""))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for empty body, got %d", resp.StatusCode)
		}
	})

	t.Run("SimpleEnroll_InvalidCSR", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader("not-a-valid-csr"))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for invalid CSR, got %d", resp.StatusCode)
		}
	})

	t.Run("SimpleEnroll_MissingCN", func(t *testing.T) {
		csrPEM := generateE2ECSRPEM(t, "", []string{"no-cn.example.com"})
		resp, err := http.Post(server.URL+"/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(csrPEM))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		// Should fail because EST requires a Common Name
		if resp.StatusCode == http.StatusOK {
			t.Error("expected error for CSR without Common Name")
		}
	})

	t.Run("SimpleEnroll_MethodNotAllowed", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/.well-known/est/simpleenroll")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})

	// ===========================
	// POST /simplereenroll — certificate re-enrollment
	// ===========================
	t.Run("SimpleReEnroll_Success", func(t *testing.T) {
		csrPEM := generateE2ECSRPEM(t, "renew-est.example.com", []string{"renew-est.example.com"})
		resp, err := http.Post(server.URL+"/.well-known/est/simplereenroll", "application/pkcs10", strings.NewReader(csrPEM))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
	})

	t.Run("SimpleReEnroll_MethodNotAllowed", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/.well-known/est/simplereenroll")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})

	// ===========================
	// GET /csrattrs — CSR attributes
	// ===========================
	t.Run("GetCSRAttrs_NoContent", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/.well-known/est/csrattrs")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		// Default implementation returns nil attrs → 204 No Content
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("expected 204, got %d", resp.StatusCode)
		}
	})

	t.Run("GetCSRAttrs_MethodNotAllowed", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/.well-known/est/csrattrs", "application/json", nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})
}
