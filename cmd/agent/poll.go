// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Phase 9 ARCH-M2 closure Sprint 12 (2026-05-14): extracted from
// cmd/agent/main.go via the Option B sibling-file pattern (mirrors
// the Sprint 8 cmd/server cut). Package stays `main`; all methods
// are still defined on *Agent so every call site continues to
// resolve through Go's same-package method-set without any
// import-path change.
//
// This file holds the WORK-POLLING entry point + CSR-job execution
// — the inbound side of the agent's pull-only deployment model
// (per CLAUDE.md "Pull-only deployment model" architecture
// decision):
//
//   - pollForWork: queries GET /api/v1/agents/{id}/work each tick;
//     dispatches each returned JobItem to the appropriate
//     executor (CSR vs deployment).
//   - executeCSRJob: handles AwaitingCSR jobs by generating an
//     ECDSA P-256 key locally, persisting it to keyDir/<certID>.key
//     with 0600 permissions (key NEVER leaves the agent — see
//     CLAUDE.md "Agent-based key management"), creating the CSR,
//     and POSTing it to the control plane for signing.
//
// The deployment-job executor lives in deploy.go alongside the
// target connector factory + deploy-only helpers (splitPEMChain,
// fetchCertificate). The discovery scan lives in discovery.go.

// pollForWork queries the control plane for actionable jobs and processes them.
// Jobs may be deployment jobs (Pending) or CSR jobs (AwaitingCSR).
// GET /api/v1/agents/{agentID}/work
func (a *Agent) pollForWork(ctx context.Context) {
	a.logger.Debug("polling for work", "agent_id", a.config.AgentID)

	path := fmt.Sprintf("/api/v1/agents/%s/work", a.config.AgentID)
	resp, err := a.makeRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		a.logger.Error("work poll failed", "error", err)
		a.consecutiveFailures++
		return
	}
	defer resp.Body.Close()

	// I-004: same terminal-retirement handling as sendHeartbeat. Work-poll is the
	// other hot path that can observe an agent's soft-retirement; if the
	// heartbeat tick happens to fire after a work-poll tick within the same
	// retirement window, this branch catches it first. markRetired's sync.Once
	// guards idempotency so racing both paths in the same tick only closes the
	// signal channel once. No consecutiveFailures increment — retirement is
	// not a transient failure.
	if resp.StatusCode == http.StatusGone {
		body, _ := io.ReadAll(resp.Body)
		a.markRetired("work_poll", resp.StatusCode, string(body))
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("work poll rejected",
			"status", resp.StatusCode,
			"body", string(body))
		a.consecutiveFailures++
		return
	}

	var workResp WorkResponse
	if err := json.NewDecoder(resp.Body).Decode(&workResp); err != nil {
		a.logger.Error("failed to decode work response", "error", err)
		a.consecutiveFailures++
		return
	}

	a.consecutiveFailures = 0

	if workResp.Count == 0 {
		a.logger.Debug("no pending work")
		return
	}

	a.logger.Info("received work", "job_count", workResp.Count)

	// Process each job based on type and status
	for _, job := range workResp.Jobs {
		switch {
		case job.Status == "AwaitingCSR":
			// Agent keygen mode: generate key locally, create CSR, submit to server
			a.executeCSRJob(ctx, job)
		case job.Type == "Deployment":
			a.executeDeploymentJob(ctx, job)
		}
	}
}

// executeCSRJob handles an AwaitingCSR job: generates a private key locally, creates a CSR,
// and submits it to the control plane for signing. The private key is stored on the local
// filesystem with 0600 permissions and NEVER sent to the server.
//
// Flow:
// 1. Generate ECDSA P-256 key pair
// 2. Store private key to disk (keyDir/certID.key) with 0600 permissions
// 3. Create CSR with common name and SANs from work response
// 4. Submit CSR to control plane via POST /agents/{id}/csr
// 5. Server signs the CSR and creates a cert version + deployment jobs
func (a *Agent) executeCSRJob(ctx context.Context, job JobItem) {
	a.logger.Info("executing CSR job (agent-side key generation)",
		"job_id", job.ID,
		"certificate_id", job.CertificateID,
		"common_name", job.CommonName)

	// Step 1: Generate ECDSA P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		a.logger.Error("failed to generate private key",
			"job_id", job.ID,
			"error", err)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("key generation failed: %v", err)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}

	a.logger.Info("generated ECDSA P-256 key pair locally",
		"job_id", job.ID,
		"certificate_id", job.CertificateID)

	// Step 2: Store private key to disk with secure permissions.
	//
	// Bundle-9 / Audit L-002 + L-003: marshal+write through helpers that
	// (a) zeroize the in-heap DER buffer immediately after the PEM block is
	// constructed so the private scalar's exposure window is bounded by
	// this function call, and (b) assert the key directory is mode 0700
	// before any write touches disk. Also defer-clear the PEM buffer for
	// the same reason — the encoded key isn't sensitive in transit (it's
	// going to disk) but lingers on the heap if we don't.
	//
	// SEC-002 closure (Sprint 1, 2026-05-16): safeAgentKeyPath validates
	// the certificate_id shape AND asserts the joined path is contained
	// within a.config.KeyDir. A crafted certificate_id like
	// "../../etc/passwd" or "/abs/path" now fails closed before any
	// disk I/O. See cmd/agent/keymem.go for the helper.
	keyPath, kerr := safeAgentKeyPath(a.config.KeyDir, job.CertificateID)
	if kerr != nil {
		a.logger.Error("agent key path validation failed", "job_id", job.ID, "certificate_id", job.CertificateID, "error", kerr)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("key path validation failed: %v", kerr)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}
	if err := ensureAgentKeyDirSecure(filepath.Dir(keyPath)); err != nil {
		a.logger.Error("agent key dir hardening failed", "job_id", job.ID, "error", err)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("key dir hardening failed: %v", err)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}
	var privKeyPEM []byte
	if marshalErr := marshalAgentKeyAndZeroize(privKey, func(der []byte) error {
		privKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		})
		return nil
	}); marshalErr != nil {
		a.logger.Error("failed to marshal private key",
			"job_id", job.ID,
			"error", marshalErr)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("key marshal failed: %v", marshalErr)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}
	defer clear(privKeyPEM)

	if err := os.WriteFile(keyPath, privKeyPEM, 0600); err != nil {
		a.logger.Error("failed to write private key to disk",
			"job_id", job.ID,
			"key_path", keyPath,
			"error", err)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("key storage failed: %v", err)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}

	a.logger.Info("private key stored securely",
		"job_id", job.ID,
		"key_path", keyPath,
		"permissions", "0600")

	// Validate common name is present
	if job.CommonName == "" {
		a.logger.Error("empty common name in CSR job", "job_id", job.ID)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", "empty common name"); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "error", reportErr)
		}
		return
	}

	// Step 3: Create CSR with common name and SANs
	// Split SANs into DNS names and email addresses for proper CSR encoding
	var dnsNames []string
	var emailAddresses []string
	for _, san := range job.SANs {
		if strings.Contains(san, "@") {
			emailAddresses = append(emailAddresses, san)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: job.CommonName,
		},
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		a.logger.Error("failed to create CSR",
			"job_id", job.ID,
			"error", err)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("CSR creation failed: %v", err)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	// Step 4: Submit CSR to the control plane (only the public key leaves the agent)
	a.logger.Info("submitting CSR to control plane",
		"job_id", job.ID,
		"certificate_id", job.CertificateID)

	submitPath := fmt.Sprintf("/api/v1/agents/%s/csr", a.config.AgentID)
	resp, err := a.makeRequest(ctx, http.MethodPost, submitPath, map[string]string{
		"csr_pem":        csrPEM,
		"certificate_id": job.CertificateID,
	})
	if err != nil {
		a.logger.Error("failed to submit CSR",
			"job_id", job.ID,
			"error", err)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("CSR submission failed: %v", err)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("CSR submission rejected",
			"job_id", job.ID,
			"status", resp.StatusCode,
			"body", string(body))
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("CSR rejected: %s", string(body))); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}

	a.logger.Info("CSR submitted and signed successfully",
		"job_id", job.ID,
		"certificate_id", job.CertificateID,
		"key_path", keyPath)
}
