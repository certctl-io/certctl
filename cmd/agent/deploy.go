// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/certctl-io/certctl/internal/connector/target"
	"github.com/certctl-io/certctl/internal/connector/target/apache"
	"github.com/certctl-io/certctl/internal/connector/target/awsacm"
	"github.com/certctl-io/certctl/internal/connector/target/azurekv"
	"github.com/certctl-io/certctl/internal/connector/target/caddy"
	"github.com/certctl-io/certctl/internal/connector/target/envoy"
	"github.com/certctl-io/certctl/internal/connector/target/f5"
	"github.com/certctl-io/certctl/internal/connector/target/haproxy"
	"github.com/certctl-io/certctl/internal/connector/target/iis"
	jks "github.com/certctl-io/certctl/internal/connector/target/javakeystore"
	k8s "github.com/certctl-io/certctl/internal/connector/target/k8ssecret"
	"github.com/certctl-io/certctl/internal/connector/target/nginx"
	pf "github.com/certctl-io/certctl/internal/connector/target/postfix"
	sshconn "github.com/certctl-io/certctl/internal/connector/target/ssh"
	"github.com/certctl-io/certctl/internal/connector/target/traefik"
	wcs "github.com/certctl-io/certctl/internal/connector/target/wincertstore"
)

// Phase 9 ARCH-M2 closure Sprint 12 (2026-05-14): extracted from
// cmd/agent/main.go via the Option B sibling-file pattern.
//
// This file holds the DEPLOYMENT executor + the target connector
// factory + the deploy-only helpers:
//
//   - executeDeploymentJob: handles Pending deployment jobs by
//     fetching the cert PEM from the control plane, loading the
//     locally-held private key (in agent keygen mode), instantiating
//     the appropriate target connector via createTargetConnector,
//     calling DeployCertificate on it, and reporting Completed or
//     Failed back to the control plane.
//   - createTargetConnector: the big switch over target_type that
//     instantiates one of 14 target connectors (apache / awsacm /
//     azurekv / caddy / envoy / f5 / haproxy / iis / javakeystore /
//     k8ssecret / nginx / postfix / ssh / traefik / wincertstore).
//     Context is threaded into SDK-driven connectors (AWSACM,
//     AzureKeyVault) so credential resolution honors caller
//     cancellation per the contextcheck linter — see CI commit
//     502823d.
//   - splitPEMChain: split a PEM chain into (first cert, rest).
//   - fetchCertificate: pull the PEM chain from
//     GET /api/v1/certificates/{certID}/version.
//
// All 14 target-connector imports were used ONLY by
// createTargetConnector; moving the factory here also moved the
// 14 connector imports out of main.go, leaving the surviving
// cmd/agent/main.go with the minimal stdlib surface its lifecycle
// + HTTP infrastructure needs.

// executeDeploymentJob executes a deployment job by fetching the certificate and deploying it
// to the target system using the appropriate connector (NGINX, F5 BIG-IP, or IIS).
//
// For agent keygen mode, the private key is read from the local key store (keyDir/certID.key)
// rather than fetched from the server. The deployment includes the locally-held key.
//
// Flow:
// 1. Report job as Running
// 2. Fetch the certificate PEM from the control plane
// 3. Load local private key if it exists (agent keygen mode)
// 4. Instantiate the target connector based on target_type from the work response
// 5. Call DeployCertificate on the connector
// 6. Report job as Completed (or Failed)
func (a *Agent) executeDeploymentJob(ctx context.Context, job JobItem) {
	a.logger.Info("executing deployment job",
		"job_id", job.ID,
		"certificate_id", job.CertificateID,
		"target_type", job.TargetType)

	// Report job as running
	if err := a.reportJobStatus(ctx, job.ID, "Running", ""); err != nil {
		a.logger.Error("failed to report job running", "error", err)
	}

	// Fetch the certificate from the control plane
	certPEM, err := a.fetchCertificate(ctx, job.CertificateID)
	if err != nil {
		a.logger.Error("failed to fetch certificate",
			"job_id", job.ID,
			"error", err)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("cert fetch failed: %v", err)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
		}
		return
	}

	a.logger.Info("certificate fetched for deployment",
		"job_id", job.ID,
		"cert_length", len(certPEM))

	// Split PEM into cert and chain (separated by double newline between PEM blocks)
	certOnly, chainPEM := splitPEMChain(certPEM)

	// Check for locally-stored private key (agent keygen mode).
	//
	// SEC-002 closure (Sprint 1, 2026-05-16): safeAgentKeyPath validates
	// the certificate_id shape AND asserts the joined path is contained
	// within a.config.KeyDir. A crafted certificate_id (path traversal,
	// absolute path, NUL byte, Windows separators) fails closed before
	// any disk I/O. See cmd/agent/keymem.go for the helper.
	keyPath, kerr := safeAgentKeyPath(a.config.KeyDir, job.CertificateID)
	if kerr != nil {
		a.logger.Error("agent key path validation failed for deployment",
			"job_id", job.ID,
			"certificate_id", job.CertificateID,
			"error", kerr)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("key path validation failed: %v", kerr)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "error", reportErr)
		}
		return
	}
	var keyPEM string
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		a.logger.Error("failed to read local private key for deployment",
			"job_id", job.ID,
			"key_path", keyPath,
			"error", err)
		if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("key read failed: %v", err)); reportErr != nil {
			a.logger.Error("failed to report job status to server", "job_id", job.ID, "error", reportErr)
		}
		return
	}
	keyPEM = string(keyData)
	a.logger.Info("loaded local private key for deployment",
		"job_id", job.ID,
		"key_path", keyPath)

	// Deploy to the target using the appropriate connector
	if job.TargetType != "" {
		connector, err := a.createTargetConnector(ctx, job.TargetType, job.TargetConfig)
		if err != nil {
			a.logger.Error("failed to create target connector",
				"job_id", job.ID,
				"target_type", job.TargetType,
				"error", err)
			if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("connector init failed: %v", err)); reportErr != nil {
				a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
			}
			return
		}

		// Bundle 1 / RT-C1 closure (2026-05-12): defense in depth. The server
		// runs internal/connector/target/configcheck.Validate on the way IN
		// (Create/Update), and rejects shell metacharacters in command-bearing
		// fields. Re-run the connector's full ValidateConfig here on the way
		// OUT, before any DeployCertificate call. This catches (a) configs
		// that pre-date the server-side guard, (b) corruption/tampering of
		// the encrypted config blob, and (c) per-connector filesystem
		// invariants (cert dir exists, paths writable) that the server can't
		// check because the filesystem is on the agent host.
		if err := connector.ValidateConfig(ctx, job.TargetConfig); err != nil {
			a.logger.Error("connector config validation failed",
				"job_id", job.ID,
				"target_type", job.TargetType,
				"error", err)
			if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("%s config validation failed: %v", job.TargetType, err)); reportErr != nil {
				a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
			}
			return
		}

		deployReq := target.DeploymentRequest{
			CertPEM:      certOnly,
			KeyPEM:       keyPEM,
			ChainPEM:     chainPEM,
			TargetConfig: job.TargetConfig,
			Metadata: map[string]string{
				"certificate_id": job.CertificateID,
				"job_id":         job.ID,
			},
		}

		// Phase 2 of the deploy-hardening I master bundle:
		// per-target deploy mutex. Acquire BEFORE
		// DeployCertificate so two concurrent renewals against
		// the same target ID serialize. The lock is held for the
		// full Deploy duration including PreCommit (validate),
		// PostCommit (reload), and post-deploy verify (Phases
		// 4-9). Released on every return path via defer.
		var targetID string
		if job.TargetID != nil {
			targetID = *job.TargetID
		}
		if mu := a.targetDeployMutex(targetID); mu != nil {
			mu.Lock()
			defer mu.Unlock()
		}

		result, err := connector.DeployCertificate(ctx, deployReq)
		if err != nil {
			a.logger.Error("deployment failed",
				"job_id", job.ID,
				"target_type", job.TargetType,
				"error", err)
			if reportErr := a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("deployment failed: %v", err)); reportErr != nil {
				a.logger.Error("failed to report job status to server", "job_id", job.ID, "status", "Failed", "error", reportErr)
			}
			return
		}

		a.logger.Info("target connector deployment completed",
			"job_id", job.ID,
			"target_type", job.TargetType,
			"success", result.Success,
			"message", result.Message)

		// If verification is enabled, verify the deployment by probing the live TLS endpoint
		targetHost, targetPort, err := extractTargetHostAndPort(job.TargetConfig)
		if err != nil {
			a.logger.Warn("could not extract target host/port for verification",
				"job_id", job.ID,
				"error", err)
		} else {
			a.verifyAndReportDeployment(ctx, job, targetHost, targetPort, certOnly)
		}
	} else {
		a.logger.Info("no target type specified, skipping connector invocation",
			"job_id", job.ID)
	}

	// Report job as completed
	if err := a.reportJobStatus(ctx, job.ID, "Completed", ""); err != nil {
		a.logger.Error("failed to report job completed", "error", err)
		return
	}

	a.logger.Info("deployment job completed", "job_id", job.ID)
}

// createTargetConnector instantiates the appropriate target connector based on type.
// ctx is threaded into SDK-driven connectors (AWSACM, AzureKeyVault) so credential
// resolution honors caller cancellation / deadlines instead of using a fresh
// context.Background() (the contextcheck linter enforces this — the original Rank 5
// implementation used Background() and tripped CI on commit 502823d).
func (a *Agent) createTargetConnector(ctx context.Context, targetType string, configJSON json.RawMessage) (target.Connector, error) {
	switch targetType {
	case "NGINX":
		var cfg nginx.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid NGINX config: %w", err)
			}
		}
		return nginx.New(&cfg, a.logger), nil

	case "Apache":
		var cfg apache.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid Apache config: %w", err)
			}
		}
		return apache.New(&cfg, a.logger), nil

	case "HAProxy":
		var cfg haproxy.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid HAProxy config: %w", err)
			}
		}
		return haproxy.New(&cfg, a.logger), nil

	case "F5":
		var cfg f5.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid F5 config: %w", err)
			}
		}
		conn, err := f5.New(&cfg, a.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create F5 connector: %w", err)
		}
		return conn, nil

	case "IIS":
		var cfg iis.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid IIS config: %w", err)
			}
		}
		return iis.New(&cfg, a.logger)

	case "Traefik":
		var cfg traefik.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid Traefik config: %w", err)
			}
		}
		return traefik.New(&cfg, a.logger), nil

	case "Caddy":
		var cfg caddy.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid Caddy config: %w", err)
			}
		}
		return caddy.New(&cfg, a.logger), nil

	case "Envoy":
		var cfg envoy.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid Envoy config: %w", err)
			}
		}
		return envoy.New(&cfg, a.logger), nil

	case "Postfix":
		var cfg pf.Config
		cfg.Mode = "postfix"
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid Postfix config: %w", err)
			}
		}
		return pf.New(&cfg, a.logger), nil

	case "Dovecot":
		var cfg pf.Config
		cfg.Mode = "dovecot"
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid Dovecot config: %w", err)
			}
		}
		return pf.New(&cfg, a.logger), nil

	case "SSH":
		var cfg sshconn.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid SSH config: %w", err)
			}
		}
		return sshconn.New(&cfg, a.logger)

	case "WinCertStore":
		var cfg wcs.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid WinCertStore config: %w", err)
			}
		}
		return wcs.New(&cfg, a.logger)

	case "JavaKeystore":
		var cfg jks.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid JavaKeystore config: %w", err)
			}
		}
		return jks.New(&cfg, a.logger), nil

	case "KubernetesSecrets":
		var cfg k8s.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid KubernetesSecrets config: %w", err)
			}
		}
		return k8s.New(&cfg, a.logger)

	case "AWSACM":
		// Rank 5 of the 2026-05-03 Infisical deep-research deliverable.
		// AWS Certificate Manager target — SDK-driven (no file I/O).
		// LoadDefaultConfig handles the standard AWS credential chain
		// (IRSA / EC2 instance profile / SSO / env vars) without any
		// long-lived creds in connector Config.
		var cfg awsacm.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid AWSACM config: %w", err)
			}
		}
		return awsacm.New(ctx, &cfg, a.logger)

	case "AzureKeyVault":
		// Rank 5 of the 2026-05-03 Infisical deep-research deliverable.
		// Azure Key Vault target — SDK-driven (no file I/O).
		// DefaultAzureCredential handles the standard Azure credential
		// chain (managed identity / workload identity / env vars / az
		// CLI fallback). Long-lived service-principal secrets are
		// supported but discouraged via the credential_mode config.
		var cfg azurekv.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid AzureKeyVault config: %w", err)
			}
		}
		return azurekv.New(ctx, &cfg, a.logger)

	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}
}

// splitPEMChain splits a PEM chain into the first certificate (cert) and the rest (chain).
// The control plane returns the full chain as a single string with PEM blocks concatenated.
func splitPEMChain(pemChain string) (string, string) {
	data := []byte(pemChain)
	block, rest := pem.Decode(data)
	if block == nil {
		return pemChain, ""
	}
	cert := string(pem.EncodeToMemory(block))

	// Skip whitespace between cert and chain
	chain := strings.TrimSpace(string(rest))
	if chain == "" {
		return cert, ""
	}
	return cert, chain
}

// fetchCertificate retrieves the certificate PEM chain from the control plane.
// GET /api/v1/agents/{agentID}/certificates/{certID}
func (a *Agent) fetchCertificate(ctx context.Context, certID string) (string, error) {
	path := fmt.Sprintf("/api/v1/agents/%s/certificates/%s", a.config.AgentID, certID)
	resp, err := a.makeRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var certResp struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return certResp.CertificatePEM, nil
}
