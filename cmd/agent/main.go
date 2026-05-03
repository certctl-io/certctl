package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/apache"
	"github.com/shankar0123/certctl/internal/connector/target/awsacm"
	"github.com/shankar0123/certctl/internal/connector/target/azurekv"
	"github.com/shankar0123/certctl/internal/connector/target/caddy"
	"github.com/shankar0123/certctl/internal/connector/target/envoy"
	"github.com/shankar0123/certctl/internal/connector/target/f5"
	"github.com/shankar0123/certctl/internal/connector/target/haproxy"
	"github.com/shankar0123/certctl/internal/connector/target/iis"
	jks "github.com/shankar0123/certctl/internal/connector/target/javakeystore"
	k8s "github.com/shankar0123/certctl/internal/connector/target/k8ssecret"
	"github.com/shankar0123/certctl/internal/connector/target/nginx"
	pf "github.com/shankar0123/certctl/internal/connector/target/postfix"
	sshconn "github.com/shankar0123/certctl/internal/connector/target/ssh"
	"github.com/shankar0123/certctl/internal/connector/target/traefik"
	wcs "github.com/shankar0123/certctl/internal/connector/target/wincertstore"
)

// AgentConfig represents the agent-side configuration.
type AgentConfig struct {
	ServerURL          string   // Control plane server URL (e.g., https://localhost:8443) — must be https:// scheme
	APIKey             string   // Agent API key for authentication
	AgentName          string   // Agent name for identification
	AgentID            string   // Agent ID for API calls (set after registration or from env)
	Hostname           string   // Server hostname
	KeyDir             string   // Directory for storing private keys (default: /var/lib/certctl/keys)
	DiscoveryDirs      []string // Directories to scan for certificates (comma-separated via env)
	CABundlePath       string   // Optional path to a PEM-encoded CA bundle that signed the server's cert (empty = system roots)
	InsecureSkipVerify bool     // Dev-only: skip TLS certificate verification. Never enable in production. See docs/tls.md.
}

// ErrAgentRetired is the sentinel returned by [Agent.Run] when the control
// plane responds with HTTP 410 Gone to a heartbeat or work-poll request — the
// canonical signal that this agent's row has been soft-retired server-side
// (see I-004 in cowork/certctl-coverage-gap-audit.md). The binary must
// terminate cleanly: an init-system restart would only produce another 410
// and wedge the host in a restart loop. main() translates this sentinel into
// a zero exit code so systemd (Restart=on-failure) and launchd do not respawn
// the process. Do not wrap this error — main() matches it with errors.Is.
var ErrAgentRetired = fmt.Errorf("agent retired by control plane")

// Agent represents the local agent that runs on target servers.
// It periodically sends heartbeats, polls for work, executes deployment and CSR jobs,
// and scans configured directories for existing certificates.
// In agent keygen mode, private keys are generated and stored locally — they never leave
// this process or filesystem.
type Agent struct {
	config *AgentConfig
	logger *slog.Logger
	client *http.Client

	// Configuration
	heartbeatInterval   time.Duration
	pollInterval        time.Duration
	discoveryInterval   time.Duration
	consecutiveFailures int

	// I-004: terminal retirement signal. retiredSignal is closed exactly once
	// (guarded by retiredOnce) when either sendHeartbeat or pollForWork
	// observes HTTP 410 Gone. The Run() select loop picks up the close and
	// returns ErrAgentRetired, unwinding the goroutine cleanly so main() can
	// log + exit(0). Using a channel + sync.Once (rather than an atomic bool
	// + polling) lets us fall through the select statement immediately instead
	// of waiting for the next ticker; the zero-allocation close is safe to
	// race with ctx.Done() and other cases.
	retiredOnce   sync.Once
	retiredSignal chan struct{}

	// Deploy-hardening I Phase 2: per-target deploy mutex.
	// Two cert renewals against the same target ID (e.g., two SAN
	// entries renewing in the same window, or a fast-cycling
	// renewal-then-test workflow) MUST serialize at the agent
	// dispatch site. Without this lock, the underlying connector's
	// temp-file path could collide and the reload command would
	// race against itself.
	//
	// Granularity is one mutex per target ID, NOT per (target, cert)
	// pair — frozen decision 0.5. Cert deploy throughput is
	// operator-grade tens-per-minute; coarse serialization is fine
	// and simplifies reasoning about reload-side race windows.
	//
	// sync.Map is sized for thousands of unique target IDs without
	// rehash thrash; LoadOrStore is atomic + lock-free on the
	// hot path. Mutexes live for the agent's lifetime — no janitor
	// because target IDs are bounded and the per-target memory
	// (~16 bytes per entry) is negligible vs. typical agent heap.
	//
	// Job items without a TargetID (e.g., agent-managed cert + no
	// connector dispatch — should never happen for deploy jobs but
	// defended anyway) bypass the lock to avoid a singleton
	// serialization point.
	deployMutexes sync.Map // map[string]*sync.Mutex, keyed on JobItem.TargetID
}

// targetDeployMutex returns the per-target-ID *sync.Mutex,
// lazy-initialising one on first acquisition. Returns nil when
// targetID is empty (caller should skip the lock entirely).
//
// Phase 2 of the deploy-hardening I master bundle: the load-bearing
// serialization point that defends against concurrent deploys to the
// same target stomping each other's temp-file paths or reload
// commands.
func (a *Agent) targetDeployMutex(targetID string) *sync.Mutex {
	if targetID == "" {
		return nil
	}
	v, _ := a.deployMutexes.LoadOrStore(targetID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// WorkResponse represents the response from the work polling endpoint.
type WorkResponse struct {
	Jobs  []JobItem `json:"jobs"`
	Count int       `json:"count"`
}

// JobItem represents a job returned from the control plane, enriched with target/cert details.
type JobItem struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	CertificateID string          `json:"certificate_id"`
	CommonName    string          `json:"common_name,omitempty"`
	SANs          []string        `json:"sans,omitempty"`
	TargetID      *string         `json:"target_id,omitempty"`
	TargetType    string          `json:"target_type,omitempty"`
	TargetConfig  json.RawMessage `json:"target_config,omitempty"`
	Status        string          `json:"status"`
}

// NewAgent creates a new agent instance.
//
// The returned HTTP client enforces HTTPS-only control-plane access per the
// HTTPS-Everywhere milestone (see docs/tls.md). TLS 1.3 is required; the
// optional CABundlePath loads a PEM bundle into RootCAs so the agent can
// trust internal / self-signed server certs without touching system trust
// stores. InsecureSkipVerify is a dev-only escape hatch — callers must log a
// loud warning when it's set; never enable in production (see §2.4 of the
// milestone spec and docs/upgrade-to-tls.md).
//
// Returns an error if CABundlePath is set but unreadable or malformed — fail
// loud at startup rather than silently fall back to system roots, which would
// turn a misconfigured bundle path into a cryptic "x509: certificate signed
// by unknown authority" on the first heartbeat.
func NewAgent(cfg *AgentConfig, logger *slog.Logger) (*Agent, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // opt-in dev escape hatch, documented in docs/tls.md
	}
	if cfg.CABundlePath != "" {
		pemBytes, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("reading CA bundle at %q: %w", cfg.CABundlePath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("CA bundle at %q contains no valid PEM-encoded certificates", cfg.CABundlePath)
		}
		tlsConfig.RootCAs = pool
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	return &Agent{
		config:            cfg,
		logger:            logger,
		client:            httpClient,
		heartbeatInterval: 60 * time.Second,
		pollInterval:      30 * time.Second,
		discoveryInterval: 6 * time.Hour, // scan for certs every 6 hours
		retiredSignal:     make(chan struct{}),
	}, nil
}

// markRetired records that the control plane has declared this agent retired
// (HTTP 410 Gone on heartbeat or work poll). Idempotent via sync.Once — if
// both the heartbeat and work-poll paths observe 410 in the same tick, only
// the first close() runs and we avoid a runtime panic. Emits an ERROR-level
// log line so init-system journaling captures it prominently, and includes
// the source (heartbeat/work_poll), response body, and status code so the
// operator can verify it's a genuine retirement signal rather than a
// misrouted request. After this returns, the select-loop case in Run()
// observes the closed channel on its next iteration and returns
// ErrAgentRetired.
func (a *Agent) markRetired(source string, statusCode int, body string) {
	a.retiredOnce.Do(func() {
		a.logger.Error("agent has been retired by control plane — shutting down",
			"source", source,
			"status", statusCode,
			"body", body,
			"agent_id", a.config.AgentID)
		close(a.retiredSignal)
	})
}

// Run starts the agent's main loop.
// It sends heartbeats, polls for work, and handles graceful shutdown via context cancellation.
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("agent starting",
		"server_url", a.config.ServerURL,
		"agent_name", a.config.AgentName,
		"agent_id", a.config.AgentID,
		"key_dir", a.config.KeyDir)

	// Ensure key directory exists with secure permissions
	if err := os.MkdirAll(a.config.KeyDir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory %s: %w", a.config.KeyDir, err)
	}

	// Enforce permissions even if directory already exists
	if err := os.Chmod(a.config.KeyDir, 0700); err != nil {
		a.logger.Warn("failed to enforce key directory permissions", "path", a.config.KeyDir, "error", err)
	}

	// Create ticker channels for heartbeat, polling, and discovery
	heartbeatTicker := time.NewTicker(a.heartbeatInterval)
	defer heartbeatTicker.Stop()

	pollTicker := time.NewTicker(a.pollInterval)
	defer pollTicker.Stop()

	// Run initial heartbeat and poll
	a.sendHeartbeat(ctx)
	a.pollForWork(ctx)

	// Discovery: run initial scan if directories configured, then on interval
	var discoveryTicker *time.Ticker
	if len(a.config.DiscoveryDirs) > 0 {
		a.logger.Info("certificate discovery enabled",
			"directories", a.config.DiscoveryDirs,
			"interval", a.discoveryInterval.String())
		a.runDiscoveryScan(ctx)
		discoveryTicker = time.NewTicker(a.discoveryInterval)
		defer discoveryTicker.Stop()
	} else {
		a.logger.Info("certificate discovery disabled (no CERTCTL_DISCOVERY_DIRS configured)")
		// Create a stopped ticker so the select compiles
		discoveryTicker = time.NewTicker(24 * time.Hour)
		discoveryTicker.Stop()
	}

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("agent shutting down", "reason", ctx.Err())
			return ctx.Err()

		// I-004: retiredSignal is closed exactly once (via markRetired's
		// sync.Once) when either sendHeartbeat or pollForWork observes HTTP 410
		// Gone from the control plane. Falling through this case immediately
		// (rather than waiting for the next ticker) lets the agent shut down
		// quickly once retirement is confirmed — every extra heartbeat against a
		// retired row is wasted work and noise in the audit trail. Returning
		// ErrAgentRetired propagates up to main(), which matches it with
		// errors.Is and exits(0) so systemd/launchd do not respawn the process.
		case <-a.retiredSignal:
			a.logger.Info("agent retired signal received — exiting event loop",
				"agent_id", a.config.AgentID)
			return ErrAgentRetired

		case <-heartbeatTicker.C:
			a.sendHeartbeat(ctx)

		case <-pollTicker.C:
			if a.consecutiveFailures > 0 {
				backoff := time.Duration(a.consecutiveFailures) * a.pollInterval
				if backoff > 5*time.Minute {
					backoff = 5 * time.Minute
				}
				a.logger.Warn("backing off due to consecutive failures",
					"failures", a.consecutiveFailures,
					"backoff", backoff.String())
				// F-003: ctx-aware wait so graceful shutdown does not stall on
				// a long backoff. If ctx cancels mid-backoff, return to the
				// outer loop so the <-ctx.Done() case can trigger clean exit.
				select {
				case <-ctx.Done():
					continue
				case <-time.After(backoff):
				}
			}
			a.pollForWork(ctx)

		case <-discoveryTicker.C:
			if len(a.config.DiscoveryDirs) > 0 {
				a.runDiscoveryScan(ctx)
			}
		}
	}
}

// getOutboundIP returns the preferred outbound IP address of this machine.
func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// sendHeartbeat sends a heartbeat to the control plane with agent metadata.
// POST /api/v1/agents/{agentID}/heartbeat
func (a *Agent) sendHeartbeat(ctx context.Context) {
	a.logger.Debug("sending heartbeat", "agent_id", a.config.AgentID)

	path := fmt.Sprintf("/api/v1/agents/%s/heartbeat", a.config.AgentID)
	resp, err := a.makeRequest(ctx, http.MethodPost, path, map[string]string{
		"version":      "1.0.0",
		"hostname":     a.config.Hostname,
		"os":           runtime.GOOS,
		"architecture": runtime.GOARCH,
		"ip_address":   getOutboundIP(),
	})
	if err != nil {
		a.logger.Error("heartbeat failed", "error", err)
		a.consecutiveFailures++
		return
	}
	defer resp.Body.Close()

	// I-004: HTTP 410 Gone is the terminal signal from the control plane that
	// this agent's row has been soft-retired (see internal/api/handler/agent.go
	// heartbeat path + AgentRetirementService). Treat it separately from the
	// generic non-200 error branch: record the event to markRetired (which closes
	// retiredSignal exactly once via sync.Once) and return without bumping
	// consecutiveFailures — this is not a transient failure, it's a clean
	// shutdown. The Run() select loop picks up the closed channel on its next
	// iteration and returns ErrAgentRetired, which main() translates into an
	// exit(0) so systemd/launchd don't respawn the process into another 410
	// loop.
	if resp.StatusCode == http.StatusGone {
		body, _ := io.ReadAll(resp.Body)
		a.markRetired("heartbeat", resp.StatusCode, string(body))
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("heartbeat rejected",
			"status", resp.StatusCode,
			"body", string(body))
		a.consecutiveFailures++
		return
	}

	a.consecutiveFailures = 0
	a.logger.Debug("heartbeat acknowledged")
}

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
	keyPath := filepath.Join(a.config.KeyDir, job.CertificateID+".key")
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

	// Check for locally-stored private key (agent keygen mode)
	keyPath := filepath.Join(a.config.KeyDir, job.CertificateID+".key")
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
		connector, err := a.createTargetConnector(job.TargetType, job.TargetConfig)
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
func (a *Agent) createTargetConnector(targetType string, configJSON json.RawMessage) (target.Connector, error) {
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
		return awsacm.New(context.Background(), &cfg, a.logger)

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
		return azurekv.New(context.Background(), &cfg, a.logger)

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

// reportJobStatus reports the result of a job back to the control plane.
// POST /api/v1/agents/{agentID}/jobs/{jobID}/status
func (a *Agent) reportJobStatus(ctx context.Context, jobID string, status string, errorMsg string) error {
	a.logger.Debug("reporting job status",
		"job_id", jobID,
		"status", status)

	path := fmt.Sprintf("/api/v1/agents/%s/jobs/%s/status", a.config.AgentID, jobID)
	payload := map[string]string{
		"status": status,
	}
	if errorMsg != "" {
		payload["error"] = errorMsg
	}

	resp, err := a.makeRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return fmt.Errorf("status report failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	a.logger.Debug("job status reported", "job_id", jobID, "status", status)
	return nil
}

// makeRequest is a helper for making authenticated HTTP requests to the control plane.
// It includes the API key in the Authorization header.
func (a *Agent) makeRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", a.config.ServerURL, path)

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.config.APIKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// runDiscoveryScan walks configured directories, parses certificate files, and reports
// discovered certificates to the control plane.
// Supports PEM and DER encoded X.509 certificates.
func (a *Agent) runDiscoveryScan(ctx context.Context) {
	a.logger.Info("starting filesystem certificate discovery scan",
		"directories", a.config.DiscoveryDirs)

	startTime := time.Now()
	var certs []discoveredCertEntry
	var scanErrors []string

	for _, dir := range a.config.DiscoveryDirs {
		a.logger.Debug("scanning directory", "path", dir)

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("walk error at %s: %v", path, err))
				return nil // continue walking
			}
			if info.IsDir() {
				return nil
			}

			// Skip files larger than 1MB (unlikely to be a certificate)
			if info.Size() > 1*1024*1024 {
				return nil
			}

			// Check file extension
			ext := strings.ToLower(filepath.Ext(path))
			switch ext {
			case ".pem", ".crt", ".cer", ".cert":
				found := a.parsePEMFile(path)
				certs = append(certs, found...)
			case ".der":
				if entry, err := a.parseDERFile(path); err == nil {
					certs = append(certs, entry)
				} else {
					a.logger.Debug("skipping non-cert DER file", "path", path, "error", err)
				}
			default:
				// Try PEM parsing for extensionless files or unknown extensions
				if ext == "" || ext == ".key" {
					return nil // skip key files and extensionless
				}
				found := a.parsePEMFile(path)
				if len(found) > 0 {
					certs = append(certs, found...)
				}
			}
			return nil
		})
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("failed to walk %s: %v", dir, err))
		}
	}

	scanDuration := time.Since(startTime)
	a.logger.Info("discovery scan completed",
		"certificates_found", len(certs),
		"errors", len(scanErrors),
		"duration_ms", scanDuration.Milliseconds())

	if len(certs) == 0 && len(scanErrors) == 0 {
		a.logger.Debug("no certificates found and no errors, skipping report")
		return
	}

	// Build report payload
	entries := make([]map[string]interface{}, len(certs))
	for i, c := range certs {
		entries[i] = map[string]interface{}{
			"fingerprint_sha256": c.FingerprintSHA256,
			"common_name":        c.CommonName,
			"sans":               c.SANs,
			"serial_number":      c.SerialNumber,
			"issuer_dn":          c.IssuerDN,
			"subject_dn":         c.SubjectDN,
			"not_before":         c.NotBefore,
			"not_after":          c.NotAfter,
			"key_algorithm":      c.KeyAlgorithm,
			"key_size":           c.KeySize,
			"is_ca":              c.IsCA,
			"pem_data":           c.PEMData,
			"source_path":        c.SourcePath,
			"source_format":      c.SourceFormat,
		}
	}

	report := map[string]interface{}{
		"agent_id":         a.config.AgentID,
		"directories":      a.config.DiscoveryDirs,
		"certificates":     entries,
		"errors":           scanErrors,
		"scan_duration_ms": int(scanDuration.Milliseconds()),
	}

	// Submit to control plane
	path := fmt.Sprintf("/api/v1/agents/%s/discoveries", a.config.AgentID)
	resp, err := a.makeRequest(ctx, http.MethodPost, path, report)
	if err != nil {
		a.logger.Error("failed to submit discovery report", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("discovery report rejected",
			"status", resp.StatusCode,
			"body", string(body))
		return
	}

	a.logger.Info("discovery report submitted successfully",
		"certificates", len(certs),
		"errors", len(scanErrors))
}

// discoveredCertEntry holds parsed certificate metadata for reporting.
type discoveredCertEntry struct {
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	CommonName        string   `json:"common_name"`
	SANs              []string `json:"sans"`
	SerialNumber      string   `json:"serial_number"`
	IssuerDN          string   `json:"issuer_dn"`
	SubjectDN         string   `json:"subject_dn"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	KeyAlgorithm      string   `json:"key_algorithm"`
	KeySize           int      `json:"key_size"`
	IsCA              bool     `json:"is_ca"`
	PEMData           string   `json:"pem_data"`
	SourcePath        string   `json:"source_path"`
	SourceFormat      string   `json:"source_format"`
}

// parsePEMFile reads a file and extracts all X.509 certificates from PEM blocks.
func (a *Agent) parsePEMFile(path string) []discoveredCertEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		a.logger.Debug("failed to read file", "path", path, "error", err)
		return nil
	}

	var entries []discoveredCertEntry
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			a.logger.Debug("failed to parse certificate in PEM", "path", path, "error", err)
			continue
		}

		pemStr := string(pem.EncodeToMemory(block))
		entries = append(entries, certToEntry(cert, path, "PEM", pemStr))
	}
	return entries
}

// parseDERFile reads a DER-encoded certificate file.
func (a *Agent) parseDERFile(path string) (discoveredCertEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return discoveredCertEntry{}, fmt.Errorf("read failed: %w", err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return discoveredCertEntry{}, fmt.Errorf("parse failed: %w", err)
	}

	// Convert to PEM for storage
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}))
	return certToEntry(cert, path, "DER", pemStr), nil
}

// certToEntry converts a parsed x509.Certificate into a discoveredCertEntry.
func certToEntry(cert *x509.Certificate, path, format, pemData string) discoveredCertEntry {
	// Compute SHA-256 fingerprint
	fingerprint := fmt.Sprintf("%x", sha256Sum(cert.Raw))

	// Determine key algorithm and size
	keyAlg, keySize := certKeyInfo(cert)

	return discoveredCertEntry{
		FingerprintSHA256: fingerprint,
		CommonName:        cert.Subject.CommonName,
		SANs:              cert.DNSNames,
		SerialNumber:      cert.SerialNumber.Text(16),
		IssuerDN:          cert.Issuer.String(),
		SubjectDN:         cert.Subject.String(),
		NotBefore:         cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
		KeyAlgorithm:      keyAlg,
		KeySize:           keySize,
		IsCA:              cert.IsCA,
		PEMData:           pemData,
		SourcePath:        path,
		SourceFormat:      format,
	}
}

// sha256Sum returns the SHA-256 hash of data.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// certKeyInfo extracts key algorithm name and size from a certificate.
func certKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	default:
		switch cert.PublicKeyAlgorithm {
		case x509.Ed25519:
			return "Ed25519", 256
		default:
			return cert.PublicKeyAlgorithm.String(), 0
		}
	}
}

func main() {
	// Parse command-line flags (with env var fallbacks for Docker deployment)
	serverURL := flag.String("server", getEnvDefault("CERTCTL_SERVER_URL", "https://localhost:8443"), "Control plane server URL (must be https://)")
	apiKey := flag.String("api-key", getEnvDefault("CERTCTL_API_KEY", ""), "Agent API key")
	agentName := flag.String("name", getEnvDefault("CERTCTL_AGENT_NAME", "certctl-agent"), "Agent name")
	agentID := flag.String("agent-id", getEnvDefault("CERTCTL_AGENT_ID", ""), "Agent ID (from registration)")
	keyDir := flag.String("key-dir", getEnvDefault("CERTCTL_KEY_DIR", "/var/lib/certctl/keys"), "Directory for storing private keys")
	discoveryDirsStr := flag.String("discovery-dirs", getEnvDefault("CERTCTL_DISCOVERY_DIRS", ""), "Comma-separated directories to scan for certificates")
	caBundlePath := flag.String("ca-bundle", getEnvDefault("CERTCTL_SERVER_CA_BUNDLE_PATH", ""), "Path to a PEM-encoded CA bundle that signed the server's TLS cert (optional; falls back to system roots)")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", getEnvBoolDefault("CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY", false), "Dev-only: skip TLS certificate verification. Never enable in production. See docs/tls.md.")
	flag.Parse()

	if *apiKey == "" {
		fmt.Fprintf(os.Stderr, "Error: -api-key flag or CERTCTL_API_KEY env var is required\n")
		os.Exit(1)
	}

	if *agentID == "" {
		fmt.Fprintf(os.Stderr, "Error: -agent-id flag or CERTCTL_AGENT_ID env var is required\n")
		fmt.Fprintf(os.Stderr, "Register an agent first via POST /api/v1/agents\n")
		os.Exit(1)
	}

	// Pre-flight URL-scheme validation — reject plaintext http:// before any
	// network call. The HTTPS-Everywhere milestone (§2.4, §7) mandates that
	// mis-configured agents fail loudly at startup with a diagnostic pointing
	// at the upgrade guide, rather than producing a TCP-refused or
	// TLS-handshake-error that obscures the actual cause.
	if err := validateHTTPSScheme(*serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nThe certctl control plane is HTTPS-only as of v2.2.\n")
		fmt.Fprintf(os.Stderr, "See docs/upgrade-to-tls.md for the cutover walkthrough.\n")
		os.Exit(1)
	}

	// Set up structured logging
	logLevel := slog.LevelInfo
	if getEnvDefault("CERTCTL_LOG_LEVEL", "info") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Parse discovery directories
	var discoveryDirs []string
	if *discoveryDirsStr != "" {
		for _, d := range strings.Split(*discoveryDirsStr, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				discoveryDirs = append(discoveryDirs, d)
			}
		}
	}

	// Create agent configuration
	agentCfg := &AgentConfig{
		ServerURL:          *serverURL,
		APIKey:             *apiKey,
		AgentName:          *agentName,
		AgentID:            *agentID,
		Hostname:           hostname,
		KeyDir:             *keyDir,
		DiscoveryDirs:      discoveryDirs,
		CABundlePath:       *caBundlePath,
		InsecureSkipVerify: *insecureSkipVerify,
	}

	if agentCfg.InsecureSkipVerify {
		logger.Warn("TLS certificate verification is disabled (CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY=true) — never enable this in production")
	}

	// Create and start agent
	agent, err := NewAgent(agentCfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize agent: %v\n", err)
		os.Exit(1)
	}

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run agent in background
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("agent panicked", "error", fmt.Sprintf("%v", r))
				errChan <- fmt.Errorf("agent panic: %v", r)
			}
		}()
		errChan <- agent.Run(ctx)
	}()

	// Wait for signal or agent error
	select {
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig.String())
		cancel()
		<-errChan
	case err := <-errChan:
		// I-004: ErrAgentRetired is a terminal, *clean* shutdown — the control
		// plane responded HTTP 410 Gone on heartbeat/work-poll, meaning this
		// agent's row has been soft-retired and will never be reachable again.
		// Exit 0 so systemd's Restart=on-failure and launchd's KeepAlive do NOT
		// respawn the process into another 410 loop (which would wedge the host
		// and spam the control plane). Operators can observe the retirement via
		// audit_events or the AgentsPage retired tab; the terminal log line on
		// the way out is enough for post-mortem forensics.
		if errors.Is(err, ErrAgentRetired) {
			logger.Info("agent retired by control plane — exiting without restart",
				"agent_id", agentCfg.AgentID)
			return
		}
		if err != context.Canceled {
			logger.Error("agent error", "error", err)
			os.Exit(1)
		}
	}

	logger.Info("agent stopped")
}

// getEnvDefault reads an environment variable with a fallback default value.
func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBoolDefault parses an environment variable as a boolean. Accepts "1",
// "t", "true", "T", "TRUE", "True" as true; anything else (including empty)
// returns the provided default. Kept permissive on purpose so operators can
// flip the dev-only TLS skip-verify toggle with any common truthy spelling
// without having to remember exactly what we parse.
func getEnvBoolDefault(key string, defaultValue bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return defaultValue
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "t", "true", "yes", "on":
		return true
	case "0", "f", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

// validateHTTPSScheme enforces the HTTPS-Everywhere milestone's §7 acceptance
// criterion: "Agent with CERTCTL_SERVER_URL=http://... fails at startup with
// a fail-loud diagnostic pointing at docs/upgrade-to-tls.md. Not TCP-refused,
// not TLS-handshake-error — a pre-flight config validation failure before any
// network call." Returns a descriptive error; the caller prints the upgrade
// guide pointer and exits non-zero.
func validateHTTPSScheme(serverURL string) error {
	if serverURL == "" {
		return fmt.Errorf("CERTCTL_SERVER_URL is empty — set it to an https:// URL (e.g., https://certctl-server:8443)")
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("CERTCTL_SERVER_URL %q is not a valid URL: %w", serverURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		return fmt.Errorf("CERTCTL_SERVER_URL %q uses plaintext http:// — the certctl control plane is HTTPS-only", serverURL)
	case "":
		return fmt.Errorf("CERTCTL_SERVER_URL %q is missing a scheme — expected https://", serverURL)
	default:
		return fmt.Errorf("CERTCTL_SERVER_URL %q uses unsupported scheme %q — expected https://", serverURL, u.Scheme)
	}
}
