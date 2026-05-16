// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/certctl-io/certctl/internal/scheduler"
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
// (see I-004 in the project's coverage-gap audit). The binary must
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

	// SCALE-006 closure (Sprint 2, 2026-05-16). Pre-fix the agent
	// started its heartbeat + poll loops on fixed time.NewTicker
	// cadence with an unjittered immediate first invocation. Mass
	// restarts (rolling K8s deploy, control-plane reboot, scheduled
	// fleet bounce) produced a thundering herd — 5K agents booting
	// in a 10-second window all hit /heartbeat in lockstep, then
	// /poll, every interval forever afterward.
	//
	// Fix: (1) sleep a random startup-jitter ∈ [0, interval) before
	// the first heartbeat + first poll to spread the initial cohort,
	// and (2) use scheduler.JitteredTicker (±10% per-tick envelope)
	// for the recurring ticks so the cohort stays spread across
	// every tick boundary. Both legs use the existing in-tree
	// JitteredTicker primitive (internal/scheduler/jitter.go) —
	// pattern already exercised by every scheduler.go loop on the
	// server side.
	heartbeatTicker := scheduler.NewJitteredTicker(a.heartbeatInterval, scheduler.DefaultSchedulerJitter)
	defer heartbeatTicker.Stop()
	pollTicker := scheduler.NewJitteredTicker(a.pollInterval, scheduler.DefaultSchedulerJitter)
	defer pollTicker.Stop()

	// Startup jitter — run-first delay drawn fresh per-agent so a
	// 5K-agent rolling-restart spreads out across (max interval).
	// Bounded by ctx so a sigint-during-startup exits cleanly rather
	// than hanging on the Sleep. Heartbeat and poll are drawn
	// independently so a single random seed doesn't create a
	// secondary correlation pattern.
	hbJitter := time.Duration(rand.Int64N(int64(a.heartbeatInterval)))
	pollJitter := time.Duration(rand.Int64N(int64(a.pollInterval)))
	a.logger.Info("startup jitter applied",
		"heartbeat_jitter", hbJitter.String(),
		"poll_jitter", pollJitter.String())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(hbJitter):
	}
	a.sendHeartbeat(ctx)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(pollJitter):
	}
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
