package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/f5"
	"github.com/shankar0123/certctl/internal/connector/target/iis"
	"github.com/shankar0123/certctl/internal/connector/target/nginx"
)

// AgentConfig represents the agent-side configuration.
type AgentConfig struct {
	ServerURL string // Control plane server URL (e.g., http://localhost:8443)
	APIKey    string // Agent API key for authentication
	AgentName string // Agent name for identification
	AgentID   string // Agent ID for API calls (set after registration or from env)
	Hostname  string // Server hostname
}

// Agent represents the local agent that runs on target servers.
// It periodically sends heartbeats, polls for work, and executes deployment jobs.
type Agent struct {
	config *AgentConfig
	logger *slog.Logger
	client *http.Client

	// Configuration
	heartbeatInterval time.Duration
	pollInterval      time.Duration
}

// WorkResponse represents the response from the work polling endpoint.
type WorkResponse struct {
	Jobs  []JobItem `json:"jobs"`
	Count int       `json:"count"`
}

// JobItem represents a job returned from the control plane, enriched with target details.
type JobItem struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	CertificateID string          `json:"certificate_id"`
	TargetID      *string         `json:"target_id,omitempty"`
	TargetType    string          `json:"target_type,omitempty"`
	TargetConfig  json.RawMessage `json:"target_config,omitempty"`
	Status        string          `json:"status"`
}

// NewAgent creates a new agent instance.
func NewAgent(cfg *AgentConfig, logger *slog.Logger) *Agent {
	return &Agent{
		config:            cfg,
		logger:            logger,
		client:            &http.Client{Timeout: 30 * time.Second},
		heartbeatInterval: 60 * time.Second,
		pollInterval:      30 * time.Second,
	}
}

// Run starts the agent's main loop.
// It sends heartbeats, polls for work, and handles graceful shutdown via context cancellation.
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("agent starting",
		"server_url", a.config.ServerURL,
		"agent_name", a.config.AgentName,
		"agent_id", a.config.AgentID)

	// Create ticker channels for heartbeat and polling
	heartbeatTicker := time.NewTicker(a.heartbeatInterval)
	defer heartbeatTicker.Stop()

	pollTicker := time.NewTicker(a.pollInterval)
	defer pollTicker.Stop()

	// Run initial heartbeat and poll
	a.sendHeartbeat(ctx)
	a.pollForWork(ctx)

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("agent shutting down", "reason", ctx.Err())
			return ctx.Err()

		case <-heartbeatTicker.C:
			a.sendHeartbeat(ctx)

		case <-pollTicker.C:
			a.pollForWork(ctx)
		}
	}
}

// sendHeartbeat sends a heartbeat to the control plane.
// POST /api/v1/agents/{agentID}/heartbeat
func (a *Agent) sendHeartbeat(ctx context.Context) {
	a.logger.Debug("sending heartbeat", "agent_id", a.config.AgentID)

	path := fmt.Sprintf("/api/v1/agents/%s/heartbeat", a.config.AgentID)
	resp, err := a.makeRequest(ctx, http.MethodPost, path, map[string]string{
		"version":  "1.0.0",
		"hostname": a.config.Hostname,
	})
	if err != nil {
		a.logger.Error("heartbeat failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("heartbeat rejected",
			"status", resp.StatusCode,
			"body", string(body))
		return
	}

	a.logger.Debug("heartbeat acknowledged")
}

// pollForWork queries the control plane for pending deployment jobs and processes them.
// GET /api/v1/agents/{agentID}/work
func (a *Agent) pollForWork(ctx context.Context) {
	a.logger.Debug("polling for work", "agent_id", a.config.AgentID)

	path := fmt.Sprintf("/api/v1/agents/%s/work", a.config.AgentID)
	resp, err := a.makeRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		a.logger.Error("work poll failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("work poll rejected",
			"status", resp.StatusCode,
			"body", string(body))
		return
	}

	var workResp WorkResponse
	if err := json.NewDecoder(resp.Body).Decode(&workResp); err != nil {
		a.logger.Error("failed to decode work response", "error", err)
		return
	}

	if workResp.Count == 0 {
		a.logger.Debug("no pending work")
		return
	}

	a.logger.Info("received work", "job_count", workResp.Count)

	// Process each job
	for _, job := range workResp.Jobs {
		if job.Type == "Deployment" {
			a.executeDeploymentJob(ctx, job)
		}
	}
}

// executeDeploymentJob executes a deployment job by fetching the certificate and deploying it
// to the target system using the appropriate connector (NGINX, F5 BIG-IP, or IIS).
//
// Flow:
// 1. Report job as Running
// 2. Fetch the certificate PEM from the control plane
// 3. Instantiate the target connector based on target_type from the work response
// 4. Call DeployCertificate on the connector
// 5. Report job as Completed (or Failed)
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
		_ = a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("cert fetch failed: %v", err))
		return
	}

	a.logger.Info("certificate fetched for deployment",
		"job_id", job.ID,
		"cert_length", len(certPEM))

	// Split PEM into cert and chain (separated by double newline between PEM blocks)
	certOnly, chainPEM := splitPEMChain(certPEM)

	// Deploy to the target using the appropriate connector
	if job.TargetType != "" {
		connector, err := a.createTargetConnector(job.TargetType, job.TargetConfig)
		if err != nil {
			a.logger.Error("failed to create target connector",
				"job_id", job.ID,
				"target_type", job.TargetType,
				"error", err)
			_ = a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("connector init failed: %v", err))
			return
		}

		deployReq := target.DeploymentRequest{
			CertPEM:      certOnly,
			ChainPEM:     chainPEM,
			TargetConfig: job.TargetConfig,
			Metadata: map[string]string{
				"certificate_id": job.CertificateID,
				"job_id":         job.ID,
			},
		}

		result, err := connector.DeployCertificate(ctx, deployReq)
		if err != nil {
			a.logger.Error("deployment failed",
				"job_id", job.ID,
				"target_type", job.TargetType,
				"error", err)
			_ = a.reportJobStatus(ctx, job.ID, "Failed", fmt.Sprintf("deployment failed: %v", err))
			return
		}

		a.logger.Info("target connector deployment completed",
			"job_id", job.ID,
			"target_type", job.TargetType,
			"success", result.Success,
			"message", result.Message)
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

	case "F5":
		var cfg f5.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid F5 config: %w", err)
			}
		}
		return f5.New(&cfg, a.logger), nil

	case "IIS":
		var cfg iis.Config
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("invalid IIS config: %w", err)
			}
		}
		return iis.New(&cfg, a.logger), nil

	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}
}

// splitPEMChain splits a PEM chain into the first certificate (cert) and the rest (chain).
// The control plane returns the full chain as a single string with PEM blocks concatenated.
func splitPEMChain(pemChain string) (string, string) {
	const endCert = "-----END CERTIFICATE-----"
	idx := 0
	count := 0
	for i := 0; i < len(pemChain); i++ {
		if i+len(endCert) <= len(pemChain) && pemChain[i:i+len(endCert)] == endCert {
			count++
			if count == 1 {
				idx = i + len(endCert)
				break
			}
		}
	}
	if idx == 0 || idx >= len(pemChain) {
		return pemChain, ""
	}
	cert := pemChain[:idx] + "\n"
	chain := ""
	// Skip whitespace between cert and chain
	for idx < len(pemChain) && (pemChain[idx] == '\n' || pemChain[idx] == '\r' || pemChain[idx] == ' ') {
		idx++
	}
	if idx < len(pemChain) {
		chain = pemChain[idx:]
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

func main() {
	// Parse command-line flags (with env var fallbacks for Docker deployment)
	serverURL := flag.String("server", getEnvDefault("CERTCTL_SERVER_URL", "http://localhost:8443"), "Control plane server URL")
	apiKey := flag.String("api-key", getEnvDefault("CERTCTL_API_KEY", ""), "Agent API key")
	agentName := flag.String("name", getEnvDefault("CERTCTL_AGENT_NAME", "certctl-agent"), "Agent name")
	agentID := flag.String("agent-id", getEnvDefault("CERTCTL_AGENT_ID", ""), "Agent ID (from registration)")
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

	// Create agent configuration
	agentCfg := &AgentConfig{
		ServerURL: *serverURL,
		APIKey:    *apiKey,
		AgentName: *agentName,
		AgentID:   *agentID,
		Hostname:  hostname,
	}

	// Create and start agent
	agent := NewAgent(agentCfg, logger)

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run agent in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- agent.Run(ctx)
	}()

	// Wait for signal or agent error
	select {
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig.String())
		cancel()
		<-errChan
	case err := <-errChan:
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
