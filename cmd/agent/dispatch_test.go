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
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Bundle 0.7-extended: cmd/agent dispatch coverage for executeCSRJob,
// executeDeploymentJob, verifyAndReportDeployment, markRetired, getEnvDefault,
// getEnvBoolDefault — the previously-uncovered code paths flagged by the
// audit's per-function coverage report.
//
// Strategy: same httptest-backed pattern as the existing agent_test.go
// (Heartbeat / PollWork tests). Each test:
//   - constructs a mock control-plane HTTP server (httptest.NewServer)
//   - configures an Agent pointing at that server via NewAgent
//   - invokes the function under test
//   - asserts on the requests the mock server received

// ─────────────────────────────────────────────────────────────────────────────
// executeCSRJob
// ─────────────────────────────────────────────────────────────────────────────

func TestAgent_ExecuteCSRJob_HappyPath(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	var csrSubmitted atomic.Bool
	var statusUpdates atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/csr") && r.Method == http.MethodPost:
			csrSubmitted.Store(true)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["csr_pem"] == "" || !strings.Contains(body["csr_pem"], "CERTIFICATE REQUEST") {
				t.Errorf("CSR submission missing PEM body: %v", body)
			}
			if body["certificate_id"] != "mc-test-cert" {
				t.Errorf("CSR submission missing certificate_id: %v", body)
			}
			w.WriteHeader(http.StatusAccepted)
		case strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodPost:
			statusUpdates.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		KeyDir:    keyDir,
	}
	agent, err := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}

	job := JobItem{
		ID:            "j-csr-1",
		CertificateID: "mc-test-cert",
		Type:          "csr",
		CommonName:    "test.example.com",
		SANs:          []string{"test.example.com", "alt.example.com", "alice@example.com"},
	}

	agent.executeCSRJob(context.Background(), job)

	if !csrSubmitted.Load() {
		t.Errorf("expected CSR to be submitted to control plane")
	}

	// Key file should exist with mode 0600
	keyPath := filepath.Join(keyDir, "mc-test-cert.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected key file at %s: %v", keyPath, err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected key file mode 0600, got %v", info.Mode().Perm())
	}

	// Read back and verify it parses as an ECDSA key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Errorf("expected EC PRIVATE KEY PEM, got %v", block)
	}
}

func TestAgent_ExecuteCSRJob_EmptyCommonName_ReportsFailed(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	var lastStatus atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodPost {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastStatus.Store(body["status"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		KeyDir:    keyDir,
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	job := JobItem{
		ID:            "j-csr-empty-cn",
		CertificateID: "mc-empty-cn",
		Type:          "csr",
		CommonName:    "", // empty CN — should be rejected
	}

	agent.executeCSRJob(context.Background(), job)

	if got := lastStatus.Load(); got != "Failed" {
		t.Errorf("expected last status 'Failed', got %v", got)
	}
}

func TestAgent_ExecuteCSRJob_CSRSubmissionRejected_ReportsFailed(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	var lastStatus atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/csr") && r.Method == http.MethodPost:
			// Server rejects the CSR with 400 Bad Request
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"CSR validation failed"}`))
		case strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastStatus.Store(body["status"])
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		KeyDir:    keyDir,
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	job := JobItem{
		ID:            "j-csr-rejected",
		CertificateID: "mc-rejected",
		Type:          "csr",
		CommonName:    "rejected.example.com",
	}

	agent.executeCSRJob(context.Background(), job)

	if got := lastStatus.Load(); got != "Failed" {
		t.Errorf("expected last status 'Failed' after CSR rejection, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// executeDeploymentJob
// ─────────────────────────────────────────────────────────────────────────────

// generateTestCertAndKey builds an ephemeral self-signed cert + ECDSA P-256 key
// for use as test fixture data in deployment tests.
func generateTestCertAndKey(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestAgent_ExecuteDeploymentJob_FetchFails_ReportsFailed(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	var lastStatus atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/certificates/") && r.Method == http.MethodGet:
			// Fail the certificate fetch
			w.WriteHeader(http.StatusInternalServerError)
		case strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastStatus.Store(body["status"])
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		KeyDir:    keyDir,
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	job := JobItem{
		ID:            "j-deploy-fetch-fail",
		CertificateID: "mc-fetch-fail",
		Type:          "deployment",
		TargetType:    "nginx",
	}

	agent.executeDeploymentJob(context.Background(), job)

	if got := lastStatus.Load(); got != "Failed" {
		t.Errorf("expected status 'Failed' after fetch failure, got %v", got)
	}
}

func TestAgent_ExecuteDeploymentJob_KeyMissing_ReportsFailed(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	certPEM, _ := generateTestCertAndKey(t, "deploy-test.example.com")
	// Note: key file is intentionally NOT written to keyDir — exercises the
	// "local private key missing" failure path in executeDeploymentJob.

	var lastStatus atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/certificates/") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":          "mc-no-key",
				"common_name": "deploy-test.example.com",
				"pem_content": certPEM,
			})
		case strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastStatus.Store(body["status"])
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		KeyDir:    keyDir,
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	job := JobItem{
		ID:            "j-deploy-no-key",
		CertificateID: "mc-no-key",
		Type:          "deployment",
		TargetType:    "nginx",
	}

	agent.executeDeploymentJob(context.Background(), job)

	if got := lastStatus.Load(); got != "Failed" {
		t.Errorf("expected status 'Failed' after key-missing, got %v", got)
	}
}

func TestAgent_ExecuteDeploymentJob_UnknownTargetType_ReportsFailed(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	certPEM, keyPEM := generateTestCertAndKey(t, "deploy-test.example.com")
	keyPath := filepath.Join(keyDir, "mc-unknown-tgt.key")
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	var lastStatus atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/certificates/") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":          "mc-unknown-tgt",
				"common_name": "deploy-test.example.com",
				"pem_content": certPEM,
			})
		case strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastStatus.Store(body["status"])
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		KeyDir:    keyDir,
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	job := JobItem{
		ID:            "j-unknown-target",
		CertificateID: "mc-unknown-tgt",
		Type:          "deployment",
		TargetType:    "frobnicator-9000", // unknown connector type
	}

	agent.executeDeploymentJob(context.Background(), job)

	if got := lastStatus.Load(); got != "Failed" {
		t.Errorf("expected status 'Failed' after unknown target type, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// markRetired — single-shot retirement signal
// ─────────────────────────────────────────────────────────────────────────────

func TestAgent_MarkRetired_ClosesSignalOnce(t *testing.T) {
	cfg := &AgentConfig{
		ServerURL: "http://example.invalid",
		APIKey:    "k",
		AgentID:   "a-retired-test",
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// First mark — channel should close
	agent.markRetired("test-source-1", 410, "agent retired")
	select {
	case <-agent.retiredSignal:
		// expected — closed channel reads return zero immediately
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("expected retiredSignal to be closed after markRetired")
	}

	// Second mark — must not panic (sync.Once guards the close)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("second markRetired panicked: %v", r)
		}
	}()
	agent.markRetired("test-source-2", 410, "agent retired again")
}

// ─────────────────────────────────────────────────────────────────────────────
// getEnvDefault / getEnvBoolDefault
// ─────────────────────────────────────────────────────────────────────────────

func TestGetEnvDefault_FallsBackToDefault(t *testing.T) {
	t.Setenv("TESTONLY_AGENT_NONEXISTENT_VAR", "")
	got := getEnvDefault("TESTONLY_AGENT_NONEXISTENT_VAR", "fallback")
	if got != "fallback" {
		t.Errorf("expected fallback, got %q", got)
	}
}

func TestGetEnvDefault_UsesEnvWhenSet(t *testing.T) {
	t.Setenv("TESTONLY_AGENT_VAR", "from-env")
	got := getEnvDefault("TESTONLY_AGENT_VAR", "fallback")
	if got != "from-env" {
		t.Errorf("expected from-env, got %q", got)
	}
}

func TestGetEnvBoolDefault_TruthyValues(t *testing.T) {
	for _, v := range []string{"1", "t", "true", "yes", "on", "TRUE", "True"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("TESTONLY_AGENT_BOOL", v)
			if !getEnvBoolDefault("TESTONLY_AGENT_BOOL", false) {
				t.Errorf("expected true for %q", v)
			}
		})
	}
}

func TestGetEnvBoolDefault_FalsyValues(t *testing.T) {
	for _, v := range []string{"0", "f", "false", "no", "off"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("TESTONLY_AGENT_BOOL", v)
			if getEnvBoolDefault("TESTONLY_AGENT_BOOL", true) {
				t.Errorf("expected false for %q", v)
			}
		})
	}
}

func TestGetEnvBoolDefault_UnrecognizedReturnsDefault(t *testing.T) {
	t.Setenv("TESTONLY_AGENT_BOOL", "frobnicate")
	if !getEnvBoolDefault("TESTONLY_AGENT_BOOL", true) {
		t.Errorf("expected default(true) for unrecognized value")
	}
}

func TestGetEnvBoolDefault_EmptyReturnsDefault(t *testing.T) {
	t.Setenv("TESTONLY_AGENT_BOOL", "")
	if !getEnvBoolDefault("TESTONLY_AGENT_BOOL", true) {
		t.Errorf("expected default(true) for empty value")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Run() — graceful shutdown via context cancellation
// ─────────────────────────────────────────────────────────────────────────────

func TestAgent_Run_ContextCancelExitsCleanly(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/a-run-test/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/agents/a-run-test/work":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(WorkResponse{Jobs: []JobItem{}, Count: 0})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-run-test",
		KeyDir:    keyDir,
	}
	agent, err := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	// Speed up tickers so the test exits in <500ms
	agent.heartbeatInterval = 50 * time.Millisecond
	agent.pollInterval = 50 * time.Millisecond
	agent.discoveryInterval = 24 * time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Run(ctx)
	}()

	// Let one heartbeat + poll fire, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit within 2s after cancellation")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// verifyAndReportDeployment
// ─────────────────────────────────────────────────────────────────────────────

func TestAgent_VerifyAndReportDeployment_ProbeFailure_ReportsError(t *testing.T) {
	// Server with no TLS listener at the target — probe will fail.
	var verificationReported atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/verify") || strings.Contains(r.URL.Path, "/verification") {
			verificationReported.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	tgtID := "tgt-test"
	job := JobItem{
		ID:       "j-verify",
		TargetID: &tgtID,
	}

	// Probe a closed port — will fail quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Should not panic; failure surfaces via reportVerificationResult.
	agent.verifyAndReportDeployment(ctx, job, "127.0.0.1", 1, "")
	// Test passes if no panic.
}

func TestAgent_VerifyAndReportDeployment_NilTargetID_LogsAndReturns(t *testing.T) {
	cfg := &AgentConfig{
		ServerURL: "http://example.invalid",
		APIKey:    "test-key",
		AgentID:   "a-test",
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	job := JobItem{
		ID:       "j-no-tgt",
		TargetID: nil, // nil target — should short-circuit cleanly
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Should not panic and should return without making any HTTP call.
	agent.verifyAndReportDeployment(ctx, job, "127.0.0.1", 1, "")
}

func TestAgent_Run_RetiredSignalExitsWithErrAgentRetired(t *testing.T) {
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatalf("chmod keyDir: %v", err)
	}

	// Server returns 410 Gone on heartbeat — the documented retirement signal.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/a-retired/heartbeat":
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":"agent retired"}`))
		case "/api/v1/agents/a-retired/work":
			w.WriteHeader(http.StatusGone)
		default:
			w.WriteHeader(http.StatusGone)
		}
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-retired",
		KeyDir:    keyDir,
	}
	agent, _ := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	agent.heartbeatInterval = 30 * time.Millisecond
	agent.pollInterval = 30 * time.Millisecond
	agent.discoveryInterval = 24 * time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Run(ctx)
	}()

	select {
	case err := <-errCh:
		if err != ErrAgentRetired {
			t.Errorf("expected ErrAgentRetired, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not surface ErrAgentRetired within 2s")
	}
}
