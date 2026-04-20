package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clearCertctlEnv unsets all CERTCTL_* environment variables to ensure test isolation.
func clearCertctlEnv(t *testing.T) {
	t.Helper()
	for _, env := range os.Environ() {
		for i := 0; i < len(env); i++ {
			if env[i] == '=' {
				key := env[:i]
				if len(key) > 7 && key[:8] == "CERTCTL_" {
					t.Setenv(key, "")
					os.Unsetenv(key)
				}
				break
			}
		}
	}
}

// setMinimalValidEnv sets the minimum env vars needed for Load() to succeed (Validate passes).
//
// HTTPS-everywhere milestone (§2.1 + §3 locked decisions): the control plane
// is TLS-only and Validate() refuses to pass without a readable cert/key pair
// on disk. setMinimalValidEnv therefore materializes a throwaway ECDSA P-256
// self-signed pair in t.TempDir() and points the two TLS env vars at it so
// every Load-based test inherits a valid HTTPS posture without each caller
// having to spell out cert generation. The temp dir is cleaned up by
// testing.T at end-of-test.
func setMinimalValidEnv(t *testing.T) {
	t.Helper()
	// api-key auth requires a secret
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret-key")
	// HTTPS-only control plane requires a real cert/key pair on disk.
	certPath, keyPath := generateTestTLSPair(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", certPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", keyPath)
}

// generateTestTLSPair writes an ECDSA P-256 self-signed certificate + private
// key pair to files inside t.TempDir() and returns the paths. Same shape used
// by cmd/server/tls_test.go — this duplicates the generator rather than
// importing it so the config package tests stay independent of cmd/server.
func generateTestTLSPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certctl-config-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// validServerConfig returns a ServerConfig with Port=8080 plus a freshly
// minted TLS cert/key pair on disk, so Validate() passes the HTTPS-only
// preflight (cert empty → stat → tls.LoadX509KeyPair round-trip). Every
// struct-based Validate test uses this so they fail for the reason they
// claim to test, not for a missing TLS pair.
func validServerConfig(t *testing.T) ServerConfig {
	t.Helper()
	certPath, keyPath := generateTestTLSPair(t)
	return ServerConfig{
		Port: 8080,
		TLS:  ServerTLSConfig{CertPath: certPath, KeyPath: keyPath},
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Server defaults
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %q, want %q", cfg.Server.Host, "127.0.0.1")
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want %d", cfg.Server.Port, 8080)
	}
	if cfg.Server.MaxBodySize != 1024*1024 {
		t.Errorf("Server.MaxBodySize = %d, want %d", cfg.Server.MaxBodySize, 1024*1024)
	}

	// Auth defaults
	if cfg.Auth.Type != "api-key" {
		t.Errorf("Auth.Type = %q, want %q", cfg.Auth.Type, "api-key")
	}

	// Keygen defaults
	if cfg.Keygen.Mode != "agent" {
		t.Errorf("Keygen.Mode = %q, want %q", cfg.Keygen.Mode, "agent")
	}

	// RateLimit defaults
	if cfg.RateLimit.Enabled != true {
		t.Errorf("RateLimit.Enabled = %v, want true", cfg.RateLimit.Enabled)
	}
	if cfg.RateLimit.RPS != 50 {
		t.Errorf("RateLimit.RPS = %f, want 50", cfg.RateLimit.RPS)
	}
	if cfg.RateLimit.BurstSize != 100 {
		t.Errorf("RateLimit.BurstSize = %d, want 100", cfg.RateLimit.BurstSize)
	}

	// Log defaults
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, "json")
	}

	// Scheduler defaults
	if cfg.Scheduler.RenewalCheckInterval != 1*time.Hour {
		t.Errorf("Scheduler.RenewalCheckInterval = %v, want 1h", cfg.Scheduler.RenewalCheckInterval)
	}
	if cfg.Scheduler.JobProcessorInterval != 30*time.Second {
		t.Errorf("Scheduler.JobProcessorInterval = %v, want 30s", cfg.Scheduler.JobProcessorInterval)
	}

	// ACME defaults
	if cfg.ACME.ChallengeType != "http-01" {
		t.Errorf("ACME.ChallengeType = %q, want %q", cfg.ACME.ChallengeType, "http-01")
	}

	// Vault defaults
	if cfg.Vault.Mount != "pki" {
		t.Errorf("Vault.Mount = %q, want %q", cfg.Vault.Mount, "pki")
	}
	if cfg.Vault.TTL != "8760h" {
		t.Errorf("Vault.TTL = %q, want %q", cfg.Vault.TTL, "8760h")
	}

	// EST defaults
	if cfg.EST.Enabled != false {
		t.Errorf("EST.Enabled = %v, want false", cfg.EST.Enabled)
	}
	if cfg.EST.IssuerID != "iss-local" {
		t.Errorf("EST.IssuerID = %q, want %q", cfg.EST.IssuerID, "iss-local")
	}

	// Verification defaults
	if cfg.Verification.Enabled != true {
		t.Errorf("Verification.Enabled = %v, want true", cfg.Verification.Enabled)
	}

	// Digest defaults
	if cfg.Digest.Enabled != false {
		t.Errorf("Digest.Enabled = %v, want false", cfg.Digest.Enabled)
	}
	if cfg.Digest.Interval != 24*time.Hour {
		t.Errorf("Digest.Interval = %v, want 24h", cfg.Digest.Interval)
	}

	// Database defaults
	if cfg.Database.URL != "postgres://localhost/certctl" {
		t.Errorf("Database.URL = %q, want default", cfg.Database.URL)
	}
	if cfg.Database.MaxConnections != 25 {
		t.Errorf("Database.MaxConnections = %d, want 25", cfg.Database.MaxConnections)
	}
}

func TestLoad_AllEnvVarsSet(t *testing.T) {
	clearCertctlEnv(t)

	// HTTPS-only control plane: Load() → Validate() refuses an empty cert path.
	// Materialize a throwaway ECDSA P-256 pair and point the two TLS env vars
	// at it before setting every other CERTCTL_* var this test cares about.
	certPath, keyPath := generateTestTLSPair(t)
	t.Setenv("CERTCTL_SERVER_TLS_CERT_PATH", certPath)
	t.Setenv("CERTCTL_SERVER_TLS_KEY_PATH", keyPath)

	t.Setenv("CERTCTL_SERVER_HOST", "0.0.0.0")
	t.Setenv("CERTCTL_SERVER_PORT", "9090")
	t.Setenv("CERTCTL_MAX_BODY_SIZE", "2097152")
	t.Setenv("CERTCTL_AUTH_TYPE", "api-key")
	t.Setenv("CERTCTL_AUTH_SECRET", "my-secret")
	t.Setenv("CERTCTL_RATE_LIMIT_ENABLED", "false")
	t.Setenv("CERTCTL_RATE_LIMIT_RPS", "100")
	t.Setenv("CERTCTL_RATE_LIMIT_BURST", "200")
	t.Setenv("CERTCTL_CORS_ORIGINS", "https://a.com,https://b.com")
	t.Setenv("CERTCTL_KEYGEN_MODE", "server")
	t.Setenv("CERTCTL_LOG_LEVEL", "debug")
	t.Setenv("CERTCTL_LOG_FORMAT", "text")
	t.Setenv("CERTCTL_DATABASE_URL", "postgres://user:pass@db:5432/certctl")
	t.Setenv("CERTCTL_DATABASE_MAX_CONNS", "50")
	t.Setenv("CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL", "2h")
	t.Setenv("CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL", "1m")
	t.Setenv("CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL", "5m")
	t.Setenv("CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL", "2m")
	t.Setenv("CERTCTL_VAULT_ADDR", "https://vault:8200")
	t.Setenv("CERTCTL_VAULT_TOKEN", "hvs.test")
	t.Setenv("CERTCTL_VAULT_MOUNT", "pki-int")
	t.Setenv("CERTCTL_VAULT_ROLE", "web")
	t.Setenv("CERTCTL_VAULT_TTL", "720h")
	t.Setenv("CERTCTL_ACME_CHALLENGE_TYPE", "dns-01")
	t.Setenv("CERTCTL_ACME_ARI_ENABLED", "true")
	t.Setenv("CERTCTL_EST_ENABLED", "true")
	t.Setenv("CERTCTL_EST_ISSUER_ID", "iss-acme")
	t.Setenv("CERTCTL_DIGEST_ENABLED", "true")
	t.Setenv("CERTCTL_DIGEST_INTERVAL", "12h")
	t.Setenv("CERTCTL_DIGEST_RECIPIENTS", "alice@co.com,bob@co.com")
	t.Setenv("CERTCTL_SMTP_HOST", "smtp.example.com")
	t.Setenv("CERTCTL_SMTP_PORT", "465")
	t.Setenv("CERTCTL_SMTP_FROM_ADDRESS", "noreply@co.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.MaxBodySize != 2097152 {
		t.Errorf("Server.MaxBodySize = %d, want 2097152", cfg.Server.MaxBodySize)
	}
	if cfg.RateLimit.Enabled != false {
		t.Errorf("RateLimit.Enabled = %v, want false", cfg.RateLimit.Enabled)
	}
	if cfg.RateLimit.RPS != 100 {
		t.Errorf("RateLimit.RPS = %f, want 100", cfg.RateLimit.RPS)
	}
	if cfg.RateLimit.BurstSize != 200 {
		t.Errorf("RateLimit.BurstSize = %d, want 200", cfg.RateLimit.BurstSize)
	}
	if len(cfg.CORS.AllowedOrigins) != 2 {
		t.Errorf("CORS.AllowedOrigins has %d items, want 2", len(cfg.CORS.AllowedOrigins))
	} else {
		if cfg.CORS.AllowedOrigins[0] != "https://a.com" {
			t.Errorf("CORS.AllowedOrigins[0] = %q, want %q", cfg.CORS.AllowedOrigins[0], "https://a.com")
		}
		if cfg.CORS.AllowedOrigins[1] != "https://b.com" {
			t.Errorf("CORS.AllowedOrigins[1] = %q, want %q", cfg.CORS.AllowedOrigins[1], "https://b.com")
		}
	}
	if cfg.Keygen.Mode != "server" {
		t.Errorf("Keygen.Mode = %q, want %q", cfg.Keygen.Mode, "server")
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
	if cfg.Log.Format != "text" {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, "text")
	}
	if cfg.Database.MaxConnections != 50 {
		t.Errorf("Database.MaxConnections = %d, want 50", cfg.Database.MaxConnections)
	}
	if cfg.Scheduler.RenewalCheckInterval != 2*time.Hour {
		t.Errorf("Scheduler.RenewalCheckInterval = %v, want 2h", cfg.Scheduler.RenewalCheckInterval)
	}
	if cfg.Scheduler.JobProcessorInterval != 1*time.Minute {
		t.Errorf("Scheduler.JobProcessorInterval = %v, want 1m", cfg.Scheduler.JobProcessorInterval)
	}
	if cfg.Vault.Addr != "https://vault:8200" {
		t.Errorf("Vault.Addr = %q, want %q", cfg.Vault.Addr, "https://vault:8200")
	}
	if cfg.Vault.Mount != "pki-int" {
		t.Errorf("Vault.Mount = %q, want %q", cfg.Vault.Mount, "pki-int")
	}
	if cfg.ACME.ChallengeType != "dns-01" {
		t.Errorf("ACME.ChallengeType = %q, want %q", cfg.ACME.ChallengeType, "dns-01")
	}
	if cfg.ACME.ARIEnabled != true {
		t.Errorf("ACME.ARIEnabled = %v, want true", cfg.ACME.ARIEnabled)
	}
	if cfg.EST.Enabled != true {
		t.Errorf("EST.Enabled = %v, want true", cfg.EST.Enabled)
	}
	if cfg.EST.IssuerID != "iss-acme" {
		t.Errorf("EST.IssuerID = %q, want %q", cfg.EST.IssuerID, "iss-acme")
	}
	if cfg.Digest.Enabled != true {
		t.Errorf("Digest.Enabled = %v, want true", cfg.Digest.Enabled)
	}
	if cfg.Digest.Interval != 12*time.Hour {
		t.Errorf("Digest.Interval = %v, want 12h", cfg.Digest.Interval)
	}
	if len(cfg.Digest.Recipients) != 2 {
		t.Errorf("Digest.Recipients has %d items, want 2", len(cfg.Digest.Recipients))
	}
	if cfg.Notifiers.SMTPHost != "smtp.example.com" {
		t.Errorf("Notifiers.SMTPHost = %q, want %q", cfg.Notifiers.SMTPHost, "smtp.example.com")
	}
	if cfg.Notifiers.SMTPPort != 465 {
		t.Errorf("Notifiers.SMTPPort = %d, want 465", cfg.Notifiers.SMTPPort)
	}
}

func TestLoad_InvalidIntEnvVar(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_SERVER_PORT", "notanint")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should fall back to default, got error: %v", err)
	}
	// Falls back to default
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080 (default fallback)", cfg.Server.Port)
	}
}

func TestLoad_InvalidDurationEnvVar(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_DIGEST_INTERVAL", "notaduration")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should fall back to default, got error: %v", err)
	}
	if cfg.Digest.Interval != 24*time.Hour {
		t.Errorf("Digest.Interval = %v, want 24h (default fallback)", cfg.Digest.Interval)
	}
}

func TestLoad_InvalidBoolEnvVar(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_RATE_LIMIT_ENABLED", "notabool")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should fall back to default, got error: %v", err)
	}
	// getEnvBool only matches "true", "1", "yes" — anything else is false
	if cfg.RateLimit.Enabled != false {
		t.Errorf("RateLimit.Enabled = %v, want false for invalid bool", cfg.RateLimit.Enabled)
	}
}

func TestLoad_CommaSeparatedList(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_CORS_ORIGINS", "https://a.com, https://b.com , https://c.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.CORS.AllowedOrigins) != 3 {
		t.Fatalf("CORS.AllowedOrigins has %d items, want 3", len(cfg.CORS.AllowedOrigins))
	}
	// trimSpace should handle spaces around items
	if cfg.CORS.AllowedOrigins[1] != "https://b.com" {
		t.Errorf("CORS.AllowedOrigins[1] = %q, want %q (trimmed)", cfg.CORS.AllowedOrigins[1], "https://b.com")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for valid config: %v", err)
	}
}

func TestValidate_AuthTypeNone(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "none", Secret: ""},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
			NotificationRetryInterval:   2 * time.Minute,
			RetryInterval:               5 * time.Minute,
			JobTimeoutInterval:          10 * time.Minute,
			AwaitingCSRTimeout:          24 * time.Hour,
			AwaitingApprovalTimeout:     168 * time.Hour,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned error for auth type 'none': %v", err)
	}
}

func TestValidate_InvalidAuthType(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "oauth", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for unsupported auth type 'oauth'")
	}
}

func TestValidate_APIKeyAuth_MissingSecret(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: ""},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error when api-key auth has empty secret")
	}
}

func TestValidate_JWTAuth_MissingSecret(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "jwt", Secret: ""},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error when jwt auth has empty secret")
	}
}

func TestValidate_InvalidKeygenMode(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "hybrid"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for unsupported keygen mode 'hybrid'")
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero", 0},
		{"negative", -1},
		{"too high", 65536},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server:   ServerConfig{Port: tt.port},
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: "api-key", Secret: "key"},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Hour,
					JobProcessorInterval:        30 * time.Second,
					AgentHealthCheckInterval:    2 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
				},
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() should return error for port %d", tt.port)
			}
		})
	}
}

// TestValidate_TLSCertPathEmpty pins the first of the HTTPS-only fail-loud
// gates in Validate(): an empty CertPath must produce the operator-facing
// "server TLS cert path is required" error. Per §2.1 + §3 locked decisions,
// there is no plaintext HTTP fallback — missing TLS config is a hard startup
// refusal, not a warning.
func TestValidate_TLSCertPathEmpty(t *testing.T) {
	_, keyPath := generateTestTLSPair(t)
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: "", KeyPath: keyPath},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty TLS cert path")
	}
	if !strings.Contains(err.Error(), "server TLS cert path is required") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS cert path is required")
	}
}

// TestValidate_TLSKeyPathEmpty pins the second HTTPS-only gate: empty KeyPath
// must produce the "server TLS key path is required" error. Runs with a valid
// CertPath so the cert-empty gate (which fires first) is cleanly bypassed —
// proves the key-empty gate is actually reached.
func TestValidate_TLSKeyPathEmpty(t *testing.T) {
	certPath, _ := generateTestTLSPair(t)
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: certPath, KeyPath: ""},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty TLS key path")
	}
	if !strings.Contains(err.Error(), "server TLS key path is required") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS key path is required")
	}
}

// TestValidate_TLSCertFileMissing pins the os.Stat gate on the cert path. A
// non-existent path must surface "server TLS cert file unreadable" so the
// operator sees the bad path in the error (file=%q) instead of a deferred
// ListenAndServeTLS panic after the scheduler has already fanned out.
func TestValidate_TLSCertFileMissing(t *testing.T) {
	_, keyPath := generateTestTLSPair(t)
	missingCert := filepath.Join(t.TempDir(), "does-not-exist.pem")
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: missingCert, KeyPath: keyPath},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for missing TLS cert file")
	}
	if !strings.Contains(err.Error(), "server TLS cert file unreadable") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS cert file unreadable")
	}
}

// TestValidate_TLSKeyFileMissing pins the os.Stat gate on the key path. Uses a
// valid CertPath so the cert-missing gate does not pre-empt; proves the key
// gate is reached and reports the bad key path.
func TestValidate_TLSKeyFileMissing(t *testing.T) {
	certPath, _ := generateTestTLSPair(t)
	missingKey := filepath.Join(t.TempDir(), "does-not-exist.key")
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: certPath, KeyPath: missingKey},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for missing TLS key file")
	}
	if !strings.Contains(err.Error(), "server TLS key file unreadable") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS key file unreadable")
	}
}

// TestValidate_TLSMismatchedPair pins the tls.LoadX509KeyPair gate — the
// classic "you shipped the wrong private key" footgun. Generates two
// independent ECDSA pairs and crosses them (pair1 cert + pair2 key). Both
// files exist and parse as PEM, so os.Stat passes; only the cryptographic
// round-trip inside LoadX509KeyPair catches the mismatch.
func TestValidate_TLSMismatchedPair(t *testing.T) {
	certPath1, _ := generateTestTLSPair(t)
	_, keyPath2 := generateTestTLSPair(t)
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS:  ServerTLSConfig{CertPath: certPath1, KeyPath: keyPath2},
		},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for mismatched TLS cert/key pair")
	}
	if !strings.Contains(err.Error(), "server TLS cert/key pair invalid") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server TLS cert/key pair invalid")
	}
}

func TestValidate_EmptyDatabaseURL(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for empty database URL")
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "verbose", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for invalid log level 'verbose'")
	}
}

func TestValidate_InvalidLogFormat(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "yaml"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for invalid log format 'yaml'")
	}
}

func TestValidate_SchedulerIntervalTooSmall(t *testing.T) {
	tests := []struct {
		name string
		cfg  SchedulerConfig
	}{
		{
			"renewal interval below 1 minute",
			SchedulerConfig{
				RenewalCheckInterval:        30 * time.Second,
				JobProcessorInterval:        30 * time.Second,
				AgentHealthCheckInterval:    2 * time.Minute,
				NotificationProcessInterval: 1 * time.Minute,
			},
		},
		{
			"job processor below 1 second",
			SchedulerConfig{
				RenewalCheckInterval:        1 * time.Hour,
				JobProcessorInterval:        500 * time.Millisecond,
				AgentHealthCheckInterval:    2 * time.Minute,
				NotificationProcessInterval: 1 * time.Minute,
			},
		},
		{
			"agent health below 1 second",
			SchedulerConfig{
				RenewalCheckInterval:        1 * time.Hour,
				JobProcessorInterval:        30 * time.Second,
				AgentHealthCheckInterval:    500 * time.Millisecond,
				NotificationProcessInterval: 1 * time.Minute,
			},
		},
		{
			"notification below 1 second",
			SchedulerConfig{
				RenewalCheckInterval:        1 * time.Hour,
				JobProcessorInterval:        30 * time.Second,
				AgentHealthCheckInterval:    2 * time.Minute,
				NotificationProcessInterval: 500 * time.Millisecond,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server:    validServerConfig(t),
				Database:  DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:       LogConfig{Level: "info", Format: "json"},
				Auth:      AuthConfig{Type: "api-key", Secret: "key"},
				Keygen:    KeygenConfig{Mode: "agent"},
				Scheduler: tt.cfg,
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() should return error for %s", tt.name)
			}
		})
	}
}

func TestValidate_DatabaseMaxConnectionsZero(t *testing.T) {
	cfg := &Config{
		Server:   validServerConfig(t),
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 0},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "key"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should return error for max_connections=0")
	}
}

func TestGetLogLevel_AllLevels(t *testing.T) {
	tests := []struct {
		level    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},  // default fallback
		{"", slog.LevelInfo},         // empty string
		{"DEBUG", slog.LevelInfo},    // case-sensitive, no match → default
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			cfg := &Config{Log: LogConfig{Level: tt.level}}
			got := cfg.GetLogLevel()
			if got != tt.expected {
				t.Errorf("GetLogLevel() for %q = %v, want %v", tt.level, got, tt.expected)
			}
		})
	}
}

// Test helper functions
func TestSplitComma(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", []string{""}},
		{",", []string{"", ""}},
		{"a,,c", []string{"a", "", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitComma(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("splitComma(%q) returned %d items, want %d", tt.input, len(got), len(tt.expected))
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("splitComma(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  hello  ", "hello"},
		{"hello", "hello"},
		{"\thello\t", "hello"},
		{"  ", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := trimSpace(tt.input)
			if got != tt.expected {
				t.Errorf("trimSpace(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetEnvFloat(t *testing.T) {
	t.Setenv("TEST_FLOAT", "3.14")
	got := getEnvFloat("TEST_FLOAT", 0)
	if got != 3.14 {
		t.Errorf("getEnvFloat = %f, want 3.14", got)
	}

	// Invalid float falls back to default
	t.Setenv("TEST_FLOAT_BAD", "notafloat")
	got = getEnvFloat("TEST_FLOAT_BAD", 99.9)
	if got != 99.9 {
		t.Errorf("getEnvFloat for invalid = %f, want 99.9", got)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"true", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"anything", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("TEST_BOOL", tt.value)
			got := getEnvBool("TEST_BOOL", false)
			if got != tt.expected {
				t.Errorf("getEnvBool(%q) = %v, want %v", tt.value, got, tt.expected)
			}
		})
	}
}
// I-003: Job timeout reaper configuration tests
func TestConfig_Scheduler_JobTimeoutDefaults(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	// Explicitly unset the three I-003 env vars to exercise the default path.
	t.Setenv("CERTCTL_JOB_TIMEOUT_INTERVAL", "")
	t.Setenv("CERTCTL_JOB_AWAITING_CSR_TIMEOUT", "")
	t.Setenv("CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Scheduler.JobTimeoutInterval != 10*time.Minute {
		t.Errorf("JobTimeoutInterval = %v, want 10m", cfg.Scheduler.JobTimeoutInterval)
	}
	if cfg.Scheduler.AwaitingCSRTimeout != 24*time.Hour {
		t.Errorf("AwaitingCSRTimeout = %v, want 24h", cfg.Scheduler.AwaitingCSRTimeout)
	}
	if cfg.Scheduler.AwaitingApprovalTimeout != 168*time.Hour {
		t.Errorf("AwaitingApprovalTimeout = %v, want 168h", cfg.Scheduler.AwaitingApprovalTimeout)
	}
}

func TestConfig_Scheduler_JobTimeoutEnvOverride(t *testing.T) {
	clearCertctlEnv(t)
	setMinimalValidEnv(t)
	t.Setenv("CERTCTL_JOB_TIMEOUT_INTERVAL", "15m")
	t.Setenv("CERTCTL_JOB_AWAITING_CSR_TIMEOUT", "48h")
	t.Setenv("CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT", "336h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Scheduler.JobTimeoutInterval != 15*time.Minute {
		t.Errorf("JobTimeoutInterval = %v, want 15m", cfg.Scheduler.JobTimeoutInterval)
	}
	if cfg.Scheduler.AwaitingCSRTimeout != 48*time.Hour {
		t.Errorf("AwaitingCSRTimeout = %v, want 48h", cfg.Scheduler.AwaitingCSRTimeout)
	}
	if cfg.Scheduler.AwaitingApprovalTimeout != 336*time.Hour {
		t.Errorf("AwaitingApprovalTimeout = %v, want 336h", cfg.Scheduler.AwaitingApprovalTimeout)
	}
}

func TestConfig_Scheduler_JobTimeoutValidation(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		value      time.Duration
		wantErrMsg string
	}{
		{
			"JobTimeoutInterval too small",
			"JobTimeoutInterval",
			500 * time.Millisecond,
			"job timeout interval must be at least 1 second",
		},
		{
			"AwaitingCSRTimeout too small",
			"AwaitingCSRTimeout",
			500 * time.Millisecond,
			"awaiting CSR timeout must be at least 1 second",
		},
		{
			"AwaitingApprovalTimeout too small",
			"AwaitingApprovalTimeout",
			500 * time.Millisecond,
			"awaiting approval timeout must be at least 1 second",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start from a fully valid config so the I-003 timeout checks
			// are the only potential failure point.
			cfg := &Config{
				Server:   validServerConfig(t),
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Minute,
					JobProcessorInterval:        1 * time.Minute,
					AgentHealthCheckInterval:    1 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
					NotificationRetryInterval:   2 * time.Minute,
					RetryInterval:               1 * time.Minute,
					JobTimeoutInterval:          10 * time.Minute,
					AwaitingCSRTimeout:          24 * time.Hour,
					AwaitingApprovalTimeout:     168 * time.Hour,
				},
			}

			// Override the specific field under test
			switch tt.field {
			case "JobTimeoutInterval":
				cfg.Scheduler.JobTimeoutInterval = tt.value
			case "AwaitingCSRTimeout":
				cfg.Scheduler.AwaitingCSRTimeout = tt.value
			case "AwaitingApprovalTimeout":
				cfg.Scheduler.AwaitingApprovalTimeout = tt.value
			}

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErrMsg)
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}
