package config

import (
	"log/slog"
	"os"
	"testing"
	"strings"
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
func setMinimalValidEnv(t *testing.T) {
	t.Helper()
	// api-key auth requires a secret
	t.Setenv("CERTCTL_AUTH_SECRET", "test-secret-key")
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
		Server:   ServerConfig{Port: 8080},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
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
		Server:   ServerConfig{Port: 8080},
		Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
		Log:      LogConfig{Level: "info", Format: "json"},
		Auth:     AuthConfig{Type: "none", Secret: ""},
		Keygen:   KeygenConfig{Mode: "agent"},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        1 * time.Hour,
			JobProcessorInterval:        30 * time.Second,
			AgentHealthCheckInterval:    2 * time.Minute,
			NotificationProcessInterval: 1 * time.Minute,
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
		Server:   ServerConfig{Port: 8080},
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
		Server:   ServerConfig{Port: 8080},
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
		Server:   ServerConfig{Port: 8080},
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
		Server:   ServerConfig{Port: 8080},
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

func TestValidate_EmptyDatabaseURL(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Port: 8080},
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
		Server:   ServerConfig{Port: 8080},
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
		Server:   ServerConfig{Port: 8080},
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
				Server:    ServerConfig{Port: 8080},
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
		Server:   ServerConfig{Port: 8080},
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
				Server:   ServerConfig{Port: 8080},
				Database: DatabaseConfig{URL: "postgres://localhost/certctl", MaxConnections: 25},
				Log:      LogConfig{Level: "info", Format: "json"},
				Auth:     AuthConfig{Type: "api-key", Secret: "test-secret"},
				Keygen:   KeygenConfig{Mode: "agent"},
				Scheduler: SchedulerConfig{
					RenewalCheckInterval:        1 * time.Minute,
					JobProcessorInterval:        1 * time.Minute,
					AgentHealthCheckInterval:    1 * time.Minute,
					NotificationProcessInterval: 1 * time.Minute,
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
