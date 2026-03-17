package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

// Config represents the complete application configuration.
// All configuration values are read from environment variables with CERTCTL_ prefix.
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Scheduler SchedulerConfig
	Log       LogConfig
	Auth      AuthConfig
	RateLimit RateLimitConfig
	CORS      CORSConfig
	Keygen    KeygenConfig
}

// KeygenConfig controls where private keys are generated.
type KeygenConfig struct {
	// Mode: "agent" (default, production) or "server" (demo only, Local CA).
	// In "agent" mode, renewal/issuance jobs enter AwaitingCSR state and agents generate keys locally.
	// In "server" mode, the control plane generates keys (private keys touch the server — demo only).
	Mode string
}

// ServerConfig contains HTTP server configuration.
type ServerConfig struct {
	Host string
	Port int
}

// DatabaseConfig contains database connection configuration.
type DatabaseConfig struct {
	URL            string
	MaxConnections int
	MigrationsPath string
}

// SchedulerConfig contains scheduler timing configuration.
type SchedulerConfig struct {
	RenewalCheckInterval        time.Duration
	JobProcessorInterval        time.Duration
	AgentHealthCheckInterval    time.Duration
	NotificationProcessInterval time.Duration
}

// LogConfig contains logging configuration.
type LogConfig struct {
	Level  string // "debug", "info", "warn", "error"
	Format string // "json" or "text"
}

// AuthConfig contains authentication configuration.
type AuthConfig struct {
	Type   string // "api-key", "jwt", "none"
	Secret string // Secret key for signing (if applicable)
}

// RateLimitConfig contains rate limiting configuration.
type RateLimitConfig struct {
	Enabled   bool
	RPS       float64 // Requests per second
	BurstSize int     // Maximum burst size
}

// CORSConfig contains CORS configuration.
type CORSConfig struct {
	AllowedOrigins []string // Allowed origins; empty = same-origin only; ["*"] = all
}

// Load reads configuration from environment variables and returns a Config.
// Environment variables must have the CERTCTL_ prefix.
// Example: CERTCTL_SERVER_HOST, CERTCTL_DATABASE_URL, etc.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host: getEnv("CERTCTL_SERVER_HOST", "127.0.0.1"),
			Port: getEnvInt("CERTCTL_SERVER_PORT", 8080),
		},
		Database: DatabaseConfig{
			URL:            getEnv("CERTCTL_DATABASE_URL", "postgres://localhost/certctl"),
			MaxConnections: getEnvInt("CERTCTL_DATABASE_MAX_CONNS", 25),
			MigrationsPath: getEnv("CERTCTL_DATABASE_MIGRATIONS_PATH", "./migrations"),
		},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        getEnvDuration("CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL", 1*time.Hour),
			JobProcessorInterval:        getEnvDuration("CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL", 30*time.Second),
			AgentHealthCheckInterval:    getEnvDuration("CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL", 2*time.Minute),
			NotificationProcessInterval: getEnvDuration("CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL", 1*time.Minute),
		},
		Log: LogConfig{
			Level:  getEnv("CERTCTL_LOG_LEVEL", "info"),
			Format: getEnv("CERTCTL_LOG_FORMAT", "json"),
		},
		Auth: AuthConfig{
			Type:   getEnv("CERTCTL_AUTH_TYPE", "api-key"),
			Secret: getEnv("CERTCTL_AUTH_SECRET", ""),
		},
		RateLimit: RateLimitConfig{
			Enabled:   getEnvBool("CERTCTL_RATE_LIMIT_ENABLED", true),
			RPS:       getEnvFloat("CERTCTL_RATE_LIMIT_RPS", 50),
			BurstSize: getEnvInt("CERTCTL_RATE_LIMIT_BURST", 100),
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnvList("CERTCTL_CORS_ORIGINS", nil),
		},
		Keygen: KeygenConfig{
			Mode: getEnv("CERTCTL_KEYGEN_MODE", "agent"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// Validate database configuration
	if c.Database.URL == "" {
		return fmt.Errorf("database URL is required")
	}

	if c.Database.MaxConnections < 1 {
		return fmt.Errorf("database max_connections must be at least 1")
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.Log.Level] {
		return fmt.Errorf("invalid log level: %s", c.Log.Level)
	}

	// Validate log format
	validFormats := map[string]bool{
		"json": true,
		"text": true,
	}
	if !validFormats[c.Log.Format] {
		return fmt.Errorf("invalid log format: %s", c.Log.Format)
	}

	// Validate auth type
	validAuthTypes := map[string]bool{
		"api-key": true,
		"jwt":     true,
		"none":    true,
	}
	if !validAuthTypes[c.Auth.Type] {
		return fmt.Errorf("invalid auth type: %s", c.Auth.Type)
	}

	// If using JWT or API-key, secret is required
	if (c.Auth.Type == "jwt" || c.Auth.Type == "api-key") && c.Auth.Secret == "" {
		return fmt.Errorf("auth secret is required for auth type %s", c.Auth.Type)
	}

	// Validate keygen mode
	validKeygenModes := map[string]bool{
		"agent":  true,
		"server": true,
	}
	if !validKeygenModes[c.Keygen.Mode] {
		return fmt.Errorf("invalid keygen mode: %s (must be 'agent' or 'server')", c.Keygen.Mode)
	}

	// Validate scheduler intervals
	if c.Scheduler.RenewalCheckInterval < 1*time.Minute {
		return fmt.Errorf("renewal check interval must be at least 1 minute")
	}

	if c.Scheduler.JobProcessorInterval < 1*time.Second {
		return fmt.Errorf("job processor interval must be at least 1 second")
	}

	if c.Scheduler.AgentHealthCheckInterval < 1*time.Second {
		return fmt.Errorf("agent health check interval must be at least 1 second")
	}

	if c.Scheduler.NotificationProcessInterval < 1*time.Second {
		return fmt.Errorf("notification process interval must be at least 1 second")
	}

	return nil
}

// getEnv reads a string environment variable with the given key and default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt reads an integer environment variable with the given key and default value.
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return defaultValue
		}
		return intVal
	}
	return defaultValue
}

// getEnvDuration reads a time.Duration environment variable.
// The value should be a valid Go duration string (e.g., "1h", "30s", "5m").
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return defaultValue
		}
		return duration
	}
	return defaultValue
}

// getEnvBool reads a boolean environment variable.
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

// getEnvFloat reads a float64 environment variable.
func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return defaultValue
		}
		return f
	}
	return defaultValue
}

// getEnvList reads a comma-separated list environment variable.
func getEnvList(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		var result []string
		for _, s := range splitComma(value) {
			s = trimSpace(s)
			if s != "" {
				result = append(result, s)
			}
		}
		return result
	}
	return defaultValue
}

// splitComma splits a string by commas (no strings import needed).
func splitComma(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// trimSpace trims leading/trailing whitespace.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// GetLogLevel returns the appropriate slog.Level from the configured log level.
func (c *Config) GetLogLevel() slog.Level {
	switch c.Log.Level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
