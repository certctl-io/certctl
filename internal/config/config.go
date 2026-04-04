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
	Server       ServerConfig
	Database     DatabaseConfig
	Scheduler    SchedulerConfig
	Log          LogConfig
	Auth         AuthConfig
	RateLimit    RateLimitConfig
	CORS         CORSConfig
	Keygen       KeygenConfig
	CA           CAConfig
	Notifiers    NotifierConfig
	NetworkScan  NetworkScanConfig
	EST          ESTConfig
	Verification VerificationConfig
	ACME         ACMEConfig
	Vault        VaultConfig
	DigiCert     DigiCertConfig
	Sectigo      SectigoConfig
	GoogleCAS    GoogleCASConfig
	Digest       DigestConfig
	Encryption   EncryptionConfig
}

// EncryptionConfig contains configuration for encrypting sensitive data at rest.
type EncryptionConfig struct {
	// ConfigEncryptionKey is the passphrase used to derive AES-256-GCM keys for encrypting
	// issuer config secrets in the database. If empty, configs are stored in plaintext (development only).
	ConfigEncryptionKey string
}

// NotifierConfig contains configuration for notification connectors.
// Each notifier is enabled by setting its required env var (webhook URL or API key).
type NotifierConfig struct {
	// SlackWebhookURL is the incoming webhook URL for Slack notifications.
	// Format: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
	// Optional: leave empty to disable Slack notifications.
	SlackWebhookURL string

	// SlackChannel optionally overrides the default channel in the Slack webhook.
	// Example: "#alerts" or "@user". Leave empty to use webhook's default channel.
	SlackChannel string

	// SlackUsername sets the display name for Slack bot messages.
	// Default: "certctl". Used in webhook message formatting.
	SlackUsername string

	// TeamsWebhookURL is the incoming webhook URL for Microsoft Teams notifications.
	// Format: https://outlook.webhook.office.com/webhookb2/...
	// Optional: leave empty to disable Teams notifications.
	TeamsWebhookURL string

	// PagerDutyRoutingKey is the integration key for PagerDuty Events API v2.
	// Obtain from PagerDuty integration settings.
	// Optional: leave empty to disable PagerDuty notifications.
	PagerDutyRoutingKey string

	// PagerDutySeverity sets the default severity level for PagerDuty events.
	// Valid values: "info", "warning", "error", "critical". Default: "warning".
	PagerDutySeverity string

	// OpsGenieAPIKey is the API key for OpsGenie Alert API v2.
	// Obtain from OpsGenie organization settings.
	// Optional: leave empty to disable OpsGenie notifications.
	OpsGenieAPIKey string

	// OpsGeniePriority sets the default priority for OpsGenie alerts.
	// Valid values: "P1", "P2", "P3", "P4", "P5". Default: "P3".
	OpsGeniePriority string

	// SMTPHost is the SMTP server hostname for sending email notifications.
	// Example: "smtp.gmail.com", "smtp.sendgrid.net". Required for email notifications.
	// Setting: CERTCTL_SMTP_HOST environment variable.
	SMTPHost string

	// SMTPPort is the SMTP server port. Default: 587 (STARTTLS).
	// Common values: 25 (plain), 465 (implicit TLS), 587 (STARTTLS).
	// Setting: CERTCTL_SMTP_PORT environment variable.
	SMTPPort int

	// SMTPUsername is the SMTP authentication username.
	// Setting: CERTCTL_SMTP_USERNAME environment variable.
	SMTPUsername string

	// SMTPPassword is the SMTP authentication password or app-specific password.
	// Setting: CERTCTL_SMTP_PASSWORD environment variable.
	SMTPPassword string

	// SMTPFromAddress is the sender email address for outbound notifications.
	// Example: "certctl@example.com", "noreply@company.com".
	// Setting: CERTCTL_SMTP_FROM_ADDRESS environment variable.
	SMTPFromAddress string

	// SMTPUseTLS enables TLS for the SMTP connection.
	// Default: true. Set to false for plain SMTP (not recommended).
	// Setting: CERTCTL_SMTP_USE_TLS environment variable.
	SMTPUseTLS bool
}

// KeygenConfig controls where private keys are generated.
type KeygenConfig struct {
	// Mode determines where certificate private keys are generated.
	// Valid values: "agent" (default, production) or "server" (demo only).
	// In "agent" mode, renewal/issuance jobs enter AwaitingCSR state and agents
	// generate ECDSA P-256 keys locally. Private keys never leave agent infrastructure.
	// In "server" mode, the control plane generates RSA keys — demo only, not for production
	// as private keys touch the server. Requires explicit opt-in.
	Mode string
}

// CAConfig controls the Local CA's operating mode.
type CAConfig struct {
	// CertPath is the path to a PEM-encoded CA certificate for sub-CA mode.
	// When set with KeyPath, the Local CA loads this cert instead of generating a self-signed root.
	// Required: sub-CA mode must have both CertPath and KeyPath set.
	// Optional: leave empty for self-signed mode (development/demo). Path must be absolute.
	CertPath string

	// KeyPath is the path to a PEM-encoded CA private key for sub-CA mode.
	// Supports RSA, ECDSA, and PKCS#8 encoded keys.
	// Required: must be set together with CertPath for sub-CA mode.
	// Optional: leave empty for self-signed mode (development/demo). Path must be absolute.
	KeyPath string
}

// StepCAConfig contains step-ca issuer connector configuration.
type StepCAConfig struct {
	// URL is the base URL of the step-ca server.
	// Example: "https://ca.example.com:9000". Required for step-ca integration.
	URL string

	// ProvisionerName is the name of the JWK provisioner configured in step-ca.
	// Used to select which provisioner signs the certificate requests.
	ProvisionerName string

	// ProvisionerKeyPath is the path to the PEM-encoded JWK provisioner private key.
	// Authenticates with the step-ca /sign API. Must be absolute path.
	ProvisionerKeyPath string

	// ProvisionerPassword is the optional password for the provisioner private key.
	// Leave empty if the key file is not encrypted.
	ProvisionerPassword string
}

// VaultConfig contains HashiCorp Vault PKI issuer connector configuration.
type VaultConfig struct {
	// Addr is the Vault server address (e.g., "https://vault.example.com:8200").
	// Required for Vault PKI integration.
	// Setting: CERTCTL_VAULT_ADDR environment variable.
	Addr string

	// Token is the Vault token for authentication.
	// Required for Vault PKI integration.
	// Setting: CERTCTL_VAULT_TOKEN environment variable.
	Token string

	// Mount is the PKI secrets engine mount path.
	// Default: "pki".
	// Setting: CERTCTL_VAULT_MOUNT environment variable.
	Mount string

	// Role is the PKI role name used for signing certificates.
	// Required for Vault PKI integration.
	// Setting: CERTCTL_VAULT_ROLE environment variable.
	Role string

	// TTL is the requested certificate time-to-live.
	// Default: "8760h" (1 year).
	// Setting: CERTCTL_VAULT_TTL environment variable.
	TTL string
}

// DigiCertConfig contains DigiCert CertCentral issuer connector configuration.
type DigiCertConfig struct {
	// APIKey is the CertCentral API key for authentication.
	// Required for DigiCert integration.
	// Setting: CERTCTL_DIGICERT_API_KEY environment variable.
	APIKey string

	// OrgID is the DigiCert organization ID for certificate orders.
	// Required for DigiCert integration.
	// Setting: CERTCTL_DIGICERT_ORG_ID environment variable.
	OrgID string

	// ProductType is the DigiCert product type for certificate orders.
	// Default: "ssl_basic". Common values: "ssl_basic", "ssl_wildcard", "ssl_ev_basic".
	// Setting: CERTCTL_DIGICERT_PRODUCT_TYPE environment variable.
	ProductType string

	// BaseURL is the DigiCert CertCentral API base URL.
	// Default: "https://www.digicert.com/services/v2".
	// Setting: CERTCTL_DIGICERT_BASE_URL environment variable.
	BaseURL string
}

// SectigoConfig contains Sectigo Certificate Manager issuer connector configuration.
type SectigoConfig struct {
	// CustomerURI is the Sectigo customer URI (organization identifier).
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_CUSTOMER_URI environment variable.
	CustomerURI string

	// Login is the Sectigo API account login.
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_LOGIN environment variable.
	Login string

	// Password is the Sectigo API account password or API key.
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_PASSWORD environment variable.
	Password string

	// OrgID is the Sectigo organization ID for certificate enrollments.
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_ORG_ID environment variable.
	OrgID int

	// CertType is the Sectigo certificate type ID (from GET /ssl/v1/types).
	// Required for enrollment. Set via CERTCTL_SECTIGO_CERT_TYPE environment variable.
	CertType int

	// Term is the certificate validity in days (e.g., 365, 730).
	// Default: 365.
	// Setting: CERTCTL_SECTIGO_TERM environment variable.
	Term int

	// BaseURL is the Sectigo SCM API base URL.
	// Default: "https://cert-manager.com/api".
	// Setting: CERTCTL_SECTIGO_BASE_URL environment variable.
	BaseURL string
}

// GoogleCASConfig contains Google Cloud Certificate Authority Service configuration.
type GoogleCASConfig struct {
	// Project is the GCP project ID.
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_PROJECT environment variable.
	Project string

	// Location is the GCP region (e.g., "us-central1").
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_LOCATION environment variable.
	Location string

	// CAPool is the Certificate Authority pool name.
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_CA_POOL environment variable.
	CAPool string

	// Credentials is the path to the service account JSON credentials file.
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_CREDENTIALS environment variable.
	Credentials string

	// TTL is the default certificate time-to-live.
	// Default: "8760h" (1 year).
	// Setting: CERTCTL_GOOGLE_CAS_TTL environment variable.
	TTL string
}

// DigestConfig controls the scheduled certificate digest email feature.
type DigestConfig struct {
	// Enabled controls whether periodic digest emails are generated and sent.
	// Default: false. When enabled, requires SMTP to be configured.
	// Setting: CERTCTL_DIGEST_ENABLED environment variable.
	Enabled bool

	// Interval is how often digest emails are generated and sent.
	// Default: 24 hours. Minimum: 1 hour.
	// Setting: CERTCTL_DIGEST_INTERVAL environment variable.
	Interval time.Duration

	// Recipients is a comma-separated list of email addresses to receive digest emails.
	// If empty, digests are sent to all certificate owners.
	// Setting: CERTCTL_DIGEST_RECIPIENTS environment variable.
	Recipients []string
}

// ACMEConfig contains ACME issuer connector configuration.
type ACMEConfig struct {
	// DirectoryURL is the ACME directory URL for certificate issuance.
	// Examples: "https://acme-v02.api.letsencrypt.org/directory" (Let's Encrypt),
	// "https://acme.zerossl.com/v2/DV90" (ZeroSSL), or custom CA directory.
	DirectoryURL string

	// Email is the email address for ACME account registration.
	// Used for certificate expiration notices and account recovery by ACME CA.
	Email string

	// ChallengeType selects the ACME challenge mechanism for domain validation.
	// Valid values: "http-01" (default, requires public HTTP endpoint),
	// "dns-01" (DNS TXT record per renewal), or "dns-persist-01" (standing DNS record).
	// Default: "http-01".
	ChallengeType string

	// DNSPresentScript is the path to a shell script that creates DNS TXT records.
	// Required for dns-01 and dns-persist-01 challenge types.
	// Script receives these environment variables:
	// - CERTCTL_DNS_DOMAIN: domain being validated (e.g., "example.com")
	// - CERTCTL_DNS_FQDN: full record name (e.g., "_acme-challenge.example.com" or "_validation-persist.example.com")
	// - CERTCTL_DNS_VALUE: TXT record value (key authorization digest for dns-01, or issuer domain info for dns-persist-01)
	// - CERTCTL_DNS_TOKEN: ACME challenge token
	// Example: /opt/dns-scripts/add-record.sh
	DNSPresentScript string

	// DNSCleanUpScript is the path to a shell script that removes DNS TXT records.
	// Used only for dns-01 challenges to clean up temporary validation records.
	// Script receives the same environment variables as DNSPresentScript.
	// Leave empty if cleanup is not needed (e.g., dns-persist-01).
	DNSCleanUpScript string

	// DNSPersistIssuerDomain is the issuer domain for dns-persist-01 standing records.
	// Example: "letsencrypt.org" or "zerossl.com". Only used if ChallengeType is "dns-persist-01".
	// The record value becomes: "<issuer_domain>; accounturi=<acme_account_uri>"
	DNSPersistIssuerDomain string

	// ARIEnabled enables ACME Renewal Information (RFC 9702) support.
	// When enabled, the renewal scheduler queries the CA for suggested renewal windows
	// instead of relying solely on static expiration thresholds.
	// Default: false. Requires a CA that supports ARI (e.g., Let's Encrypt).
	// Setting: CERTCTL_ACME_ARI_ENABLED environment variable.
	ARIEnabled bool

	// Insecure skips TLS certificate verification when connecting to the ACME directory.
	// Only use for testing with self-signed ACME servers like Pebble. Never in production.
	// Setting: CERTCTL_ACME_INSECURE environment variable.
	Insecure bool
}

// OpenSSLConfig contains OpenSSL/Custom CA issuer connector configuration.
type OpenSSLConfig struct {
	// SignScript is the path to a shell script that signs certificate requests.
	// Script receives: CSR_PATH, COMMON_NAME, OUTPUT_CERT_PATH as env vars.
	// Must output the signed certificate PEM to OUTPUT_CERT_PATH.
	// Example: /opt/ca-scripts/sign.sh
	SignScript string

	// RevokeScript is the path to a shell script that revokes certificates.
	// Script receives: SERIAL_NUMBER, REASON_CODE as env vars.
	// Best-effort: script failures do not block revocation recording.
	// Leave empty if revocation is not supported by the custom CA.
	RevokeScript string

	// CRLScript is the path to a shell script that generates CRL (Certificate Revocation List).
	// Script should output the DER-encoded CRL to stdout.
	// Leave empty if CRL generation is not supported by the custom CA.
	CRLScript string

	// TimeoutSeconds is the maximum execution time for any shell script invocation.
	// Default: 30 seconds. Prevents hung processes from blocking certificate operations.
	TimeoutSeconds int
}

// ESTConfig controls the RFC 7030 Enrollment over Secure Transport server.
type ESTConfig struct {
	// Enabled controls whether EST endpoints are available for device enrollment.
	// Default: false (EST disabled). Set to true to enable RFC 7030 endpoints
	// under /.well-known/est/ (cacerts, simpleenroll, simplereenroll, csrattrs).
	Enabled bool

	// IssuerID selects which issuer connector processes EST certificate requests.
	// Valid values: "iss-local" (default), "iss-acme", "iss-stepca", "iss-openssl".
	// Default: "iss-local". Must reference a configured issuer.
	IssuerID string

	// ProfileID optionally constrains EST enrollments to a specific certificate profile.
	// When set, all EST enrollments must match the profile's crypto constraints.
	// Leave empty to allow EST to use any configured issuer's defaults.
	ProfileID string
}

// NetworkScanConfig controls the server-side active TLS scanner.
type NetworkScanConfig struct {
	Enabled      bool          // Enable network scanning (default false)
	ScanInterval time.Duration // How often to run network scans (default 6h)
}

// VerificationConfig controls post-deployment TLS verification behavior.
type VerificationConfig struct {
	Enabled bool          // Enable verification (default true)
	Timeout time.Duration // Timeout for TLS probe (default 10s)
	Delay   time.Duration // Wait before verification after deployment (default 2s)
}

// ServerConfig contains HTTP server configuration.
type ServerConfig struct {
	Host        string // Server host (default: 127.0.0.1). Set via CERTCTL_SERVER_HOST.
	Port        int    // Server port (default: 8080). Set via CERTCTL_SERVER_PORT.
	MaxBodySize int64  // Maximum request body size in bytes (default: 1MB). Set via CERTCTL_MAX_BODY_SIZE.
}

// DatabaseConfig contains database connection configuration.
type DatabaseConfig struct {
	URL            string
	MaxConnections int
	MigrationsPath string
}

// SchedulerConfig contains scheduler timing configuration.
type SchedulerConfig struct {
	// RenewalCheckInterval is how often the renewal scheduler checks for expiring certs.
	// Default: 1 hour. Minimum: 1 minute. Certs are flagged for renewal at configured thresholds.
	// Setting: CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL environment variable.
	RenewalCheckInterval time.Duration

	// JobProcessorInterval is how often the job scheduler processes pending jobs.
	// Default: 30 seconds. Minimum: 1 second. Controls issuance, renewal, and deployment latency.
	// Setting: CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL environment variable.
	JobProcessorInterval time.Duration

	// AgentHealthCheckInterval is how often the scheduler checks agent heartbeats.
	// Default: 2 minutes. Minimum: 1 second. Marks agents offline if no recent heartbeat.
	// Setting: CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL environment variable.
	AgentHealthCheckInterval time.Duration

	// NotificationProcessInterval is how often the scheduler processes pending notifications.
	// Default: 1 minute. Minimum: 1 second. Sends notifications to Slack, Teams, PagerDuty, etc.
	// Setting: CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL environment variable.
	NotificationProcessInterval time.Duration
}

// LogConfig contains logging configuration.
type LogConfig struct {
	// Level sets the minimum log level for output.
	// Valid values: "debug" (verbose), "info" (default), "warn" (warnings), "error" (errors only).
	// Setting: CERTCTL_LOG_LEVEL environment variable. Default: "info".
	Level string

	// Format sets the output format for logs.
	// Valid values: "json" (structured, for parsing), "text" (human-readable).
	// Setting: CERTCTL_LOG_FORMAT environment variable. Default: "json".
	Format string
}

// AuthConfig contains authentication configuration.
type AuthConfig struct {
	// Type sets the authentication mechanism for the REST API.
	// Valid values: "api-key" (default, production), "jwt", "none" (development only).
	// When "api-key", clients must provide Authorization: Bearer <key> header.
	// "none" requires explicit opt-in via CERTCTL_AUTH_TYPE env var with warning logged.
	// Setting: CERTCTL_AUTH_TYPE environment variable. Default: "api-key".
	Type string

	// Secret is the authentication secret (API key hash, JWT signing key, etc.).
	// For "api-key": the base64-encoded API key to validate against.
	// For "jwt": the secret used to verify JWT token signatures.
	// For "none": ignored.
	// Setting: CERTCTL_AUTH_SECRET environment variable. Required for "api-key" and "jwt".
	Secret string
}

// RateLimitConfig contains rate limiting configuration.
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is enforced on API endpoints.
	// Default: true. Set to false to disable rate limits (not recommended for production).
	// Setting: CERTCTL_RATE_LIMIT_ENABLED environment variable.
	Enabled bool

	// RPS is the target requests per second allowed per client (token bucket rate).
	// Default: 50. Higher values allow burst throughput; lower values restrict load.
	// Setting: CERTCTL_RATE_LIMIT_RPS environment variable.
	RPS float64

	// BurstSize is the maximum number of requests allowed in a single burst.
	// Default: 100. Allows clients to exceed RPS briefly when BurstSize tokens available.
	// Must be at least as large as RPS. Higher = more lenient burst handling.
	// Setting: CERTCTL_RATE_LIMIT_BURST environment variable.
	BurstSize int
}

// CORSConfig contains CORS configuration.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins for CORS requests.
	// Security default: empty list denies all CORS requests (same-origin only).
	// ["*"] allows all origins (development/demo mode only, security risk).
	// Specific origins (e.g., ["https://app.example.com"]) whitelist only those origins.
	AllowedOrigins []string
}

// Load reads configuration from environment variables and returns a Config.
// Environment variables must have the CERTCTL_ prefix.
// Example: CERTCTL_SERVER_HOST, CERTCTL_DATABASE_URL, etc.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:        getEnv("CERTCTL_SERVER_HOST", "127.0.0.1"),
			Port:        getEnvInt("CERTCTL_SERVER_PORT", 8080),
			MaxBodySize: getEnvInt64("CERTCTL_MAX_BODY_SIZE", 1024*1024), // 1MB default
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
		CA: CAConfig{
			CertPath: getEnv("CERTCTL_CA_CERT_PATH", ""),
			KeyPath:  getEnv("CERTCTL_CA_KEY_PATH", ""),
		},
		Notifiers: NotifierConfig{
			SlackWebhookURL:     getEnv("CERTCTL_SLACK_WEBHOOK_URL", ""),
			SlackChannel:        getEnv("CERTCTL_SLACK_CHANNEL", ""),
			SlackUsername:        getEnv("CERTCTL_SLACK_USERNAME", "certctl"),
			TeamsWebhookURL:     getEnv("CERTCTL_TEAMS_WEBHOOK_URL", ""),
			PagerDutyRoutingKey: getEnv("CERTCTL_PAGERDUTY_ROUTING_KEY", ""),
			PagerDutySeverity:   getEnv("CERTCTL_PAGERDUTY_SEVERITY", "warning"),
			OpsGenieAPIKey:      getEnv("CERTCTL_OPSGENIE_API_KEY", ""),
			OpsGeniePriority:    getEnv("CERTCTL_OPSGENIE_PRIORITY", "P3"),
			SMTPHost:            getEnv("CERTCTL_SMTP_HOST", ""),
			SMTPPort:            getEnvInt("CERTCTL_SMTP_PORT", 587),
			SMTPUsername:        getEnv("CERTCTL_SMTP_USERNAME", ""),
			SMTPPassword:        getEnv("CERTCTL_SMTP_PASSWORD", ""),
			SMTPFromAddress:     getEnv("CERTCTL_SMTP_FROM_ADDRESS", ""),
			SMTPUseTLS:          getEnvBool("CERTCTL_SMTP_USE_TLS", true),
		},
		NetworkScan: NetworkScanConfig{
			Enabled:      getEnvBool("CERTCTL_NETWORK_SCAN_ENABLED", false),
			ScanInterval: getEnvDuration("CERTCTL_NETWORK_SCAN_INTERVAL", 6*time.Hour),
		},
		EST: ESTConfig{
			Enabled:   getEnvBool("CERTCTL_EST_ENABLED", false),
			IssuerID:  getEnv("CERTCTL_EST_ISSUER_ID", "iss-local"),
			ProfileID: getEnv("CERTCTL_EST_PROFILE_ID", ""),
		},
		Verification: VerificationConfig{
			Enabled: getEnvBool("CERTCTL_VERIFY_DEPLOYMENT", true),
			Timeout: getEnvDuration("CERTCTL_VERIFY_TIMEOUT", 10*time.Second),
			Delay:   getEnvDuration("CERTCTL_VERIFY_DELAY", 2*time.Second),
		},
		Vault: VaultConfig{
			Addr:  getEnv("CERTCTL_VAULT_ADDR", ""),
			Token: getEnv("CERTCTL_VAULT_TOKEN", ""),
			Mount: getEnv("CERTCTL_VAULT_MOUNT", "pki"),
			Role:  getEnv("CERTCTL_VAULT_ROLE", ""),
			TTL:   getEnv("CERTCTL_VAULT_TTL", "8760h"),
		},
		DigiCert: DigiCertConfig{
			APIKey:      getEnv("CERTCTL_DIGICERT_API_KEY", ""),
			OrgID:       getEnv("CERTCTL_DIGICERT_ORG_ID", ""),
			ProductType: getEnv("CERTCTL_DIGICERT_PRODUCT_TYPE", "ssl_basic"),
			BaseURL:     getEnv("CERTCTL_DIGICERT_BASE_URL", "https://www.digicert.com/services/v2"),
		},
		Sectigo: SectigoConfig{
			CustomerURI: getEnv("CERTCTL_SECTIGO_CUSTOMER_URI", ""),
			Login:       getEnv("CERTCTL_SECTIGO_LOGIN", ""),
			Password:    getEnv("CERTCTL_SECTIGO_PASSWORD", ""),
			OrgID:       getEnvInt("CERTCTL_SECTIGO_ORG_ID", 0),
			CertType:    getEnvInt("CERTCTL_SECTIGO_CERT_TYPE", 0),
			Term:        getEnvInt("CERTCTL_SECTIGO_TERM", 365),
			BaseURL:     getEnv("CERTCTL_SECTIGO_BASE_URL", "https://cert-manager.com/api"),
		},
		GoogleCAS: GoogleCASConfig{
			Project:     getEnv("CERTCTL_GOOGLE_CAS_PROJECT", ""),
			Location:    getEnv("CERTCTL_GOOGLE_CAS_LOCATION", ""),
			CAPool:      getEnv("CERTCTL_GOOGLE_CAS_CA_POOL", ""),
			Credentials: getEnv("CERTCTL_GOOGLE_CAS_CREDENTIALS", ""),
			TTL:         getEnv("CERTCTL_GOOGLE_CAS_TTL", "8760h"),
		},
		ACME: ACMEConfig{
			DirectoryURL:           getEnv("CERTCTL_ACME_DIRECTORY_URL", ""),
			Email:                  getEnv("CERTCTL_ACME_EMAIL", ""),
			ChallengeType:          getEnv("CERTCTL_ACME_CHALLENGE_TYPE", "http-01"),
			DNSPresentScript:       getEnv("CERTCTL_ACME_DNS_PRESENT_SCRIPT", ""),
			DNSCleanUpScript:       getEnv("CERTCTL_ACME_DNS_CLEANUP_SCRIPT", ""),
			DNSPersistIssuerDomain: getEnv("CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN", ""),
			ARIEnabled:             getEnvBool("CERTCTL_ACME_ARI_ENABLED", false),
			Insecure:               getEnvBool("CERTCTL_ACME_INSECURE", false),
		},
		Digest: DigestConfig{
			Enabled:    getEnvBool("CERTCTL_DIGEST_ENABLED", false),
			Interval:   getEnvDuration("CERTCTL_DIGEST_INTERVAL", 24*time.Hour),
			Recipients: getEnvList("CERTCTL_DIGEST_RECIPIENTS", nil),
		},
		Encryption: EncryptionConfig{
			ConfigEncryptionKey: getEnv("CERTCTL_CONFIG_ENCRYPTION_KEY", ""),
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

// getEnvInt64 reads an int64 environment variable with the given key and default value.
func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		intVal, err := strconv.ParseInt(value, 10, 64)
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
