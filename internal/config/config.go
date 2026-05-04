package config

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
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
	SCEP         SCEPConfig
	Verification VerificationConfig
	ACME         ACMEConfig
	// Approval is the issuance approval-workflow primitive's runtime
	// config. Rank 7 of the 2026-05-03 Infisical deep-research
	// deliverable. The single field — BypassEnabled — short-circuits
	// the workflow for dev/CI; production deploys MUST leave it false.
	Approval ApprovalConfig
	// ACMEServer is the SERVER-side ACME (RFC 8555 + RFC 9773 ARI)
	// configuration. Distinct from ACME above (which is the consumer-
	// side issuer connector that talks UP to Let's Encrypt / pebble).
	// Server uses CERTCTL_ACME_SERVER_* prefix throughout so the two
	// namespaces stay unambiguous in operator docs and shell env.
	ACMEServer     ACMEServerConfig
	Vault          VaultConfig
	DigiCert       DigiCertConfig
	Sectigo        SectigoConfig
	GoogleCAS      GoogleCASConfig
	AWSACMPCA      AWSACMPCAConfig
	Entrust        EntrustConfig
	GlobalSign     GlobalSignConfig
	EJBCA          EJBCAConfig
	Digest         DigestConfig
	HealthCheck    HealthCheckConfig
	Encryption     EncryptionConfig
	CloudDiscovery CloudDiscoveryConfig
	OCSPResponder  OCSPResponderConfig
}

// OCSPResponderConfig configures the dedicated OCSP-responder cert
// per issuer (RFC 6960 §2.6 + §4.2.2.2). When unset, the local issuer
// falls back to signing OCSP responses with the CA key directly.
//
// Bundle CRL/OCSP-Responder Phase 2.
type OCSPResponderConfig struct {
	// KeyDir is the filesystem directory where FileDriver-backed
	// responder keys are written. Operators MUST set this in
	// production (the default of "" maps to cwd, which is fine for
	// tests but not for serious deployments).
	// Setting: CERTCTL_OCSP_RESPONDER_KEY_DIR.
	KeyDir string

	// RotationGrace is the window before NotAfter at which the
	// responder cert is rotated. Default: 7 days. Operators with
	// stricter relying-party caching expectations may shorten;
	// operators with looser ones may lengthen.
	// Setting: CERTCTL_OCSP_RESPONDER_ROTATION_GRACE.
	RotationGrace time.Duration

	// Validity is how long a freshly-bootstrapped responder cert is
	// valid for. Default: 30 days. Shorter validity means more
	// frequent rotations + smaller revocation-list windows.
	// Setting: CERTCTL_OCSP_RESPONDER_VALIDITY.
	Validity time.Duration
}

// AWSACMPCAConfig contains AWS ACM Private CA issuer connector configuration.
type AWSACMPCAConfig struct {
	// Region is the AWS region where the Private CA resides (e.g., "us-east-1").
	// Required for AWS ACM PCA integration.
	// Setting: CERTCTL_AWS_PCA_REGION environment variable.
	Region string

	// CAArn is the ARN of the ACM Private CA certificate authority.
	// Format: arn:aws:acm-pca:<region>:<account>:certificate-authority/<id>
	// Required for AWS ACM PCA integration.
	// Setting: CERTCTL_AWS_PCA_CA_ARN environment variable.
	CAArn string

	// SigningAlgorithm is the signing algorithm for certificate issuance.
	// Valid: SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA, SHA256WITHECDSA, SHA384WITHECDSA, SHA512WITHECDSA.
	// Default: "SHA256WITHRSA".
	// Setting: CERTCTL_AWS_PCA_SIGNING_ALGORITHM environment variable.
	SigningAlgorithm string

	// ValidityDays is the certificate validity period in days.
	// Default: 365.
	// Setting: CERTCTL_AWS_PCA_VALIDITY_DAYS environment variable.
	ValidityDays int

	// TemplateArn is the optional ARN of an ACM PCA certificate template.
	// Used for constrained subordinate CAs or custom certificate profiles.
	// Setting: CERTCTL_AWS_PCA_TEMPLATE_ARN environment variable.
	TemplateArn string
}

// EntrustConfig contains Entrust Certificate Services issuer connector configuration.
// Entrust uses mTLS client certificate authentication.
type EntrustConfig struct {
	// APIUrl is the Entrust CA Gateway base URL.
	// Setting: CERTCTL_ENTRUST_API_URL environment variable.
	APIUrl string

	// ClientCertPath is the path to the mTLS client certificate PEM file.
	// Setting: CERTCTL_ENTRUST_CLIENT_CERT_PATH environment variable.
	ClientCertPath string

	// ClientKeyPath is the path to the mTLS client private key PEM file.
	// Setting: CERTCTL_ENTRUST_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string

	// CAId is the Entrust CA identifier.
	// Setting: CERTCTL_ENTRUST_CA_ID environment variable.
	CAId string

	// ProfileId is the optional enrollment profile identifier.
	// Setting: CERTCTL_ENTRUST_PROFILE_ID environment variable.
	ProfileId string

	// PollMaxWaitSeconds caps GetOrderStatus's bounded-polling
	// deadline. Approval-pending workflows should bump this (e.g.,
	// 86400 = 24h) so a single tick can wait through the approval
	// window. Default 600. Audit fix #5.
	// Setting: CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS.
	PollMaxWaitSeconds int
}

// GlobalSignConfig contains GlobalSign Atlas HVCA issuer connector configuration.
// GlobalSign uses mTLS client certificate authentication plus API key/secret headers.
type GlobalSignConfig struct {
	// APIUrl is the GlobalSign Atlas HVCA base URL (region-aware).
	// Setting: CERTCTL_GLOBALSIGN_API_URL environment variable.
	APIUrl string

	// APIKey is the GlobalSign API key.
	// Setting: CERTCTL_GLOBALSIGN_API_KEY environment variable.
	APIKey string

	// APISecret is the GlobalSign API secret.
	// Setting: CERTCTL_GLOBALSIGN_API_SECRET environment variable.
	APISecret string

	// ClientCertPath is the path to the mTLS client certificate PEM file.
	// Setting: CERTCTL_GLOBALSIGN_CLIENT_CERT_PATH environment variable.
	ClientCertPath string

	// ClientKeyPath is the path to the mTLS client private key PEM file.
	// Setting: CERTCTL_GLOBALSIGN_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string

	// ServerCAPath is the optional path to a PEM file containing the CA
	// certificate(s) used to verify the GlobalSign Atlas HVCA API server
	// certificate. If empty, the system trust store is used. Set this
	// for private/lab Atlas deployments whose server TLS chain is not
	// present in the host's default trust bundle.
	// Setting: CERTCTL_GLOBALSIGN_SERVER_CA_PATH environment variable.
	ServerCAPath string

	// PollMaxWaitSeconds caps GetOrderStatus's bounded-polling
	// deadline. Default 600 (10 minutes). Audit fix #5.
	// Setting: CERTCTL_GLOBALSIGN_POLL_MAX_WAIT_SECONDS.
	PollMaxWaitSeconds int
}

// EJBCAConfig contains EJBCA (Keyfactor) issuer connector configuration.
// EJBCA supports dual authentication: mTLS or OAuth2 Bearer token.
type EJBCAConfig struct {
	// APIUrl is the EJBCA REST API base URL.
	// Setting: CERTCTL_EJBCA_API_URL environment variable.
	APIUrl string

	// AuthMode selects the authentication method: "mtls" or "oauth2". Default: "mtls".
	// Setting: CERTCTL_EJBCA_AUTH_MODE environment variable.
	AuthMode string

	// ClientCertPath is the path to the mTLS client certificate PEM file (required when auth_mode=mtls).
	// Setting: CERTCTL_EJBCA_CLIENT_CERT_PATH environment variable.
	ClientCertPath string

	// ClientKeyPath is the path to the mTLS client private key PEM file (required when auth_mode=mtls).
	// Setting: CERTCTL_EJBCA_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string

	// Token is the OAuth2 Bearer token (required when auth_mode=oauth2).
	// Setting: CERTCTL_EJBCA_TOKEN environment variable.
	Token string

	// CAName is the EJBCA CA name. Required.
	// Setting: CERTCTL_EJBCA_CA_NAME environment variable.
	CAName string

	// CertProfile is the optional EJBCA certificate profile name.
	// Setting: CERTCTL_EJBCA_CERT_PROFILE environment variable.
	CertProfile string

	// EEProfile is the optional EJBCA end-entity profile name.
	// Setting: CERTCTL_EJBCA_EE_PROFILE environment variable.
	EEProfile string
}

// EncryptionConfig contains configuration for encrypting sensitive data at rest.
type EncryptionConfig struct {
	// ConfigEncryptionKey is the passphrase used to derive AES-256-GCM keys for encrypting
	// issuer config secrets in the database. If empty, configs are stored in plaintext (development only).
	ConfigEncryptionKey string
}

// CloudDiscoveryConfig contains configuration for cloud secret manager discovery sources.
// Each source is enabled by setting its required env var(s).
type CloudDiscoveryConfig struct {
	// Enabled controls whether cloud discovery sources run on a schedule.
	// Default: false. Setting: CERTCTL_CLOUD_DISCOVERY_ENABLED.
	Enabled bool

	// Interval is the scheduler loop interval for cloud discovery.
	// Default: 6 hours. Setting: CERTCTL_CLOUD_DISCOVERY_INTERVAL.
	Interval time.Duration

	// AWS Secrets Manager discovery
	AWSSM AWSSecretsMgrDiscoveryConfig

	// Azure Key Vault discovery
	AzureKV AzureKVDiscoveryConfig

	// GCP Secret Manager discovery
	GCPSM GCPSecretMgrDiscoveryConfig
}

// AWSSecretsMgrDiscoveryConfig contains AWS Secrets Manager discovery settings.
type AWSSecretsMgrDiscoveryConfig struct {
	// Enabled controls whether AWS SM discovery is active.
	// Default: false. Setting: CERTCTL_AWS_SM_DISCOVERY_ENABLED.
	Enabled bool

	// Region is the AWS region to scan (e.g., "us-east-1").
	// Setting: CERTCTL_AWS_SM_REGION.
	Region string

	// TagFilter is the tag key=value used to identify certificate secrets.
	// Default: "type=certificate". Setting: CERTCTL_AWS_SM_TAG_FILTER.
	TagFilter string

	// NamePrefix filters secrets by name prefix (optional).
	// Setting: CERTCTL_AWS_SM_NAME_PREFIX.
	NamePrefix string
}

// AzureKVDiscoveryConfig contains Azure Key Vault discovery settings.
type AzureKVDiscoveryConfig struct {
	// Enabled controls whether Azure KV discovery is active.
	// Default: false. Setting: CERTCTL_AZURE_KV_DISCOVERY_ENABLED.
	Enabled bool

	// VaultURL is the Azure Key Vault URL (e.g., "https://myvault.vault.azure.net").
	// Setting: CERTCTL_AZURE_KV_VAULT_URL.
	VaultURL string

	// TenantID is the Azure AD tenant ID.
	// Setting: CERTCTL_AZURE_KV_TENANT_ID.
	TenantID string

	// ClientID is the Azure AD application (client) ID.
	// Setting: CERTCTL_AZURE_KV_CLIENT_ID.
	ClientID string

	// ClientSecret is the Azure AD application secret.
	// Setting: CERTCTL_AZURE_KV_CLIENT_SECRET.
	ClientSecret string
}

// GCPSecretMgrDiscoveryConfig contains GCP Secret Manager discovery settings.
type GCPSecretMgrDiscoveryConfig struct {
	// Enabled controls whether GCP SM discovery is active.
	// Default: false. Setting: CERTCTL_GCP_SM_DISCOVERY_ENABLED.
	Enabled bool

	// Project is the GCP project ID.
	// Setting: CERTCTL_GCP_SM_PROJECT.
	Project string

	// Credentials is the path to the GCP service account JSON file.
	// Setting: CERTCTL_GCP_SM_CREDENTIALS.
	Credentials string
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

	// PollMaxWaitSeconds caps how long GetOrderStatus blocks doing
	// internal exponential-backoff polling before returning. Default
	// 600 (10 minutes); 0 falls back to asyncpoll default.
	// Setting: CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS. Audit fix #5.
	PollMaxWaitSeconds int
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

	// PollMaxWaitSeconds caps how long GetOrderStatus blocks doing
	// internal exponential-backoff polling. Default 600. Sectigo's
	// collectNotReady sentinel rides the backoff schedule.
	// Setting: CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS. Audit fix #5.
	PollMaxWaitSeconds int
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

// HealthCheckConfig contains configuration for continuous TLS health monitoring (M48).
type HealthCheckConfig struct {
	// Enabled controls whether health checks are enabled.
	// Default: false.
	// Setting: CERTCTL_HEALTH_CHECK_ENABLED environment variable.
	Enabled bool

	// CheckInterval is the main scheduler loop interval for polling due checks.
	// Default: 60 seconds. Each endpoint has its own check_interval_seconds.
	// Setting: CERTCTL_HEALTH_CHECK_INTERVAL environment variable.
	CheckInterval time.Duration

	// DefaultInterval is the default probe interval in seconds for each endpoint (per-endpoint basis).
	// Default: 300 seconds (5 minutes).
	// Setting: CERTCTL_HEALTH_CHECK_DEFAULT_INTERVAL environment variable.
	DefaultInterval int

	// DefaultTimeout is the default TLS connection timeout in milliseconds.
	// Default: 5000 milliseconds (5 seconds).
	// Setting: CERTCTL_HEALTH_CHECK_DEFAULT_TIMEOUT environment variable.
	DefaultTimeout int

	// MaxConcurrent is the maximum number of concurrent TLS probes.
	// Default: 20.
	// Setting: CERTCTL_HEALTH_CHECK_MAX_CONCURRENT environment variable.
	MaxConcurrent int

	// HistoryRetention controls how long probe history records are kept.
	// Default: 30 days. Older records are purged by the scheduler.
	// Setting: CERTCTL_HEALTH_CHECK_HISTORY_RETENTION environment variable.
	HistoryRetention time.Duration

	// AutoCreate controls whether health checks are auto-created when:
	// - A deployment job completes with verification success
	// - A network scan target has health_check_enabled=true
	// Default: true.
	// Setting: CERTCTL_HEALTH_CHECK_AUTO_CREATE environment variable.
	AutoCreate bool
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

	// Profile selects the ACME certificate profile for newOrder requests.
	// Let's Encrypt supports "tlsserver" (standard TLS) and "shortlived" (6-day certs).
	// Leave empty for the CA's default profile (backward-compatible).
	// Setting: CERTCTL_ACME_PROFILE environment variable.
	Profile string

	// ARIEnabled enables ACME Renewal Information (RFC 9773) support.
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

// ACMEServerConfig is the SERVER-side ACME (RFC 8555 + RFC 9773 ARI)
// configuration. Distinct from ACMEConfig (the consumer-side issuer
// connector that talks UP to Let's Encrypt / pebble). Server uses
// CERTCTL_ACME_SERVER_* prefix throughout to avoid colliding with
// the existing CERTCTL_ACME_* consumer namespace (DIRECTORY_URL /
// PROFILE / CHALLENGE_TYPE / etc.).
//
// Phase 1a wires Enabled / DefaultAuthMode / DefaultProfileID /
// NonceTTL / DirectoryMeta. Order/Authz TTLs + the per-challenge-type
// concurrency caps + DNS01 resolver are reserved fields populated for
// Phases 2/3 — exposing them now keeps the env-var surface stable
// from day one (operators can set CERTCTL_ACME_SERVER_HTTP01_CONCURRENCY
// today; it's a no-op until Phase 3 reads it).
type ACMEServerConfig struct {
	// Enabled is the master toggle. When false, the ACME handler is
	// constructed (so the registry-shape stays stable) but no routes
	// are registered. Operators flip this on after configuring the
	// per-profile auth_mode column on certificate_profiles.
	// Setting: CERTCTL_ACME_SERVER_ENABLED.
	Enabled bool

	// DefaultAuthMode sets the default value of certificate_profiles.acme_auth_mode
	// for NEWLY-created profiles (e.g. via API). Existing profile rows
	// retain whatever value they were created with — per-profile
	// values, once set, override this default. Architecture decision:
	// auth mode is per-profile, not server-wide.
	// Valid: "trust_authenticated" (default) or "challenge".
	// Setting: CERTCTL_ACME_SERVER_DEFAULT_AUTH_MODE.
	DefaultAuthMode string

	// DefaultProfileID, when set, activates the /acme/* shorthand
	// path family — /acme/directory mirrors
	// /acme/profile/<DefaultProfileID>/directory etc. When empty,
	// requests to the shorthand return RFC 7807
	// userActionRequired with a hint pointing at the per-profile
	// path. Single-profile deployments can set this for ergonomic
	// client config; multi-profile deployments leave it empty.
	// Setting: CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID.
	DefaultProfileID string

	// NonceTTL is how long an issued ACME nonce remains valid before
	// the server rejects it as expired. RFC 8555 §6.5.1 allows the
	// server to set any TTL; 5 minutes is the operator-friendly
	// default (clock-skew tolerant without enabling long-replay
	// attacks). Setting: CERTCTL_ACME_SERVER_NONCE_TTL.
	NonceTTL time.Duration

	// OrderTTL is the lifetime of an unfulfilled ACME order. Phase 2
	// reads; Phase 1a reserves the field. Default: 24h.
	// Setting: CERTCTL_ACME_SERVER_ORDER_TTL.
	OrderTTL time.Duration

	// AuthzTTL is the lifetime of an unfulfilled authorization. Phase 2
	// reads; Phase 1a reserves. Default: 24h.
	// Setting: CERTCTL_ACME_SERVER_AUTHZ_TTL.
	AuthzTTL time.Duration

	// HTTP01ConcurrencyMax is the bound on concurrent HTTP-01 validators
	// (semaphore weight). Phase 3 reads; Phase 1a reserves. Default: 10.
	// Setting: CERTCTL_ACME_SERVER_HTTP01_CONCURRENCY.
	HTTP01ConcurrencyMax int

	// DNS01Resolver is the resolver address used by the DNS-01 validator.
	// Phase 3 reads; Phase 1a reserves. Default: "8.8.8.8:53".
	// Setting: CERTCTL_ACME_SERVER_DNS01_RESOLVER.
	DNS01Resolver string

	// DNS01ConcurrencyMax bounds concurrent DNS-01 validators. Default: 10.
	// Setting: CERTCTL_ACME_SERVER_DNS01_CONCURRENCY.
	DNS01ConcurrencyMax int

	// TLSALPN01ConcurrencyMax bounds concurrent TLS-ALPN-01 validators.
	// Default: 10. Setting: CERTCTL_ACME_SERVER_TLSALPN01_CONCURRENCY.
	TLSALPN01ConcurrencyMax int

	// ARIEnabled toggles RFC 9773 ACME Renewal Information surface
	// (the `renewalInfo` directory entry + GET
	// /acme/profile/<id>/renewal-info/<cert-id>). Default: true.
	// Operators wanting Phase-1a-style "directory + nonce + accounts +
	// orders + finalize + challenges only" can flip this off; doing so
	// drops the renewalInfo URL from the directory document so ACME
	// clients fall back to their static renewal scheduler. Phase 4 wires.
	// Setting: CERTCTL_ACME_SERVER_ARI_ENABLED.
	ARIEnabled bool

	// ARIPollInterval is the value the server returns in the Retry-After
	// response header on a 200 ARI response — i.e., the suggested gap
	// between successive ARI polls a client should respect. RFC 9773 §4.2
	// leaves this server-policy. Default: 6h. Tighter intervals (e.g. 1h)
	// suit short-lived certs; looser intervals (24h) suit standard 90-day
	// certs. Setting: CERTCTL_ACME_SERVER_ARI_POLL_INTERVAL.
	ARIPollInterval time.Duration

	// RateLimitOrdersPerHour caps new-order requests per ACME account per
	// rolling hour. 0 disables (no limit). Default: 100. Hits return RFC
	// 7807 + RFC 8555 §6.7 `urn:ietf:params:acme:error:rateLimited` with
	// a Retry-After header. In-memory token-bucket — restart wipes the
	// counter, which is acceptable for orders/hour caps (eventual-
	// consistency anyway). Setting:
	// CERTCTL_ACME_SERVER_RATE_LIMIT_ORDERS_PER_HOUR.
	RateLimitOrdersPerHour int

	// RateLimitConcurrentOrders caps the number of orders an ACME account
	// can have in pending/ready/processing state simultaneously. 0
	// disables. Default: 5. Same Problem shape as the per-hour limit.
	// Setting: CERTCTL_ACME_SERVER_RATE_LIMIT_CONCURRENT_ORDERS.
	RateLimitConcurrentOrders int

	// RateLimitKeyChangePerHour caps account-key rollovers per account
	// per rolling hour. 0 disables. Default: 5 (rollovers should be rare;
	// a flood is an attack signal). Setting:
	// CERTCTL_ACME_SERVER_RATE_LIMIT_KEY_CHANGE_PER_HOUR.
	RateLimitKeyChangePerHour int

	// RateLimitChallengeRespondsPerHour caps challenge-respond requests
	// per challenge per rolling hour. 0 disables. Default: 60 (defends
	// against retry storms from a misbehaving client). Setting:
	// CERTCTL_ACME_SERVER_RATE_LIMIT_CHALLENGE_RESPONDS_PER_HOUR.
	RateLimitChallengeRespondsPerHour int

	// GCInterval is the tick interval for the ACME GC scheduler loop.
	// On each tick the loop sweeps expired nonces, transitions expired
	// pending authzs to `expired`, transitions expired
	// pending/ready/processing orders to `invalid`, and reaps Phase-2
	// atomicity-window orphans (orders without a linked cert when one
	// should exist). 0 disables the loop entirely. Default: 1m. Setting:
	// CERTCTL_ACME_SERVER_GC_INTERVAL.
	GCInterval time.Duration

	// DirectoryMeta is the optional metadata advertised in the directory
	// document per RFC 8555 §7.1.1.
	DirectoryMeta ACMEServerDirectoryMeta
}

// ACMEServerDirectoryMeta holds the optional fields of the directory
// `meta` block. Each is populated from a CERTCTL_ACME_SERVER_*
// env var; an all-empty struct produces an omitempty-suppressed JSON
// `meta` field on the directory.
type ACMEServerDirectoryMeta struct {
	// TermsOfService is a URL pointing to the operator's ToS document.
	// Setting: CERTCTL_ACME_SERVER_TOS_URL.
	TermsOfService string
	// Website is a URL pointing to the operator's homepage.
	// Setting: CERTCTL_ACME_SERVER_WEBSITE.
	Website string
	// CAAIdentities is the list of CAA-record domain values clients
	// should authorize for this server. Setting:
	// CERTCTL_ACME_SERVER_CAA_IDENTITIES (comma-separated).
	CAAIdentities []string
	// ExternalAccountRequired, when true, signals to clients that
	// new-account requires an EAB token (RFC 8555 §7.3.4). Phase 1a
	// advertises but does not enforce; EAB enforcement is a follow-up.
	// Setting: CERTCTL_ACME_SERVER_EAB_REQUIRED.
	ExternalAccountRequired bool
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
// EST RFC 7030 hardening master bundle Phase 1: this type was originally a
// flat single-issuer struct. Real enterprise deployments need to expose
// multiple EST endpoints from one certctl instance — corp-laptop CA, IoT
// CA, WiFi/802.1X CA — each with its own issuer + auth modes + URL path
// (/.well-known/est/<pathID>/). The Profiles slice carries that. Existing
// operators see no behavior change: when Profiles is empty AND the legacy
// single-issuer flat fields below are set, ConfigLoad synthesizes a
// single-element Profiles[0] with PathID="" (which maps to the legacy
// /.well-known/est/ root path).
type ESTConfig struct {
	// Enabled controls whether EST endpoints are available for device enrollment.
	// Default: false (EST disabled). Set to true to enable RFC 7030 endpoints
	// under /.well-known/est/ (cacerts, simpleenroll, simplereenroll, csrattrs).
	Enabled bool

	// IssuerID selects which issuer connector processes EST certificate requests.
	// Default: "iss-local". Legacy single-issuer field; merged into Profiles[0]
	// by mergeESTLegacyIntoProfiles when Profiles is empty.
	IssuerID string

	// ProfileID optionally constrains EST enrollments to a specific certificate profile.
	// Legacy single-issuer field; merged into Profiles[0] when applicable.
	ProfileID string

	// Profiles is the multi-endpoint configuration. Each profile gets its own
	// URL path (/.well-known/est/<PathID>/), its own bound issuer, its own auth
	// modes, and its own per-profile policy knobs (rate limit, server-keygen
	// gate, mTLS bundle, RFC 9266 channel-binding requirement). Population
	// sources, in priority order:
	//
	//   1. Explicit list via CERTCTL_EST_PROFILES (e.g. "corp,iot,wifi").
	//   2. Backward-compat shim: when CERTCTL_EST_PROFILES is unset AND the
	//      legacy flat fields above are populated AND Enabled=true, ConfigLoad
	//      synthesizes a single-element Profiles[0] with PathID="" so
	//      /.well-known/est/ continues to route the same way it did
	//      pre-Phase-1.
	//
	// EST RFC 7030 hardening master bundle Phase 1.
	Profiles []ESTProfileConfig
}

// ESTProfileConfig is one EST endpoint's configuration. Each profile is
// bound to one issuer + one optional certctl CertificateProfile + one set
// of per-profile auth modes (mTLS / HTTP Basic / both). Future phases of
// the hardening bundle wire the additional per-profile fields:
//
//   - Phase 2 reads MTLSEnabled + MTLSClientCATrustBundlePath +
//     ChannelBindingRequired to enable the /.well-known/est-mtls/<PathID>
//     sibling route (mirrors SCEP's /scep-mtls/<PathID> from commit e7a3075).
//   - Phase 3 reads EnrollmentPassword + AllowedAuthModes to enforce HTTP
//     Basic auth on the standard /.well-known/est/<PathID>/ route.
//   - Phase 4 reads RateLimitPerPrincipal24h to apply per-CN+source-IP
//     sliding-window rate limiting (mirrors SCEP/Intune's
//     PerDeviceRateLimiter from internal/scep/intune/rate_limit.go).
//   - Phase 5 reads ServerKeygenEnabled to gate the new /serverkeygen
//     endpoint per RFC 7030 §4.4.
//
// Phase 1 (this commit) lays the FIELD CONTRACTS + per-profile Validate()
// gates so an operator who flips MTLSEnabled=true without supplying the
// bundle path gets a loud refuse-to-start error rather than a silent
// no-op. The actual auth/limit/keygen handlers ship in Phases 2-5.
//
// EST RFC 7030 hardening master bundle Phase 1.
type ESTProfileConfig struct {
	// PathID is the URL segment after /.well-known/est/. Empty string maps
	// to the legacy /.well-known/est/ root for backward compatibility (so
	// existing operators with the flat single-issuer config see no URL
	// change). Non-empty values MUST be a single path-safe slug
	// ([a-z0-9-], no slashes); validated at startup by Config.Validate().
	// Multi-profile deployments typically use short tokens like "corp",
	// "iot", "wifi" — the URL becomes /.well-known/est/corp/cacerts,
	// /.well-known/est/iot/simpleenroll, etc.
	PathID string

	// IssuerID selects which issuer connector this profile's enrollments
	// go through. Must reference a configured issuer. Required (Validate
	// refuses empty IssuerID).
	IssuerID string

	// ProfileID optionally constrains enrollments under this PathID to a
	// specific CertificateProfile. Leave empty to allow the issuer's
	// defaults. When non-empty, profile crypto policy (allowed key
	// algorithms, required EKUs, max TTL) is enforced at enrollment time
	// via service.ValidateCSRAgainstProfile.
	ProfileID string

	// EnrollmentPassword is the per-profile shared secret for HTTP Basic
	// auth on the standard /.well-known/est/<PathID>/ route (Phase 3).
	// Empty value means HTTP Basic auth is NOT required for this profile
	// (mTLS-only or anonymous, depending on AllowedAuthModes). Stored only
	// in process memory; never logged. Constant-time comparison via
	// crypto/subtle.ConstantTimeCompare in the handler.
	EnrollmentPassword string

	// MTLSEnabled gates the sibling /.well-known/est-mtls/<PathID>/ route
	// (Phase 2). When true, the route requires a client cert that chains
	// to one of the certs in MTLSClientCATrustBundlePath. The standard
	// /.well-known/est/<PathID>/ route remains application-layer-auth
	// (HTTP Basic password) so existing clients keep working — mTLS is
	// additive, not replacement.
	//
	// Mirrors SCEP's MTLSEnabled (commit e7a3075). Same defense-in-depth
	// rationale: enterprise procurement teams routinely reject 'shared
	// password authentication' as a checkbox-fail regardless of how
	// strong the password is. This flag wires up a sibling route that
	// adds client-cert auth at the handler layer.
	MTLSEnabled bool

	// MTLSClientCATrustBundlePath is the PEM bundle of CA certs that sign
	// the client (device-bootstrap) certs the operator allows to enroll
	// via the mTLS sibling route. Required when MTLSEnabled is true.
	// Validated at startup by cmd/server/main.go's
	// preflightESTMTLSClientCATrustBundle (Phase 2): file exists, parses
	// as PEM, contains ≥1 cert, none expired.
	MTLSClientCATrustBundlePath string

	// ChannelBindingRequired forces the EST mTLS handler (Phase 2) to
	// require RFC 9266 tls-exporter channel binding in the CSR's CMC
	// id-aa-channelBindings attribute. When true, CSRs without the
	// binding are refused with ErrChannelBindingMissing; mismatched
	// bindings refused with ErrChannelBindingMismatch. Defaults true for
	// new-cert-issuance flows (Phase 2 default), false for re-enrollment
	// where the previous-cert presentation is the trust signal. Operators
	// running clients that don't support RFC 9266 (older libest, etc.)
	// can opt out per-profile.
	//
	// EST RFC 7030 hardening master bundle Phase 0 frozen decision 0.2.
	ChannelBindingRequired bool

	// AllowedAuthModes enumerates which application-layer auth modes
	// this profile accepts. Valid entries: "mtls", "basic". Empty slice
	// means no auth required (the unauthenticated default that EST
	// shipped with at v2.0.66; preserved for backward compat — Validate
	// emits a warning log for empty slices to nudge operators toward
	// explicit opt-in). Phase 2 + 3 read this to enforce per-mode
	// requirements; Phase 1 just validates shape.
	//
	// EST RFC 7030 hardening master bundle Phase 0 frozen decision 0.1.
	AllowedAuthModes []string

	// RateLimitPerPrincipal24h caps enrollments per (CSR.Subject.CN,
	// sourceIP) pair in any rolling 24-hour window. Default 0 (Phase 1
	// preserves the unauthenticated/unlimited default to avoid changing
	// production behavior); Phase 4 will wire this against the extracted
	// internal/ratelimit/SlidingWindowLimiter. Negative values are
	// rejected at Validate time as a config typo.
	//
	// EST RFC 7030 hardening master bundle Phase 1 + Phase 4.
	RateLimitPerPrincipal24h int

	// ServerKeygenEnabled gates the /.well-known/est/<PathID>/serverkeygen
	// endpoint (RFC 7030 §4.4) for this profile. When true, the server
	// generates the keypair on behalf of the client and returns both
	// cert + private key (the latter wrapped in CMS EnvelopedData).
	// Default false. Phase 5 wires the handler; Phase 1 lays the gate
	// + the Validate refusal for ServerKeygenEnabled=true without a
	// CertificateProfile that pins AllowedKeyAlgorithms (the server
	// must know what algorithm to generate).
	//
	// EST RFC 7030 hardening master bundle Phase 5.
	ServerKeygenEnabled bool
}

// SCEPConfig controls the RFC 8894 Simple Certificate Enrollment Protocol server.
//
// SCEP RFC 8894 + Intune master bundle Phase 1.5: this type was originally a
// single flat struct with one IssuerID + one RA pair + one challenge password
// (the shape of v2.0.x). Real enterprise deployments need to expose multiple
// SCEP endpoints from one certctl instance — corp-laptop CA, server CA, IoT
// CA — each with its own issuer + RA pair + challenge password + URL path
// (/scep/<pathID>). The Profiles slice carries that. Existing operators see
// no behavior change: when Profiles is empty AND the legacy single-profile
// fields below are set, ConfigLoad synthesizes a single-element Profiles[0]
// with PathID="" (which maps to the legacy /scep root path).
type SCEPConfig struct {
	// Enabled controls whether SCEP endpoints are available for device enrollment.
	// Default: false (SCEP disabled). Set to true to enable SCEP endpoints under /scep/.
	Enabled bool

	// Profiles is the multi-endpoint configuration. Each profile gets its own
	// URL path (/scep/<PathID>), its own RA cert + key, its own challenge
	// password, and its own bound issuer. Population sources, in priority order:
	//
	//   1. Explicit list via CERTCTL_SCEP_PROFILES (e.g. "corp,iot,server").
	//   2. Backward-compat shim: when CERTCTL_SCEP_PROFILES is unset AND the
	//      legacy flat fields below have ChallengePassword OR RACertPath set,
	//      ConfigLoad synthesizes a single-element Profiles[0] with PathID=""
	//      so /scep continues to route the same way it did pre-Phase-1.5.
	//
	// Validate() iterates Profiles and refuses to boot if any profile is
	// malformed (empty ChallengePassword, missing RA pair, invalid PathID).
	// Each profile's ChallengePassword + RA pair are independently mandatory
	// — the profile-load shim never silently borrows from a sibling profile.
	Profiles []SCEPProfileConfig

	// Legacy single-profile fields — preserved for backward compatibility. New
	// operators should populate Profiles directly via the indexed env-var form.
	// These fields are merged into Profiles[0] by ConfigLoad when Profiles is
	// empty AND any of these fields are non-zero.

	// IssuerID selects which issuer connector processes SCEP certificate requests
	// for the legacy single-profile config. Default: "iss-local". Must reference a
	// configured issuer.
	IssuerID string

	// ProfileID optionally constrains SCEP enrollments to a specific certificate profile
	// for the legacy single-profile config. Leave empty to allow SCEP to use any
	// configured issuer's defaults.
	ProfileID string

	// ChallengePassword is the shared secret used to authenticate SCEP enrollment requests.
	// Clients include this in the PKCS#10 CSR challengePassword attribute.
	//
	// REQUIRED when Enabled is true. Config.Validate() below refuses to start the
	// server if SCEP is enabled and this value is empty (H-2, CWE-306): post-M-001
	// under option (D), the /scep endpoint rides the no-auth middleware chain per
	// RFC 8894 §3.2, so the challenge password is the sole application-layer
	// authentication boundary for SCEP enrollment. An empty shared secret would
	// allow any client that can reach /scep to enroll a CSR against the configured
	// issuer. The service-layer PKCSReq path also rejects this configuration
	// defense-in-depth.
	//
	// Legacy single-profile field; merged into Profiles[0].ChallengePassword by
	// ConfigLoad when Profiles is empty.
	ChallengePassword string

	// RACertPath is the path to a PEM-encoded RA (Registration Authority)
	// certificate used by the RFC 8894 SCEP path. SCEP clients encrypt their
	// PKCS#10 CSR to this cert's public key (via the EnvelopedData wrapper, RFC
	// 8894 §3.2.2). The certctl server uses RAKeyPath to decrypt inbound
	// EnvelopedData and to sign outbound CertRep PKIMessage signerInfo (RFC
	// 8894 §3.3.2).
	//
	// Required when Enabled is true; Config.Validate() refuses to start without
	// it. Without an RA pair the new RFC 8894 path silently falls through to
	// the MVP raw-CSR path on every request and the operator's intent is
	// unclear — fail loud at startup instead.
	//
	// Generation: a self-signed RA cert with subject "CN=<your-ca-id>-RA" and
	// the id-kp-emailProtection / id-kp-cmcRA EKU is sufficient. The RA cert
	// SHOULD be the same cert returned by GetCACert (RFC 8894 §3.5.1) so
	// clients encrypt to a key the server can decrypt with. See
	// docs/legacy-est-scep.md for the openssl recipe.
	RACertPath string

	// RAKeyPath is the path to the PEM-encoded private key matching RACertPath.
	// File MUST be mode 0600 (owner read/write only); preflight refuses to load
	// a world-readable RA key as defense-in-depth against credential leak. The
	// server only ever reads this file at startup; rotation requires a restart
	// (per the existing CERTCTL_TLS_CERT_PATH precedent in cmd/server/tls.go).
	//
	// Legacy single-profile field; merged into Profiles[0].RAKeyPath by
	// ConfigLoad when Profiles is empty.
	RAKeyPath string
}

// SCEPProfileConfig is one SCEP endpoint's configuration. Each profile is
// bound to one issuer + one optional certctl CertificateProfile + one RA
// pair + one challenge password (the per-profile Intune trust anchor lands
// here in Phase 8 of the master bundle).
//
// Multi-profile motivation: a real enterprise deployment exposes distinct
// SCEP endpoints to distinct fleets — corp-laptop CA bound to one issuer
// with one challenge password; IoT CA bound to a different issuer with a
// different challenge password — so a single set of credentials can never
// enroll across CA boundaries by accident. Each SCEPProfileConfig drives
// a separate handler + service instance built at server startup.
type SCEPProfileConfig struct {
	// PathID is the URL segment after /scep/. Empty string maps to the legacy
	// /scep root for backward compatibility (so existing operators with the
	// flat single-profile config see no URL change). Non-empty values MUST
	// be a single path-safe slug ([a-z0-9-], no slashes); validated at
	// startup by Config.Validate(). Multi-profile deployments typically use
	// short tokens like "corp", "iot", "server" — the URL becomes
	// /scep/corp, /scep/iot, /scep/server.
	PathID string

	// IssuerID selects which issuer connector this profile's enrollments go
	// through. Must reference a configured issuer.
	IssuerID string

	// ProfileID optionally constrains enrollments under this PathID to a
	// specific CertificateProfile. Leave empty to allow the issuer's defaults.
	ProfileID string

	// ChallengePassword is the per-profile shared secret. Same constant-time
	// compare semantics as the flat field; empty value at validate time fails
	// the boot.
	ChallengePassword string

	// RACertPath / RAKeyPath are the per-profile RA pair used by the RFC 8894
	// EnvelopedData decryption + CertRep signing path. Same preflight semantics
	// as the legacy flat fields (file existence, key mode 0600, cert/key
	// match, expiry, RSA-or-ECDSA alg).
	RACertPath string
	RAKeyPath  string

	// MTLSEnabled gates the sibling `/scep-mtls/<PathID>` route. When true,
	// the route requires a client cert that chains to one of the certs in
	// MTLSClientCATrustBundlePath. The standard `/scep[/<PathID>]` route
	// remains application-layer-auth (challenge password) so existing
	// clients keep working — mTLS is additive, not replacement.
	//
	// SCEP RFC 8894 + Intune master bundle Phase 6.5: enterprise procurement
	// teams routinely reject 'shared password authentication' as a checkbox-
	// fail regardless of how strong the password is. This flag wires up a
	// sibling route that adds client-cert auth at the handler layer AND keeps
	// the challenge password (defense in depth, not replacement). Devices
	// present a bootstrap cert from a trusted CA (e.g. a manufacturing-time
	// cert), then SCEP-enroll for their long-lived cert. Same model Apple's
	// MDM and Cisco's BRSKI use.
	MTLSEnabled bool

	// MTLSClientCATrustBundlePath is the PEM bundle of CA certs that sign
	// the client (device-bootstrap) certs the operator allows to enroll.
	// Required when MTLSEnabled is true. Operators with multiple bootstrap
	// CAs concatenate them. Validated at startup by
	// `cmd/server/main.go::preflightSCEPMTLSTrustBundle` — file exists,
	// parses as PEM, contains ≥1 cert, none expired.
	MTLSClientCATrustBundlePath string

	// Intune is the per-profile Microsoft Intune Certificate Connector
	// integration block. When Enabled is false (default), this profile only
	// honors the static ChallengePassword; when true, requests with an
	// Intune-shaped challenge password (length + dot-count heuristic) are
	// routed to the Intune dynamic-challenge validator.
	//
	// SCEP RFC 8894 + Intune master bundle Phase 8.8: per-profile dispatch
	// is what makes the heterogeneous-fleet story work — an operator
	// running corp-laptops via Intune AND IoT devices via static challenge
	// configures Intune-mode on the corp profile only; the IoT profile's
	// PKCSReq path skips the Intune dispatcher entirely.
	Intune SCEPIntuneProfileConfig
}

// SCEPIntuneProfileConfig is the per-profile Microsoft Intune Certificate
// Connector integration sub-block on SCEPProfileConfig.
//
// SCEP RFC 8894 + Intune master bundle Phase 8.1.
//
// All fields here are populated from CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_*
// env vars (e.g. CERTCTL_SCEP_PROFILE_CORP_INTUNE_ENABLED=true). Per-profile
// overrides means an operator with two Intune-backed profiles (corp + iot,
// say) can pin distinct Connectors + audiences + rate limits per fleet.
type SCEPIntuneProfileConfig struct {
	// Enabled gates the Intune dynamic-challenge validation path. When
	// false (default), this profile honors only the static ChallengePassword.
	// When true, ConnectorCertPath becomes a required boot gate.
	Enabled bool

	// ConnectorCertPath is the filesystem path to a PEM bundle of one or
	// more Microsoft Intune Certificate Connector signing certs. Required
	// when Enabled=true. Reloaded on SIGHUP via the per-profile
	// TrustAnchorHolder wired in cmd/server/main.go.
	ConnectorCertPath string

	// Audience is the expected "aud" claim value in the Intune challenge —
	// typically the public SCEP endpoint URL the Connector is configured to
	// call (e.g. "https://certctl.example.com/scep/corp"). Defaults to
	// empty (audience check disabled) for proxy / load-balancer scenarios
	// where the URL the Connector saw isn't the URL we see; operators
	// who pin a public URL here gain defense-in-depth against challenge
	// re-use across endpoints.
	Audience string

	// ChallengeValidity caps the maximum age of an Intune challenge, on
	// top of the challenge's own iat/exp claims. Default 60 minutes per
	// Microsoft's published Connector defaults — operators may want a
	// stricter cap to reduce the replay-window exposure on a stolen
	// challenge. Zero means "use Connector's exp claim only" (no extra cap).
	ChallengeValidity time.Duration

	// PerDeviceRateLimit24h caps the number of enrollments per
	// (claim.Subject, claim.Issuer) pair in any rolling 24-hour window.
	// Default 3 (covers legitimate first-cert + recovery + post-wipe
	// re-enrollment, blocks bulk-enumeration from a compromised Connector
	// signing key). Zero means "unlimited" (defense-in-depth disabled;
	// not recommended for production).
	PerDeviceRateLimit24h int

	// ClockSkewTolerance widens the iat/exp validation window by
	// ±|tolerance| to absorb modest clock drift between the Microsoft
	// Intune Certificate Connector and the certctl host. Default 60s
	// per master prompt §15 ("known hazards"). Operators on tightly
	// time-synced fleets can set this to zero to enforce strict
	// iat/exp checks; operators on loosely synced fleets (e.g. field
	// devices with no NTP) may raise to 5m. Validate() refuses any
	// tolerance ≥ ChallengeValidity (which would make the per-profile
	// validity cap meaningless). Source env var:
	// CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CLOCK_SKEW_TOLERANCE.
	ClockSkewTolerance time.Duration
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
	Host        string          // Server host (default: 127.0.0.1). Set via CERTCTL_SERVER_HOST.
	Port        int             // Server port (default: 8080). Set via CERTCTL_SERVER_PORT.
	MaxBodySize int64           // Maximum request body size in bytes (default: 1MB). Set via CERTCTL_MAX_BODY_SIZE.
	TLS         ServerTLSConfig // HTTPS-only TLS configuration. Both CertPath and KeyPath are required.

	// AuditFlushTimeoutSeconds is the budget (in seconds) main.go gives the
	// audit middleware to drain in-flight recordings during graceful
	// shutdown. Bundle-5 / Audit M-011: pre-Bundle-5 this was hard-coded
	// 30s, which dropped events silently in high-volume environments
	// because the same context governed HTTP server shutdown + audit
	// flush. Post-Bundle-5: configurable; default 30s preserves prior
	// behaviour. WARN-log on deadline exceeded, but never exit hard.
	// Setting: CERTCTL_AUDIT_FLUSH_TIMEOUT_SECONDS environment variable.
	AuditFlushTimeoutSeconds int
}

// ServerTLSConfig holds the server-side TLS material.
//
// The control plane is HTTPS-only as of the HTTPS-everywhere milestone
// (§3 locked decisions: no `http` mode, no dual-listener, TLS 1.3 only).
// Both CertPath and KeyPath are required; an empty value causes
// Config.Validate() to return a fail-loud error and the server refuses
// to start. There is no plaintext HTTP fallback, no N-release migration
// bridge, and no auto-generated self-signed cert — operators either
// supply a cert on disk (docker-compose init container, operator-managed
// file, cert-manager mount) or the process exits non-zero.
type ServerTLSConfig struct {
	// CertPath is the filesystem path to the server's PEM-encoded X.509
	// certificate. Set via CERTCTL_SERVER_TLS_CERT_PATH. Required.
	CertPath string

	// KeyPath is the filesystem path to the server's PEM-encoded private
	// key that signs CertPath. Set via CERTCTL_SERVER_TLS_KEY_PATH. Required.
	KeyPath string
}

// DatabaseConfig contains database connection configuration.
type DatabaseConfig struct {
	URL            string
	MaxConnections int
	MigrationsPath string

	// DemoSeed, when true, makes the server apply
	// `<MigrationsPath>/seed_demo.sql` after the baseline `seed.sql`. Set
	// via CERTCTL_DEMO_SEED. The compose demo overlay
	// (deploy/docker-compose.demo.yml) sets this to keep the demo path
	// alive after U-3 dropped initdb-mounted seed files. The seed file
	// uses ON CONFLICT (id) DO NOTHING so re-running on a populated
	// database is safe; missing-file is a no-op (returns nil) so a
	// minimal-image deploy that strips seed_demo.sql still boots cleanly.
	DemoSeed bool
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

	// RenewalConcurrency caps the number of concurrent renewal/issuance/
	// deployment goroutines launched per job-processor tick. Default 25 —
	// high enough to make use of HTTP/1.1 connection reuse against an
	// upstream CA, low enough to stay under typical per-customer rate
	// limits. Operators with permissive upstream limits and large fleets
	// (>10k certs) can bump to 100; operators with strict limits or
	// async-CA-heavy fleets should keep at 25 or lower.
	//
	// Values ≤ 0 fall back to 1 (sequential) — fail-safe rather than
	// panicking on semaphore.NewWeighted(0) semantics.
	//
	// Closes the #9 acquisition-readiness blocker from the 2026-05-01
	// issuer coverage audit. Pre-fix the per-tick fan-out had no cap,
	// so a 5k-cert sweep launched 5k in-flight HTTP calls to upstream
	// CAs and tripped DigiCert/Entrust/Sectigo rate limits.
	//
	// Setting: CERTCTL_RENEWAL_CONCURRENCY environment variable.
	RenewalConcurrency int

	// AgentHealthCheckInterval is how often the scheduler checks agent heartbeats.
	// Default: 2 minutes. Minimum: 1 second. Marks agents offline if no recent heartbeat.
	// Setting: CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL environment variable.
	AgentHealthCheckInterval time.Duration

	// NotificationProcessInterval is how often the scheduler processes pending notifications.
	// Default: 1 minute. Minimum: 1 second. Sends notifications to Slack, Teams, PagerDuty, etc.
	// Setting: CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL environment variable.
	NotificationProcessInterval time.Duration

	// NotificationRetryInterval is how often the scheduler retries failed
	// notifications whose retry_count is below the service-layer 5-attempt
	// DLQ budget. Default: 2 minutes. Minimum: 1 second. Mirrors the I-001
	// RetryInterval knob: transitions eligible Failed notifications whose
	// next_retry_at has arrived back to Pending so the notification processor
	// picks them up on its next tick (closes coverage gap I-005 — HEAD had
	// no retry path for transient SMTP/webhook failures and notifications
	// stayed Failed forever).
	// Setting: CERTCTL_NOTIFICATION_RETRY_INTERVAL environment variable.
	NotificationRetryInterval time.Duration

	// RetryInterval is how often the scheduler retries failed jobs whose Attempts
	// counter is below MaxAttempts. Default: 5 minutes. Minimum: 1 second.
	// Transitions eligible Failed jobs back to Pending so the job processor can
	// pick them up again (closes coverage gap I-001 — JobService.RetryFailedJobs
	// had no caller prior to this loop being wired).
	// Setting: CERTCTL_SCHEDULER_RETRY_INTERVAL environment variable.
	RetryInterval time.Duration

	// JobTimeoutInterval is how often the reaper loop sweeps AwaitingCSR and
	// AwaitingApproval jobs for TTL expiration. Default: 10 minutes. Minimum: 1
	// second. Timed-out jobs are transitioned to Failed with a descriptive error
	// message; I-001's retry loop then auto-promotes eligible Failed jobs back
	// to Pending (closes coverage gap I-003).
	// Setting: CERTCTL_JOB_TIMEOUT_INTERVAL environment variable.
	JobTimeoutInterval time.Duration

	// AwaitingCSRTimeout is the maximum age an AwaitingCSR job can remain in
	// that state before the reaper transitions it to Failed. Default: 24 hours.
	// An agent that hasn't submitted a CSR within this window is presumed
	// unreachable. Minimum: 1 second.
	// Setting: CERTCTL_JOB_AWAITING_CSR_TIMEOUT environment variable.
	AwaitingCSRTimeout time.Duration

	// AwaitingApprovalTimeout is the maximum age an AwaitingApproval job can
	// remain in that state before the reaper transitions it to Failed. Default:
	// 168 hours (7 days). Reviewers who haven't approved within this window
	// force the renewal to fail loudly rather than silently stall. Minimum: 1
	// second.
	// Setting: CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT environment variable.
	AwaitingApprovalTimeout time.Duration

	// ShortLivedExpiryCheckInterval is how often the scheduler scans
	// short-lived certificates and marks expired rows as Expired. Default:
	// 30 seconds (matches the in-memory default in scheduler.NewScheduler).
	// C-1 closure (cat-g-7e38f9708e20 + diff-10xmain-2bf4a0a60388):
	// pre-C-1 the setter scheduler.SetShortLivedExpiryCheckInterval was
	// defined + tested but never called from cmd/server/main.go, so the
	// 30-second default was effectively hardcoded. Operators who needed
	// to tune the cadence (e.g. a high-churn short-lived cert tenant)
	// had no path. Post-C-1 main.go wires this knob.
	// Setting: CERTCTL_SHORT_LIVED_EXPIRY_CHECK_INTERVAL environment variable.
	ShortLivedExpiryCheckInterval time.Duration

	// CRLGenerationInterval is how often the scheduler pre-generates
	// CRLs into the crl_cache table. The /.well-known/pki/crl/{issuer_id}
	// HTTP endpoint reads from this cache instead of regenerating per
	// request. Default: 1 hour.
	// Setting: CERTCTL_CRL_GENERATION_INTERVAL environment variable.
	// Bundle CRL/OCSP-Responder Phase 3.
	CRLGenerationInterval time.Duration

	// OCSPRateLimitPerIPMin is the per-source-IP cap on OCSP requests
	// per minute. Defaults to 1000 (production hardening II Phase 3
	// frozen decision 0.5). Zero disables the limit.
	// Setting: CERTCTL_OCSP_RATE_LIMIT_PER_IP_MIN environment variable.
	OCSPRateLimitPerIPMin int

	// CertExportRateLimitPerActorHr is the per-actor cap on cert-export
	// requests per hour. Defaults to 50 (production hardening II Phase
	// 3 frozen decision 0.6). Zero disables the limit.
	// Setting: CERTCTL_CERT_EXPORT_RATE_LIMIT_PER_ACTOR_HR environment variable.
	CertExportRateLimitPerActorHr int

	// DeployBackupRetention is the default backup retention applied
	// to every connector's deploy.Plan when the per-target config
	// doesn't override. Defaults to 3 (deploy-hardening I frozen
	// decision 0.2). Set to -1 to disable backups entirely (rollback
	// becomes impossible — documented foot-gun).
	// Setting: CERTCTL_DEPLOY_BACKUP_RETENTION environment variable.
	DeployBackupRetention int

	// K8sDeployKubeletSyncTimeout is how long the k8ssecret connector
	// waits for kubelet sync (Pod.Status.ContainerStatuses indicating
	// the new Secret has been mounted) after a Secret update before
	// timing out the post-deploy verify. Defaults to 60s.
	// Setting: CERTCTL_K8S_DEPLOY_KUBELET_SYNC_TIMEOUT environment variable.
	// Deploy-hardening I Phase 9.
	K8sDeployKubeletSyncTimeout time.Duration
}

// ApprovalConfig contains issuance approval-workflow runtime configuration.
// Rank 7 of the 2026-05-03 Infisical deep-research deliverable.
type ApprovalConfig struct {
	// BypassEnabled short-circuits the approval workflow — every
	// RequestApproval call auto-approves with decidedBy="system-bypass"
	// (see domain.ApprovalActorSystemBypass) and emits an audit row with
	// ActorType=System. Used by dev / CI to keep renewal-scheduler tests
	// fast without standing up an approver.
	//
	// **PRODUCTION DEPLOYS MUST LEAVE THIS FALSE.** A simple SQL query
	// detects misuse:
	//
	//   SELECT count(*) FROM audit_events WHERE actor = 'system-bypass';
	//
	// returns zero in production and a high count in dev. The bypass
	// also emits a typed audit event (action=approval_bypassed) so
	// compliance auditors can pattern-match without scanning JSON
	// metadata.
	//
	// Setting: CERTCTL_APPROVAL_BYPASS environment variable. Default: false.
	BypassEnabled bool
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

// NamedAPIKey represents a single named API key with an optional admin flag.
// Named keys allow real actor attribution in the audit trail (M-002) and provide
// the admin-gate basis for privileged endpoints like bulk revocation (M-003).
type NamedAPIKey struct {
	// Name is the identifier for the key (alphanumeric, hyphens, underscores).
	// This value is recorded as the actor on every audit event the key authenticates.
	Name string
	// Key is the raw API-key secret the client presents as `Authorization: Bearer <key>`.
	Key string
	// Admin controls whether the key has admin privileges (bulk revocation, etc.).
	Admin bool
}

// AuthType is the discriminator for the API auth middleware shape. The
// string alias preserves env-var roundtrip (the value flows through getEnv
// as a plain string) while giving us a typed surface for switches and
// validation. Use the named constants below rather than string literals
// so future enum additions/removals are caught at compile time.
//
// G-1 (P1): the pre-G-1 validAuthTypes map literal accepted "jwt" with no
// JWT middleware behind it (silent auth downgrade — the configured type
// was logged as "jwt" but every request routed through the api-key bearer
// middleware regardless). Operators who set CERTCTL_AUTH_TYPE=jwt thought
// they had JWT auth; they didn't. The typed alias + ValidAuthTypes()
// helper make the allowed set the single source of truth across config
// validation, the runtime defense-in-depth switch in main.go, and the
// helm-chart template guard (`certctl.validateAuthType`).
type AuthType string

const (
	// AuthTypeAPIKey routes requests through the api-key bearer middleware.
	// CERTCTL_AUTH_SECRET (or CERTCTL_API_KEYS_NAMED) is required.
	AuthTypeAPIKey AuthType = "api-key"

	// AuthTypeNone disables authentication entirely. Development only —
	// the server logs a loud Warn at startup. Operators who need
	// JWT/OIDC/mTLS run an authenticating gateway (oauth2-proxy / Envoy
	// ext_authz / Traefik ForwardAuth / Pomerium) in front of certctl
	// and set this value on the upstream certctl process. See
	// docs/architecture.md "Authenticating-gateway pattern".
	AuthTypeNone AuthType = "none"
)

// ValidAuthTypes returns the allowed CERTCTL_AUTH_TYPE values. The set is
// intentionally narrow — JWT was accepted pre-G-1 with no middleware
// implementation behind it. Single source of truth referenced by the
// validator below, the runtime guard in cmd/server/main.go, the helm
// chart template (`certctl.validateAuthType`), and the property test in
// config_test.go that pins "jwt" out of the slice forever.
func ValidAuthTypes() []AuthType {
	return []AuthType{AuthTypeAPIKey, AuthTypeNone}
}

// AuthConfig contains authentication configuration.
type AuthConfig struct {
	// Type sets the authentication mechanism for the REST API.
	// Valid values: "api-key" (default, production) and "none" (development
	// only — disables authentication on the API and logs a loud Warn at
	// startup). For JWT/OIDC, run an authenticating gateway (oauth2-proxy /
	// Envoy / Traefik ForwardAuth / Pomerium) in front of certctl and set
	// CERTCTL_AUTH_TYPE=none on the upstream — see docs/architecture.md
	// "Authenticating-gateway pattern" and docs/upgrade-to-v2-jwt-removal.md.
	// Setting: CERTCTL_AUTH_TYPE environment variable. Default: "api-key".
	// Use the AuthType constants (AuthTypeAPIKey / AuthTypeNone) for typed
	// comparisons; the field stays `string` to preserve env-var roundtrip
	// shape used by getEnv() and downstream Helm/compose interpolation.
	Type string

	// Secret is the legacy authentication secret (comma-separated API keys).
	// DEPRECATED in favor of NamedKeys — retained for backward compatibility.
	// When NamedKeys is empty and Secret is set, each comma-separated key is
	// registered as a synthesized named key (legacy-key-0, legacy-key-1, ...)
	// with actor attribution defaulting to "legacy-key-<index>".
	// Setting: CERTCTL_AUTH_SECRET environment variable.
	Secret string

	// NamedKeys is the parsed set of named API keys. Populated from
	// CERTCTL_API_KEYS_NAMED via ParseNamedAPIKeys during Load(). When
	// non-empty, this takes precedence over the legacy Secret field.
	// Setting: CERTCTL_API_KEYS_NAMED="name1:key1,name2:key2:admin"
	NamedKeys []NamedAPIKey

	// AgentBootstrapToken is the pre-shared secret enforced on the agent
	// registration endpoint (POST /api/v1/agents). Bundle-5 / Audit H-007 /
	// CWE-306 + CWE-288: pre-Bundle-5, any host with network reach to the
	// server could self-register an agent and start polling for work — no
	// shared secret required. Post-Bundle-5: when this field is non-empty,
	// the registration handler requires `Authorization: Bearer <token>`
	// (constant-time comparison via crypto/subtle.ConstantTimeCompare); 401
	// on missing/wrong/malformed.
	//
	// Backwards compatibility: when empty (the v2.0.x default), the server
	// logs a startup WARN announcing the v2.2.0 deprecation — the field
	// will become required in v2.2.0 and unset will fail-loud — and accepts
	// registrations as today. Existing demo deploys that don't set it keep
	// working through v2.1.x.
	//
	// Generation guidance: `openssl rand -hex 32` (256-bit entropy).
	// Setting: CERTCTL_AGENT_BOOTSTRAP_TOKEN environment variable.
	AgentBootstrapToken string
}

// RateLimitConfig contains rate limiting configuration.
//
// Bundle B / Audit M-025 (OWASP ASVS L2 §11.2.1): pre-bundle the rate
// limiter was global (a single token bucket shared across every request);
// post-bundle it is per-key with separate budgets for IP-keyed and
// user-keyed buckets. RPS / BurstSize are PER-KEY budgets.
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is enforced on API endpoints.
	// Default: true. Set to false to disable rate limits (not recommended for production).
	// Setting: CERTCTL_RATE_LIMIT_ENABLED environment variable.
	Enabled bool

	// RPS is the target requests per second allowed PER KEY (token bucket
	// rate). For unauthenticated callers the key is the source IP; for
	// authenticated callers the key is the API-key name (UserKey context
	// value populated by NewAuthWithNamedKeys).
	// Default: 50. Higher values allow burst throughput; lower values restrict load.
	// Setting: CERTCTL_RATE_LIMIT_RPS environment variable.
	RPS float64

	// BurstSize is the maximum number of requests allowed in a single burst.
	// Default: 100. Allows clients to exceed RPS briefly when BurstSize tokens available.
	// Must be at least as large as RPS. Higher = more lenient burst handling.
	// Setting: CERTCTL_RATE_LIMIT_BURST environment variable.
	BurstSize int

	// PerUserRPS overrides RPS for authenticated callers. When zero, RPS is
	// used for both keying dimensions. Set this higher than RPS to grant
	// authenticated clients a more generous budget than anonymous probes.
	// Default: 0 (use RPS).
	// Setting: CERTCTL_RATE_LIMIT_PER_USER_RPS environment variable.
	PerUserRPS float64

	// PerUserBurstSize overrides BurstSize for authenticated callers. When
	// zero, BurstSize is used. Default: 0 (use BurstSize).
	// Setting: CERTCTL_RATE_LIMIT_PER_USER_BURST environment variable.
	PerUserBurstSize int
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
			// HTTPS-everywhere milestone §2.1: both paths REQUIRED. Empty defaults
			// are intentional so Validate() emits a fail-loud error pointing at
			// docs/tls.md rather than silently binding plaintext HTTP.
			TLS: ServerTLSConfig{
				CertPath: getEnv("CERTCTL_SERVER_TLS_CERT_PATH", ""),
				KeyPath:  getEnv("CERTCTL_SERVER_TLS_KEY_PATH", ""),
			},
			// Bundle-5 / M-011: configurable shutdown audit-flush budget.
			// Default 30s preserves pre-Bundle-5 behaviour.
			AuditFlushTimeoutSeconds: getEnvInt("CERTCTL_AUDIT_FLUSH_TIMEOUT_SECONDS", 30),
		},
		Database: DatabaseConfig{
			URL:            getEnv("CERTCTL_DATABASE_URL", "postgres://localhost/certctl"),
			MaxConnections: getEnvInt("CERTCTL_DATABASE_MAX_CONNS", 25),
			MigrationsPath: getEnv("CERTCTL_DATABASE_MIGRATIONS_PATH", "./migrations"),
			DemoSeed:       getEnvBool("CERTCTL_DEMO_SEED", false),
		},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval: getEnvDuration("CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL", 1*time.Hour),
			JobProcessorInterval: getEnvDuration("CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL", 30*time.Second),
			// Audit fix #9 — per-tick concurrency cap on the renewal/issuance/
			// deployment goroutine fan-out. ≤0 → 1 (sequential).
			RenewalConcurrency:          getEnvInt("CERTCTL_RENEWAL_CONCURRENCY", 25),
			AgentHealthCheckInterval:    getEnvDuration("CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL", 2*time.Minute),
			NotificationProcessInterval: getEnvDuration("CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL", 1*time.Minute),
			// I-005: retry sweep for failed notifications. Mirrors RetryInterval
			// (I-001 job retry) but scoped to the notification DLQ machinery.
			// Default 2 minutes — fast enough to absorb transient SMTP/webhook
			// blips, slow enough to respect the service-layer 5-attempt budget
			// without hammering external notifier endpoints.
			NotificationRetryInterval: getEnvDuration("CERTCTL_NOTIFICATION_RETRY_INTERVAL", 2*time.Minute),
			RetryInterval:             getEnvDuration("CERTCTL_SCHEDULER_RETRY_INTERVAL", 5*time.Minute),
			JobTimeoutInterval:        getEnvDuration("CERTCTL_JOB_TIMEOUT_INTERVAL", 10*time.Minute),
			AwaitingCSRTimeout:        getEnvDuration("CERTCTL_JOB_AWAITING_CSR_TIMEOUT", 24*time.Hour),
			AwaitingApprovalTimeout:   getEnvDuration("CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT", 168*time.Hour),
			// C-1 closure: matches the in-memory default at
			// internal/scheduler/scheduler.go:145 (30 * time.Second).
			ShortLivedExpiryCheckInterval: getEnvDuration("CERTCTL_SHORT_LIVED_EXPIRY_CHECK_INTERVAL", 30*time.Second),
			// CRL/OCSP-Responder Phase 3: pre-generation cadence.
			// Default 1h matches the in-scheduler default; relying-party
			// CRL refresh expectations under RFC 5280 are typically
			// hourly to daily, so 1h gives operators plenty of margin.
			CRLGenerationInterval:         getEnvDuration("CERTCTL_CRL_GENERATION_INTERVAL", 1*time.Hour),
			OCSPRateLimitPerIPMin:         getEnvInt("CERTCTL_OCSP_RATE_LIMIT_PER_IP_MIN", 1000),
			CertExportRateLimitPerActorHr: getEnvInt("CERTCTL_CERT_EXPORT_RATE_LIMIT_PER_ACTOR_HR", 50),
			// Deploy-hardening I (frozen decisions 0.2 + Phase 9).
			DeployBackupRetention:       getEnvInt("CERTCTL_DEPLOY_BACKUP_RETENTION", 3),
			K8sDeployKubeletSyncTimeout: getEnvDuration("CERTCTL_K8S_DEPLOY_KUBELET_SYNC_TIMEOUT", 60*time.Second),
		},
		Log: LogConfig{
			Level:  getEnv("CERTCTL_LOG_LEVEL", "info"),
			Format: getEnv("CERTCTL_LOG_FORMAT", "json"),
		},
		Auth: AuthConfig{
			Type:   getEnv("CERTCTL_AUTH_TYPE", "api-key"),
			Secret: getEnv("CERTCTL_AUTH_SECRET", ""),
			// NamedKeys is populated from CERTCTL_API_KEYS_NAMED below so Load()
			// can surface parse errors alongside other config errors.

			// Bundle-5 / Audit H-007: agent-registration bootstrap secret.
			// Empty (default) = warn-mode pass-through; v2.2.0 will require it.
			AgentBootstrapToken: getEnv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", ""),
		},
		RateLimit: RateLimitConfig{
			Enabled:          getEnvBool("CERTCTL_RATE_LIMIT_ENABLED", true),
			RPS:              getEnvFloat("CERTCTL_RATE_LIMIT_RPS", 50),
			BurstSize:        getEnvInt("CERTCTL_RATE_LIMIT_BURST", 100),
			PerUserRPS:       getEnvFloat("CERTCTL_RATE_LIMIT_PER_USER_RPS", 0),
			PerUserBurstSize: getEnvInt("CERTCTL_RATE_LIMIT_PER_USER_BURST", 0),
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
			SlackUsername:       getEnv("CERTCTL_SLACK_USERNAME", "certctl"),
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
			// EST RFC 7030 hardening Phase 1: multi-profile dispatch. When
			// CERTCTL_EST_PROFILES is set (e.g. "corp,iot,wifi"), each name
			// expands to per-profile env vars CERTCTL_EST_PROFILE_<NAME>_*.
			// When unset, the legacy single-issuer flat fields above are
			// merged into Profiles[0] by mergeESTLegacyIntoProfiles below.
			Profiles: loadESTProfilesFromEnv(),
		},
		SCEP: SCEPConfig{
			Enabled:           getEnvBool("CERTCTL_SCEP_ENABLED", false),
			IssuerID:          getEnv("CERTCTL_SCEP_ISSUER_ID", "iss-local"),
			ProfileID:         getEnv("CERTCTL_SCEP_PROFILE_ID", ""),
			ChallengePassword: getEnv("CERTCTL_SCEP_CHALLENGE_PASSWORD", ""),
			// SCEP RFC 8894 Phase 1: RA cert + key for the EnvelopedData /
			// signerInfo path. Required when Enabled is true (Validate() refuse
			// + cmd/server/main.go::preflightSCEPRACertKey). Loaded from
			// CERTCTL_SCEP_RA_CERT_PATH / CERTCTL_SCEP_RA_KEY_PATH per the
			// existing CERTCTL_SCEP_* prefix convention.
			RACertPath: getEnv("CERTCTL_SCEP_RA_CERT_PATH", ""),
			RAKeyPath:  getEnv("CERTCTL_SCEP_RA_KEY_PATH", ""),
			// SCEP RFC 8894 Phase 1.5: multi-profile dispatch. When
			// CERTCTL_SCEP_PROFILES is set (e.g. "corp,iot"), each name
			// expands to per-profile env vars CERTCTL_SCEP_PROFILE_<NAME>_*.
			// When unset, the legacy single-profile flat fields above are
			// merged into Profiles[0] by mergeSCEPLegacyIntoProfiles below.
			Profiles: loadSCEPProfilesFromEnv(),
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
			APIKey:             getEnv("CERTCTL_DIGICERT_API_KEY", ""),
			OrgID:              getEnv("CERTCTL_DIGICERT_ORG_ID", ""),
			ProductType:        getEnv("CERTCTL_DIGICERT_PRODUCT_TYPE", "ssl_basic"),
			BaseURL:            getEnv("CERTCTL_DIGICERT_BASE_URL", "https://www.digicert.com/services/v2"),
			PollMaxWaitSeconds: getEnvInt("CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS", 0),
		},
		Sectigo: SectigoConfig{
			CustomerURI:        getEnv("CERTCTL_SECTIGO_CUSTOMER_URI", ""),
			Login:              getEnv("CERTCTL_SECTIGO_LOGIN", ""),
			Password:           getEnv("CERTCTL_SECTIGO_PASSWORD", ""),
			OrgID:              getEnvInt("CERTCTL_SECTIGO_ORG_ID", 0),
			CertType:           getEnvInt("CERTCTL_SECTIGO_CERT_TYPE", 0),
			Term:               getEnvInt("CERTCTL_SECTIGO_TERM", 365),
			BaseURL:            getEnv("CERTCTL_SECTIGO_BASE_URL", "https://cert-manager.com/api"),
			PollMaxWaitSeconds: getEnvInt("CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS", 0),
		},
		GoogleCAS: GoogleCASConfig{
			Project:     getEnv("CERTCTL_GOOGLE_CAS_PROJECT", ""),
			Location:    getEnv("CERTCTL_GOOGLE_CAS_LOCATION", ""),
			CAPool:      getEnv("CERTCTL_GOOGLE_CAS_CA_POOL", ""),
			Credentials: getEnv("CERTCTL_GOOGLE_CAS_CREDENTIALS", ""),
			TTL:         getEnv("CERTCTL_GOOGLE_CAS_TTL", "8760h"),
		},
		AWSACMPCA: AWSACMPCAConfig{
			Region:           getEnv("CERTCTL_AWS_PCA_REGION", ""),
			CAArn:            getEnv("CERTCTL_AWS_PCA_CA_ARN", ""),
			SigningAlgorithm: getEnv("CERTCTL_AWS_PCA_SIGNING_ALGORITHM", "SHA256WITHRSA"),
			ValidityDays:     getEnvInt("CERTCTL_AWS_PCA_VALIDITY_DAYS", 365),
			TemplateArn:      getEnv("CERTCTL_AWS_PCA_TEMPLATE_ARN", ""),
		},
		Entrust: EntrustConfig{
			APIUrl:             getEnv("CERTCTL_ENTRUST_API_URL", ""),
			ClientCertPath:     getEnv("CERTCTL_ENTRUST_CLIENT_CERT_PATH", ""),
			ClientKeyPath:      getEnv("CERTCTL_ENTRUST_CLIENT_KEY_PATH", ""),
			CAId:               getEnv("CERTCTL_ENTRUST_CA_ID", ""),
			ProfileId:          getEnv("CERTCTL_ENTRUST_PROFILE_ID", ""),
			PollMaxWaitSeconds: getEnvInt("CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS", 0),
		},
		GlobalSign: GlobalSignConfig{
			APIUrl:             getEnv("CERTCTL_GLOBALSIGN_API_URL", ""),
			APIKey:             getEnv("CERTCTL_GLOBALSIGN_API_KEY", ""),
			APISecret:          getEnv("CERTCTL_GLOBALSIGN_API_SECRET", ""),
			ClientCertPath:     getEnv("CERTCTL_GLOBALSIGN_CLIENT_CERT_PATH", ""),
			ClientKeyPath:      getEnv("CERTCTL_GLOBALSIGN_CLIENT_KEY_PATH", ""),
			ServerCAPath:       getEnv("CERTCTL_GLOBALSIGN_SERVER_CA_PATH", ""),
			PollMaxWaitSeconds: getEnvInt("CERTCTL_GLOBALSIGN_POLL_MAX_WAIT_SECONDS", 0),
		},
		EJBCA: EJBCAConfig{
			APIUrl:         getEnv("CERTCTL_EJBCA_API_URL", ""),
			AuthMode:       getEnv("CERTCTL_EJBCA_AUTH_MODE", "mtls"),
			ClientCertPath: getEnv("CERTCTL_EJBCA_CLIENT_CERT_PATH", ""),
			ClientKeyPath:  getEnv("CERTCTL_EJBCA_CLIENT_KEY_PATH", ""),
			Token:          getEnv("CERTCTL_EJBCA_TOKEN", ""),
			CAName:         getEnv("CERTCTL_EJBCA_CA_NAME", ""),
			CertProfile:    getEnv("CERTCTL_EJBCA_CERT_PROFILE", ""),
			EEProfile:      getEnv("CERTCTL_EJBCA_EE_PROFILE", ""),
		},
		ACME: ACMEConfig{
			DirectoryURL:           getEnv("CERTCTL_ACME_DIRECTORY_URL", ""),
			Email:                  getEnv("CERTCTL_ACME_EMAIL", ""),
			ChallengeType:          getEnv("CERTCTL_ACME_CHALLENGE_TYPE", "http-01"),
			DNSPresentScript:       getEnv("CERTCTL_ACME_DNS_PRESENT_SCRIPT", ""),
			DNSCleanUpScript:       getEnv("CERTCTL_ACME_DNS_CLEANUP_SCRIPT", ""),
			DNSPersistIssuerDomain: getEnv("CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN", ""),
			Profile:                getEnv("CERTCTL_ACME_PROFILE", ""),
			ARIEnabled:             getEnvBool("CERTCTL_ACME_ARI_ENABLED", false),
			Insecure:               getEnvBool("CERTCTL_ACME_INSECURE", false),
		},
		// ACME server (RFC 8555 + RFC 9773 ARI) — distinct from the
		// consumer-side ACME issuer connector above. Server uses
		// CERTCTL_ACME_SERVER_* prefix throughout (audit fix #11).
		// Phase 1a wires Enabled / DefaultAuthMode / DefaultProfileID /
		// NonceTTL + DirectoryMeta. Order/Authz TTLs + concurrency
		// caps + DNS01 resolver are reserved (Phases 2/3 read).
		ACMEServer: ACMEServerConfig{
			Enabled:                           getEnvBool("CERTCTL_ACME_SERVER_ENABLED", false),
			DefaultAuthMode:                   getEnv("CERTCTL_ACME_SERVER_DEFAULT_AUTH_MODE", "trust_authenticated"),
			DefaultProfileID:                  getEnv("CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID", ""),
			NonceTTL:                          getEnvDuration("CERTCTL_ACME_SERVER_NONCE_TTL", 5*time.Minute),
			OrderTTL:                          getEnvDuration("CERTCTL_ACME_SERVER_ORDER_TTL", 24*time.Hour),
			AuthzTTL:                          getEnvDuration("CERTCTL_ACME_SERVER_AUTHZ_TTL", 24*time.Hour),
			HTTP01ConcurrencyMax:              getEnvInt("CERTCTL_ACME_SERVER_HTTP01_CONCURRENCY", 10),
			DNS01Resolver:                     getEnv("CERTCTL_ACME_SERVER_DNS01_RESOLVER", "8.8.8.8:53"),
			DNS01ConcurrencyMax:               getEnvInt("CERTCTL_ACME_SERVER_DNS01_CONCURRENCY", 10),
			TLSALPN01ConcurrencyMax:           getEnvInt("CERTCTL_ACME_SERVER_TLSALPN01_CONCURRENCY", 10),
			ARIEnabled:                        getEnvBool("CERTCTL_ACME_SERVER_ARI_ENABLED", true),
			ARIPollInterval:                   getEnvDuration("CERTCTL_ACME_SERVER_ARI_POLL_INTERVAL", 6*time.Hour),
			RateLimitOrdersPerHour:            getEnvInt("CERTCTL_ACME_SERVER_RATE_LIMIT_ORDERS_PER_HOUR", 100),
			RateLimitConcurrentOrders:         getEnvInt("CERTCTL_ACME_SERVER_RATE_LIMIT_CONCURRENT_ORDERS", 5),
			RateLimitKeyChangePerHour:         getEnvInt("CERTCTL_ACME_SERVER_RATE_LIMIT_KEY_CHANGE_PER_HOUR", 5),
			RateLimitChallengeRespondsPerHour: getEnvInt("CERTCTL_ACME_SERVER_RATE_LIMIT_CHALLENGE_RESPONDS_PER_HOUR", 60),
			GCInterval:                        getEnvDuration("CERTCTL_ACME_SERVER_GC_INTERVAL", time.Minute),
			DirectoryMeta: ACMEServerDirectoryMeta{
				TermsOfService:          getEnv("CERTCTL_ACME_SERVER_TOS_URL", ""),
				Website:                 getEnv("CERTCTL_ACME_SERVER_WEBSITE", ""),
				CAAIdentities:           getEnvList("CERTCTL_ACME_SERVER_CAA_IDENTITIES", nil),
				ExternalAccountRequired: getEnvBool("CERTCTL_ACME_SERVER_EAB_REQUIRED", false),
			},
		},
		Approval: ApprovalConfig{
			// Rank 7. Default: false. Production deploys must leave it false;
			// the bypass emits a typed audit row (action=approval_bypassed,
			// actor=system-bypass) so compliance auditors detect misuse via
			// SELECT count(*) FROM audit_events WHERE actor='system-bypass'
			// returning > 0.
			BypassEnabled: getEnvBool("CERTCTL_APPROVAL_BYPASS", false),
		},
		Digest: DigestConfig{
			Enabled:    getEnvBool("CERTCTL_DIGEST_ENABLED", false),
			Interval:   getEnvDuration("CERTCTL_DIGEST_INTERVAL", 24*time.Hour),
			Recipients: getEnvList("CERTCTL_DIGEST_RECIPIENTS", nil),
		},
		HealthCheck: HealthCheckConfig{
			Enabled:          getEnvBool("CERTCTL_HEALTH_CHECK_ENABLED", false),
			CheckInterval:    getEnvDuration("CERTCTL_HEALTH_CHECK_INTERVAL", 60*time.Second),
			DefaultInterval:  getEnvInt("CERTCTL_HEALTH_CHECK_DEFAULT_INTERVAL", 300),
			DefaultTimeout:   getEnvInt("CERTCTL_HEALTH_CHECK_DEFAULT_TIMEOUT", 5000),
			MaxConcurrent:    getEnvInt("CERTCTL_HEALTH_CHECK_MAX_CONCURRENT", 20),
			HistoryRetention: getEnvDuration("CERTCTL_HEALTH_CHECK_HISTORY_RETENTION", 30*24*time.Hour),
			AutoCreate:       getEnvBool("CERTCTL_HEALTH_CHECK_AUTO_CREATE", true),
		},
		Encryption: EncryptionConfig{
			ConfigEncryptionKey: getEnv("CERTCTL_CONFIG_ENCRYPTION_KEY", ""),
		},
		CloudDiscovery: CloudDiscoveryConfig{
			Enabled:  getEnvBool("CERTCTL_CLOUD_DISCOVERY_ENABLED", false),
			Interval: getEnvDuration("CERTCTL_CLOUD_DISCOVERY_INTERVAL", 6*time.Hour),
			AWSSM: AWSSecretsMgrDiscoveryConfig{
				Enabled:    getEnvBool("CERTCTL_AWS_SM_DISCOVERY_ENABLED", false),
				Region:     getEnv("CERTCTL_AWS_SM_REGION", ""),
				TagFilter:  getEnv("CERTCTL_AWS_SM_TAG_FILTER", "type=certificate"),
				NamePrefix: getEnv("CERTCTL_AWS_SM_NAME_PREFIX", ""),
			},
			AzureKV: AzureKVDiscoveryConfig{
				Enabled:      getEnvBool("CERTCTL_AZURE_KV_DISCOVERY_ENABLED", false),
				VaultURL:     getEnv("CERTCTL_AZURE_KV_VAULT_URL", ""),
				TenantID:     getEnv("CERTCTL_AZURE_KV_TENANT_ID", ""),
				ClientID:     getEnv("CERTCTL_AZURE_KV_CLIENT_ID", ""),
				ClientSecret: getEnv("CERTCTL_AZURE_KV_CLIENT_SECRET", ""),
			},
			GCPSM: GCPSecretMgrDiscoveryConfig{
				Enabled:     getEnvBool("CERTCTL_GCP_SM_DISCOVERY_ENABLED", false),
				Project:     getEnv("CERTCTL_GCP_SM_PROJECT", ""),
				Credentials: getEnv("CERTCTL_GCP_SM_CREDENTIALS", ""),
			},
		},
		OCSPResponder: OCSPResponderConfig{
			KeyDir:        getEnv("CERTCTL_OCSP_RESPONDER_KEY_DIR", ""),
			RotationGrace: getEnvDuration("CERTCTL_OCSP_RESPONDER_ROTATION_GRACE", 7*24*time.Hour),
			Validity:      getEnvDuration("CERTCTL_OCSP_RESPONDER_VALIDITY", 30*24*time.Hour),
		},
	}

	// Parse CERTCTL_API_KEYS_NAMED for named key authentication (M-002).
	// Parse errors surface here so invalid config fails fast at startup.
	named, err := ParseNamedAPIKeys(getEnv("CERTCTL_API_KEYS_NAMED", ""))
	if err != nil {
		return nil, fmt.Errorf("parse CERTCTL_API_KEYS_NAMED: %w", err)
	}
	cfg.Auth.NamedKeys = named

	// SCEP RFC 8894 Phase 1.5: backward-compat shim. When the operator hasn't
	// set CERTCTL_SCEP_PROFILES (so loadSCEPProfilesFromEnv returned nil) but
	// the legacy single-profile flat fields (ChallengePassword OR RACertPath)
	// are populated, synthesize a single-element Profiles[0] with PathID=""
	// so /scep continues to dispatch the same way it did pre-Phase-1.5. Done
	// AFTER the field-by-field load so it can read from the populated cfg.SCEP
	// struct.
	mergeSCEPLegacyIntoProfiles(&cfg.SCEP)

	// EST RFC 7030 hardening Phase 1: same back-compat shim, EST flavor.
	// When CERTCTL_EST_PROFILES is unset AND the legacy flat single-issuer
	// fields are populated AND Enabled=true, synthesise a single-element
	// Profiles[0] with PathID="" so /.well-known/est/ continues to dispatch
	// the same way it did pre-Phase-1. Done AFTER the field-by-field load
	// so it can read from the populated cfg.EST struct.
	mergeESTLegacyIntoProfiles(&cfg.EST)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadSCEPProfilesFromEnv reads the indexed CERTCTL_SCEP_PROFILES env var
// (e.g. "corp,iot,server") and expands each name into a SCEPProfileConfig
// populated from CERTCTL_SCEP_PROFILE_<NAME>_*. Returns nil when the
// CERTCTL_SCEP_PROFILES env var is unset or empty — in that case the
// legacy-shim path (mergeSCEPLegacyIntoProfiles, called from Load after the
// initial config build) populates Profiles[0] from the flat fields if needed.
//
// PathID for each profile is the lowercased trimmed name from the
// CERTCTL_SCEP_PROFILES list (e.g. "Corp" -> "corp"). Validation that the
// PathID is path-safe ([a-z0-9-]+) lives in Config.Validate() so the loader
// can stay free of error returns.
func loadSCEPProfilesFromEnv() []SCEPProfileConfig {
	raw := strings.TrimSpace(os.Getenv("CERTCTL_SCEP_PROFILES"))
	if raw == "" {
		return nil
	}
	names := strings.Split(raw, ",")
	out := make([]SCEPProfileConfig, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		// The env-var key is the upper-cased name (CERTCTL_SCEP_PROFILE_CORP_*),
		// but the URL path segment is the lower-cased name to match the
		// path-safe slug constraint enforced in Validate.
		envName := strings.ToUpper(n)
		pathID := strings.ToLower(n)
		out = append(out, SCEPProfileConfig{
			PathID:            pathID,
			IssuerID:          getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_ISSUER_ID", ""),
			ProfileID:         getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_PROFILE_ID", ""),
			ChallengePassword: getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_CHALLENGE_PASSWORD", ""),
			RACertPath:        getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_RA_CERT_PATH", ""),
			RAKeyPath:         getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_RA_KEY_PATH", ""),
			// SCEP RFC 8894 Phase 6.5: opt-in mTLS sibling route.
			MTLSEnabled:                 getEnvBool("CERTCTL_SCEP_PROFILE_"+envName+"_MTLS_ENABLED", false),
			MTLSClientCATrustBundlePath: getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH", ""),
			// SCEP RFC 8894 Phase 8.1: per-profile Intune Connector dispatch.
			Intune: SCEPIntuneProfileConfig{
				Enabled:               getEnvBool("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_ENABLED", false),
				ConnectorCertPath:     getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_CONNECTOR_CERT_PATH", ""),
				Audience:              getEnv("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_AUDIENCE", ""),
				ChallengeValidity:     getEnvDuration("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_CHALLENGE_VALIDITY", 60*time.Minute),
				PerDeviceRateLimit24h: getEnvInt("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_PER_DEVICE_RATE_LIMIT_24H", 3),
				ClockSkewTolerance:    getEnvDuration("CERTCTL_SCEP_PROFILE_"+envName+"_INTUNE_CLOCK_SKEW_TOLERANCE", 60*time.Second),
			},
		})
	}
	return out
}

// mergeSCEPLegacyIntoProfiles is the backward-compat shim. When Profiles is
// empty AND any legacy single-profile field is populated, synthesise a
// single-element Profiles[0] with PathID="" so /scep dispatches identically
// to the pre-Phase-1.5 deploy. No-op when Profiles is non-empty (the operator
// explicitly opted into the structured form via CERTCTL_SCEP_PROFILES) or
// when SCEP is disabled.
//
// "Any legacy field populated" means at least one of ChallengePassword,
// RACertPath, RAKeyPath is non-empty. IssuerID has a non-empty default
// ("iss-local") so it can't be the trigger; ProfileID is optional. The
// trigger set matches what the Validate() refuse cares about.
func mergeSCEPLegacyIntoProfiles(c *SCEPConfig) {
	if c == nil || !c.Enabled || len(c.Profiles) > 0 {
		return
	}
	hasLegacy := c.ChallengePassword != "" || c.RACertPath != "" || c.RAKeyPath != ""
	if !hasLegacy {
		return
	}
	c.Profiles = []SCEPProfileConfig{{
		PathID:            "", // empty pathID maps to the legacy /scep root
		IssuerID:          c.IssuerID,
		ProfileID:         c.ProfileID,
		ChallengePassword: c.ChallengePassword,
		RACertPath:        c.RACertPath,
		RAKeyPath:         c.RAKeyPath,
	}}
}

// validSCEPPathID reports whether s is a valid SCEP profile path segment.
// The empty string is allowed (legacy root /scep). Non-empty values must
// be ASCII lowercase letters / digits / hyphens with no leading/trailing
// hyphen — keeps URL-construction trivial at the router layer and avoids
// percent-encoding surprises for SCEP clients that build the URL by string
// concat rather than url.PathEscape.
func validSCEPPathID(s string) bool {
	if s == "" {
		return true // empty maps to legacy /scep root
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// loadESTProfilesFromEnv reads the indexed CERTCTL_EST_PROFILES env var
// (e.g. "corp,iot,wifi") and expands each name into an ESTProfileConfig
// populated from CERTCTL_EST_PROFILE_<NAME>_*. Returns nil when the
// CERTCTL_EST_PROFILES env var is unset or empty — in that case the
// legacy-shim path (mergeESTLegacyIntoProfiles, called from Load after
// the initial config build) populates Profiles[0] from the flat fields
// if needed.
//
// PathID for each profile is the lowercased trimmed name from the
// CERTCTL_EST_PROFILES list (e.g. "Corp" -> "corp"). Validation that
// the PathID is path-safe ([a-z0-9-]+) lives in Config.Validate() so
// the loader can stay free of error returns.
//
// Mirrors loadSCEPProfilesFromEnv exactly. EST RFC 7030 hardening Phase 1.
func loadESTProfilesFromEnv() []ESTProfileConfig {
	raw := strings.TrimSpace(os.Getenv("CERTCTL_EST_PROFILES"))
	if raw == "" {
		return nil
	}
	names := strings.Split(raw, ",")
	out := make([]ESTProfileConfig, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		// The env-var key is the upper-cased name (CERTCTL_EST_PROFILE_CORP_*),
		// but the URL path segment is the lower-cased name to match the
		// path-safe slug constraint enforced in Validate.
		envName := strings.ToUpper(n)
		pathID := strings.ToLower(n)
		out = append(out, ESTProfileConfig{
			PathID:                      pathID,
			IssuerID:                    getEnv("CERTCTL_EST_PROFILE_"+envName+"_ISSUER_ID", ""),
			ProfileID:                   getEnv("CERTCTL_EST_PROFILE_"+envName+"_PROFILE_ID", ""),
			EnrollmentPassword:          getEnv("CERTCTL_EST_PROFILE_"+envName+"_ENROLLMENT_PASSWORD", ""),
			MTLSEnabled:                 getEnvBool("CERTCTL_EST_PROFILE_"+envName+"_MTLS_ENABLED", false),
			MTLSClientCATrustBundlePath: getEnv("CERTCTL_EST_PROFILE_"+envName+"_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH", ""),
			ChannelBindingRequired:      getEnvBool("CERTCTL_EST_PROFILE_"+envName+"_CHANNEL_BINDING_REQUIRED", false),
			AllowedAuthModes:            parseAuthModes(getEnv("CERTCTL_EST_PROFILE_"+envName+"_ALLOWED_AUTH_MODES", "")),
			RateLimitPerPrincipal24h:    getEnvInt("CERTCTL_EST_PROFILE_"+envName+"_RATE_LIMIT_PER_PRINCIPAL_24H", 0),
			ServerKeygenEnabled:         getEnvBool("CERTCTL_EST_PROFILE_"+envName+"_SERVERKEYGEN_ENABLED", false),
		})
	}
	return out
}

// parseAuthModes splits a comma-separated env value into a normalized
// []string of auth-mode tokens. Empty input returns nil (the
// "unauthenticated default" Phase 1 preserves for back-compat). Tokens
// are lowercased + trimmed; unknown tokens are kept as-is so Validate
// can refuse them with a typed error message naming the offending token.
func parseAuthModes(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// mergeESTLegacyIntoProfiles is the EST backward-compat shim. When
// Profiles is empty AND the legacy single-issuer fields are populated
// (Enabled=true is the trigger; IssuerID has a non-empty default so it
// can't be the trigger by itself), synthesise a single-element
// Profiles[0] with PathID="" so /.well-known/est/ dispatches identically
// to the pre-Phase-1 deploy. No-op when Profiles is non-empty (the
// operator explicitly opted into the structured form via
// CERTCTL_EST_PROFILES) or when EST is disabled.
//
// EST's legacy single-issuer config has fewer "trigger" fields than
// SCEP's (no per-profile RA pair, no per-profile challenge password —
// both of those land in Phases 2/3 of the hardening bundle). The shim
// triggers whenever EST is enabled, since the operator clearly intends
// to serve EST. This makes the back-compat behavior identical to v2.0.66
// (single /.well-known/est/ root with the operator's chosen issuer).
//
// EST RFC 7030 hardening Phase 1.
func mergeESTLegacyIntoProfiles(c *ESTConfig) {
	if c == nil || !c.Enabled || len(c.Profiles) > 0 {
		return
	}
	c.Profiles = []ESTProfileConfig{{
		PathID:    "", // empty pathID maps to the legacy /.well-known/est/ root
		IssuerID:  c.IssuerID,
		ProfileID: c.ProfileID,
		// No legacy fields exist for EnrollmentPassword, MTLS*, etc. —
		// those land in Phases 2/3. Operators upgrading from v2.0.66 get
		// the same unauthenticated behavior they had before; opting into
		// auth requires moving to the structured CERTCTL_EST_PROFILES
		// form (which Phase 12 docs as the recommended migration path).
	}}
}

// validESTPathID reports whether s is a valid EST profile path segment.
// Same shape as validSCEPPathID — empty string allowed (legacy root),
// otherwise ASCII lowercase letters / digits / hyphens with no
// leading/trailing hyphen. Kept as a separate function (rather than
// generalizing) so that future EST-specific path constraints (e.g. RFC
// 7030 §3.2.2 reserved path segments) can land here without affecting
// SCEP's validator.
//
// EST RFC 7030 hardening Phase 1.
func validESTPathID(s string) bool {
	if s == "" {
		return true // empty maps to legacy /.well-known/est/ root
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// validESTAuthMode reports whether mode is one of the documented EST
// auth modes Phase 2 + Phase 3 will dispatch on. Kept here so Validate
// can refuse unknown modes (typos, future modes the binary doesn't yet
// implement) at startup with a clear error rather than at first-request
// with a confusing 401/403.
//
// EST RFC 7030 hardening Phase 1.
func validESTAuthMode(mode string) bool {
	switch mode {
	case "mtls", "basic":
		return true
	}
	return false
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// HTTPS-everywhere milestone §2.1 + §3 locked decisions: the control plane
	// is TLS-only and refuses to start without a cert. No plaintext HTTP fallback,
	// no auto-generated self-signed cert, no N-release migration window. An empty
	// CertPath or KeyPath is operator-visible misconfiguration, not a soft warning.
	if c.Server.TLS.CertPath == "" {
		return fmt.Errorf("server TLS cert path is required — refuse to start (HTTPS-only: set CERTCTL_SERVER_TLS_CERT_PATH to a PEM-encoded certificate; see docs/tls.md)")
	}
	if c.Server.TLS.KeyPath == "" {
		return fmt.Errorf("server TLS key path is required — refuse to start (HTTPS-only: set CERTCTL_SERVER_TLS_KEY_PATH to the PEM-encoded private key matching CERTCTL_SERVER_TLS_CERT_PATH; see docs/tls.md)")
	}

	// Files must exist and be readable. Catches typos and missing mount paths
	// up-front so the operator gets a structured error on startup instead of
	// a deferred ListenAndServeTLS failure after the scheduler has already
	// fanned out its goroutines.
	if _, err := os.Stat(c.Server.TLS.CertPath); err != nil {
		return fmt.Errorf("server TLS cert file unreadable at %q: %w — refuse to start (HTTPS-only; see docs/tls.md)", c.Server.TLS.CertPath, err)
	}
	if _, err := os.Stat(c.Server.TLS.KeyPath); err != nil {
		return fmt.Errorf("server TLS key file unreadable at %q: %w — refuse to start (HTTPS-only; see docs/tls.md)", c.Server.TLS.KeyPath, err)
	}

	// Parse the cert+key pair up-front. tls.LoadX509KeyPair verifies that the
	// key signs the cert (prevents the classic footgun of shipping a pair
	// whose private key doesn't match). Discard the returned Certificate — the
	// server constructs its own holder from fresh reads so SIGHUP reload is
	// authoritative.
	if _, err := tls.LoadX509KeyPair(c.Server.TLS.CertPath, c.Server.TLS.KeyPath); err != nil {
		return fmt.Errorf("server TLS cert/key pair invalid (cert=%q key=%q): %w — refuse to start (HTTPS-only; see docs/tls.md)", c.Server.TLS.CertPath, c.Server.TLS.KeyPath, err)
	}

	// H-1 closure (cat-r-encryption_key_no_length_validation): if
	// CERTCTL_CONFIG_ENCRYPTION_KEY is set, enforce a minimum length of
	// 32 bytes. Pre-H-1 the field was accepted with any non-empty value
	// — including a single character — and PBKDF2-SHA256 (100k rounds)
	// alone does not compensate for low-entropy passphrases at scale
	// (CWE-916 Use of Password Hash With Insufficient Computational
	// Effort + CWE-329 Generation of Predictable IV with CBC Mode).
	// 32 bytes ≈ 256 bits when generated via `openssl rand -base64 32`,
	// matching the AES-256-GCM key size the passphrase derives. An
	// empty key remains accepted — the fail-closed sentinel
	// crypto.ErrEncryptionKeyRequired triggers downstream when an
	// empty key is asked to encrypt or decrypt sensitive config.
	const minEncryptionKeyLength = 32
	if c.Encryption.ConfigEncryptionKey != "" && len(c.Encryption.ConfigEncryptionKey) < minEncryptionKeyLength {
		return fmt.Errorf(
			"CERTCTL_CONFIG_ENCRYPTION_KEY too short (%d bytes; minimum %d). Generate with: openssl rand -base64 32",
			len(c.Encryption.ConfigEncryptionKey), minEncryptionKeyLength,
		)
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

	// Validate auth type.
	//
	// G-1 (P1): the pre-G-1 set was {"api-key", "jwt", "none"} with "jwt"
	// accepted but no JWT middleware shipped — silent auth downgrade.
	// Post-G-1 we route a literal "jwt" value through a dedicated
	// rejection that gives operators actionable guidance (the
	// authenticating-gateway pattern) instead of the generic
	// "invalid auth type". Then we cross-check against ValidAuthTypes()
	// so any value outside {api-key, none} surfaces uniformly.
	if c.Auth.Type == "jwt" {
		return fmt.Errorf(
			"CERTCTL_AUTH_TYPE=jwt is no longer accepted (G-1 silent auth " +
				"downgrade): no JWT middleware ships with certctl. To use " +
				"JWT/OIDC, run an authenticating gateway (oauth2-proxy / " +
				"Envoy ext_authz / Traefik ForwardAuth / Pomerium) in " +
				"front of certctl and set CERTCTL_AUTH_TYPE=none on the " +
				"upstream. See docs/architecture.md \"Authenticating-" +
				"gateway pattern\" and docs/upgrade-to-v2-jwt-removal.md " +
				"for the migration walkthrough")
	}
	authTypeValid := false
	for _, t := range ValidAuthTypes() {
		if AuthType(c.Auth.Type) == t {
			authTypeValid = true
			break
		}
	}
	if !authTypeValid {
		return fmt.Errorf("invalid auth type: %s (valid: %v)", c.Auth.Type, ValidAuthTypes())
	}

	// If using API-key, secret is required. (Secret was previously also
	// required for "jwt"; removed with the jwt rejection above.)
	if c.Auth.Type == string(AuthTypeAPIKey) && c.Auth.Secret == "" {
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

	// SCEP fail-loud startup gate (H-2, CWE-306).
	//
	// Post-M-001 option (D) routes /scep through the no-auth middleware chain per
	// RFC 8894 §3.2 — SCEP clients authenticate via the challengePassword attribute
	// in the PKCS#10 CSR, not via HTTP Bearer tokens or TLS client certs. That makes
	// CERTCTL_SCEP_CHALLENGE_PASSWORD the sole application-layer authentication
	// boundary for SCEP enrollment. Refuse to start if it is empty when SCEP is
	// enabled: an empty shared secret would allow any client that can reach /scep to
	// enroll a CSR against the configured issuer (anonymous issuance).
	if c.SCEP.Enabled && c.SCEP.ChallengePassword == "" {
		// Phase 1.5: only enforce the legacy single-profile gate when the
		// operator has NOT opted into the structured Profiles form. When
		// CERTCTL_SCEP_PROFILES is set, the per-profile loop below covers
		// the same gate per profile (with per-profile error messages).
		if len(c.SCEP.Profiles) == 0 {
			return fmt.Errorf("SCEP is enabled but CERTCTL_SCEP_CHALLENGE_PASSWORD is empty — refuse to start (CWE-306: anonymous SCEP issuance is insecure; set a non-empty shared secret or disable SCEP with CERTCTL_SCEP_ENABLED=false). This gate duplicates cmd/server/main.go:preflightSCEPChallengePassword for defense in depth")
		}
	}

	// SCEP RFC 8894 Phase 1: RA cert + key are mandatory when SCEP is enabled.
	// Without them the new RFC 8894 PKIMessage path (EnvelopedData decryption,
	// CertRep signing) cannot run and every SCEP request silently falls through
	// to the MVP raw-CSR path — fail loud at startup so the operator's intent
	// is unambiguous. Mirrors the ChallengePassword gate above; defense in
	// depth with cmd/server/main.go::preflightSCEPRACertKey which additionally
	// validates file mode + cert/key match + expiry + algorithm.
	if c.SCEP.Enabled && (c.SCEP.RACertPath == "" || c.SCEP.RAKeyPath == "") {
		// Phase 1.5: only refuse on the legacy flat fields when neither the
		// flat fields nor the structured Profiles slice are populated. When
		// the operator opts into the structured form via CERTCTL_SCEP_PROFILES,
		// the per-profile checks below cover the same gate.
		if len(c.SCEP.Profiles) == 0 {
			return fmt.Errorf("SCEP is enabled but RA cert/key path missing — refuse to start (RFC 8894 §3.2.2 requires an RA cert clients can encrypt their CSR to and an RA key the server uses to decrypt + sign CertRep): set both CERTCTL_SCEP_RA_CERT_PATH and CERTCTL_SCEP_RA_KEY_PATH or disable SCEP with CERTCTL_SCEP_ENABLED=false. See docs/legacy-est-scep.md for the openssl recipe to generate the RA pair. This gate duplicates cmd/server/main.go:preflightSCEPRACertKey for defense in depth")
		}
	}

	// SCEP RFC 8894 Phase 1.5: per-profile validation. When the structured
	// Profiles slice is populated (either via CERTCTL_SCEP_PROFILES or via
	// the legacy-shim merge in Load), iterate each profile and refuse boot
	// if any is malformed. PathID format, ChallengePassword presence, and
	// RA pair presence are all gated here; preflight validates the RA files
	// themselves (mode, match, expiry, alg).
	if c.SCEP.Enabled {
		seenPath := map[string]bool{}
		for i, p := range c.SCEP.Profiles {
			if !validSCEPPathID(p.PathID) {
				return fmt.Errorf("SCEP profile %d (%q) has invalid PathID — refuse to start: must be empty (legacy /scep root) or a path-safe slug matching [a-z0-9-]+ with no leading/trailing hyphen (got %q)", i, p.PathID, p.PathID)
			}
			if seenPath[p.PathID] {
				return fmt.Errorf("SCEP profile %d duplicates PathID %q — refuse to start: each profile must have a unique URL segment so the router can dispatch unambiguously", i, p.PathID)
			}
			seenPath[p.PathID] = true
			if p.ChallengePassword == "" {
				return fmt.Errorf("SCEP profile %d (PathID=%q) has empty CHALLENGE_PASSWORD — refuse to start (CWE-306: per-profile shared secret is the sole application-layer auth boundary; an empty password would allow any client reaching /scep/%s to enroll a CSR against issuer %q)", i, p.PathID, p.PathID, p.IssuerID)
			}
			if p.RACertPath == "" || p.RAKeyPath == "" {
				return fmt.Errorf("SCEP profile %d (PathID=%q) missing RA cert/key path — refuse to start (RFC 8894 §3.2.2): set CERTCTL_SCEP_PROFILE_<NAME>_RA_CERT_PATH and _RA_KEY_PATH for every profile listed in CERTCTL_SCEP_PROFILES, or remove the profile from the list", i, p.PathID)
			}
			if p.IssuerID == "" {
				return fmt.Errorf("SCEP profile %d (PathID=%q) has empty IssuerID — refuse to start: each SCEP profile must bind to a configured issuer", i, p.PathID)
			}
			// Phase 6.5: when mTLS is enabled, the trust bundle path must
			// be set. Preflight in cmd/server/main.go validates the file
			// itself (exists, parseable PEM, ≥1 cert, none expired); this
			// gate is the structural-config refuse, defense in depth.
			if p.MTLSEnabled && p.MTLSClientCATrustBundlePath == "" {
				return fmt.Errorf("SCEP profile %d (PathID=%q) has MTLSEnabled=true but MTLS_CLIENT_CA_TRUST_BUNDLE_PATH is empty — refuse to start: the mTLS sibling route /scep-mtls/%s would have no client-cert trust anchor", i, p.PathID, p.PathID)
			}
			// Phase 8.1: when Intune is enabled, the Connector trust anchor
			// path must be set. Preflight in cmd/server/main.go validates the
			// file itself (intune.LoadTrustAnchor: exists, parseable PEM,
			// ≥1 CERTIFICATE block, none expired); this gate is the
			// structural-config refuse, defense in depth — without it an
			// operator who flips INTUNE_ENABLED=true but forgets to set
			// CONNECTOR_CERT_PATH would get every Intune enrollment
			// rejected at runtime with no trust anchor configured (much
			// worse failure mode than failing fast at boot).
			if p.Intune.Enabled && p.Intune.ConnectorCertPath == "" {
				return fmt.Errorf("SCEP profile %d (PathID=%q) has INTUNE_ENABLED=true but INTUNE_CONNECTOR_CERT_PATH is empty — refuse to start: the Intune dynamic-challenge validator would have no trust anchor and reject every Microsoft Intune enrollment", i, p.PathID)
			}
			// Phase 8.6: a non-zero rate limit must be sane. Negative is a
			// config typo; positive values are the per-(Subject,Issuer)
			// 24-hour cap; zero means 'disabled' (allowed for tests + the
			// rare operator who wants no per-device cap).
			if p.Intune.PerDeviceRateLimit24h < 0 {
				return fmt.Errorf("SCEP profile %d (PathID=%q) has INTUNE_PER_DEVICE_RATE_LIMIT_24H=%d — refuse to start: must be ≥0 (zero disables the per-device cap, positive values enforce it)", i, p.PathID, p.Intune.PerDeviceRateLimit24h)
			}
			// Master prompt §15 hazard closure: clock-skew tolerance must
			// be ≥0 AND strictly less than ChallengeValidity. A negative
			// value is operator typo; a value ≥ ChallengeValidity makes
			// the iat/exp checks vacuously pass (a Connector challenge
			// minted at NotBefore-tolerance still validates), defeating
			// the per-profile validity cap. Reject at startup so the
			// operator's first grep narrows it down fast.
			if p.Intune.ClockSkewTolerance < 0 {
				return fmt.Errorf("SCEP profile %d (PathID=%q) has INTUNE_CLOCK_SKEW_TOLERANCE=%s — refuse to start: must be ≥0 (zero disables the grace window, positive values widen it)", i, p.PathID, p.Intune.ClockSkewTolerance)
			}
			if p.Intune.ChallengeValidity > 0 && p.Intune.ClockSkewTolerance >= p.Intune.ChallengeValidity {
				return fmt.Errorf("SCEP profile %d (PathID=%q) has INTUNE_CLOCK_SKEW_TOLERANCE=%s ≥ INTUNE_CHALLENGE_VALIDITY=%s — refuse to start: tolerance ≥ validity makes the per-profile validity cap vacuous", i, p.PathID, p.Intune.ClockSkewTolerance, p.Intune.ChallengeValidity)
			}
		}
	}

	// EST RFC 7030 hardening Phase 1: per-profile validation. When the
	// structured Profiles slice is populated (either via CERTCTL_EST_PROFILES
	// or via the legacy-shim merge in Load), iterate each profile and refuse
	// boot if any is malformed. PathID format + uniqueness, IssuerID
	// presence, MTLS-bundle-required-when-enabled, AllowedAuthModes shape,
	// RateLimit ≥0 are all gated here. Phase 2/3 preflights validate the
	// MTLS trust bundle file itself (mode, parse, expiry); Phase 1 is
	// the structural-config refuse, defense in depth.
	if c.EST.Enabled {
		seenESTPath := map[string]bool{}
		for i, p := range c.EST.Profiles {
			if !validESTPathID(p.PathID) {
				return fmt.Errorf("EST profile %d (%q) has invalid PathID — refuse to start: must be empty (legacy /.well-known/est/ root) or a path-safe slug matching [a-z0-9-]+ with no leading/trailing hyphen (got %q)", i, p.PathID, p.PathID)
			}
			if seenESTPath[p.PathID] {
				return fmt.Errorf("EST profile %d duplicates PathID %q — refuse to start: each profile must have a unique URL segment so the router can dispatch unambiguously", i, p.PathID)
			}
			seenESTPath[p.PathID] = true
			if p.IssuerID == "" {
				return fmt.Errorf("EST profile %d (PathID=%q) has empty IssuerID — refuse to start: each EST profile must bind to a configured issuer", i, p.PathID)
			}
			// Phase 2: when mTLS is enabled, the trust bundle path must be
			// set. The Phase 2 preflight in cmd/server/main.go validates
			// the file itself (exists, parseable PEM, ≥1 cert, none
			// expired); this gate is the structural-config refuse,
			// defense in depth — without it an operator who flips
			// MTLS_ENABLED=true but forgets to set
			// MTLS_CLIENT_CA_TRUST_BUNDLE_PATH would get every mTLS
			// enrollment rejected at runtime with no trust anchor
			// configured.
			if p.MTLSEnabled && p.MTLSClientCATrustBundlePath == "" {
				return fmt.Errorf("EST profile %d (PathID=%q) has MTLSEnabled=true but MTLS_CLIENT_CA_TRUST_BUNDLE_PATH is empty — refuse to start: the mTLS sibling route /.well-known/est-mtls/%s/ would have no client-cert trust anchor", i, p.PathID, p.PathID)
			}
			// Channel-binding is meaningful only when mTLS is in use (RFC
			// 9266 binds the TLS-presented client cert to the CSR's CMC
			// id-aa-channelBindings attribute). Channel-binding-required-
			// without-mTLS is operator confusion; refuse at boot so the
			// intent is unambiguous.
			if p.ChannelBindingRequired && !p.MTLSEnabled {
				return fmt.Errorf("EST profile %d (PathID=%q) has ChannelBindingRequired=true but MTLSEnabled=false — refuse to start: RFC 9266 channel binding is meaningful only when mTLS is in use; either enable mTLS (set MTLS_ENABLED=true + MTLS_CLIENT_CA_TRUST_BUNDLE_PATH) or disable the channel-binding requirement", i, p.PathID)
			}
			// AllowedAuthModes shape: every entry must be a known mode.
			// Empty slice is allowed (Phase 1 preserves the unauthenticated
			// default for back-compat); Phase 3 docs nudge operators to set
			// this explicitly, and a future bundle may flip the default to
			// require explicit opt-in.
			for _, mode := range p.AllowedAuthModes {
				if !validESTAuthMode(mode) {
					return fmt.Errorf("EST profile %d (PathID=%q) has unknown AllowedAuthModes entry %q — refuse to start: valid modes are \"mtls\" + \"basic\" (Phase 2/3 of the EST hardening bundle wire each)", i, p.PathID, mode)
				}
			}
			// Cross-check: when AllowedAuthModes mentions "mtls", the
			// profile's MTLSEnabled MUST be true (otherwise the auth mode
			// references infrastructure the operator hasn't configured).
			// Conversely, "basic" in AllowedAuthModes requires a non-empty
			// EnrollmentPassword (Phase 3 will ALSO refuse a configured
			// "basic" mode without a password; we duplicate the gate here
			// for defense in depth).
			authModeIndex := map[string]bool{}
			for _, mode := range p.AllowedAuthModes {
				authModeIndex[mode] = true
			}
			if authModeIndex["mtls"] && !p.MTLSEnabled {
				return fmt.Errorf("EST profile %d (PathID=%q) lists \"mtls\" in AllowedAuthModes but MTLSEnabled=false — refuse to start: enable mTLS or remove \"mtls\" from the auth-mode list", i, p.PathID)
			}
			if authModeIndex["basic"] && p.EnrollmentPassword == "" {
				return fmt.Errorf("EST profile %d (PathID=%q) lists \"basic\" in AllowedAuthModes but ENROLLMENT_PASSWORD is empty — refuse to start: HTTP Basic auth needs a per-profile shared secret (set CERTCTL_EST_PROFILE_<NAME>_ENROLLMENT_PASSWORD)", i, p.PathID)
			}
			// RateLimitPerPrincipal24h ≥ 0. Negative is a config typo;
			// zero means 'disabled' (allowed for tests + the rare operator
			// who wants no per-device cap, mirrors SCEP's same default).
			if p.RateLimitPerPrincipal24h < 0 {
				return fmt.Errorf("EST profile %d (PathID=%q) has RATE_LIMIT_PER_PRINCIPAL_24H=%d — refuse to start: must be ≥0 (zero disables the per-principal cap, positive values enforce it)", i, p.PathID, p.RateLimitPerPrincipal24h)
			}
			// ServerKeygenEnabled requires an explicit ProfileID + the
			// referenced CertificateProfile to pin AllowedKeyAlgorithms
			// (the server has to decide what algorithm to generate). The
			// presence of the CertificateProfile in the registry is checked
			// at boot by the Phase 5 preflight; here we just gate the
			// presence of ProfileID.
			if p.ServerKeygenEnabled && p.ProfileID == "" {
				return fmt.Errorf("EST profile %d (PathID=%q) has SERVERKEYGEN_ENABLED=true but PROFILE_ID is empty — refuse to start: server-side keygen needs a CertificateProfile to pin AllowedKeyAlgorithms (the server must know what key to generate)", i, p.PathID)
			}
		}
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

	// I-005: guard against a misconfigured retry sweep that would either
	// spin-wait or never fire. Matches the NotificationProcessInterval
	// minimum (1s) so operators can tune both knobs from the same floor.
	if c.Scheduler.NotificationRetryInterval < 1*time.Second {
		return fmt.Errorf("notification retry interval must be at least 1 second")
	}

	if c.Scheduler.RetryInterval < 1*time.Second {
		return fmt.Errorf("retry interval must be at least 1 second")
	}

	if c.Scheduler.JobTimeoutInterval < 1*time.Second {
		return fmt.Errorf("job timeout interval must be at least 1 second")
	}

	if c.Scheduler.AwaitingCSRTimeout < 1*time.Second {
		return fmt.Errorf("awaiting CSR timeout must be at least 1 second")
	}

	if c.Scheduler.AwaitingApprovalTimeout < 1*time.Second {
		return fmt.Errorf("awaiting approval timeout must be at least 1 second")
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

// ParseNamedAPIKeys parses the CERTCTL_API_KEYS_NAMED environment variable.
// Format: "name1:key1,name2:key2:admin,name3:key3"
// The ":admin" suffix is optional; if present, the key has admin privileges.
// Returns a typed []NamedAPIKey so main.go can pass it directly to the
// middleware layer without type assertion gymnastics.
//
// Audit L-004 (CWE-924) — graceful key rotation contract:
//
//	Two entries MAY share the same Name during a rotation overlap window:
//	    CERTCTL_API_KEYS_NAMED="alice:OLDKEY:admin,alice:NEWKEY:admin"
//	When duplicates appear, both keys validate at the auth middleware
//	(NewAuthWithNamedKeys iterates every entry on every request, so the
//	match is by hash regardless of name collisions). Both produce the
//	same UserKey context value (the shared name), which keeps the audit
//	trail and per-user rate-limit bucket (Bundle B M-025) consistent
//	across the rollover.
//
//	The duplicate-name path is restricted: every entry sharing a name
//	MUST carry the same admin flag — mixing admin=true with admin=false
//	under the same identity would let a non-admin caller present the
//	admin-flagged key and bypass the gate (or vice-versa). The contract
//	is "rotate ONE key at a time"; the privilege level stays constant
//	within the overlap window.
//
//	Exact (name,key) duplicates are still rejected — that's a typo,
//	not a rotation. Rotation requires DIFFERENT keys under the same
//	name.
//
//	Once the rollover is complete, the operator removes the OLDKEY
//	entry and restarts. Single-entry steady state resumes.
//
//	See docs/security.md::API key rotation for the full operator runbook.
func ParseNamedAPIKeys(input string) ([]NamedAPIKey, error) {
	if input == "" {
		return nil, nil
	}

	parts := splitComma(input)
	var keys []NamedAPIKey
	// nameToAdmin pins the admin flag for any name we've seen before; it
	// is consulted on subsequent duplicate-name entries to enforce the
	// "matching admin" contract above.
	nameToAdmin := make(map[string]bool)
	// nameSeen records whether we've seen a name at all (used to
	// distinguish first-occurrence from duplicate-occurrence; we need
	// this separate from nameToAdmin because admin=false is a valid
	// recorded state).
	nameSeen := make(map[string]bool)
	// pairSeen rejects exact (name,key) duplicates as typos.
	pairSeen := make(map[string]bool)

	for _, part := range parts {
		part = trimSpace(part)
		if part == "" {
			continue
		}

		// Split by colon: name:key or name:key:admin
		fields := strings.Split(part, ":")
		if len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf("invalid named key format: %s (expected name:key or name:key:admin)", part)
		}

		name := trimSpace(fields[0])
		key := trimSpace(fields[1])
		admin := false

		if len(fields) == 3 {
			adminStr := trimSpace(fields[2])
			if adminStr == "admin" {
				admin = true
			} else {
				return nil, fmt.Errorf("invalid admin flag: %s (expected 'admin')", adminStr)
			}
		}

		// Validate name format: alphanumeric, hyphens, underscores
		if !isValidKeyName(name) {
			return nil, fmt.Errorf("invalid key name: %s (must be alphanumeric, hyphens, underscores)", name)
		}

		if key == "" {
			return nil, fmt.Errorf("empty key for name: %s", name)
		}

		// Typo guard: same (name,key) pair twice is never legitimate —
		// rotation requires DIFFERENT keys under the same name.
		pairKey := name + "\x00" + key
		if pairSeen[pairKey] {
			return nil, fmt.Errorf("duplicate (name,key) entry for name %q — rotation requires DIFFERENT keys under the same name", name)
		}
		pairSeen[pairKey] = true

		// Duplicate-name path: allowed iff admin flag matches the prior
		// entry for the same name (L-004 rotation overlap contract).
		if nameSeen[name] {
			priorAdmin := nameToAdmin[name]
			if priorAdmin != admin {
				return nil, fmt.Errorf("duplicate key name %q with mismatched admin flag — rotation overlap requires both entries carry the same privilege level (prior=%v, this=%v)", name, priorAdmin, admin)
			}
		} else {
			nameSeen[name] = true
			nameToAdmin[name] = admin
		}

		keys = append(keys, NamedAPIKey{
			Name:  name,
			Key:   key,
			Admin: admin,
		})
	}

	// Rotation-window observability: emit a one-shot startup INFO log
	// per name with multiple entries so operators can see the active
	// overlap state in logs. (Single-entry steady state stays silent.)
	nameCounts := make(map[string]int)
	for _, k := range keys {
		nameCounts[k.Name]++
	}
	for name, count := range nameCounts {
		if count > 1 {
			slog.Info("api-key rotation window active",
				"name", name,
				"entries", count,
				"see", "docs/security.md::api-key-rotation",
			)
		}
	}

	return keys, nil
}

// isValidKeyName checks if a key name is valid (alphanumeric, hyphens, underscores).
func isValidKeyName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
