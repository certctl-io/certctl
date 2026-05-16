// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Phase 2 (Default Hardening + Operator Docs) introduced three new
// error sentinels surfaced by Validate(). Tests pin them by
// errors.Is(err, ErrX) AND by message-text match for double safety;
// downstream callers may inspect the wrapped chain to react to a
// specific failure class without parsing the user-facing message.
//
// All three are staged behavior. Their default in this release is
// "off / opt-in" — production deploys must explicitly acknowledge to
// activate. The default-flip schedule lives in WORKSPACE-ROADMAP.md.
var (
	// ErrAgentBootstrapTokenRequired is returned by Validate() when
	// CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY=true and the token is
	// empty. Phase 2 SEC-H1 closure — staged feature flag (default
	// false this release; default true scheduled for v2.2.0).
	ErrAgentBootstrapTokenRequired = errors.New(
		"CERTCTL_AGENT_BOOTSTRAP_TOKEN is empty and CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY=true — refuse to start. " +
			"Generate a real secret (e.g. openssl rand -base64 32) and set CERTCTL_AGENT_BOOTSTRAP_TOKEN, " +
			"or unset CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY to keep the warn-mode pass-through default",
	)

	// ErrACMEInsecureWithoutAck is returned by Validate() when
	// CERTCTL_ACME_INSECURE=true and CERTCTL_ACME_INSECURE_ACK is missing
	// or false. Phase 2 SEC-M4 closure: upgrade the existing boot-time
	// WARN log to a hard refuse-to-start gate behind an explicit ACK.
	ErrACMEInsecureWithoutAck = errors.New(
		"CERTCTL_ACME_INSECURE=true but CERTCTL_ACME_INSECURE_ACK is not true — refuse to start. " +
			"ACME directory TLS verification is DISABLED; every round-trip skips certificate chain validation. " +
			"Production deploys MUST NOT enable this. To unlock for dev / Pebble / step-ca with self-signed roots, " +
			"set CERTCTL_ACME_INSECURE_ACK=true alongside CERTCTL_ACME_INSECURE=true",
	)

	// ErrDemoModeAckExpired is returned by Validate() when
	// DemoModeAck=true and CERTCTL_DEMO_MODE_ACK_TS is missing or older
	// than 24h. Phase 2 SEC-H3 closure: the sticky DemoModeAck bit now
	// expires, forcing operators of accidentally-promoted demo
	// deployments to re-acknowledge the synthetic-admin posture daily.
	ErrDemoModeAckExpired = errors.New(
		"CERTCTL_DEMO_MODE_ACK=true requires CERTCTL_DEMO_MODE_ACK_TS=<unix-epoch> set within the last 24h — refuse to start. " +
			"This guard catches forgotten demo deployments accidentally left in production. " +
			"Set CERTCTL_DEMO_MODE_ACK_TS=$(date +%s) at every compose-up; the demo compose helper script does this automatically",
	)
)

// demoModeAckMaxAge is the maximum allowable age of
// CERTCTL_DEMO_MODE_ACK_TS before the demo-mode ACK is considered
// expired. Hard-coded at 24h per Phase 2 SEC-H3.
const demoModeAckMaxAge = 24 * time.Hour

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
	// AuditChain holds the Sprint 6 COMP-001-HASH chain-verify tick
	// cadence. Scheduler loop auditChainVerifyLoop reads VerifyInterval;
	// the metric-side counter is wired separately in cmd/server/main.go.
	AuditChain AuditChainConfig
	// UserRetention holds the Sprint 6 COMP-002-RETENTION purge cadence
	// + window. The scheduler's userRetentionLoop reads Interval; the
	// UserRetentionService reads RetentionWindow + BatchCap.
	UserRetention UserRetentionConfig
	// Network holds outbound-egress policy tunables. Acquisition-audit
	// SEC-009 + RED-005 closure (Sprint 5 ACQ, 2026-05-16). Today the
	// only field is BlockRFC1918Outbound; future egress-policy knobs
	// (per-host allowlists, max-dial-time overrides) go here.
	Network NetworkConfig
	// Observability holds the optional OpenTelemetry seed config.
	// Acquisition-audit DEPL-006 closure (Sprint 6 ACQ, 2026-05-16).
	// Default Enabled=false — operators opt in via CERTCTL_OTEL_ENABLED=true.
	Observability ObservabilityConfig
}

// ObservabilityConfig is the operator-facing config surface for the
// OTel seed. Acquisition-audit DEPL-006 closure (Sprint 6 ACQ,
// 2026-05-16). Plumbed through to internal/observability.Init at
// boot from cmd/server/main.go.
//
// The single gate is CERTCTL_OTEL_ENABLED. Everything else (endpoint,
// headers, protocol, service name, resource attributes) flows
// through the standard OTEL_* env vars the OTel SDK's
// resource.WithFromEnv + otlptracehttp.New honor directly — no
// certctl-specific re-implementation of those env vars (avoids the
// "lying field" footgun where an env var exists in code but doesn't
// reach the consumer).
type ObservabilityConfig struct {
	// OTelEnabled gates the optional OpenTelemetry tracer-provider
	// initialization. Default false (zero behavior change for
	// operators who don't opt in). When true, the boot path wires
	// up an OTLP/HTTP exporter and registers it as the otel global
	// tracer provider. CERTCTL_OTEL_ENABLED.
	//
	// Per-handler / per-query / per-connector span instrumentation
	// is NOT added by Sprint 6 — this commit stands up the surface
	// only; instrumentation is a v2.3 follow-up. Operators who
	// enable the toggle today will see process-level resource
	// attributes and (eventually) any spans the OTel SDK emits
	// from its own internal paths, but no certctl-domain spans
	// until the v2.3 work lands.
	OTelEnabled bool
}

// NetworkConfig is the outbound-egress policy surface for certctl.
// Acquisition-audit SEC-009 + RED-005 closure (Sprint 5 ACQ,
// 2026-05-16).
type NetworkConfig struct {
	// BlockRFC1918Outbound, when true, extends the SSRF reserved-IP
	// gate (internal/validation/ssrf.go::IsReservedIP) to include the
	// three RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12,
	// 192.168.0.0/16). Default false (preserves the certctl threat-
	// model default that RFC1918 is legitimate destination space).
	// Operators on hosted IaaS where RFC1918 is internal trust
	// (Kubernetes service CIDRs that expose the API server inside
	// RFC1918, internal-only monitoring stacks, etc.) opt in via
	// CERTCTL_BLOCK_RFC1918_OUTBOUND=true. Wired at boot from
	// cmd/server/main.go via validation.SetBlockRFC1918Outbound.
	//
	// IMPORTANT: enabling this also blocks RFC1918 from the certctl
	// network scanner. Operators who scan their own RFC1918 space
	// for cert-discovery MUST leave this disabled.
	BlockRFC1918Outbound bool
}

// AuditChainConfig configures the audit_events tamper-evidence
// chain-verify scheduler loop (Sprint 6 COMP-001-HASH closure).
//
// The walk runs migration 000047's audit_events_verify_chain()
// plpgsql function entirely server-side and emits the
// certctl_audit_chain_break_detected_total counter on any detection.
type AuditChainConfig struct {
	// VerifyInterval is the tick cadence for the chain-verify sweep.
	// Default 6h. Operators with huge audit_events tables (millions of
	// rows) may want to lengthen; operators with stricter detection
	// targets may shorten — the walk is O(N) plpgsql and finishes in
	// seconds even at the 1M-row mark.
	// Setting: CERTCTL_AUDIT_CHAIN_VERIFY_INTERVAL.
	VerifyInterval time.Duration
}

// UserRetentionConfig configures the Sprint 6 COMP-002-RETENTION user
// PII purge sweeper. The scheduler's userRetentionLoop walks every
// user with deactivated_at older than RetentionWindow and scrubs the
// PII columns via UserRetentionService.DeleteUserPII.
type UserRetentionConfig struct {
	// Interval is the tick cadence. Default 24h.
	// Setting: CERTCTL_USER_RETENTION_INTERVAL.
	Interval time.Duration
	// RetentionWindow is how long after deactivated_at a row's PII
	// stays in the table. Default 30 days. Operators with strict
	// GDPR / CCPA expectations may shorten; operators who need
	// forensic recovery latitude may lengthen.
	// Setting: CERTCTL_USER_RETENTION_WINDOW.
	RetentionWindow time.Duration
	// BatchCap bounds how many users a single tick processes. Default
	// 200 — keeps blast radius predictable. Set to 0 to disable the
	// cap (test fixtures only).
	// Setting: CERTCTL_USER_RETENTION_BATCH_CAP.
	BatchCap int
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
			// DEPL-004 closure (Sprint 3, 2026-05-16). The Helm chart's
			// _helpers.tpl renders the bundled-Postgres URL with a literal
			// `$(POSTGRES_PASSWORD)` placeholder (see
			// deploy/helm/certctl/templates/_helpers.tpl line 133). The
			// Kubernetes env-substitution `$(VAR)` syntax ONLY expands
			// when the value is a string literal in `env:` — values
			// sourced from Secrets (via `valueFrom.secretKeyRef`) are
			// passed through verbatim with no expansion. Pre-fix the
			// server received the literal "postgres://user:$(POSTGRES_PASSWORD)@..."
			// string and tried to dial Postgres with that as the password,
			// failing with auth error and leaking the placeholder into
			// error logs. expandDatabaseURL substitutes the placeholder
			// with os.Getenv("POSTGRES_PASSWORD") when present; external-
			// Postgres deploys that bake the password directly into the
			// URL string are unaffected because there is no placeholder
			// to match.
			URL: expandDatabaseURL(getEnv("CERTCTL_DATABASE_URL", "postgres://localhost/certctl")),
			// Phase 6 SCALE-M1 closure (2026-05-14): bumped default from
			// 25 → 50 to relieve pool-saturation pressure on 1K+ agent /
			// 10K+ cert fleets. Postgres default max_connections is 100
			// on the smallest tier; 50 leaves headroom for backups, ad-hoc
			// psql sessions, and one extra server replica without
			// exhausting the DB-side cap. Operator-tune ladder for larger
			// fleets documented in docs/operator/scale.md.
			MaxConnections: getEnvInt("CERTCTL_DATABASE_MAX_CONNS", 50),
			MigrationsPath: getEnv("CERTCTL_DATABASE_MIGRATIONS_PATH", "./migrations"),
			DemoSeed:       getEnvBool("CERTCTL_DEMO_SEED", false),
		},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval: getEnvDuration("CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL", 1*time.Hour),
			JobProcessorInterval: getEnvDuration("CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL", 30*time.Second),
			// Audit fix #9 — per-tick concurrency cap on the renewal/issuance/
			// deployment goroutine fan-out. ≤0 → 1 (sequential).
			RenewalConcurrency: getEnvInt("CERTCTL_RENEWAL_CONCURRENCY", 25),
			// SCALE-001 closure (Sprint 2, 2026-05-16) — per-tick claim cap on
			// the scheduler's ClaimPendingJobs sweep. Default 1000 keeps the
			// fan-out busy (≈40× the renewal-concurrency cap) without
			// page-thrashing on a 100K-job burst. ≤0 → 1000 (fail-safe).
			JobClaimLimit:               getEnvInt("CERTCTL_SCHEDULER_JOB_CLAIM_LIMIT", 1000),
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
			// Audit 2026-05-10 HIGH-12 closure: required-true to allow
			// CERTCTL_AUTH_TYPE=none with a non-loopback listen address.
			DemoModeAck:   getEnvBool("CERTCTL_DEMO_MODE_ACK", false),
			DemoModeAckTS: getEnv("CERTCTL_DEMO_MODE_ACK_TS", ""),
			// Audit 2026-05-11 A-8 closure: when true, the preflight
			// residual-grants detector refuses startup if actor-demo-anon
			// has any actor_roles rows. Default false (WARN-only).
			DemoModeResidualStrict: getEnvBool("CERTCTL_DEMO_MODE_RESIDUAL_STRICT", false),
			// LOW-5: XFF trust allowlist (CIDRs). Empty = ignore XFF.
			TrustedProxies: getEnvList("CERTCTL_TRUSTED_PROXIES", nil),
			// NamedKeys is populated from CERTCTL_API_KEYS_NAMED below so Load()
			// can surface parse errors alongside other config errors.

			// Bundle-5 / Audit H-007 + acquisition-audit RED-003 closure
			// (Sprint 5 ACQ, 2026-05-16): agent-registration bootstrap
			// secret. The deny-empty default flipped from false → true
			// on 2026-05-16. Operators upgrading from v2.1.x can re-
			// open the warn-mode escape hatch by explicitly setting
			// CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY=false (one
			// upgrade window); see CHANGELOG v2.2.0 for the migration
			// note. Demo mode (CERTCTL_DEMO_MODE_ACK=true) keeps the
			// pre-flip warn-mode for the screenshot path — see
			// Validate() for the override site.
			AgentBootstrapToken:          getEnv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", ""),
			AgentBootstrapTokenDenyEmpty: getEnvBool("CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY", true),
			// Bundle 1 Phase 6: one-shot bootstrap token for the
			// /v1/auth/bootstrap endpoint that mints the first admin
			// key. Empty = bootstrap endpoint disabled (default).
			BootstrapToken: getEnv("CERTCTL_BOOTSTRAP_TOKEN", ""),
			// Bundle 2 Phase 7: OIDC-first-admin bootstrap. When the
			// configured group list is non-empty, the first OIDC
			// login that carries any of those groups is auto-granted
			// r-admin. Coexists with BootstrapToken.
			BootstrapAdminGroups:    getEnvList("CERTCTL_BOOTSTRAP_ADMIN_GROUPS", nil),
			BootstrapOIDCProviderID: getEnv("CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID", ""),
			// Bundle 2 Phase 4: session-service tunables. Defaults match
			// the prompt; high-security deployments tighten via the env
			// vars documented on SessionConfig fields.
			Session: SessionConfig{
				IdleTimeout:         getEnvDuration("CERTCTL_SESSION_IDLE_TIMEOUT", 1*time.Hour),
				AbsoluteTimeout:     getEnvDuration("CERTCTL_SESSION_ABSOLUTE_TIMEOUT", 8*time.Hour),
				SigningKeyRetention: getEnvDuration("CERTCTL_SESSION_SIGNING_KEY_RETENTION", 24*time.Hour),
				GCInterval:          getEnvDuration("CERTCTL_SESSION_GC_INTERVAL", 1*time.Hour),
				SameSite:            getEnv("CERTCTL_SESSION_SAMESITE", "Lax"),
				BindIP:              getEnvBool("CERTCTL_SESSION_BIND_IP", false),
				BindUserAgent:       getEnvBool("CERTCTL_SESSION_BIND_USER_AGENT", false),
			},
			// Audit 2026-05-10 HIGH-3 — BCL iat-skew window.
			OIDCBCLMaxAgeSeconds: getEnvInt("CERTCTL_OIDC_BCL_MAX_AGE_SECONDS", 60),

			// Audit 2026-05-10 MED-16 — pre-login UA/IP binding toggles.
			OIDCPreLoginRequireUA: getEnvBool("CERTCTL_OIDC_PRELOGIN_REQUIRE_UA", true),
			OIDCPreLoginRequireIP: getEnvBool("CERTCTL_OIDC_PRELOGIN_REQUIRE_IP", true),
			// Bundle 2 Phase 7.5: break-glass admin tunables. Default-
			// OFF; the entire surface is invisible (404 NOT 403) when
			// Enabled=false. Threat model + recommendation in the
			// BreakglassConfig docstring.
			Breakglass: BreakglassConfig{
				Enabled:              getEnvBool("CERTCTL_BREAKGLASS_ENABLED", false),
				LockoutThreshold:     getEnvInt("CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD", 5),
				LockoutDuration:      getEnvDuration("CERTCTL_BREAKGLASS_LOCKOUT_DURATION", 15*time.Minute),
				LockoutResetInterval: getEnvDuration("CERTCTL_BREAKGLASS_LOCKOUT_RESET_INTERVAL", 1*time.Hour),
			},
		},
		RateLimit: RateLimitConfig{
			Enabled:          getEnvBool("CERTCTL_RATE_LIMIT_ENABLED", true),
			RPS:              getEnvFloat("CERTCTL_RATE_LIMIT_RPS", 50),
			BurstSize:        getEnvInt("CERTCTL_RATE_LIMIT_BURST", 100),
			PerUserRPS:       getEnvFloat("CERTCTL_RATE_LIMIT_PER_USER_RPS", 0),
			PerUserBurstSize: getEnvInt("CERTCTL_RATE_LIMIT_PER_USER_BURST", 0),
			// SEC-006 closure (Sprint 2, 2026-05-16): bounded unused-bucket
			// lifetime. 1h chosen to be well above realistic operator IP
			// churn (returning clients keep their bucket) and well below
			// the unbounded-leak window the pre-fix code allowed.
			BucketTTL:                    getEnvDuration("CERTCTL_RATE_LIMIT_BUCKET_TTL", 1*time.Hour),
			SlidingWindowBackend:         getEnv("CERTCTL_RATE_LIMIT_BACKEND", "memory"),
			SlidingWindowJanitorInterval: getEnvDuration("CERTCTL_RATE_LIMIT_JANITOR_INTERVAL", 5*time.Minute),
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
			// Acquisition-audit DOC-001 closure (Sprint 7 ACQ, 2026-05-16).
			// Wire the previously-orphan webhook notifier
			// (internal/connector/notifier/webhook/) into the boot
			// path. Empty WebhookURL = notifier disabled.
			WebhookURL:    getEnv("CERTCTL_WEBHOOK_URL", ""),
			WebhookSecret: getEnv("CERTCTL_WEBHOOK_SECRET", ""),
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
			InsecureAck:            getEnvBool("CERTCTL_ACME_INSECURE_ACK", false),
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
		AuditChain: AuditChainConfig{
			VerifyInterval: getEnvDuration("CERTCTL_AUDIT_CHAIN_VERIFY_INTERVAL", 6*time.Hour),
		},
		UserRetention: UserRetentionConfig{
			Interval:        getEnvDuration("CERTCTL_USER_RETENTION_INTERVAL", 24*time.Hour),
			RetentionWindow: getEnvDuration("CERTCTL_USER_RETENTION_WINDOW", 30*24*time.Hour),
			BatchCap:        getEnvInt("CERTCTL_USER_RETENTION_BATCH_CAP", 200),
		},
		// Acquisition-audit SEC-009 + RED-005 closure (Sprint 5 ACQ,
		// 2026-05-16). Default false preserves the existing threat-model
		// default (RFC1918 is legitimate destination space); operators
		// on hosted IaaS opt in via CERTCTL_BLOCK_RFC1918_OUTBOUND=true.
		// Wired into validation.SetBlockRFC1918Outbound at boot from
		// cmd/server/main.go.
		Network: NetworkConfig{
			BlockRFC1918Outbound: getEnvBool("CERTCTL_BLOCK_RFC1918_OUTBOUND", false),
		},
		// Acquisition-audit DEPL-006 closure (Sprint 6 ACQ,
		// 2026-05-16). Optional OpenTelemetry seed. Default Enabled=false
		// preserves zero-overhead behavior for operators who don't opt
		// in; the boot path calls observability.Init unconditionally
		// (observability.Init short-circuits to a no-op shutdown when
		// disabled). Operators set CERTCTL_OTEL_ENABLED=true plus the
		// standard OTEL_* env vars (OTEL_EXPORTER_OTLP_ENDPOINT, etc.)
		// to wire spans to their collector. Per-handler / per-query
		// instrumentation is a v2.3 roadmap follow-up; this sprint
		// stands up the surface only.
		Observability: ObservabilityConfig{
			OTelEnabled: getEnvBool("CERTCTL_OTEL_ENABLED", false),
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

	// Phase 13 Sprint 13.3 closure (ARCH-M1): validate
	// CERTCTL_RATE_LIMIT_BACKEND is one of the two supported values.
	// Fail-closed on any other input so a typo doesn't silently fall
	// back to the wrong backend (the operator picked "postgress" and
	// got memory rate-limits in a 3-replica cluster).
	switch c.RateLimit.SlidingWindowBackend {
	case "", "memory", "postgres":
		// "" is treated as "memory" — test-built Configs (which
		// construct the struct literal directly without going
		// through Load()) don't get the default; Load() always
		// fills "memory". Either path lands the runtime on the
		// in-memory backend.
	default:
		return fmt.Errorf(
			"invalid CERTCTL_RATE_LIMIT_BACKEND=%q — refuse to start: must be \"memory\" (default, per-process limits; for single-replica deploys) or \"postgres\" (cross-replica-consistent via the rate_limit_buckets table; required for HA deploys). See docs/operator/observability.md.",
			c.RateLimit.SlidingWindowBackend,
		)
	}
	// Janitor interval lower bound — 1 minute. Below this the sweep
	// cost outweighs the row-cleanup benefit; above this still
	// matches the operator's bound (5 minutes default; can be raised
	// indefinitely).
	if c.RateLimit.SlidingWindowJanitorInterval > 0 &&
		c.RateLimit.SlidingWindowJanitorInterval < time.Minute {
		return fmt.Errorf(
			"invalid CERTCTL_RATE_LIMIT_JANITOR_INTERVAL=%v — refuse to start: must be ≥ 1 minute (default 5m).",
			c.RateLimit.SlidingWindowJanitorInterval,
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

	// Phase 2 SEC-H1 closure (2026-05-13) + acquisition-audit RED-003
	// closure (Sprint 5 ACQ, 2026-05-16): the AgentBootstrapTokenDenyEmpty
	// fail-closed gate. The flag flipped default from false → true on
	// 2026-05-16; operators upgrading from v2.1.x can reopen the
	// warn-mode escape hatch with CERTCTL_AGENT_BOOTSTRAP_TOKEN_DENY_EMPTY=false
	// for one upgrade window. CHANGELOG v2.2.0 documents the cutover.
	//
	// Demo-mode override: a screenshot/demo deploy with
	// CERTCTL_DEMO_MODE_ACK=true skips this guard so the demo path
	// stays one-command-up. The accompanying boot banner WARN in
	// cmd/server/main.go keeps the posture visible — demo deploys
	// already log a prominent "DEMO MODE ACTIVE" line at every boot.
	// Production deploys never set DemoModeAck, so this override
	// cannot inadvertently re-enable warn-mode in production.
	if c.Auth.AgentBootstrapTokenDenyEmpty && c.Auth.AgentBootstrapToken == "" && !c.Auth.DemoModeAck {
		return fmt.Errorf("phase-2 SEC-H1 fail-closed guard: %w", ErrAgentBootstrapTokenRequired)
	}

	// Phase 2 SEC-M4 closure (2026-05-13): convert the existing boot-time
	// WARN log for CERTCTL_ACME_INSECURE=true into a hard refuse-to-start
	// gate behind an explicit ACK env var. The dev-only escape hatch can
	// no longer be flipped accidentally via a copy-pasted Pebble runbook
	// — production deploys must explicitly set both Insecure=true AND
	// InsecureAck=true to acknowledge they understand the consequences.
	// The boot-time WARN log path in cmd/server/main.go continues to fire
	// for the ACK'd case so the operator sees the reminder every restart.
	if c.ACME.Insecure && !c.ACME.InsecureAck {
		return fmt.Errorf("phase-2 SEC-M4 fail-closed guard: %w", ErrACMEInsecureWithoutAck)
	}

	// Phase 2 SEC-H3 closure (2026-05-13): the sticky DemoModeAck bit
	// now expires after demoModeAckMaxAge (24h). When the operator sets
	// CERTCTL_DEMO_MODE_ACK=true, they MUST also set
	// CERTCTL_DEMO_MODE_ACK_TS=$(date +%s) and re-supply it within the
	// 24h window on every restart. The demo compose helper script does
	// this automatically at compose-up. Catches the canonical
	// "forgotten demo deployment promoted to production" failure mode:
	// the next container restart refuses unless the operator re-acks.
	if c.Auth.DemoModeAck {
		if c.Auth.DemoModeAckTS == "" {
			return fmt.Errorf("phase-2 SEC-H3 fail-closed guard (missing TS): %w", ErrDemoModeAckExpired)
		}
		ackEpoch, err := strconv.ParseInt(strings.TrimSpace(c.Auth.DemoModeAckTS), 10, 64)
		if err != nil {
			return fmt.Errorf("phase-2 SEC-H3 fail-closed guard: CERTCTL_DEMO_MODE_ACK_TS=%q must parse as a unix epoch integer (try $(date +%%s)); parse error %w: %w",
				c.Auth.DemoModeAckTS, err, ErrDemoModeAckExpired)
		}
		ackTime := time.Unix(ackEpoch, 0)
		if time.Since(ackTime) > demoModeAckMaxAge {
			return fmt.Errorf("phase-2 SEC-H3 fail-closed guard (TS age %s exceeds %s): %w",
				time.Since(ackTime).Round(time.Second), demoModeAckMaxAge, ErrDemoModeAckExpired)
		}
		// Future-dated timestamps are also rejected — likely operator clock skew
		// or a typo. Allow a small future skew (1m) to absorb minor clock drift.
		if time.Until(ackTime) > time.Minute {
			return fmt.Errorf("phase-2 SEC-H3 fail-closed guard (TS is %s in the future, exceeds 1m clock-skew tolerance): %w",
				time.Until(ackTime).Round(time.Second), ErrDemoModeAckExpired)
		}
	}

	// Audit 2026-05-10 HIGH-12 closure: refuse to start when
	// CERTCTL_AUTH_TYPE=none is bound to a non-loopback address unless
	// the operator explicitly acknowledges the bypass via
	// CERTCTL_DEMO_MODE_ACK=true.
	//
	// Rationale: demo mode wires the synthetic actor `actor-demo-anon`
	// with `AdminKey=true` on every request. The control plane is
	// HTTPS-only, but a misconfigured ingress / public listen-bind
	// means any reachable client gets full admin without authentication.
	// The fail-closed guard converts what was a documentation-only
	// warning into a hard runtime check operators cannot ignore.
	//
	// Localhost / loopback (127.0.0.1, ::1, "localhost") is exempt
	// because the demo `docker compose up` flow legitimately serves
	// the dashboard to the operator's own browser; binding to
	// 0.0.0.0 / :: / a routable IP is what surfaces the admin to the
	// network and triggers the guard.
	if c.Auth.Type == string(AuthTypeNone) {
		if !isLoopbackAddr(c.Server.Host) && !c.Auth.DemoModeAck {
			return fmt.Errorf(
				"CERTCTL_AUTH_TYPE=none with non-loopback CERTCTL_SERVER_HOST=%q "+
					"requires CERTCTL_DEMO_MODE_ACK=true to acknowledge that every "+
					"request will be served as the synthetic admin actor `actor-demo-anon`. "+
					"This is INSECURE — operators must explicitly opt in. Production "+
					"deployments MUST set CERTCTL_AUTH_TYPE to a real authn type "+
					"(api-key | oidc); see docs/operator/security.md for guidance.",
				c.Server.Host)
		}
	}

	// Bundle 2 (2026-05-12) — fail-closed startup guards for placeholder
	// credentials shipped by the demo overlay (docker-compose.demo.yml).
	//
	// Rationale: pre-Bundle-2 the base docker-compose.yml file interpolated
	// these strings as the default value when an operator didn't set
	// CERTCTL_AUTH_SECRET / CERTCTL_API_KEY / CERTCTL_CONFIG_ENCRYPTION_KEY
	// in deploy/.env. The result: `docker compose up` produced a working
	// stack with documented "weak" credentials that nobody actually
	// remembered to rotate before going to production. The Bundle 2 compose
	// split moved those defaults into the demo overlay; the guards below
	// catch any path that still surfaces them in a non-demo deploy (e.g.
	// the .env-example was committed unedited, or a custom compose copied
	// the placeholder verbatim).
	//
	// All three sentinels exactly match the literal strings shipped in
	// deploy/docker-compose.demo.yml. The demo overlay also sets
	// DemoModeAck=true, so the demo path itself is exempt and these
	// strings only fail in production.
	const (
		placeholderAPISecret     = "change-me-in-production"
		placeholderEncryptionKey = "change-me-32-char-encryption-key"
	)
	if !c.Auth.DemoModeAck {
		// HIGH-6 closure (Audit Bundle 2): placeholder API-key secret.
		if c.Auth.Type == string(AuthTypeAPIKey) && c.Auth.Secret == placeholderAPISecret {
			return fmt.Errorf(
				"CERTCTL_AUTH_SECRET is set to the demo placeholder %q — refuse to start. "+
					"Generate a real value with: openssl rand -base64 32. "+
					"This guard exempts demo mode (CERTCTL_DEMO_MODE_ACK=true); production "+
					"deploys MUST rotate.",
				placeholderAPISecret)
		}
		// HIGH-6 closure (Audit Bundle 2): placeholder encryption key.
		if c.Encryption.ConfigEncryptionKey == placeholderEncryptionKey {
			return fmt.Errorf(
				"CERTCTL_CONFIG_ENCRYPTION_KEY is set to the demo placeholder %q — refuse to start. "+
					"Generate a real value with: openssl rand -base64 32 (must be ≥ 32 bytes). "+
					"This guard exempts demo mode (CERTCTL_DEMO_MODE_ACK=true); production "+
					"deploys MUST rotate before any issuer/target credentials are encrypted at rest "+
					"with the placeholder passphrase.",
				placeholderEncryptionKey)
		}
		// LOW-5 closure (Audit Bundle 2): CORS wildcard in non-demo mode.
		// Wildcard CORS combined with credentialed cookies (the session
		// auth Bundle 2 ships) is a CSRF cross-origin escalation channel
		// (CWE-942 + CWE-352). The auth-exempt routes already route through
		// middleware.NewCORS with the operator's allowlist; "*" in the
		// allowlist short-circuits the entire defense. Demo mode is
		// exempt because the demo synthetic actor has no real credentials
		// worth stealing, and demo screencaps frequently want to exercise
		// the dashboard from a Mermaid-rendered URL or whatever.
		for _, origin := range c.CORS.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf(
					"CERTCTL_CORS_ORIGINS contains \"*\" wildcard — refuse to start. " +
						"Wildcard CORS combined with credentialed cookies is a cross-origin " +
						"CSRF / session-theft channel (CWE-942 + CWE-352). Set a concrete " +
						"allowlist (e.g. CERTCTL_CORS_ORIGINS=https://dashboard.example.com) " +
						"or set CERTCTL_DEMO_MODE_ACK=true if this is a demo deploy that " +
						"has no real session credentials worth defending.")
			}
		}
	}

	// Validate keygen mode
	validKeygenModes := map[string]bool{
		"agent":  true,
		"server": true,
	}
	if !validKeygenModes[c.Keygen.Mode] {
		return fmt.Errorf("invalid keygen mode: %s (must be 'agent' or 'server')", c.Keygen.Mode)
	}
	// ARCH-003 closure (Sprint 4, 2026-05-16). README L12 + L82 say
	// "private keys stay on your infrastructure" and "never touch the
	// control plane" as blanket claims. CERTCTL_KEYGEN_MODE=server
	// breaks both claims — the control plane mints the keys directly,
	// in process memory, and writes them to the renewal job for
	// delivery. Pre-fix the server printed a boot WARN and started
	// anyway, so the blanket claim was silently false in any deploy
	// where the operator flipped the flag without reading their logs.
	// Mirror the Phase-2 SEC-H3 DemoModeAck pattern: refuse to boot
	// in server-keygen mode unless the operator has explicitly
	// acknowledged the demo posture via CERTCTL_DEMO_MODE_ACK=true.
	// Bypass for tests that legitimately exercise the server-keygen
	// path: those construct Config directly without going through
	// Validate(), so this gate doesn't fire there.
	if c.Keygen.Mode == "server" && !c.Auth.DemoModeAck {
		return fmt.Errorf(
			"CERTCTL_KEYGEN_MODE=server is demo-only — the control plane mints private keys in process memory, " +
				"breaking the 'keys never touch the control plane' production posture. Set " +
				"CERTCTL_DEMO_MODE_ACK=true + CERTCTL_DEMO_MODE_ACK_TS=$(date +%%s) to acknowledge, " +
				"OR set CERTCTL_KEYGEN_MODE=agent (the default) for production")
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

	// Acquisition-audit SEC-013 closure (Sprint 2, 2026-05-16).
	// Post-validate advisory WARN — NOT fail-closed — when
	// CERTCTL_DATABASE_URL carries sslmode=disable AND the host is
	// external (not loopback / not a known in-cluster service name).
	// The compose bridge network legitimately uses sslmode=disable on
	// the docker-internal hop to postgres:5432; failing closed would
	// break the production-shaped quickstart. The WARN catches the
	// real-world landmine: an operator who points CERTCTL_DATABASE_URL
	// at an RDS / managed-Postgres host outside the bridge network
	// without flipping sslmode to verify-full.
	warnExternalSslmodeDisable(c.Database.URL, slog.Default())

	return nil
}

// dbHostLocalSafelist is the set of hosts where sslmode=disable is an
// acceptable default (loopback + in-cluster service-name conventions).
// SEC-013 closure (Sprint 2 ACQ, 2026-05-16). Match is exact host
// equality except for the .svc.cluster.local suffix which is a
// substring match. Adding entries here is an operator-judgment call;
// keep the list tight (a too-permissive list silences a real
// landmine warning).
var dbHostLocalSafelist = map[string]struct{}{
	"localhost":        {},
	"127.0.0.1":        {},
	"::1":              {},
	"postgres":         {},
	"certctl-postgres": {},
}

// warnExternalSslmodeDisable emits an slog.Warn (matching the
// cmd/server/main.go demo-mode WARN shape) when the database URL
// parses as a Postgres URL with sslmode=disable AND the host is
// outside the local-safelist. The function is intentionally
// permissive on parse failures — if the URL is malformed, the
// downstream sql.Open will surface a clearer error than a noisy
// WARN here would. SEC-013 closure (Sprint 2 ACQ).
func warnExternalSslmodeDisable(rawURL string, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	if rawURL == "" {
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return
	}
	q := u.Query()
	if q.Get("sslmode") != "disable" {
		return
	}
	host := u.Hostname()
	if _, ok := dbHostLocalSafelist[host]; ok {
		return
	}
	// In-cluster service names of the form <name>.svc.cluster.local
	// (or longer K8s cluster-domain variants) are acceptable; the
	// docker-bridge / pod-network hop is treated as trusted by the
	// existing compose + Helm conventions.
	if strings.HasSuffix(host, ".svc.cluster.local") {
		return
	}
	logger.Warn("CERTCTL_DATABASE_URL points at a non-local Postgres host with sslmode=disable — Postgres traffic crosses an untrusted network in cleartext. Set sslmode=verify-full and provide a CA bundle. See docs/operator/database-tls.md for the full upgrade procedure. Override env var: CERTCTL_DATABASE_URL (set the URL with sslmode=verify-full + sslrootcert=<ca-path>).",
		"host", host,
		"sslmode", "disable",
	)
}

// getEnv reads a string environment variable with the given key and default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// expandDatabaseURL substitutes the literal "$(POSTGRES_PASSWORD)"
// placeholder in a database URL with the value of the POSTGRES_PASSWORD
// environment variable. DEPL-004 closure (Sprint 3, 2026-05-16).
//
// Kubernetes ONLY expands `$(VAR)` syntax when the env value is a
// string literal in the Pod spec. Values sourced from
// `valueFrom.secretKeyRef` (which is how the Helm chart wires
// CERTCTL_DATABASE_URL) are NOT expanded — the literal makes it all
// the way to the application. This helper does the expansion in-process
// so the bundled-Postgres flow Just Works without a per-pod entrypoint
// shim.
//
// Conservative: a strings.Replace on exactly one well-known token
// (the chart's `_helpers.tpl` produces `$(POSTGRES_PASSWORD)` and
// nothing else). External-Postgres deploys whose URL embeds the
// real password don't match the placeholder and pass through untouched.
// When POSTGRES_PASSWORD is unset, the URL is left as-is so the
// downstream connection failure is the same as before (and a missing
// password is the operator's mis-config, not our regression).
func expandDatabaseURL(url string) string {
	const placeholder = "$(POSTGRES_PASSWORD)"
	if !strings.Contains(url, placeholder) {
		return url
	}
	pw := os.Getenv("POSTGRES_PASSWORD")
	if pw == "" {
		return url
	}
	return strings.ReplaceAll(url, placeholder, pw)
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
