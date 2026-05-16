// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"net"
	"time"
)

// Phase 9 ARCH-M2 closure Sprint 6 (2026-05-14): extracted from
// config.go. Sprint 6 groups the server-tier infrastructure structs
// — the things that configure HOW the server runs (HTTP listener,
// TLS, DB pool, scheduler loops, log level, rate limiting, CORS)
// rather than WHAT it serves (issuer configs, ACME, SCEP, EST,
// auth identity).
//
// Seven structs + one unexported helper move:
//
//   ServerConfig       — HTTP listener (Host, Port, MaxBodySize,
//                        TLS sub-struct, AuditFlushTimeoutSeconds).
//   ServerTLSConfig    — HTTPS-only TLS material (CertPath +
//                        KeyPath). HTTPS-everywhere milestone: no
//                        plaintext fallback, no dual-listener.
//   DatabaseConfig     — DB connection + pool settings + DemoSeed
//                        toggle for the compose demo overlay.
//   SchedulerConfig    — all 15 scheduler-loop tunables + the
//                        per-tick concurrency cap + the deploy/
//                        connector timeouts that ride the same
//                        env-var family.
//   LogConfig          — Level + Format (info/json defaults).
//   RateLimitConfig    — Bundle B / M-025: per-key token bucket
//                        with separate IP-keyed + user-keyed
//                        budgets.
//   CORSConfig         — AllowedOrigins (deny-by-default empty).
//
//   isLoopbackAddr()   — HIGH-12 demo-mode startup guard helper.
//                        Returns true ONLY for 127.0.0.1 / ::1 /
//                        "localhost"; everything else (including
//                        0.0.0.0, ::, and hostnames that aren't
//                        "localhost") returns false. Same-package
//                        caller is Validate() in config.go which
//                        gates Type=none on non-loopback binds.
//                        Test caller in config_test.go is also
//                        package `config` so the unexported callable
//                        surface stays accessible.
//
// What stayed in config.go
// ========================
// - ApprovalConfig — RBAC-related (issuance-approval workflow), not
//   server-tier infrastructure. Sits between SchedulerConfig and
//   LogConfig in the original file ordering; Sprint 6's two-pass
//   sed deliberately preserves it where it is. Candidate for a
//   future Auth/RBAC follow-up cut if the operator wants the
//   approval surface adjacent to AuthConfig.
// - The Validate() body that uses isLoopbackAddr to gate
//   CERTCTL_AUTH_TYPE=none — cross-cutting validation logic stays
//   in config.go.
// - The Load() body that synthesizes ServerConfig / ServerTLSConfig
//   / DatabaseConfig / SchedulerConfig / LogConfig / RateLimitConfig
//   / CORSConfig from env vars via the shared getEnv* helpers.
// - The shared getEnv* helpers (getEnv / getEnvBool / getEnvInt /
//   getEnvDuration / getEnvFloat / getEnvInt64 / getEnvList).
//
// Import-graph hygiene
// ====================
// isLoopbackAddr is the ONLY user of the `net` package in config.go.
// After this move, config.go's `net` import becomes unused; the
// Sprint 6 commit removes it from config.go's import block. server.go
// imports `net` directly. The `time` import in config.go stays
// because other configs (notably ApprovalConfig isn't time-typed but
// SCEP/EST helpers in their respective .go files import their own
// `time`; config.go retains `time.Duration` uses in OCSPResponderConfig,
// DigestConfig, HealthCheckConfig, NetworkScanConfig, VerificationConfig,
// and the various issuer-specific configs that haven't been split yet).
//
// Public-surface invariant
// ========================
// Every type, exported field, and doc-comment is byte-identical to
// pre-split. Package stays `config`. Every external caller of
// `config.ServerConfig` / `config.ServerTLSConfig` / etc. resolves
// the same way. The unexported `isLoopbackAddr` is invisible to
// package consumers; its same-package caller (Validate in config.go)
// + its test (config_test.go in package `config`) continue to
// resolve via the package symbol table.

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

	// JobClaimLimit caps the number of Pending rows a single
	// scheduler tick may claim via repository.JobRepository.ClaimPendingJobs.
	// Default 1000.
	//
	// SCALE-001 closure (Sprint 2, 2026-05-16). Pre-fix the scheduler
	// invoked ClaimPendingJobs with limit:0, which loads every Pending
	// row in a single transaction. A 100K-job burst (cert-fleet sweep,
	// post-outage recovery, etc.) would marshal the full queue into
	// process memory before boundedFanOut's semaphore could back-
	// pressure the upstream CAs. Capping the claim per tick keeps
	// memory bounded; the next tick (JobProcessorInterval=30s default)
	// picks up the rest.
	//
	// Operator-tune: bump for very-large-fleet deploys where 1000
	// per 30s isn't enough throughput. Values ≤ 0 fall back to 1000
	// rather than the legacy unlimited semantics — fail-safe.
	//
	// Setting: CERTCTL_SCHEDULER_JOB_CLAIM_LIMIT environment variable.
	JobClaimLimit int

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

	// BucketTTL bounds the unused-bucket lifetime in the token-bucket
	// map. Idle buckets older than BucketTTL are reclaimed by a
	// background sweeper running every (BucketTTL/4). Default 1 hour;
	// values < 1 minute are clamped up to 1 minute in the limiter
	// constructor. Set this lower if the server faces high-cardinality
	// unauthenticated traffic (CGNAT churn, Tor exit lists, scanners)
	// and the map RSS becomes a concern.
	// SEC-006 closure (Sprint 2, 2026-05-16).
	// Setting: CERTCTL_RATE_LIMIT_BUCKET_TTL environment variable.
	BucketTTL time.Duration

	// SlidingWindowBackend selects which backend implements the
	// per-key sliding-window-log limiters wired in cmd/server/main.go
	// (break-glass login, OCSP per-IP, cert-export per-actor, EST
	// per-principal, EST failed-basic source-IP). Distinct from the
	// token-bucket fields above — those are middleware RPS limits
	// applied across every request via the http handler chain; this
	// field controls the sliding-window-log primitive used by
	// authenticated-but-shared-credential code paths.
	//
	// Valid values:
	//   "memory"   — per-process, sync.Mutex-guarded map (historical
	//                default; perfect for single-replica deploys).
	//   "postgres" — cross-replica-consistent via the
	//                rate_limit_buckets table (migration 000046).
	//                SELECT FOR UPDATE arbitrates per-key access
	//                across the cluster. Adds ~2 DB round-trips per
	//                Allow call; acceptable on the gated hot path.
	//
	// Default: "memory". HA deploys with server.replicas > 1 should
	// flip to "postgres" so a 2-replica deployment doesn't effectively
	// double the per-key cap.
	//
	// Phase 13 Sprint 13.2/13.3 closure (architecture diligence audit
	// ARCH-M1). See docs/operator/observability.md.
	//
	// Setting: CERTCTL_RATE_LIMIT_BACKEND environment variable.
	SlidingWindowBackend string

	// SlidingWindowJanitorInterval is how often the scheduler sweeps
	// stale rows from rate_limit_buckets. A row is stale when its
	// updated_at is older than the longest configured window any
	// caller uses (currently 24h for the EST per-principal limiter).
	// Default: 5 minutes. Minimum: 1 minute. No-op when
	// SlidingWindowBackend = "memory" (the in-memory backend's
	// prune-on-Allow path keeps buckets short-lived without a
	// separate sweep).
	//
	// Setting: CERTCTL_RATE_LIMIT_JANITOR_INTERVAL environment variable.
	SlidingWindowJanitorInterval time.Duration
}

// CORSConfig contains CORS configuration.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins for CORS requests.
	// Security default: empty list denies all CORS requests (same-origin only).
	// ["*"] allows all origins (development/demo mode only, security risk).
	// Specific origins (e.g., ["https://app.example.com"]) whitelist only those origins.
	AllowedOrigins []string
}

// isLoopbackAddr returns true when host is bound to a loopback
// interface only (127.0.0.1, ::1, or "localhost"). Used by the
// HIGH-12 demo-mode startup guard to refuse non-loopback binds when
// CERTCTL_AUTH_TYPE=none is in effect.
//
// "" (unset) AND "0.0.0.0" / "::" / "[::]" return false because those
// surface the listener to every interface — exactly the misconfiguration
// the guard is designed to catch.
//
// Hostnames other than "localhost" return false defensively: a hostname
// could resolve to a non-loopback IP at runtime; we don't perform DNS
// here because the guard runs at startup before any network state is
// available, and we don't want a misconfigured /etc/hosts to silently
// pass the guard. Operators wanting to bind to a non-default loopback
// alias must either use 127.0.0.1 / ::1 directly or set
// CERTCTL_DEMO_MODE_ACK=true.
func isLoopbackAddr(host string) bool {
	switch host {
	case "":
		// Empty / unset host — Go's net/http.Server treats this as
		// "all interfaces" (equivalent to 0.0.0.0). Surface it to the
		// network → not loopback.
		return false
	case "0.0.0.0", "::", "[::]":
		return false
	case "localhost":
		return true
	}
	// Strip a trailing :port if the operator passed a host:port pair
	// rather than a bare host (defensive — Server.Host is documented
	// as host-only, but be lenient).
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// Hostname that isn't "localhost" — fail closed.
	return false
}
