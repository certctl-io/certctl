# SOC 2 Type II Compliance Mapping

This guide maps certctl's implemented features to AICPA SOC 2 Trust Service Criteria (TSC). It is **not a SOC 2 certification claim** — rather, it helps security engineers, auditors, and evaluators understand how certctl supports your organization's SOC 2 compliance posture. Use this as evidence input for your own control assessment during SOC 2 audits.

## How to Use This Guide

SOC 2 audits require evidence that your infrastructure meets specific Trust Service Criteria. Auditors ask: "Does your certificate management tooling support CC6.1 logical access controls?" This guide answers by mapping certctl's features to specific criteria and pointing to evidence (API endpoints, configuration, audit trail).

Each section includes:

- **The TSC requirement** — what the auditor is looking for
- **certctl's implementation** — which features address it
- **Evidence location** — where to find proof (API endpoint, config variable, source code, audit events)
- **V2 vs V3 status** — whether feature is in the free community edition (V2) or paid Pro edition (V3)
- **Operator responsibility** — aspects your organization must handle outside of certctl

## Contents

1. [How to Use This Guide](#how-to-use-this-guide)
2. [CC6: Logical and Physical Access Controls](#cc6-logical-and-physical-access-controls)
   - [CC6.1 — Logical Access Security](#cc61--logical-access-security)
   - [CC6.2 — Prior to Issuing System Credentials](#cc62--prior-to-issuing-system-credentials)
   - [CC6.3 — Authentication Policies](#cc63--authentication-policies)
   - [CC6.7 — Information Transmission Protection](#cc67--information-transmission-protection)
3. [CC7: System Operations](#cc7-system-operations)
   - [CC7.1 — System Monitoring](#cc71--system-monitoring)
   - [CC7.2 — Anomaly Detection](#cc72--anomaly-detection)
   - [CC7.3 — Incident Response](#cc73--incident-response)
   - [CC7.4 — Identify and Develop Risk Mitigation Activities](#cc74--identify-and-develop-risk-mitigation-activities)
4. [A1: Availability](#a1-availability)
   - [A1.1/A1.2 — Availability and Recovery](#a11a12--availability-and-recovery)
5. [CC8: Change Management](#cc8-change-management)
   - [CC8.1 — Change Control](#cc81--change-control)
6. [Evidence Summary Table](#evidence-summary-table)
7. [What Requires Operator Action](#what-requires-operator-action)
8. [V3 Enhancements](#v3-enhancements)
9. [Conclusion](#conclusion)

## CC6: Logical and Physical Access Controls

### CC6.1 — Logical Access Security

**Requirement**: The entity restricts logical access to digital and information assets and related facilities by applying user identity authentication, registration, access rights, and usage policies.

**certctl Implementation** (V2 — Community Edition):

- **API Key Authentication** — All `/api/v1/*` calls require a Bearer token (hashed with SHA-256, stored securely, validated with constant-time comparison) or are rejected with 401 Unauthorized. Environment: `CERTCTL_AUTH_TYPE` (default `api-key`; `none` requires explicit opt-in with log warning)
- **Standards-based enrollment and PKI distribution endpoints** — EST (`/.well-known/est/*`, RFC 7030), SCEP (`/scep`, `/scep/*`, RFC 8894), and CRL/OCSP (`/.well-known/pki/crl/{issuer_id}`, `/.well-known/pki/ocsp/{issuer_id}/{serial}`, RFC 5280 §5 / RFC 6960 / RFC 8615) are served unauthenticated at the HTTP layer because these protocols cannot present certctl Bearer tokens. Authentication is enforced in-protocol: EST relies on CSR signature verification plus profile policy (RFC 7030 §3.2.3 says EST auth is deployment-specific; §4.1.1 makes `/cacerts` explicitly anonymous); SCEP requires a shared `challengePassword` in the PKCS#10 CSR attributes (OID 1.2.840.113549.1.9.7, RFC 8894 §3.2), validated with `crypto/subtle.ConstantTimeCompare`; CRL and OCSP are intentionally anonymous for relying-party accessibility. CWE-306 (missing authentication for a critical function) is closed for SCEP by `preflightSCEPChallengePassword` in `cmd/server/main.go`, which refuses to start the control plane when `CERTCTL_SCEP_ENABLED=true` is set without `CERTCTL_SCEP_CHALLENGE_PASSWORD`. The HTTP dispatch is implemented in `cmd/server/main.go:buildFinalHandler`, which routes these prefixes through `noAuthHandler` (RequestID + structuredLogger + Recovery only, no auth or rate-limit middleware) and is pinned by the 27-subtest regression harness at `cmd/server/finalhandler_test.go`.
- **GUI Authentication** — Web dashboard includes login screen requiring API key entry. Failed auth redirects to login on 401. Auth context persists across page navigation. Logout clears session.
- **Configurable CORS** — API restricts cross-origin requests via `CERTCTL_CORS_ORIGINS` allowlist or wildcard. Preflight caching prevents chatty browser auth flows.
- **Token Bucket Rate Limiting** — Per-IP rate limiting (configurable via `CERTCTL_RATE_LIMIT_RPS` / `CERTCTL_RATE_LIMIT_BURST`) returns 429 Too Many Requests with Retry-After header. Prevents credential stuffing and brute-force attacks.
- **No Password Storage** — certctl does not store user passwords. API keys are the sole authentication mechanism. Your API key generation, distribution, and rotation policies are your responsibility (see "Operator Responsibility" below).
- **Zero-Downtime Key Rotation** — `CERTCTL_AUTH_SECRET` accepts comma-separated keys (e.g., `new-key,old-key`). All listed keys are validated with constant-time comparison. Operators can add a new key, migrate clients, then remove the old key — no service restart required for the client migration phase. A single-key warning is logged at startup to encourage rotation configuration.

**Evidence Locations**:

- API auth implementation: `internal/api/middleware/auth.go`
- Auth check endpoint: `GET /api/v1/auth/check` (validates credentials)
- Auth info endpoint: `GET /api/v1/auth/info` (returns current auth mode, served without auth so GUI detects mode)
- Rate limiting middleware: `internal/api/middleware/rate_limit.go`
- CORS configuration: `cmd/server/main.go`, search for `CERTCTL_CORS_ORIGINS`
- Final handler dispatch (authenticated vs. unauthenticated routing): `cmd/server/main.go:buildFinalHandler`
- SCEP preflight gate (CWE-306 closure): `cmd/server/main.go:preflightSCEPChallengePassword`
- SCEP service-layer defense-in-depth (rejects enrollment on empty challenge password, `crypto/subtle.ConstantTimeCompare`): `internal/service/scep.go`
- Final handler dispatch regression harness (27 subtests): `cmd/server/finalhandler_test.go`
- OpenAPI spec `security: []` overrides on unauthenticated paths: `api/openapi.yaml` (EST `/cacerts`, `/simpleenroll`, `/simplereenroll`, `/csrattrs`; SCEP `/scep` GET+POST; PKI `/crl/{issuer_id}`, `/ocsp/{issuer_id}/{serial}`)

**V3 Enhancement**:

- **OIDC / SSO Integration** — Optional OIDC providers (Okta, Azure AD, Google) with multi-tenant support. API key fallback for service accounts.
- **API Key Scoping** — Per-resource or per-action permissions (e.g., "read certificates from production only" or "issue certs, no revoke")

**Operator Responsibility**:

- Generate and securely distribute API keys to authorized users and systems
- Rotate API keys regularly (recommend quarterly)
- Revoke API keys immediately upon employee departure
- Do not commit API keys to version control (use `.env` or secrets management)
- Implement your own IP allowlisting at the firewall if needed (certctl enforces CORS at the HTTP layer, not at network layer)

---

### CC6.2 — Prior to Issuing System Credentials

**Requirement**: The entity provisions, modifies, disables, and removes user identities and rights based on an authorization process that considers user responsibility level and changes in those responsibilities.

**certctl Implementation** (V2):

- **Ownership Attribution** — Certificates can be assigned to an owner (email + name). Owner information is stored and audited (see CC7.2). Ownership is tracked through the lifecycle (issuance, renewal, deployment, revocation). Ownership reassignment is audited via the immutable audit trail.
- **Team Assignment** — Owners can be organized into teams. Certificate policies can route notifications to team email addresses.
- **Audit Trail Attribution** — Every API call records the actor (extracted from the API key or auth context). The audit trail is immutable — no retroactive modification of who did what.

**Evidence Locations**:

- Ownership domain model: `internal/domain/certificate.go` (OwnerID field)
- Owner CRUD API: `GET /api/v1/owners`, `POST /api/v1/owners`, `DELETE /api/v1/owners/{id}`
- Team CRUD API: `GET /api/v1/teams`, `POST /api/v1/teams`, `DELETE /api/v1/teams/{id}`
- Audit trail API: `GET /api/v1/audit` (actor field in every record)

**V3 Enhancement**:

- **RBAC (Role-Based Access Control)** — Predefined roles (Admin, Operator, Viewer) with profile-gated permissions. Administrators manage role assignments.

**Operator Responsibility**:

- Map certctl's ownership model to your organizational structure (departments, teams, on-call rotations)
- Establish a formal access request and approval process
- Remove ownership access when team members depart
- Document your access review process (audit trail shows *who* made changes, but you must justify *why*)

---

### CC6.3 — Authentication Policies

**Requirement**: The entity determines, documents, communicates, and enforces authentication policies that support the identification and authentication of authorized internal and external users and the transmission of user credentials.

**certctl Implementation** (V2):

- **API Key Policy** — All `/api/v1/*` access requires an API key or explicit opt-out. Opt-out (`CERTCTL_AUTH_TYPE=none`) logs a warning: "WARNING: Auth disabled (CERTCTL_AUTH_TYPE=none) — this is insecure and only for development". Configuration choice is logged at startup. The standards-based enrollment and PKI distribution endpoints (EST, SCEP, CRL, OCSP) are served unauthenticated at the HTTP layer per their respective RFCs; see CC6.1 for the full authentication contract and CWE-306 closure via `preflightSCEPChallengePassword`.
- **Agent Authentication** — Agents authenticate to the server via API keys (same mechanism as users). Agent credentials are separate from user API keys.
- **Private Key Policy** — Agent-side key generation is the default (`CERTCTL_KEYGEN_MODE=agent`). Server-side keygen (`CERTCTL_KEYGEN_MODE=server`) requires explicit configuration and logs a warning: "server-side key generation enabled (CERTCTL_KEYGEN_MODE=server) — private keys touch control plane, demo only".
- **Password Policy** — Not applicable; certctl uses API keys exclusively. Password management is delegated to your organization's IAM system if you integrate OIDC/SSO (V3).

**Evidence Locations**:

- Auth type configuration: `internal/config/config.go`, `CERTCTL_AUTH_TYPE` env var
- Startup logging: `cmd/server/main.go` (logs auth mode at server startup)
- Keygen mode configuration: `internal/config/config.go`, `CERTCTL_KEYGEN_MODE` env var
- Keygen mode warning: `cmd/server/main.go` and `cmd/agent/main.go`

**V3 Enhancement**:

- **OIDC Policy** — Mandatory MFA when OIDC is enabled
- **API Key Expiration** — Automatic key rotation policies (e.g., 90-day expiration for user keys, no expiration for long-lived service account keys)

**Operator Responsibility**:

- Document your API key generation and distribution policy
- Establish a formal change control process for auth configuration changes
- Test authentication failures (e.g., expired keys, malformed tokens) in a non-production environment
- Integrate certctl authentication into your organization's IAM audit reports (who has API keys, when were they issued, who has revoked them)

---

### CC6.7 — Information Transmission Protection

**Requirement**: The entity restricts the transmission, movement, and removal of information in a manner that prevents unauthorized disclosure, whether through digital or non-digital means.

**certctl Implementation** (V2):

- **TLS for Control Plane** — All API communication occurs over HTTPS (TLS 1.2+). Server uses `tls.Dial()` for outbound connections to issuers and targets. Configuration: `CERTCTL_SERVER_HOST` (default `127.0.0.1`) + `CERTCTL_SERVER_PORT` (default `8080`; Docker Compose maps to `8443`).
- **Agent-to-Server Communication** — Agents submit CSRs and heartbeats over HTTPS to the server using the same TLS stack.
- **Private Key Isolation** — Agents generate ECDSA P-256 private keys locally (`crypto/ecdsa` + `crypto/elliptic`). Private keys are never transmitted to the server — agents submit CSRs only. Private keys are stored on agent filesystem (`CERTCTL_KEY_DIR`, default `/var/lib/certctl/keys`) with 0600 (owner read/write only) permissions. Server-side keygen mode logs a development warning; production must use agent-side keygen.
- **Certificate Storage** — Signed certificates are stored in PostgreSQL as PEM text (along with metadata). Certificates are not secrets and may be transmitted plaintext. Private keys are never stored on the control plane in production (agent-side keygen mode).
- **Deployment via Target Connectors** — Target connectors write certificates and keys to local filesystem or network appliance APIs. For NGINX/Apache httpd, files are written with restrictive permissions (0600 for keys). For F5/IIS (V3+), credentials are scoped to a proxy agent in the same network zone — the server never holds network appliance credentials.

**Evidence Locations**:

- TLS configuration: deploy certctl behind a TLS-terminating reverse proxy (NGINX, HAProxy, or cloud load balancer) or use a TLS sidecar
- Agent keygen mode: `cmd/agent/main.go` (ECDSA key generation, filesystem storage with 0600)
- Private key handling: `internal/connector/target/nginx/nginx.go` and similar (cert/key file write)
- Server-side keygen deprecation: `internal/service/renewal.go` (log warning when enabled)

**V3 Enhancement**:

- **Hardware Security Module (HSM) Support** — Optional HSM backend for CA key storage (SubCA and Local CA modes)
- **Secrets Rotation** — Encrypted key rotation without server restart

**Operator Responsibility**:

- Enable TLS on the control plane in production (deploy behind a TLS-terminating reverse proxy or load balancer with valid certificates)
- Enforce TLS on agent-to-server communication via firewall rules (no cleartext HTTP)
- Protect agent filesystem key storage with:
  - File-level permissions (already 0600)
  - Encrypted filesystems (LUKS, BitLocker, or cloud provider equivalents)
  - Backup encryption (keys backed up to vault or HSM, never in cleartext backups)
- Restrict PostgreSQL access to authorized services only (network isolation, authentication)
- For target systems, ensure network traffic from agents to targets is encrypted (TLS, IPsec, or VPN)

---

## CC7: System Operations

### CC7.1 — System Monitoring

**Requirement**: The entity monitors system components and the operation of those components for anomalies that are indicative of malfunction, including the implementation of monitoring tools, the reporting of results of those monitoring activities, and the identification, documentation, analysis, and resolution of system anomalies.

**certctl Implementation** (V2):

- **Health Endpoint** — `GET /health` returns 200 OK with service status. Consumed by Docker health checks and Kubernetes probes.
- **Readiness Endpoint** — `GET /ready` returns 200 OK when the database is connected and migrations are applied.
- **Background Scheduler Monitoring** — 7 background loops run on a fixed schedule:
  - Renewal loop: every 1 hour, scans for certificates approaching renewal threshold
  - Job processor loop: every 30 seconds, picks up pending/waiting jobs and advances their state
  - Health check loop: every 2 minutes, pings agents to detect downtime
  - Notification dispatcher loop: every 1 minute, sends queued alerts
  - Short-lived cert expiry loop: every 30 seconds, marks expired short-lived credentials
  - Network scanner loop: every 6 hours, scans enabled TLS endpoints for certificate discovery
  - Digest emailer loop: every 24 hours, sends scheduled certificate digest email to configured recipients
  Each loop includes error handling and logs failures via structured slog.
- **Metrics Endpoints** — Two formats for monitoring integration:
  - `GET /api/v1/metrics` — JSON object with gauges, counters, and uptime for custom dashboards
  - `GET /api/v1/metrics/prometheus` — Prometheus exposition format (`text/plain; version=0.0.4`) for native scraping by Prometheus, Grafana Agent, Datadog, and other OpenMetrics-compatible collectors
  - **Gauges** — `certctl_certificate_total`, `certctl_certificate_active`, `certctl_certificate_expiring`, `certctl_certificate_expired`, `certctl_certificate_revoked`, `certctl_agent_total`, `certctl_agent_active`, `certctl_job_pending`
  - **Counters** — `certctl_job_completed_total`, `certctl_job_failed_total`
  - **Uptime** — `certctl_uptime_seconds` (seconds since server start)
  All values are point-in-time snapshots computed from database tables.
- **Structured Logging** — All scheduler operations, API calls, and connector actions log via `slog` (Go's structured logger). Logs include timestamp, level (DEBUG/INFO/WARN/ERROR), structured fields (e.g., `actor`, `resource_id`, `latency_ms`), and request IDs for tracing.
- **Request ID Propagation** — Each HTTP request gets a unique ID (`X-Request-ID` header). The ID is included in all correlated logs, making it easy to trace a single request through multiple service layers.

**Evidence Locations**:

- Health/readiness endpoints: `internal/api/handler/health.go`
- Background scheduler: `internal/scheduler/scheduler.go` (Start method)
- Metrics endpoint: `internal/api/handler/metrics.go`
- Stats API endpoints (for detailed time-series): `internal/api/handler/stats.go`
  - `GET /api/v1/stats/summary` — dashboard KPIs
  - `GET /api/v1/stats/certificates-by-status` — cert counts by status
  - `GET /api/v1/stats/expiration-timeline?days=N` — cert expiry distribution
  - `GET /api/v1/stats/job-trends?days=N` — job completion/failure rates
  - `GET /api/v1/stats/issuance-rate?days=N` — cert issuance volume
- Structured logging middleware: `internal/api/middleware/middleware.go`

**Operator Responsibility**:

- Configure log aggregation (e.g., ELK, Datadog, Splunk) to centralize certctl logs
- Set up alerting on scheduler loop failures (e.g., "renewal loop failed to complete within 2h")
- Configure health check monitoring (e.g., Prometheus scrape of `/health` and `/ready`)
- Establish thresholds for metrics (e.g., alert if `pending_jobs > 50` or `agents_healthy < total_agents`)
- Document your log retention policy (audit requirement often mandates 1+ years)
- Integrate certctl metrics into your broader observability stack (Grafana dashboards, SLO tracking)

---

### CC7.2 — Anomaly Detection

**Requirement**: The entity monitors system components and the operation of those components for anomalies that are indicative of malfunction, including the implementation of monitoring tools, the reporting of results of those monitoring activities, and the identification, documentation, analysis, and resolution of system anomalies.

(This criterion overlaps CC7.1 and extends it to specific anomaly response mechanisms.)

**certctl Implementation** (V2):

- **Immutable API Audit Trail** (M19) — Every API call is recorded to `audit_events` table (append-only, no update/delete). Recorded: HTTP method, URL path (query parameters intentionally excluded — see security note), actor (user/agent ID), SHA-256 hash of request body (truncated 16 chars for brevity), response status code, latency in milliseconds. Excluded paths (health, ready) are configurable. Audit records are async (non-blocking) and include a timestamp. **Security: Query parameters are excluded from the audit path** because they may contain cursor tokens, API keys, or sensitive filter values; since the audit trail is append-only with no deletion, any sensitive data recorded would persist permanently.
- **Audit Trail API** — `GET /api/v1/audit?actor=...&action=...&resource_id=...&created_after=...&created_before=...` allows searching for anomalous patterns (e.g., "who accessed certificate XYZ and when?", "did anyone revoke certs at 2 AM?").
- **Expiration Threshold Alerting** — Certificate renewal policies define alert thresholds (days before expiry): default `[30, 14, 7, 0]`. When a certificate approaches a threshold, a notification is enqueued. Deduplication prevents duplicate alerts for the same cert at the same threshold. Auto status transition: cert moves to `Expiring` status at 30 days, `Expired` at 0 days.
- **Certificate Status Auto-Transitions** — When a cert is issued, it's `Active`. As expiry approaches, status auto-transitions to `Expiring` (at 30d threshold). At expiry, status becomes `Expired`. Revoked certs move to `Revoked`. These transitions are recorded in the audit trail.
- **Notification Routing** — Alerts are sent via configured notifiers (Email, Slack, Teams, PagerDuty, OpsGenie). Certificates are routed to their owner's email address (or team email if no individual owner). This allows on-call teams to react to anomalies (e.g., "your production cert will expire in 7 days, request renewal now").
- **Deployment Rollback** — If a deployment fails or an older certificate needs to be reactivated, operators can trigger a "rollback" via the GUI. This redeploys a previous certificate version to the target. Rollback actions are audited.

**Evidence Locations**:

- Audit middleware: `internal/api/middleware/audit.go`
- Audit trail API: `internal/api/handler/audit.go`, `GET /api/v1/audit`
- Expiration alerting: `internal/service/renewal.go` (CheckRenewal method)
- Notification dispatcher: `internal/scheduler/scheduler.go` (notificationTicker)
- Status transitions: `internal/service/certificate.go` (auto status update logic)
- Audit trail CLI export: `certctl-cli audit export --format csv` / `--format json`

**V3 Enhancement**:

- **SIEM Export** — Real-time audit event streaming to SIEM systems (via NATS event bus with JetStream sink)
- **Anomaly Rules Engine** — Configurable rules (e.g., "alert if certificate revoked by non-admin", "alert if >10 certs issued in < 1 hour")

**Operator Responsibility**:

- Integrate audit trail into your SIEM / log analysis platform
- Define alerting rules and thresholds for anomalies (e.g., "revocation of critical cert", "mass issuance")
- Establish a formal incident response workflow (audit trail shows *what* happened; you must decide *what to do* about it)
- Regularly review audit logs (e.g., monthly compliance audit of who accessed what)
- Configure email/Slack/Teams integration so on-call teams are notified of cert expirations immediately
- Encrypt audit trail backups (ACID guarantees don't prevent theft of database backups)

---

### CC7.3 — Incident Response

**Requirement**: The entity detects, investigates, and responds to incidents by executing a defined incident response and management process that includes preparation, detection and analysis, containment, eradication, recovery, and post-incident activities.

**certctl Implementation** (V2):

- **Revocation API** — `POST /api/v1/certificates/{id}/revoke` with RFC 5280 reason codes:
  - `unspecified` — catch-all
  - `keyCompromise` — private key was exposed
  - `caCompromise` — CA itself was compromised (rare)
  - `affiliationChanged` — certificate no longer applies to the organization
  - `superseded` — newer cert is in use
  - `cessationOfOperation` — service is shutting down
  - `certificateHold` — temporary revocation (can be "unhold" by reissue)
  - `privilegeWithdrawn` — access rights revoked
  Revocation is **immediate** (no approval workflow). The certificate is marked `Revoked` in inventory, an audit event is logged, and optional issuer notification is best-effort. All revoked certs are excluded from active deployments.
- **CRL Endpoint** — `GET /.well-known/pki/crl/{issuer_id}` returns a DER-encoded X.509 CRL signed by the issuing CA (RFC 5280 §5, RFC 8615, `Content-Type: application/pkix-crl`), served unauthenticated for relying parties that don't hold certctl API credentials.
- **OCSP Responder** — `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` returns a signed OCSP response indicating whether a cert is good, revoked, or unknown (RFC 6960, `Content-Type: application/ocsp-response`). Also unauthenticated. Clients (browsers, TLS libraries) query this endpoint to verify cert validity in real-time.
- **Revocation Notifications** — When a cert is revoked, notifications are sent to:
  - Certificate owner (email)
  - Configured webhooks (if you have a SIEM that subscribes)
  - Slack/Teams channels (if notifiers are configured)
- **Bulk Revocation for Fleet-Wide Incidents** (V2.2) — `POST /api/v1/certificates/bulk-revoke` with filter criteria (profile, owner, agent, issuer) revokes all matching certificates in a single operation. Essential for incident response: key compromise affecting multiple certs, CA distrust events, decommissioning a team's infrastructure. Each bulk revocation creates individual jobs reusing the existing revocation pipeline, ensuring audit trail and notifications for every certificate.
- **Short-Lived Cert Exemption** — Certificates with TTL < 1 hour (configured in profile) skip CRL/OCSP publication. Expiry is the revocation mechanism for short-lived certs (e.g., Kubernetes pod certs, session tokens).
- **Deployment Rollback** — If a revoked cert is still deployed (shouldn't happen, but race conditions exist), operators can manually redeploy a previous version via the GUI. Rollback is audited.

**Evidence Locations**:

- Revocation API: `internal/api/handler/certificates.go`, `POST /api/v1/certificates/{id}/revoke`
- Revocation domain model: `internal/domain/revocation.go` (RevocationReason type with RFC 5280 mapping)
- CRL generation: `internal/service/certificate.go` (GenerateDERCRL method)
- OCSP signing: `internal/service/certificate.go` (GetOCSPResponse method)
- Revocation notifications: `internal/service/notification.go` (SendRevocationNotification)
- Short-lived exemption: `internal/domain/revocation.go` (IsShortLivedCert check)

**V3 Enhancement**:

- **Revocation Automation** — Trigger revocation based on external events (e.g., employee termination, security breach alert from CT Log monitoring)

**Operator Responsibility**:

- Establish an incident response policy (e.g., "keyCompromise → immediate deployment to new cert + notify CISO")
- Ensure CRL/OCSP are accessible to all systems using the certs (e.g., CDN or highly-available endpoints if you host on-premises)
- Test revocation workflow in staging (verify that revoked certs are actually blocked by clients)
- Document justification for revocation (audit trail records *that* a cert was revoked, but not *why* — you must document it separately)
- Integrate revocation notifications into your on-call rotation (don't let revocation alerts get lost)

---

### CC7.4 — Identify and Develop Risk Mitigation Activities

**Requirement**: The entity identifies, develops, and implements risk mitigation activities for risks arising from potential business disruptions.

**certctl Implementation** (V2):

- **Renewal Job Tracking** — Renewal jobs track the certificate, target agents, and issuance outcome. Failed renewals are retried (configurable backoff). Job state diagram: Pending → Running → Completed (or Failed). Failed jobs trigger notifications.
- **Agent Health Monitoring** — Health check loop (every 2m) pings all agents via heartbeat. If an agent misses 3 consecutive heartbeats, it's marked as `Unhealthy`. Unhealthy agents are excluded from new deployments.
- **Job Cancellation** — Operators can cancel pending jobs via `POST /api/v1/jobs/{id}/cancel`. Useful when a renewal is already in progress elsewhere (multi-instance deployments) or when a certificate is being phased out.
- **Interactive Approval** — Renewal/issuance jobs can be put in `AwaitingApproval` status. An authorized operator reviews the pending cert and approves or rejects it. Rejection records a reason in the audit trail. This provides a separation of duty between requestor and approver.
- **Scheduled Scanning** — Agents scan configured directories for existing certs (M18b discovery). Operators triage discovered certs (claim = "we manage this now", dismiss = "this is unmanaged and we're OK with that"). Triage decisions are audited.

**Evidence Locations**:

- Job state machine: `internal/domain/job.go` (JobStatus enum)
- Job retry logic: `internal/scheduler/scheduler.go` (jobProcessorTicker)
- Agent health check: `internal/scheduler/scheduler.go` (healthCheckTicker)
- Job cancellation: `internal/api/handler/jobs.go`, `POST /api/v1/jobs/{id}/cancel`
- Approval workflow: `internal/api/handler/jobs.go`, `POST /api/v1/jobs/{id}/approve` / `reject`
- Discovery scan results: `internal/api/handler/discovery.go`, `GET /api/v1/discovered-certificates`

**Operator Responsibility**:

- Monitor renewal job success rate (are certs being renewed before expiry?)
- Set up alert for unhealthy agents (missing 3+ heartbeats = broken agent, take action)
- Establish a formal approval policy (who can approve certs? do they need to involve CISO?)
- Test job cancellation and recovery flows in staging
- Review discovered certs regularly (are there unmanaged certs that should be managed?)
- Document your disaster recovery process (what if control plane database is corrupted?)

---

## A1: Availability

### A1.1/A1.2 — Availability and Recovery

**Requirement**: The entity obtains or generates, uses, retains, and disposes of information to enable the entity to meet its objectives and respond to its responsibility to provide information.

**certctl Implementation** (V2):

- **Health Probes** — `/health` and `/ready` endpoints support container orchestration (Docker Compose, Kubernetes, etc.). Docker Compose defines health checks for the server and database. Kubernetes would use liveness/readiness probes pointing to these endpoints.
- **Database Migrations (Idempotent)** — PostgreSQL migrations use `IF NOT EXISTS` and `ON CONFLICT ... DO NOTHING` patterns. Migrations can be safely reapplied — no risk of doubling data or dropping tables mid-migration.
- **Agent Panic Recovery** — Agent binary includes panic recovery in job execution loops. If an agent crashes during a deployment, the control plane marks the job as failed and can retry on a healthy agent.
- **Exponential Backoff** — Agent-to-server communication uses exponential backoff (starting at 1s, capped at 5m) to handle transient network failures. This prevents thundering herd when the control plane is temporarily down.
- **Docker Compose Deployment** — Includes health checks for server and database. Services auto-restart on failure.
- **PostgreSQL Connection Pooling** — Server uses `database/sql` with configurable `MaxOpenConns` and `MaxIdleConns` (default 25/5). Prevents connection exhaustion.

**Evidence Locations**:

- Health endpoints: `internal/api/handler/health.go`
- Database migrations: `migrations/` directory (all use `IF NOT EXISTS`, idempotent patterns)
- Agent panic recovery: `cmd/agent/main.go` (defer recover() in job execution)
- Exponential backoff: `cmd/agent/main.go` (heartbeat and work poll backoff logic)
- Connection pooling: `cmd/server/main.go` (SetMaxOpenConns, SetMaxIdleConns)

**V3 Enhancement**:

- **Multi-Region HA** — Control plane federation with etcd consensus (operator can run N replicas)
- **PostgreSQL HA** — Replication standby with automatic failover (operator responsibility to configure)

**Operator Responsibility**:

- Configure PostgreSQL backups (e.g., WAL archiving, daily full backups). Certctl stores certificates but *also* stores renewal policies, audit trail, deployment history.
- Test backup/restore process in staging (broken backups are discovered during incidents)
- Monitor disk usage (PostgreSQL will fail if `/var` fills up)
- Plan capacity (how many certs, agents, jobs can your PostgreSQL handle? Certctl is tested with 10k+ certs, 100+ agents, but your infra may differ)
- Set up high-availability PostgreSQL if you need zero-downtime upgrades
- Implement network segmentation (only authorized services can reach certctl API and database)

---

## CC8: Change Management

### CC8.1 — Change Control

**Requirement**: The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.

**certctl Implementation** (V2):

- **Certificate Profiles** — Named profiles define allowed key types, max TTL, required SANs, and permitted EKUs. Changes to profiles are common (e.g., "increase max TTL from 1 year to 3 years"). All profile changes are audited (who changed what, when). Profile updates are versioned.
- **Policy Engine** — Renewal policies define alert thresholds and approval workflows. Policy changes (e.g., "lower alert threshold from 30 days to 14 days") are audited. Policies have violation rules (e.g., "flag certs longer than 3 years") — violations are recorded in the audit trail.
- **Target Configuration** — When a new target (NGINX server, HAProxy load balancer) is added, it's registered with a name and configuration (JSON). Target deletions require confirmation (to prevent accidental removal). All target changes are audited.
- **Immutable Audit Trail** — Every change (profile, policy, target, cert, agent, owner, team, approval, revocation, deployment) is recorded in `audit_events`. Audit records are append-only; no retroactive modification is possible. Audit trail is encrypted at rest (operator responsibility).
- **GitHub Actions CI** — Pull requests must pass:
  - Go unit tests (`go test ./...`) with coverage gates (service layer ≥30%, handler layer ≥50%)
  - Go vet (static analysis)
  - Frontend TypeScript type checking (`tsc`)
  - Frontend Vitest unit tests
  - Frontend Vite build (ensures no broken imports)
  Only after all checks pass can the PR be merged and deployed.

**Evidence Locations**:

- Profile CRUD: `internal/api/handler/profiles.go`, `GET /api/v1/profiles` / `POST` / `PUT` / `DELETE`
- Policy CRUD: `internal/api/handler/policies.go`
- Target CRUD: `internal/api/handler/targets.go`
- Audit trail: `internal/api/handler/audit.go`, `GET /api/v1/audit` (records action, actor, resource_id, timestamp)
- CI configuration: `.github/workflows/ci.yml` (test, vet, coverage gates, build checks)

**V3 Enhancement**:

- **Change Approval Workflow** — Optional approval gate before profile/policy changes go live
- **Feature Flags** — Enable/disable new features without redeployment (backward compatibility during rolling upgrades)

**Operator Responsibility**:

- Implement formal change control (ticket system, approval, peer review)
- Document the business justification for profile/policy changes
- Test changes in a non-production environment before deploying to production
- Have a rollback plan (can you revert a profile change instantly if it breaks issuance?)
- Include certctl configuration changes in your change log (for audits and incident investigations)
- Version control your certctl configuration (Docker Compose file, environment variables) so you can track changes

---

## Evidence Summary Table

| SOC 2 Criterion | certctl Feature | Evidence Location | V2 (Free) | V3 (Pro) | Operator Responsibility |
|---|---|---|---|---|---|
| **CC6.1** Logical Access Security | API Key Authentication (SHA-256 hashed, constant-time comparison) | `internal/api/middleware/auth.go` | ✅ | Enhanced | API key generation, distribution, rotation |
| | GUI Login with API Key | `web/src/pages/LoginPage.tsx` | ✅ | Enhanced (OIDC) | NA |
| | CORS Allowlist | `CERTCTL_CORS_ORIGINS` env var | ✅ | ✅ | Configure appropriately |
| | Token Bucket Rate Limiting | `internal/api/middleware/rate_limit.go` | ✅ | ✅ | Monitor for brute-force attempts |
| **CC6.2** Prior to Issuing System Credentials | Ownership Attribution | `GET /api/v1/owners`, audit trail records owner assignment | ✅ | Enhanced (RBAC) | Map to org structure, remove on departure |
| | Team Assignment | `GET /api/v1/teams` | ✅ | ✅ | NA |
| | Actor Attribution in Audit Trail | `GET /api/v1/audit` (actor field) | ✅ | ✅ | Justify all changes via separate documentation |
| **CC6.3** Authentication Policies | API Key Enforcement | `CERTCTL_AUTH_TYPE=api-key` (default) | ✅ | Enhanced (OIDC, MFA) | Document policy, test failures, integrate into IAM audit |
| | Agent Authentication | Separate API keys for agents | ✅ | ✅ | Rotate agent keys, monitor compromise |
| | Agent-Side Key Generation | `CERTCTL_KEYGEN_MODE=agent` (default) | ✅ | ✅ | Protect agent filesystem keys via encryption/backup |
| | Private Key Policy | Server-side keygen logs warning, disabled in production | ✅ | ✅ | Never use server-side keygen in production |
| **CC6.7** Information Transmission Protection | TLS for Control Plane | Deploy behind TLS-terminating reverse proxy | ✅ | ✅ | Enable TLS in production via reverse proxy |
| | Agent-to-Server HTTPS | Agents use HTTPS for all API calls | ✅ | ✅ | Enforce TLS via firewall rules |
| | Private Key Isolation | Agent-side keygen (ECDSA P-256), keys stored 0600 on agent FS | ✅ | ✅ | Encrypt agent filesystems, backup securely |
| | Pull-Only Deployment | Server never initiates outbound to agents/targets | ✅ | Enhanced (HSM, proxy agents) | Encrypt agent↔target comms, isolate proxy agents |
| **CC7.1** System Monitoring | Health Endpoint | `GET /health`, `GET /ready` | ✅ | ✅ | Integrate into monitoring (Prometheus, DataDog) |
| | Metrics JSON Endpoint | `GET /api/v1/metrics` (gauges, counters, uptime) | ✅ | ✅ | Set thresholds, configure alerting |
| | Stats API (time-series) | `GET /api/v1/stats/*` (summary, status, expiration, jobs, issuance) | ✅ | ✅ | Integrate into dashboards, SLO tracking |
| | Structured Logging | `slog` middleware with request IDs | ✅ | ✅ | Aggregate logs to SIEM, define retention policy |
| | Background Scheduler | 7 loops (renewal 1h, jobs 30s, health 2m, notifications 1m, short-lived 30s, network scan 6h, digest 24h) | ✅ | ✅ | Alert on scheduler loop failures |
| **CC7.2** Anomaly Detection | Immutable API Audit Trail | `internal/api/middleware/audit.go`, `GET /api/v1/audit` | ✅ | Enhanced (SIEM export) | Integrate into SIEM, search for anomalies, archive long-term |
| | Expiration Threshold Alerting | Configurable per-policy (default 30/14/7/0 days) | ✅ | ✅ | Configure thresholds, integrate notifications |
| | Status Auto-Transitions | Active → Expiring (30d) → Expired (0d) | ✅ | ✅ | Monitor status changes in audit trail |
| | Notification Routing | Email, Slack, Teams, PagerDuty, OpsGenie | ✅ | ✅ | Configure notifiers, on-call integration |
| | Deployment Rollback | Redeploy previous cert version via GUI | ✅ | ✅ | Audit rollback decisions |
| **CC7.3** Incident Response | Revocation API (RFC 5280 reasons) | `POST /api/v1/certificates/{id}/revoke` | ✅ | Enhanced (bulk revocation) | Establish incident response policy |
| | CRL Endpoint (DER, RFC 5280 §5) | `GET /.well-known/pki/crl/{issuer_id}` (unauthenticated, `application/pkix-crl`) | ✅ | ✅ | Ensure CRL/OCSP accessible to all clients without API keys |
| | OCSP Responder (RFC 6960) | `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` (unauthenticated, `application/ocsp-response`) | ✅ | ✅ | Test revocation in staging |
| | Revocation Notifications | Email, webhook, Slack/Teams on revocation | ✅ | ✅ | Integrate into on-call, document justification separately |
| | Short-Lived Cert Exemption | TTL < 1h skip CRL/OCSP | ✅ | ✅ | Configure profiles appropriately |
| **CC7.4** Risk Mitigation | Renewal Job Tracking | Job state machine (Pending → Running → Completed/Failed) | ✅ | ✅ | Monitor renewal success rate |
| | Agent Health Monitoring | Health check loop (ping every 2m, mark unhealthy after 3 misses) | ✅ | ✅ | Alert on unhealthy agents, investigate |
| | Job Cancellation | `POST /api/v1/jobs/{id}/cancel` | ✅ | ✅ | Test in staging |
| | Interactive Approval | AwaitingApproval state, `POST /api/v1/jobs/{id}/approve\|reject` | ✅ | ✅ | Define approval policy, audit decisions |
| | Certificate Discovery | Agents scan directories, triage (claim/dismiss) | ✅ | ✅ | Review discovered certs regularly |
| **A1.1/A1.2** Availability and Recovery | Health Probes (Docker, Kubernetes) | `/health` and `/ready` endpoints | ✅ | ✅ | Use in container orchestration |
| | Idempotent Migrations | `IF NOT EXISTS`, `ON CONFLICT ... DO NOTHING` | ✅ | ✅ | Test migration replay in staging |
| | Agent Panic Recovery | Panic recovery in job loops | ✅ | ✅ | Monitor agent crashes in logs |
| | Exponential Backoff | Agent heartbeat/work poll backoff (1s → 5m) | ✅ | ✅ | Monitor for control plane downtime |
| | PostgreSQL Connection Pooling | MaxOpenConns=25, MaxIdleConns=5 (configurable) | ✅ | ✅ | Monitor connection usage |
| **CC8.1** Change Control | Certificate Profiles | CRUD API + GUI, profile changes audited | ✅ | ✅ | Formal change control, test in staging |
| | Policy Engine + Violations | CRUD API + GUI, policy changes audited | ✅ | ✅ | Document justification, implement approval workflow |
| | Target Registration | CRUD API + GUI, changes audited | ✅ | ✅ | Confirm deletions, version control config |
| | Immutable Audit Trail | Append-only `audit_events` table | ✅ | ✅ | Encrypt at rest, archive long-term, no manual edits |
| | GitHub Actions CI | Unit tests, vet, coverage gates, build checks | ✅ | ✅ | Review PRs before merge, maintain test quality |

---

## What Requires Operator Action

**certctl is a tool, not a complete compliance solution.** Your organization must handle:

1. **Physical Security** — Protect the infrastructure (servers, network) running certctl. Certctl can't control who has physical access to your datacenter.

2. **Personnel Background Checks** — Before granting anyone API key access, conduct background checks per your policy. Certctl records *who* accessed *what*, but doesn't verify that people are trustworthy.

3. **Formal Incident Response Plan** — Certctl provides incident detection (anomalies in audit trail) and tools for response (revocation, rollback), but you must define *when* to use them and *who* decides.

4. **Access Review and Removal** — Certctl stores ownership, teams, and API keys. You must:
   - Regularly review who has access (quarterly or semi-annually)
   - Immediately revoke API keys for departing employees
   - Audit that removed access is actually removed (test that old keys fail)

5. **Log Retention and Archival** — Certctl logs to stdout (Docker) and stores audit events in PostgreSQL. You must:
   - Ship logs to a long-term archive (SIEM, S3, or equivalent)
   - Define retention policy (often 1-7 years per industry regulation)
   - Encrypt archived logs
   - Test that you can retrieve logs from archive (restoration drills)

6. **Encryption at Rest** — PostgreSQL data (including audit trail) is stored on disk. You must:
   - Enable transparent data encryption (TDE) on your database VM
   - Encrypt container persistent volumes (if using Kubernetes)
   - Encrypt database backups

7. **Network Segmentation** — Certctl API and database must be protected by network access controls. You must:
   - Firewall the control plane (only authorized services can connect)
   - Use VPN or private networks for agent-to-server communication
   - Isolate proxy agents (for F5, IIS, etc.) in the same network zone as their targets

8. **Capacity Planning** — Certctl's performance scales with your PostgreSQL. You must:
   - Estimate certificate inventory size (10k, 100k, 1M certs?)
   - Test Certctl with your expected scale in staging
   - Monitor disk usage, CPU, memory
   - Plan for growth (add PostgreSQL replicas, increase connection pool, etc.)

9. **Disaster Recovery** — Certctl data lives in PostgreSQL. You must:
   - Back up PostgreSQL regularly (daily or hourly, depending on RPO)
   - Test restore process in staging (broken backups discovered during incidents)
   - Have a runbook for failover to replica or recovery from backup
   - Document RTO/RPO targets (how long can cert management be down? how much data can you afford to lose?)

10. **Integration with Your IAM** — If using OIDC/SSO (V3), you must:
    - Configure your OIDC provider (Okta, Azure AD, Google)
    - Map user groups to Certctl roles (Admin, Operator, Viewer)
    - Manage MFA policy (enforce MFA if required)
    - Audit user provisioning/deprovisioning

11. **Documentation and Runbooks** — Certctl documents *what it does* (this guide), but you must document:
    - Your organization's certificate lifecycle policy (who requests, who approves, who deploys)
    - How to respond to specific incidents (cert compromise, CA compromise, agent down, renewal failed)
    - How to operate certctl (day-to-day tasks, escalation procedures)
    - Contact info for on-call teams

---

## V3 Enhancements

**certctl Pro (V3, paid edition) adds features that significantly strengthen SOC 2 evidence:**

- **OIDC / SSO Integration** — Integrate with Okta, Azure AD, Google to replace API keys with federated identity. Enables MFA enforcement and centralized access management. Auditors love federated identity (easier to remove access at source).

- **Role-Based Access Control (RBAC)** — Predefined roles (Admin: full access; Operator: issue/renew/revoke, no policy changes; Viewer: read-only) with profile-gated enforcement. Allows separation of duties (e.g., junior operator can't change global policy).

- **NATS Event Bus** — Real-time audit streaming to your SIEM. Hybrid model: HTTP for synchronous APIs, NATS for async events (cert.issued, cert.expiring, agent.heartbeat, job.completed). JetStream persistence for replay and durability.

- **SIEM Export** — Automated export of audit trail to Splunk, ELK, DataDog, etc. (webhooks, syslog, or pull-based APIs). Makes it easy for security teams to hunt for anomalies.

- **Advanced Search DSL** — `POST /api/v1/search` with tree-based filters (nested AND/OR, regex, field projection). Enables complex compliance queries (e.g., "all certs issued in the last 30 days by team X that are longer than 1 year").

- **Bulk Revocation** — Revoke all certs issued by a profile, owner, or agent in one operation. Critical for large-scale incidents (e.g., "a team's CA key was compromised, revoke all their certs").

- **Certificate Health Scores** — Composite risk scoring (e.g., "this cert has no short-lived TTL enforcement, extends past your policy max, and hasn't been renewed in 2 years" → health=30%). Helps prioritize remediation.

- **Compliance Scoring** — Audit readiness reporting per certificate (e.g., "compliance=95% — missing only a 3-year max-TTL constraint"). Exportable compliance report.

- **DigiCert Issuer Connector** — OV/EV certificate issuance for public-facing services (web servers, CDNs). Complements Local CA for internal use.

- **CT Log Monitoring** — Passive detection of unauthorized cert issuance. Monitors public CT logs for certs matching your domains and alerts if unexpected certs appear (e.g., attacker obtained a cert for your domain).

- **F5 BIG-IP Implementation** — Full target connector with iControl REST API. Agents can deploy certs to F5 load balancers.

- **IIS Implementation** — Dual-mode: agent-local PowerShell (default) for servers with agents, or proxy agent WinRM (agentless targets). Full Windows Server integration.

---

## Conclusion

certctl provides a strong foundation for SOC 2 compliance with API key authentication, immutable audit logging, automated alerting, and revocation capabilities. However, SOC 2 audits require evidence across your entire infrastructure — certctl is one piece. Use this guide to map certctl features to your audit questionnaire, then work with your auditors to identify gaps that must be filled by your own organizational policies and controls.

For a deeper SOC 2 discussion or a mock audit against this guide, contact your certctl Pro support team.
