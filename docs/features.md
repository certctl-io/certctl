# certctl V2 Feature Inventory

Complete reference of all features shipped in the V2 release (as of March 2026).

---

## API Surface

### Overview
- **97 endpoints** across 21 resource domains under `/api/v1/` + `/.well-known/est/`
- REST API with HTTP semantics (GET, POST, PUT, DELETE)
- All endpoints require authentication by default (configurable)
- OpenAPI 3.1 spec with full schema documentation

### Authentication & Security

Every API call requires authentication by default — this ensures that only authorized operators and agents can issue, renew, or revoke certificates. Without this, anyone with network access to the control plane could compromise your entire certificate infrastructure.

- **API Key Authentication** — SHA-256 hashed keys with constant-time comparison
- **Bearer Token Flow** — `Authorization: Bearer {api_key}` header
- **Auth Configuration** — Configurable via `CERTCTL_AUTH_TYPE` (api-key, jwt, none)
- **Auth Info Endpoint** — `GET /api/v1/auth/info` (no auth required for GUI pre-login detection)
- **Auth Check Endpoint** — `GET /api/v1/auth/check` (validate credentials)

```bash
# Authenticate with API key
curl -H "Authorization: Bearer your-api-key" http://localhost:8443/api/v1/certificates

# Check auth mode (no auth required — used by GUI login page)
curl http://localhost:8443/api/v1/auth/info
# {"auth_type":"api-key"}
```

### Rate Limiting

Protects the control plane from being overwhelmed by a single client — whether a misconfigured monitoring script polling every millisecond or a bug in an agent's retry logic. Without rate limiting, one misbehaving client can DoS the server for everyone.

- **Token Bucket Algorithm** — Configurable requests-per-second (RPS) and burst size
- **429 Responses** — Rate limit exceeded with `Retry-After` header telling clients when to retry
- **Configuration** — `CERTCTL_RATE_LIMIT_ENABLED`, `CERTCTL_RATE_LIMIT_RPS` (default 50), `CERTCTL_RATE_LIMIT_BURST` (default 100)

### CORS

Required for the web dashboard to communicate with the API when served from a different origin (e.g., during development on `localhost:3000` while the API runs on `localhost:8443`). Without CORS headers, browsers block the requests silently.

- **Configurable Per-Origin Allowlist** — `CERTCTL_CORS_ORIGINS` (comma-separated or wildcard)
- **Preflight Caching** — Standard CORS headers

### Query Features (M20)

These features reduce API response sizes and enable efficient pagination at scale. When you have 10,000+ certificates, fetching the full object for each one on every list call wastes bandwidth and slows down dashboards. Sparse fields, cursor pagination, and sorting let clients request exactly what they need.

```bash
# Sparse fields — only return id, name, and status (smaller payload)
curl -H "$AUTH" "$SERVER/api/v1/certificates?fields=id,common_name,status"

# Sort by expiration date descending (most urgent first)
curl -H "$AUTH" "$SERVER/api/v1/certificates?sort=-notAfter"

# Cursor pagination — efficient for large datasets
curl -H "$AUTH" "$SERVER/api/v1/certificates?cursor=eyJpZCI6Im1jLWFwaS1wcm9kIn0&page_size=100"

# Time-range filter — certs expiring in next 30 days
curl -H "$AUTH" "$SERVER/api/v1/certificates?expires_before=2026-04-24T00:00:00Z&expires_after=2026-03-24T00:00:00Z"
```

| Feature | Details |
|---------|---------|
| **Sorting** | `?sort=-notAfter` (8 fields: notAfter, expiresAt, createdAt, updatedAt, commonName, name, status, environment) |
| **Pagination (Page-Based)** | `?page=1&per_page=50` (max 500, default 50) |
| **Pagination (Cursor)** | `?cursor=base64_token&page_size=100` (keyset pagination with `next_cursor` in response) |
| **Time-Range Filters** | `?expires_before=2026-12-31T23:59:59Z&expires_after=2026-01-01T00:00:00Z&created_after=...&updated_after=...` (RFC3339 format) |
| **Sparse Fields** | `?fields=id,common_name,status` (reduce response size) |
| **Additional Filters** | `?status=active&agent_id=a-xxx&profile_id=p-xxx&issuer_id=...&owner_id=...&team_id=...` |

### Endpoint Breakdown by Domain

| Domain | Endpoints | Key Operations |
|--------|-----------|-----------------|
| **Certificates** | 11 | List, create, get, update (archive), versions, deployments, trigger renewal, trigger deployment, revoke |
| **CRL & OCSP** | 3 | JSON CRL, DER CRL per issuer, OCSP responder |
| **Issuers** | 6 | List, create, get, update, delete, test connection |
| **Targets** | 5 | List, create, get, update, delete |
| **Agents** | 7 | List, register, get, heartbeat, CSR submit, certificate pickup, get work, report job status |
| **Jobs** | 5 | List, get, cancel, approve, reject |
| **Policies** | 6 | List, create, get, update, delete, list violations |
| **Profiles** | 5 | List, create, get, update, delete |
| **Teams** | 5 | List, create, get, update, delete |
| **Owners** | 5 | List, create, get, update, delete |
| **Agent Groups** | 6 | List, create, get, update, delete, list agents in group |
| **Discovery** | 7 | Submit scan results, list discovered certs, get detail, claim, dismiss, list scans, summary stats |
| **Network Scan** | 6 | List targets, create, get, update, delete, trigger scan |
| **Audit** | 3 | List events, list by resource, export (CSV/JSON) |
| **Notifications** | 3 | List, get, mark as read |
| **Stats** | 5 | Dashboard summary, certificates by status, expiration timeline, job trends, issuance rate |
| **Metrics** | 2 | JSON metrics (gauges, counters, uptime), Prometheus exposition format |
| **Verification** | 2 | Submit verification result, get verification status |
| **EST (RFC 7030)** | 4 | CA certs (PKCS#7), simple enrollment, re-enrollment, CSR attributes |
| **Health** | 4 | Health check, readiness check, auth info, auth check |

---

## Certificate Lifecycle

### Certificate States (8 total)
- **Pending** — Created, awaiting issuance
- **Active** — Valid and deployed
- **Expiring** — Within configured threshold (default 30 days)
- **Expired** — Past NotAfter date
- **RenewalInProgress** — Renewal job submitted
- **Failed** — Issuance or renewal failed
- **Revoked** — Revoked via POST /api/v1/certificates/{id}/revoke
- **Archived** — Manually archived via DELETE endpoint

### Key Generation Modes
| Mode | Details |
|------|---------|
| **Agent-Side (Default)** | ECDSA P-256 key generation on agent; private keys never touch control plane |
| **Server-Side (Demo Only)** | RSA-2048 key generation on server; requires explicit `CERTCTL_KEYGEN_MODE=server` with log warning |

### Certificate Versions
- Multiple versions per certificate (issuance, renewal)
- Each version includes: serial number, fingerprint, PEM-encoded chain
- CSR preserved for audit trail
- Version history with rollback capability in GUI

### AwaitingCSR Job State
- Renewal and issuance jobs pause when `CERTCTL_KEYGEN_MODE=agent`
- Agent generates ECDSA P-256 key locally, creates CSR, submits via `POST /api/v1/agents/{id}/csr`
- Server signs and stores certificate version
- Work endpoint enriched with `common_name` and `sans` for agent CSR generation

### Deployment Trigger
Push certificates to targets on demand, outside of the normal scheduler-driven flow:

```bash
# Deploy to all mapped targets
curl -X POST -H "$AUTH" $SERVER/api/v1/certificates/mc-api-prod/deploy

# Deploy to a specific target
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/certificates/mc-api-prod/deploy \
  -d '{"target_id": "tgt-nginx-prod"}'

# Check deployment job status
curl -H "$AUTH" "$SERVER/api/v1/certificates/mc-api-prod/deployments" | jq '.data[] | {id, name, type}'
```

### Post-Deployment TLS Verification (M25)

After deploying a certificate, the agent connects back to the target's live TLS endpoint and verifies the served certificate matches what was deployed — using SHA-256 fingerprint comparison. This catches failures that deployment commands can't: wrong virtual host, stale cache, config that validates but doesn't apply.

```bash
# Agent submits verification result after probing the live endpoint
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/jobs/j-deploy-123/verify -d '{
  "target_id": "tgt-nginx-prod",
  "expected_fingerprint": "sha256:a1b2c3...",
  "actual_fingerprint": "sha256:a1b2c3...",
  "verified": true
}'

# Check verification status for a job
curl -H "$AUTH" $SERVER/api/v1/jobs/j-deploy-123/verification | jq .
```

| Feature | Details |
|---------|---------|
| **Verification Method** | `crypto/tls.DialWithDialer` with `InsecureSkipVerify=true` to handle self-signed and internal CA certs |
| **Fingerprint Comparison** | SHA-256 of raw certificate DER bytes |
| **Best-Effort** | Verification failures are recorded but don't block or rollback deployments |
| **Job Fields** | `verification_status` (pending/success/failed/skipped), `verified_at`, `verification_fingerprint`, `verification_error` |
| **Audit Trail** | `job_verification_success` and `job_verification_failed` events recorded |
| **Configuration** | `CERTCTL_VERIFY_DEPLOYMENT` (enable/disable), `CERTCTL_VERIFY_TIMEOUT` (TLS dial timeout), `CERTCTL_VERIFY_DELAY` (wait after deploy before probing) |

---

## Revocation Infrastructure

When a private key is compromised or a certificate is no longer needed, revocation tells clients to stop trusting it immediately. Without revocation, a stolen certificate remains valid until it expires — which could be months.

```bash
# Revoke a certificate (key compromise — most urgent reason)
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/certificates/mc-api-prod/revoke \
  -d '{"reason": "keyCompromise"}'

# Check the CRL for an issuer
curl -H "$AUTH" $SERVER/api/v1/crl/iss-local | jq '.entries'

# Query OCSP status for a specific cert
curl $SERVER/api/v1/ocsp/iss-local/ABC123DEF456
```

### Revocation API
- **Endpoint** — `POST /api/v1/certificates/{id}/revoke` (RFC 5280 reason codes)
- **8 Reason Codes** — unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, privilegeWithdrawn
- **Best-Effort Issuer Notification** — Issuer connector failure doesn't block revocation
- **Immutable Recording** — `certificate_revocations` table with idempotent ON CONFLICT logic

### CRL (Certificate Revocation List)
- **JSON CRL** — `GET /api/v1/crl` returns entries array with serial numbers, reasons, revoked timestamps
- **DER X.509 CRL** — `GET /api/v1/crl/{issuer_id}` returns proper DER-encoded CRL signed by issuing CA
- **24-Hour Validity** — CRL refreshed every 24 hours
- **CA Key Required** — Sub-CA or issuing CA key must be available for signing

### OCSP Responder
- **Endpoint** — `GET /api/v1/ocsp/{issuer_id}/{serial}`
- **Responses** — good (certificate valid), revoked (in CRL), unknown (not issued by this CA)
- **Signed** — OCSP responses signed by issuing CA

### Short-Lived Certificate Exemption
- **Policy** — Certificates with TTL < 1 hour (from profile) skip CRL/OCSP
- **Rationale** — Expiry is sufficient revocation signal for short-lived certs
- **Exemption Applied** — During CRL generation and OCSP response construction

### Revocation Notifications
- Webhook + email notifications on revocation events
- Routed by certificate owner email via existing notifier system

---

## Certificate Profiles

### Profile Model
Named enrollment profiles defining certificate issuance constraints. Profiles prevent drift — without them, different teams might issue certs with inconsistent key sizes, TTLs, or key algorithms. A profile says "all certs in this category must use ECDSA P-256, max 90-day TTL, serverAuth EKU only."

```bash
# Create a profile enforcing short-lived certs with ECDSA keys
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/profiles -d '{
  "name": "Short-Lived Service Mesh",
  "allowed_key_algorithms": ["ECDSA"],
  "max_ttl_hours": 1,
  "allowed_ekus": ["serverAuth", "clientAuth"]
}'

# Assign profile to a certificate
curl -X PUT -H "$AUTH" -H "$CT" $SERVER/api/v1/certificates/mc-api-prod -d '{
  "profile_id": "prof-short-lived"
}'

# List all profiles
curl -H "$AUTH" "$SERVER/api/v1/profiles" | jq '.data[] | {id, name, max_ttl_hours, allowed_key_algorithms}'

# Get profile details
curl -H "$AUTH" "$SERVER/api/v1/profiles/prof-standard-tls" | jq .

# Update profile constraints
curl -X PUT -H "$AUTH" -H "$CT" $SERVER/api/v1/profiles/prof-standard-tls -d '{
  "name": "Standard TLS", "max_ttl_hours": 2160, "allowed_key_algorithms": ["RSA", "ECDSA"]
}'
```

| Field | Details |
|-------|---------|
| **ID** | Prefixed text PK (p-xxx) |
| **Name** | Human-readable profile name |
| **Allowed Key Algorithms** | RSA, ECDSA, Ed25519 with minimum key sizes (e.g., RSA 2048+, ECDSA P-256+) |
| **Max TTL** | Maximum certificate lifetime (days or duration) |
| **Allowed EKUs** | Extended key usage OIDs (serverAuth, clientAuth, etc.) |
| **Required SANs** | Mandatory Subject Alternative Names (patterns or fixed values) |
| **Short-Lived Support** | TTL < 1 hour triggers CRL/OCSP exemption |

### GUI Management
- Full CRUD page with profile details
- Crypto constraint badges visible in list view
- Profile assignment dropdown on certificate detail

---

## Policy Engine

Policies catch misconfigurations before they reach production. For example, a policy can prevent staging certificates from being issued by your production CA, or flag certificates missing an owner (which means nobody gets alerted when they expire).

```bash
# Create a policy requiring all certs to have an owner
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/policies -d '{
  "name": "Require Ownership",
  "type": "RequiredMetadata",
  "severity": "Error",
  "config": {"required_fields": ["owner_id", "team_id"]}
}'

# Check violations for a policy
curl -H "$AUTH" "$SERVER/api/v1/policies/rp-standard/violations"
```

### Policy Rules (5 types)
| Rule Type | Purpose | Example |
|-----------|---------|---------|
| **AllowedIssuers** | Restrict which CAs can issue | Only LetsEncrypt or Internal CA |
| **AllowedDomains** | Domain whitelist/blacklist | Allow *.example.com, deny *.staging.example.com |
| **RequiredMetadata** | Enforce ownership, team | Require owner_id and team_id populated |
| **AllowedEnvironments** | Environment constraints | Restrict to production or staging |
| **RenewalLeadTime** | Minimum renewal window | Renew 60 days before expiry (minimum) |

### Violation Tracking
- **Severity Levels** — Warning, Error, Critical
- **Per-Policy Violations** — `GET /api/v1/policies/{id}/violations` with timestamp and violated certificate ID
- **Real-Time Evaluation** — Violations checked during issuance, renewal, and deployment
- **Audit Trail** — All violations logged to audit events table

### Policy Application Scope
- Applied at renewal policy level
- Scoped to agent groups via `agent_group_id` foreign key
- Rule set can be enabled/disabled per policy

---

## Issuer Connectors (4 Implemented)

### Local CA
- **Mode** — Self-signed (default) or sub-CA (production)
- **Sub-CA Configuration** — Load CA cert+key from disk (`CERTCTL_CA_CERT_PATH`, `CERTCTL_CA_KEY_PATH`)
- **Key Formats Supported** — RSA, ECDSA, PKCS#8
- **CRL Generation** — Signed by CA, 24h validity
- **OCSP Signing** — Delegates to CA's private key
- **Use Case** — Internal PKI, enterprise trust chains

### ACME v2
- **Challenge Types** — HTTP-01 (default), DNS-01 (wildcard support), and DNS-PERSIST-01 (standing record, no per-renewal DNS updates)
- **DNS-01 Script Hooks** — Pluggable DNS solver for any provider (Cloudflare, Route53, Azure DNS, etc.)
- **DNS-PERSIST-01** — Standing `_validation-persist` TXT record set once, reused forever. Auto-fallback to DNS-01 if CA doesn't support it yet.
- **Configuration** — `CERTCTL_ACME_DIRECTORY_URL`, `CERTCTL_ACME_EMAIL`, `CERTCTL_ACME_CHALLENGE_TYPE`, `CERTCTL_ACME_DNS_PRESENT_SCRIPT`, `CERTCTL_ACME_DNS_CLEANUP_SCRIPT`, `CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN`
- **DNS Propagation Wait** — Configurable timeout before validation
- **Use Case** — Public CAs (LetsEncrypt), wildcard certs

### step-ca
- **Protocol** — Native `/sign` and `/revoke` API (not ACME)
- **Authentication** — JWK provisioner with key file + password
- **Configuration** — `CERTCTL_STEPCA_URL`, `CERTCTL_STEPCA_PROVISIONER`, `CERTCTL_STEPCA_KEY_PATH`, `CERTCTL_STEPCA_PASSWORD`
- **Operations** — Issue, renew, revoke
- **Use Case** — Smallstep private CA, internal PKI with strong auth

### OpenSSL / Custom CA
- **Mechanism** — Delegate signing to user-provided shell scripts
- **Scripts** — Sign script (CSR→cert), revoke script (serial+reason), CRL script (full CRL)
- **Timeout** — Configurable timeout (default 30s) with process interruption
- **Configuration** — `CERTCTL_OPENSSL_SIGN_SCRIPT`, `CERTCTL_OPENSSL_REVOKE_SCRIPT`, `CERTCTL_OPENSSL_CRL_SCRIPT`, `CERTCTL_OPENSSL_TIMEOUT_SECONDS`
- **Use Case** — PKIX-compliant external CAs, PowerShell issuers, custom workflows

---

## Target Connectors (5 Implemented + 2 Stubs)

### NGINX
- **Deployment** — Separate cert, chain, and key files
- **Validation** — `nginx -t` configuration test
- **Reload** — Graceful reload via SIGHUP (or nginx -s reload)
- **Target Config** — Certificate path, chain path, key path
- **Status** — Fully implemented (M10)

### Apache httpd
- **Deployment** — Separate cert, chain, and key files
- **Validation** — `apachectl configtest` or `apache2ctl configtest`
- **Reload** — Graceful reload via `apachectl graceful` or `apache2ctl graceful`
- **Target Config** — Certificate path, chain path, key path
- **Status** — Fully implemented (M10)

### HAProxy
- **Deployment** — Combined PEM file (cert + chain + key concatenated)
- **Validation** — Optional `haproxy -c -f config` test
- **Reload** — Process signal or socket-based reload (configurable)
- **Target Config** — Combined PEM path, optional reload command
- **Status** — Fully implemented (M10)

### Traefik
- **Deployment** — File provider: writes cert and key to Traefik's watched certificate directory
- **Auto-Reload** — Traefik's file provider watches the directory for changes; no explicit reload needed
- **Target Config** — Certificate directory, cert filename, key filename
- **Status** — Fully implemented (M26)

### Caddy
- **Dual-Mode Deployment** — Admin API (hot-reload via `POST /load`) or file-based (write cert+key, Caddy watches)
- **API Mode** — Posts certificate to Caddy's admin API endpoint for zero-downtime reload
- **File Mode** — Writes cert and key files to configured directory (fallback when admin API is unavailable)
- **Target Config** — Admin API URL, certificate directory, cert filename, key filename, mode (api/file)
- **Status** — Fully implemented (M26)

### F5 BIG-IP (Stub)
- **Protocol** — iControl REST API via proxy agent
- **Status** — Interface only in V2; implementation in V3 (paid)
- **Deployment Model** — Proxy agent + BIG-IP API client in same network zone
- **Authentication** — iControl credentials stored in target config

### IIS (Stub)
- **Dual-Mode Architecture** — Agent-local PowerShell (primary) or proxy agent WinRM (agentless)
- **Status** — Interface only in V2; implementation in V3 (paid)
- **Deployment Model** — Agent runs PowerShell cmdlets locally or proxy agent invokes WinRM
- **Binding** — Bind certificate to IIS site by hostname

---

## Notifier Connectors (6 Channels)

Notifications route certificate events to the people and systems that need to know. Each channel is enabled by setting its env var — no code changes needed.

```bash
# Enable Slack notifications (just set the webhook URL)
export CERTCTL_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx"

# Enable PagerDuty escalation for critical events
export CERTCTL_PAGERDUTY_ROUTING_KEY="your-routing-key"
export CERTCTL_PAGERDUTY_SEVERITY="critical"
```

### Email
- **SMTP** — Standard SMTP or TLS endpoint
- **Configuration** — Server, port, auth credentials (env vars)
- **Use Case** — Owner notifications, compliance distribution lists

### Webhook
- **HTTP POST** — Custom JSON payload to any endpoint
- **Headers** — Content-Type, custom auth headers (configurable)
- **Use Case** — Slack (via custom webhook), Microsoft Power Automate, custom platforms

### Slack
- **Protocol** — Incoming Webhook
- **Message Format** — Markdown with bold subject, formatted body
- **Overrides** — Channel (`CERTCTL_SLACK_CHANNEL`), username (`CERTCTL_SLACK_USERNAME`), emoji
- **Configuration** — `CERTCTL_SLACK_WEBHOOK_URL`
- **Use Case** — Team notifications, ops channels

### Microsoft Teams
- **Protocol** — Incoming Webhook
- **Message Format** — MessageCard with ThemeColor, Summary, Sections
- **Markdown Support** — Formatted text within sections
- **Configuration** — `CERTCTL_TEAMS_WEBHOOK_URL`
- **Use Case** — Team-wide alerts, cross-team visibility

### PagerDuty
- **Protocol** — Events API v2
- **Trigger Events** — Alert on expiration, failure, revocation
- **Severity** — Configurable default (default "warning")
- **Custom Details** — Certificate ID, days remaining, owner, etc.
- **Configuration** — `CERTCTL_PAGERDUTY_ROUTING_KEY`, `CERTCTL_PAGERDUTY_SEVERITY`
- **Use Case** — Incident response, on-call escalations

### OpsGenie
- **Protocol** — Alert API v2
- **Priority** — Configurable default (default "P3")
- **Tags** — Category tags (cert expiration, deployment failure, etc.)
- **Responders** — Optional team routing
- **Configuration** — `CERTCTL_OPSGENIE_API_KEY`, `CERTCTL_OPSGENIE_PRIORITY`
- **Use Case** — Multi-team alerting, escalation policies

### Notification Types
- **Expiration Alert** — Certificate approaching threshold (30/14/7/0 days)
- **Renewal Started** — Renewal job initiated
- **Renewal Completed** — Certificate successfully renewed
- **Deployment Completed** — Certificate deployed to target
- **Deployment Failed** — Target deployment error
- **Revocation** — Certificate revoked with reason
- **Policy Violation** — Certificate violates renewal policy

---

## Agent Fleet

Agents are lightweight Go binaries deployed on your servers that handle the last mile — generating private keys locally, submitting CSRs, and deploying signed certificates to web servers. The control plane never touches private keys or initiates outbound connections, keeping your security perimeter intact.

```bash
# Start an agent (it auto-registers and begins polling for work)
export CERTCTL_SERVER_URL=http://certctl.internal:8443
export CERTCTL_API_KEY=agent-api-key
export CERTCTL_AGENT_ID=ag-nginx-prod-1
./certctl-agent --key-dir /var/lib/certctl/keys --discovery-dirs /etc/ssl/certs

# Check agent status from the control plane
curl -H "$AUTH" $SERVER/api/v1/agents/ag-nginx-prod-1 | jq '{status, last_heartbeat, os, architecture}'
```

### Agent Registration & Heartbeat
- **Registration** — `POST /api/v1/agents` with agent name and API key
- **Heartbeat** — `POST /api/v1/agents/{id}/heartbeat` every 60 seconds
- **Auto-Offline** — Agents marked offline after 3 missed heartbeats (configurable)
- **Last Heartbeat Timestamp** — Tracked in `agents` table

### Agent Metadata (M10)
Collected via runtime introspection and network utilities.

| Field | Source | Example |
|-------|--------|---------|
| **OS** | `runtime.GOOS` | linux, darwin, windows |
| **Architecture** | `runtime.GOARCH` | amd64, arm64 |
| **Hostname** | `os.Hostname()` | nginx-prod-1 |
| **IP Address** | `net.Interface` + `net.IP` | 10.0.1.5 |
| **Version** | Agent binary version (from build flags) | v2.1.0 |

### Agent Groups (M11b)
Dynamic grouping and filtering for policy assignment and deployment targeting. Agent groups let you apply renewal policies to subsets of your fleet — for example, "all Linux amd64 agents in the 10.0.0.0/8 network" — without manually listing every agent.

```bash
# Create a group matching all Linux agents in a specific subnet
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/agent-groups -d '{
  "id": "ag-linux-dc1", "name": "Linux DC1",
  "os_match": "linux", "ip_cidr_match": "10.0.1.0/24"
}'

# List groups and their criteria
curl -H "$AUTH" "$SERVER/api/v1/agent-groups" | jq '.items[] | {id, name, os_match, ip_cidr_match}'

# View members of a group (dynamically matched + manual includes)
curl -H "$AUTH" "$SERVER/api/v1/agent-groups/ag-linux-dc1/members" | jq '.items[].agent_id'
```

| Criterion | Details | Example |
|-----------|---------|---------|
| **OS Match** | Exact string match | linux, darwin, windows |
| **Architecture Match** | Exact string match | amd64, arm64, 386 |
| **IP CIDR Match** | IPv4 or IPv6 CIDR block | 10.0.0.0/8, 192.168.1.0/24 |
| **Version Match** | Semantic version range (optional) | >=2.0.0, <3.0.0 |
| **Manual Membership** | Explicit include/exclude | Include a-xxx, exclude a-yyy |
| **MatchesAgent()** | Dynamic evaluation at job time | Criteria match→agent included |

### Agent Group GUI
- List with dynamic match criteria badges (color-coded)
- Enable/disable toggle per group
- Manual membership editor (include/exclude lists)
- Agent count per group (dynamic)
- Scoped to renewal policies via `agent_group_id` FK

### Agent Capabilities
Agents report to `/api/v1/agents/{id}/work` with supported target types and issuers.

- **Target Deployment** — NGINX, Apache httpd, HAProxy, Traefik, Caddy, F5 BIG-IP (proxy), IIS (proxy)
- **Key Management** — ECDSA P-256 keygen, key storage at `CERTCTL_KEY_DIR` (default `/var/lib/certctl/keys`), 0600 file permissions
- **CSR Submission** — `POST /api/v1/agents/{id}/csr` for AwaitingCSR jobs

### Fleet Overview Page
- **OS/Architecture Grouping** — Agents grouped by GOOS + GOARCH
- **Charts** — Status distribution (pie), version breakdown (bar)
- **Per-Platform Listing** — Expandable agent list under each OS/Arch combo
- **Health Indicators** — Online/offline status, last heartbeat, uptime

---

## Certificate Discovery (M18b)

### Overview
Agents automatically discover existing certificates in the infrastructure — on filesystem, in key stores, or elsewhere — report findings to the control plane, and operators triage them for enrollment.

### Agent-Side Discovery
- **Configuration** — `CERTCTL_DISCOVERY_DIRS` env var (comma-separated list) or `--discovery-dirs` CLI flag
- **Scan Execution** — Runs on agent startup and every 6 hours in background
- **Supported Formats** — PEM (.pem, .crt, .cer, .cert) and DER (.der) files
- **Recursive Walk** — Scans directory trees to find all certificates
- **File Filtering** — Skips files > 1MB and obvious key files

### Certificate Extraction
Each discovered certificate is parsed and its metadata extracted:

| Field | Source | Example |
|-------|--------|---------|
| **Common Name** | X.509 Subject CN | api.example.com |
| **SANs** | X.509 SubjectAltNames | api.example.com, *.api.example.com |
| **Serial** | Certificate serial number | 0x123abc... |
| **Issuer DN** | X.509 Issuer | CN=Internal CA, O=Acme Inc |
| **Subject DN** | X.509 Subject | CN=api.example.com, O=Acme Inc |
| **Not Before** | Validity start | 2024-01-15T00:00:00Z |
| **Not After** | Validity end | 2026-01-15T00:00:00Z |
| **Key Algorithm** | Key type | RSA, ECDSA, Ed25519 |
| **Key Size** | Bits | 2048, 256, 4096 |
| **Is CA** | CA flag in extensions | true/false |
| **Fingerprint** | SHA-256 hash (dedup key) | a1b2c3d4e5f6... |

### Server-Side Processing
- **Deduplication** — Uses fingerprint + agent ID + path as unique key; prevents duplicates
- **Status Tracking** — Three statuses: **Unmanaged** (discovered, not yet claimed), **Managed** (linked to control plane cert), **Dismissed** (operator decided not to manage)
- **Audit Trail** — `discovery_scan_completed`, `discovery_cert_claimed`, `discovery_cert_dismissed` events logged with actor and reason
- **Storage** — `discovered_certificates` and `discovery_scans` tables in PostgreSQL

### Triage Workflow
1. Agent submits scan results via `POST /api/v1/agents/{id}/discoveries`
2. Server deduplicates and stores discovery records
3. Operator views `GET /api/v1/discovered-certificates?status=Unmanaged`
4. For each unmanaged cert:
   - **Claim it** — `POST /api/v1/discovered-certificates/{id}/claim` links to managed cert or creates new enrollment
   - **Dismiss it** — `POST /api/v1/discovered-certificates/{id}/dismiss` removes from triage queue
5. Tracking enables visibility into what's deployed vs. what's managed

### Discovery API Endpoints (M18b)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/agents/{id}/discoveries` | POST | Agent submits scan results |
| `/api/v1/discovered-certificates` | GET | List discovered certs (with ?agent_id, ?status filters) |
| `/api/v1/discovered-certificates/{id}` | GET | Get single discovered cert detail |
| `/api/v1/discovered-certificates/{id}/claim` | POST | Link to managed cert or create enrollment |
| `/api/v1/discovered-certificates/{id}/dismiss` | POST | Dismiss from triage |
| `/api/v1/discovery-scans` | GET | List scan history with timestamps |
| `/api/v1/discovery-summary` | GET | Aggregate status counts (Unmanaged, Managed, Dismissed) |

```bash
# Check triage status at a glance
curl -H "$AUTH" "$SERVER/api/v1/discovery-summary" | jq .
# → {"Unmanaged": 12, "Managed": 45, "Dismissed": 3}

# Review scan execution history
curl -H "$AUTH" "$SERVER/api/v1/discovery-scans" | jq '.data[] | {agent_id, certificates_found, certificates_new, started_at}'
```

### Use Cases
- **Inventory Baseline** — Scan production servers at deployment time to establish baseline of existing certificates
- **Compliance Discovery** — Find all TLS certs before renewing certificate policies
- **Migration Planning** — Discover unmanaged certs to plan migration from other CA/platforms
- **Audit Preparation** — Triage discovered certs into managed and dismissed for compliance reports
- **Multi-CA Migration** — Find all certs currently issued by old CA, claim them for renewal under new issuer

---

## Network Certificate Discovery (M21)

### Overview
Server-side active TLS scanning probes network endpoints across CIDR ranges, extracts certificate metadata from TLS handshakes, and feeds results into the existing filesystem discovery pipeline. No agent deployment required — the control plane scans directly.

### Configuration
- **Enable** — `CERTCTL_NETWORK_SCAN_ENABLED=true` (disabled by default)
- **Scan Interval** — `CERTCTL_NETWORK_SCAN_INTERVAL=6h` (default 6 hours, configurable)

### Network Scan Targets
Scan targets define what CIDR ranges and ports to probe.

| Field | Details | Example |
|-------|---------|---------|
| **ID** | Prefixed text PK (nst-xxx) | nst-datacenter-east |
| **Name** | Human-readable target name | Datacenter East Production |
| **CIDRs** | Array of CIDR ranges | ["10.0.1.0/24", "10.0.2.0/24"] |
| **Ports** | Array of TCP ports | [443, 8443, 6443] |
| **Enabled** | Toggle scanning on/off | true |
| **Scan Interval Hours** | Per-target scan frequency | 6 |
| **Timeout Ms** | Per-connection timeout | 5000 |

### Scanning Behavior
- **CIDR Expansion** — Ranges expanded to individual IPs; safety cap at /20 (4096 IPs) prevents accidental large scans
- **Concurrent Probing** — 50 goroutines (semaphore-based), configurable timeout per TLS connection
- **TLS Extraction** — `crypto/tls.DialWithDialer` with `InsecureSkipVerify=true` discovers all certs including self-signed, expired, and internal CA certs
- **Sentinel Agent Pattern** — Uses `server-scanner` as virtual agent ID, reusing the existing `discovered_certificates` dedup constraint without schema changes
- **Discovery Pipeline** — Scan results feed into `DiscoveryService.ProcessDiscoveryReport()` for fingerprint dedup, audit trail, and triage workflow

### Network Scan API Endpoints (M21)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/network-scan-targets` | GET | List all scan targets with metrics |
| `/api/v1/network-scan-targets` | POST | Create a new scan target |
| `/api/v1/network-scan-targets/{id}` | GET | Get scan target details |
| `/api/v1/network-scan-targets/{id}` | PUT | Update scan target configuration |
| `/api/v1/network-scan-targets/{id}` | DELETE | Delete a scan target |
| `/api/v1/network-scan-targets/{id}/scan` | POST | Trigger an immediate scan |

### Scheduler Integration
- **6th scheduler loop** — runs at configured interval (default 6h) alongside renewal (1h), jobs (30s), health (2m), notifications (1m), short-lived expiry (30s)
- **Conditional** — only starts if `CERTCTL_NETWORK_SCAN_ENABLED=true` and network scan service is initialized
- **Scan Metrics** — each target tracks `last_scan_at`, `last_scan_duration_ms`, `last_scan_certs_found`

### Use Cases
- **Network Inventory** — "What TLS certs are deployed across my network?" without deploying agents
- **Shadow Certificate Detection** — Find certificates on services you didn't know were running TLS
- **Compliance Scanning** — Prove to auditors that all TLS endpoints are inventoried
- **Migration Assessment** — Scan a network range before onboarding to certctl management
- **Expiration Monitoring** — Discover soon-to-expire certs on network endpoints before they cause outages

---

## Ownership & Accountability

Without ownership, expiring certificates become "someone else's problem." Ownership tracking ensures every certificate has a named person and team who receive alerts and are accountable for renewal. When an auditor asks "who owns this cert?", the answer is one API call away.

```bash
# Create a team
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/teams -d '{"name": "Platform Engineering", "email": "platform@example.com"}'

# Create an owner
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/owners -d '{"name": "Alice Chen", "email": "alice@example.com", "team_id": "t-platform"}'

# Assign owner to certificate — Alice now receives all alerts for this cert
curl -X PUT -H "$AUTH" -H "$CT" $SERVER/api/v1/certificates/mc-api-prod -d '{"owner_id": "o-alice"}'
```

### Teams
- **Model** — Team grouping for organizational structure
- **Team Assignment** — Certificates and policies assigned to teams
- **Email Distribution** — Optional team email for notifications
- **Resolver Logic** — Team name → member lookup via API (external resolution)
- **GUI** — CRUD page with member management

### Owners
- **Model** — Individual person responsible for certificates
- **Email Routing** — Owner email used for notification delivery
- **Team Association** — Owners belong to teams
- **Certificate Assignment** — Certificates assigned to owner (1:1 or group)
- **Notification Routing** — Expiration/renewal/revocation alerts sent to owner email
- **GUI** — CRUD page with team picker, email validation

### Interactive Renewal Approval (M11b)
- **AwaitingApproval Job State** — Renewal jobs pause for human approval
- **Approval Flow** — `POST /api/v1/jobs/{id}/approve` (proceed with renewal)
- **Rejection Flow** — `POST /api/v1/jobs/{id}/reject` with reason text (cancel job)
- **Reason Tracking** — Approval/rejection reason logged to job history and audit
- **Use Case** — Change control, compliance gates, sensitive certificate renewal

---

## Observability

Observability answers "is certctl healthy and are my certificates safe?" without opening the dashboard. Metrics integrate with your existing monitoring stack (Prometheus, Grafana, Datadog), stats power the dashboard charts, structured logs feed your SIEM, and the audit trail proves to auditors what happened and when.

```bash
# Quick health check
curl $SERVER/health
# {"status":"healthy"}

# Dashboard summary — how many certs, what's expiring, agent health
curl -H "$AUTH" $SERVER/api/v1/stats/summary | jq .

# Prometheus metrics — scrape this from your monitoring stack
curl -H "$AUTH" $SERVER/api/v1/metrics/prometheus
# certctl_certificate_total 15
# certctl_certificate_expiring 3
# certctl_agent_active 4
# ...

# JSON metrics — for custom dashboards
curl -H "$AUTH" $SERVER/api/v1/metrics | jq .
```

### Observability Layers

#### Dashboard Charts (M14)
Live aggregated views of certificate and job metrics.

| Chart | Type | Details |
|-------|------|---------|
| **Expiration Heatmap** | Stacked bar | 90-day weekly buckets; per-status color bands |
| **Renewal Success Rate** | Line (30-day) | Success % trending over time |
| **Certificate Status Distribution** | Donut | Pie breakdown: Active, Expiring, Expired, Failed, Revoked, etc. |
| **Issuance Rate** | Bar (30-day) | Certs issued per day; trend line |

#### Metrics Endpoints

**JSON Format**
- **URL** — `GET /api/v1/metrics`
- **Format** — JSON with timestamp
- **Gauges** — Certificate counts by status, agent count (online/offline), pending job count
- **Counters** — Total jobs completed, total jobs failed, total renewals, total issuances
- **Uptime** — Server uptime in seconds

**Prometheus Exposition Format (M22)**
- **URL** — `GET /api/v1/metrics/prometheus`
- **Content-Type** — `text/plain; version=0.0.4; charset=utf-8`
- **Compatible with** — Prometheus, Grafana Agent, Datadog Agent, Victoria Metrics, OpenMetrics scrapers
- **Naming** — `certctl_` prefix, snake_case (e.g., `certctl_certificate_total`, `certctl_agent_online`)
- **11 Metrics** — 8 gauges (cert total/active/expiring/expired/revoked, agent total/online, job pending), 2 counters (job completed/failed totals), 1 gauge (uptime seconds)
- **Scrape Config** — Add to `prometheus.yml`: `scrape_configs: [{job_name: certctl, static_configs: [{targets: ['localhost:8443']}], metrics_path: /api/v1/metrics/prometheus}]`

#### Stats API (M14)
Five parameterized endpoints for dashboard data.

| Endpoint | Parameters | Response |
|----------|------------|----------|
| **GET /api/v1/stats/summary** | None | Total certs, expiring soon, renewals in progress, failed jobs, agents online |
| **GET /api/v1/stats/certificates-by-status** | None | Count per status (Active, Expiring, Expired, etc.) |
| **GET /api/v1/stats/expiration-timeline** | days (default 90) | Weekly buckets with cert counts; 90-day default |
| **GET /api/v1/stats/job-trends** | days (default 30) | Daily completed/failed job counts; line chart ready |
| **GET /api/v1/stats/issuance-rate** | days (default 30) | Certs issued per day; 30-day default |

#### Structured Logging (M14)
- **Library** — Go's `log/slog` (structured, context-aware)
- **Request ID Propagation** — Per-request UUID in context; logged on all operations
- **Middleware** — `NewLogging(logger *slog.Logger)` middleware wrapping all API calls
- **Log Format** — JSON (default) or text; configurable via `CERTCTL_LOG_FORMAT`
- **Log Level** — debug, info, warn, error; configurable via `CERTCTL_LOG_LEVEL`

#### API Audit Middleware (M19)
Every API call recorded to immutable `audit_events` table.

| Logged Field | Details |
|--------------|---------|
| **Method** | HTTP verb (GET, POST, PUT, DELETE) |
| **Path** | Request path (e.g., /api/v1/certificates) |
| **Actor** | Authenticated user/API key (or "anonymous") |
| **Body Hash** | SHA-256 of request body (truncated first 16 chars for brevity) |
| **Response Status** | HTTP status code |
| **Latency** | Request processing time in ms |
| **Timestamp** | RFC3339 format |

#### Immutable Audit Trail
- **Table** — `audit_events` append-only (no UPDATE/DELETE)
- **Events** — Issuance, renewal, deployment, revocation, policy violations, approval/rejection
- **Retention** — Indefinite (no expiration)
- **GUI Export** — CSV/JSON export with applied time-range, actor, action filters
- **Query API** — `GET /api/v1/audit?actor=...&resource=...&action=...&before=...&after=...`

#### Deployment Rollback Support (M14)
- **Version History** — Sorted by deployment timestamp
- **Current Badge** — Visual indicator on latest deployed version
- **Rollback Button** — Click to re-deploy previous version
- **Versioning** — Each cert version tracked (serial, fingerprint, PEM)

---

## Job System

Jobs are the work units that drive the certificate lifecycle. Every issuance, renewal, and deployment is tracked as a job with a clear state machine, so operators always know exactly where each operation stands and can troubleshoot failures.

```bash
# List pending jobs
curl -H "$AUTH" "$SERVER/api/v1/jobs?status=Pending" | jq '.items[] | {id, type, status, certificate_id}'

# Cancel a stuck job
curl -X POST -H "$AUTH" $SERVER/api/v1/jobs/j-abc123/cancel

# Approve a renewal waiting for human sign-off
curl -X POST -H "$AUTH" -H "$CT" $SERVER/api/v1/jobs/j-abc123/approve -d '{"reason": "Approved per change ticket #1234"}'
```

### Job Types (4 total)
| Type | Trigger | States | Output |
|------|---------|--------|--------|
| **Issuance** | New certificate creation | Pending → AwaitingCSR/Running → Completed/Failed | Certificate version with serial |
| **Renewal** | Auto-renewal or manual trigger | Pending → AwaitingCSR/AwaitingApproval/Running → Completed/Failed | New certificate version |
| **Deployment** | Automatic or manual post-renewal | Pending → AwaitingCSR/Running → Completed/Failed | Target-specific status |
| **Validation** | Scheduled or manual | Pending → Running → Completed/Failed | Validation report (TBD V3) |

### Job States (7 total)
| State | Meaning | Transition |
|-------|---------|-----------|
| **Pending** | Created, awaiting processing | → AwaitingCSR or Running |
| **AwaitingCSR** | Agent needs to generate key + submit CSR | → Running (after CSR received) |
| **AwaitingApproval** | Human approval required (renewal only) | → Running (approve) or Cancelled (reject) |
| **Running** | Active processing (issuance, deployment, etc.) | → Completed or Failed |
| **Completed** | Successfully finished | (terminal) |
| **Failed** | Error during processing; no retry auto-scheduled | (terminal; manual retry available) |
| **Cancelled** | Explicitly cancelled by user or system | (terminal) |

### Job Lifecycle Example (Agent Keygen)
1. **Renewal triggered** → Job created in `Pending` state
2. **Scheduler polls** → Job transitioned to `AwaitingCSR`
3. **Work endpoint** → Agent receives job with common_name and SANs
4. **Agent keygen** → ECDSA P-256 key created locally; CSR submitted
5. **CSR received** → Server signs; Job transitioned to `Running`
6. **Deployment scheduled** → New Deployment job created in `Pending`
7. **Agent deploys** → Deployment job → `Running` → `Completed`
8. **Post-deployment verification** → Agent probes live TLS endpoint, compares SHA-256 fingerprint
9. **Status reported** → `POST /api/v1/agents/{id}/jobs/{job_id}/status`

### Approval Flow (Interactive)
1. **Renewal job created** in `AwaitingApproval` state (if policy requires)
2. **Human reviews** on GUI
3. **Approve** → `POST /api/v1/jobs/{id}/approve` → Job → `Running`
4. **Reject** → `POST /api/v1/jobs/{id}/reject` + reason → Job → `Cancelled`

### Background Scheduler (6 loops)
| Loop | Interval | Task |
|------|----------|------|
| **Renewal Checker** | 1 hour | Scan policies; trigger renewals if cert expires soon |
| **Job Processor** | 30 seconds | Process Pending → AwaitingCSR/Running; poll agent status |
| **Health Checker** | 2 minutes | Check agent heartbeat; mark offline if >3 missed |
| **Notification Processor** | 1 minute | Send queued notifications (email, Slack, webhook, etc.) |
| **Short-Lived Cleanup** | 30 seconds | Audit short-lived credential expirations |
| **Network Scanner** | 6 hours | Scan enabled network targets; discover TLS certificates |

All loops have configurable intervals via environment variables (`CERTCTL_SCHEDULER_*_INTERVAL`).

---

## Web Dashboard

### Overview
The web dashboard is the primary operational interface for certctl. Built with **Vite + React 18 + TypeScript + TanStack Query v5 + Tailwind CSS 3 + Recharts**.

| Page | Route | Purpose |
|------|-------|---------|
| **Dashboard** | `/` | Overview: summary cards, 4 charts (expiration, renewal rate, status, issuance), quick actions |
| **Certificates** | `/certificates` | List with multi-select, bulk operations (renew/revoke/reassign), new cert modal, sorting/filtering |
| **Certificate Detail** | `/certificates/:id` | Full cert view: deployment timeline, inline policy editor, version history, rollback, revoke, archive, renew actions |
| **Agents** | `/agents` | List with metadata (OS, architecture, IP, version), online status, uptime |
| **Agent Detail** | `/agents/:id` | Full system information, recent jobs, heartbeat graph, capabilities, metrics |
| **Agent Fleet Overview** | `/fleet` | OS/architecture grouping with pie charts (status, version), per-platform agent listing |
| **Jobs** | `/jobs` | Queue view with type filter, status filter, inline cancel/approve/reject, retry button |
| **Notifications** | `/notifications` | Grouped by certificate, mark-as-read toggle, filter by type (expiration, deployment, revocation) |
| **Policies** | `/policies` | CRUD with rule builder, enable/disable toggle, violations summary bar, violation list |
| **Profiles** | `/profiles` | List with crypto constraints (key algorithms, TTL, EKUs), create/edit/delete |
| **Issuers** | `/issuers` | List, create new issuer, test connection button, delete |
| **Targets** | `/targets` | List, 3-step configuration wizard (Select Type → Configure → Review), type-specific fields |
| **Owners** | `/owners` | List, create/edit with team picker, email field, delete |
| **Teams** | `/teams` | List, create/edit with member resolver, delete |
| **Agent Groups** | `/agent-groups` | List with dynamic match criteria badges (OS, arch, IP CIDR, version), manual membership editor |
| **Audit Trail** | `/audit` | Filtered view (time range, actor, action), CSV/JSON export buttons, event detail modal |
| **Short-Lived Credentials** | `/short-lived` | Filtered by profile with TTL < 1 hour, live countdown timer, auto-refresh every 10s, stats bar |
| **Login** | `/login` | API key entry, auth mode detection, redirect after successful auth |
| **ErrorBoundary** | (all pages) | Graceful crash recovery; displays user-friendly error message instead of white screen |

### Dashboard Features

#### Bulk Operations
- **Multi-Select** — Checkbox column in certificate list; "Select All" toggle
- **Bulk Renew** — Trigger renewal on selected certs; progress bar
- **Bulk Revoke** — Select reason codes per cert; sequential revocation; progress
- **Bulk Reassign** — Owner picker modal; assign to multiple certs at once

#### Deployment Timeline
- **Visual 4-Step Timeline** — Requested → Issued → Deploying → Active
- **Per-Certificate Job Queries** — Query jobs to get current phase
- **Status Indicators** — Checkmarks for completed phases; spinner for running; X for failed

#### Inline Policy Editor
- **Edit Mode** — Click edit button on cert detail
- **Policy Dropdown** — Select from list of policies
- **Renewal Threshold Config** — Inline sliders/inputs for 30/14/7/0 day thresholds
- **Save/Cancel** — API mutations with optimistic updates via TanStack Query

#### Target Configuration Wizard
- **Step 1: Select Type** — Radio or dropdown (NGINX, Apache, HAProxy, Traefik, Caddy, F5, IIS)
- **Step 2: Configure** — Type-specific fields (cert path, chain path, key path, etc.)
- **Step 3: Review** — Summary of config; confirm create
- **Validation** — Real-time field validation; show errors; disable Create if invalid

#### Auth & Session
- **Auth Context** — React context with API key, auth mode, session state
- **Auto-Redirect** — 401 response → redirect to /login
- **Logout** — Button in sidebar; clears context; redirects to /login
- **Remember API Key** — Persisted in localStorage (production should clear on logout)

#### Demo Mode
- Activates when API is unreachable
- Renders realistic mock data for screenshots
- Useful for offline presentations

---

## Integration Interfaces

### MCP Server (M18a)
**Separate binary** (`cmd/mcp-server/`) providing AI-native access to certctl via Claude, Cursor, OpenClaw. Instead of memorizing 91 API endpoints, ask your AI assistant "what certificates are expiring this week?" or "renew the API prod cert" and it translates to the right API calls.

- **Transport** — stdio (stdin/stdout)
- **Protocol** — Model Context Protocol v1
- **SDK** — Official `modelcontextprotocol/go-sdk` v1.4.1
- **Tools** — 78 MCP tools covering all API endpoints
- **Organization** — 16 resource domains (Certificates, Issuers, Targets, Agents, Jobs, etc.)
- **Authentication** — Bearer token via `CERTCTL_API_KEY` env var
- **Configuration** — `CERTCTL_SERVER_URL` (e.g., http://localhost:8080) + `CERTCTL_API_KEY`
- **Input Types** — 33 typed structs with `jsonschema` tags for auto-generated LLM-friendly schemas
- **Stateless Design** — HTTP proxy (no state held in MCP server; all logic in REST API)

### CLI Tool (certctl-cli, M16b)
**Lightweight command-line wrapper** around REST API.

| Subcommand | Usage | Output Format |
|------------|-------|----------------|
| **certs list** | `certctl-cli certs list` | Table or JSON (--format=json) |
| **certs get** | `certctl-cli certs get <id>` | JSON cert details |
| **certs renew** | `certctl-cli certs renew <id>` | Job ID confirmation |
| **certs revoke** | `certctl-cli certs revoke <id> [--reason]` | Revocation confirmation |
| **agents list** | `certctl-cli agents list` | Table or JSON |
| **agents get** | `certctl-cli agents get <id>` | Agent details |
| **jobs list** | `certctl-cli jobs list` | Table or JSON |
| **jobs get** | `certctl-cli jobs get <id>` | Job details |
| **jobs cancel** | `certctl-cli jobs cancel <id>` | Cancellation confirmation |
| **status** | `certctl-cli status` | Health + summary stats |
| **import** | `certctl-cli import <pem-file>` | Bulk import cert count |
| **version** | `certctl-cli version` | Version string |

**Implementation Details:**
- Stdlib-only (flag + text/tabwriter); no Cobra dependency
- JSON + table output formatters
- PEM parser for bulk import (multi-cert PEM files)
- Environment variables: `CERTCTL_SERVER_URL`, `CERTCTL_API_KEY`
- CLI flags: `--server`, `--api-key`, `--format` (json/table)
- Tested with httptest mock server; all commands covered

### EST Server (RFC 7030, M23)
**Enrollment over Secure Transport** — industry-standard protocol for device certificate enrollment. Enables WiFi/802.1X, MDM, IoT, and BYOD use cases where devices need certificates without direct API access.

**Endpoints** (under `/.well-known/est/` per RFC 7030):

| Endpoint | Method | Description | Wire Format |
|----------|--------|-------------|-------------|
| `/cacerts` | GET | CA certificate chain distribution | Base64 PKCS#7 certs-only (application/pkcs7-mime) |
| `/simpleenroll` | POST | Initial certificate enrollment | Request: PEM or base64-DER PKCS#10; Response: PKCS#7 |
| `/simplereenroll` | POST | Certificate re-enrollment (renewal) | Same as simpleenroll |
| `/csrattrs` | GET | CSR attributes the server requires | ASN.1 DER (application/csrattrs) |

**Architecture:**
- **ESTService** bridges handler to existing `IssuerConnector` — no new issuance logic, reuses existing CA connectors
- **CSR input handling** — accepts both base64-encoded DER (EST wire standard) and PEM-encoded PKCS#10 (convenience)
- **PKCS#7 output** — hand-rolled ASN.1 degenerate SignedData builder (no external PKCS#7 dependency)
- **CSR validation** — signature verification, Common Name extraction, SAN extraction (DNS, IP, email, URI)
- **Configurable issuer binding** — `CERTCTL_EST_ISSUER_ID` selects which issuer connector processes enrollment
- **Optional profile binding** — `CERTCTL_EST_PROFILE_ID` constrains enrollments to a specific certificate profile
- **Audit trail** — all EST enrollments recorded with protocol=EST, CN, SANs, issuer ID, serial, profile ID

**Configuration:**
| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_EST_ENABLED` | `false` | Enable EST enrollment endpoints |
| `CERTCTL_EST_ISSUER_ID` | `iss-local` | Issuer connector for EST enrollments |
| `CERTCTL_EST_PROFILE_ID` | — | Optional profile ID to constrain enrollments |

**Note:** EST endpoints currently use the same middleware stack as the REST API (API key auth). TLS client certificate authentication for EST is planned for V3.

### OpenAPI 3.1 Specification
- **File** — `api/openapi.yaml`
- **Scope** — 99 operations (97 API + /health + /ready), all request/response schemas, enums, pagination
- **Schemas** — Complete domain models with examples
- **Enums** — Job types, states, policy rule types, notification types
- **Pagination** — Standard envelope (data, total, page, per_page)
- **Security** — Bearer token security scheme
- **SDK Generation** — Supports go-swagger, openapi-generator, etc.

---

## Security Architecture

### Private Key Isolation
- **Agent-Side Keygen (Default)** — ECDSA P-256 keys generated on agents via Go's `crypto/ecdsa`
- **Local Key Storage** — Keys written to agent's `CERTCTL_KEY_DIR` (default `/var/lib/certctl/keys`) with 0600 permissions (user-readable only)
- **Server-Side Keygen (Demo Only)** — RSA-2048 keygen available via `CERTCTL_KEYGEN_MODE=server` with explicit log warning; never used in production
- **CSR Submission Only** — Agents submit CSRs (public) to control plane; private keys never leave agent infrastructure
- **Key Rotation** — Agents can re-key without control plane involvement (local only)

### Pull-Only Deployment Model
- **No Outbound Initiations** — Server never initiates connections to agents or targets
- **Agent Polling** — Agents poll `GET /api/v1/agents/{id}/work` every 30 seconds
- **Proxy Agent Pattern** — For network appliances (F5, Palo Alto) or agentless targets (Windows servers), a "proxy agent" in the same network zone executes deployments via the target's API
- **Credential Scope** — Proxy agent credentials limited to its zone; control plane never stores target credentials directly
- **Firewall-Friendly** — Control plane can be completely locked down; no inbound rules needed for agents

### Sub-CA Capability
- **Enterprise Integration** — Local CA can operate as subordinate CA under enterprise root (e.g., ADCS)
- **Disk-Based Cert+Key** — `CERTCTL_CA_CERT_PATH` + `CERTCTL_CA_KEY_PATH` load pre-signed CA cert and key
- **Chain Validation** — Issued certs chain to enterprise root; full trust hierarchy
- **Self-Signed Fallback** — Default mode generates self-signed root if paths not set (development/demo)
- **Key Formats** — RSA, ECDSA, PKCS#8 support with auto-detection

### API Authentication
- **SHA-256 Hashing** — API keys hashed with SHA-256 before storage
- **Constant-Time Comparison** — Prevents timing attacks during key validation
- **Bearer Token** — `Authorization: Bearer {api_key}` header on all authenticated endpoints
- **Configurable** — `CERTCTL_AUTH_TYPE=api-key` (default) enforced; "none" requires explicit opt-in with log warning

### Rate Limiting
- **Token Bucket** — Smooth rate limiting with burst capacity
- **RPS + Burst** — Configurable `CERTCTL_RATE_LIMIT_RPS` (default 50) and `CERTCTL_RATE_LIMIT_BURST` (default 100)
- **429 Responses** — Rate limit exceeded responses include `Retry-After` header
- **Per-Client** — Implemented per IP (future: per API key)

### Audit & Compliance
- **Immutable Audit Trail** — Append-only table; no UPDATE/DELETE operations
- **API Audit Middleware** — Every call logged with method, path, actor, body hash, status, latency
- **Event Timestamps** — RFC3339 format with second precision
- **Actor Tracking** — API key ID or username extracted from auth context
- **Compliance Export** — CSV/JSON export of audit events with filtering

---

## Infrastructure

### Deployment Architecture
- **Server** — Go HTTP server (net/http stdlib) on `:8080` (default) or `:8443` (Docker)
- **Database** — PostgreSQL 16 with 21 tables, TEXT primary keys (human-readable prefixed IDs)
- **Agent** — Lightweight Go binary on target infrastructure
- **Dashboard** — React SPA served from `/web/dist/` (Vite build)

### Docker Compose Deployment
- **Services** — PostgreSQL 16, certctl server, agent
- **Health Checks** — On all services (server health check, database readiness)
- **Seed Data** — Demo dataset with 15 certs, 5 agents, 5 targets, policies, audit events
- **Credentials** — Environment variables in `.env` file; app.key for API key

### PostgreSQL Schema
- **21 Tables** — Certificates, certificate versions, agents, deployment targets, certificate-target mappings, renewal policies, jobs, audit events, notifications, issuers, policy rules, policy violations, certificate profiles, teams, owners, agent groups, agent group members, certificate revocations, discovered certificates, discovery scans, network scan targets
- **TEXT Primary Keys** — Human-readable prefixed IDs: mc-*, t-*, a-*, j-*, p-*, etc.
- **Indexes** — 5+ performance indexes on foreign keys, timestamps, status fields
- **Migrations** — Idempotent migrations with `IF NOT EXISTS`, `ON CONFLICT`, numbered sequentially
- **Max Connections** — Configurable via `CERTCTL_DATABASE_MAX_CONNS` (default 25)

### CI/CD Pipeline
- **GitHub Actions** — `.github/workflows/ci.yml`
- **Parallel Jobs** — Go (build, vet, test+coverage, gates) and Frontend (tsc, vitest, vite build)
- **Coverage Gates** — Service layer ≥30%, handler layer ≥50%
- **Release Workflow** — Tag push → build → publish Docker images to GitHub Container Registry
- **Docker Tags** — `:latest`, `:v{version}` (`shankar0123.docker.scarf.sh/certctl-server`, `shankar0123.docker.scarf.sh/certctl-agent`)

### Test Suite
- **Unit Tests** — 625+ test functions across service, handler, middleware, domain layers
- **Integration Tests** — End-to-end workflows (issuance→renewal→deployment)
- **Negative Tests** — Malformed input, nonexistent resources, error conditions
- **Frontend Tests** — 86 Vitest tests (API client, utilities, stats/metrics, full endpoint coverage)
- **Total Coverage** — 900+ tests (Go + frontend combined)

### Licensing
- **License** — Business Source License 1.1 (BSL 1.1)
- **Conversion** — Automatic conversion to Apache 2.0 on March 23, 2033 (7-year term)
- **Source-Available** — Code available for inspection; copying/modification restricted until conversion

---

## Configuration Reference

### Environment Variables (All `CERTCTL_` Prefixed)

#### Server
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_SERVER_HOST` | string | 127.0.0.1 | Bind address |
| `CERTCTL_SERVER_PORT` | int | 8080 | Listen port |

#### Database
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_DATABASE_URL` | string | postgres://localhost/certctl | PostgreSQL connection string |
| `CERTCTL_DATABASE_MAX_CONNS` | int | 25 | Max connection pool size |
| `CERTCTL_DATABASE_MIGRATIONS_PATH` | string | ./migrations | Migration file directory |

#### Scheduler
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL` | duration | 1h | Renewal checker loop interval |
| `CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL` | duration | 30s | Job processor loop interval |
| `CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL` | duration | 2m | Agent health checker loop interval |
| `CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL` | duration | 1m | Notification processor loop interval |

#### Logging
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_LOG_LEVEL` | string | info | debug, info, warn, error |
| `CERTCTL_LOG_FORMAT` | string | json | json or text |

#### Authentication
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_AUTH_TYPE` | string | api-key | api-key, jwt, or none |
| `CERTCTL_AUTH_SECRET` | string | (required) | API key or JWT secret |

#### Rate Limiting
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_RATE_LIMIT_ENABLED` | bool | true | Enable/disable rate limiting |
| `CERTCTL_RATE_LIMIT_RPS` | float | 50 | Requests per second |
| `CERTCTL_RATE_LIMIT_BURST` | int | 100 | Max burst size |

#### CORS
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_CORS_ORIGINS` | string | (empty) | Comma-separated origins or * for all |

#### Key Generation
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_KEYGEN_MODE` | string | agent | agent or server |

#### Local CA Sub-CA Mode
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_CA_CERT_PATH` | string | (empty) | Path to PEM-encoded CA cert (sub-CA mode) |
| `CERTCTL_CA_KEY_PATH` | string | (empty) | Path to PEM-encoded CA key (sub-CA mode) |

#### ACME Issuer
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_ACME_DIRECTORY_URL` | string | (empty) | ACME server directory URL |
| `CERTCTL_ACME_EMAIL` | string | (empty) | Account email for ACME registration |
| `CERTCTL_ACME_CHALLENGE_TYPE` | string | http-01 | http-01, dns-01, or dns-persist-01 |
| `CERTCTL_ACME_DNS_PRESENT_SCRIPT` | string | (empty) | Script path for DNS present hook (dns-01 and dns-persist-01) |
| `CERTCTL_ACME_DNS_CLEANUP_SCRIPT` | string | (empty) | Script path for DNS cleanup hook (dns-01 only) |
| `CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN` | string | (empty) | CA issuer domain for dns-persist-01 (e.g., letsencrypt.org) |

#### step-ca Issuer
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_STEPCA_URL` | string | (empty) | step-ca server URL |
| `CERTCTL_STEPCA_PROVISIONER` | string | (empty) | JWK provisioner name |
| `CERTCTL_STEPCA_KEY_PATH` | string | (empty) | Path to provisioner JWK private key |
| `CERTCTL_STEPCA_PASSWORD` | string | (empty) | Provisioner key password (if encrypted) |

#### OpenSSL/Custom CA Issuer
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_OPENSSL_SIGN_SCRIPT` | string | (empty) | Path to sign script (CSR → cert) |
| `CERTCTL_OPENSSL_REVOKE_SCRIPT` | string | (empty) | Path to revoke script (serial+reason) |
| `CERTCTL_OPENSSL_CRL_SCRIPT` | string | (empty) | Path to CRL generation script |
| `CERTCTL_OPENSSL_TIMEOUT_SECONDS` | int | 30 | Script timeout in seconds |

#### Network Discovery
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_NETWORK_SCAN_ENABLED` | bool | false | Enable server-side network certificate discovery |
| `CERTCTL_NETWORK_SCAN_INTERVAL` | duration | 6h | How often the scheduler runs network scans |

#### Notifiers
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_SLACK_WEBHOOK_URL` | string | (empty) | Slack incoming webhook URL |
| `CERTCTL_SLACK_CHANNEL` | string | (empty) | Slack channel override |
| `CERTCTL_SLACK_USERNAME` | string | certctl | Slack username override |
| `CERTCTL_TEAMS_WEBHOOK_URL` | string | (empty) | Microsoft Teams webhook URL |
| `CERTCTL_PAGERDUTY_ROUTING_KEY` | string | (empty) | PagerDuty Events API routing key |
| `CERTCTL_PAGERDUTY_SEVERITY` | string | warning | PagerDuty event severity |
| `CERTCTL_OPSGENIE_API_KEY` | string | (empty) | OpsGenie API key |
| `CERTCTL_OPSGENIE_PRIORITY` | string | P3 | OpsGenie alert priority |

#### Agent
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_AGENT_NAME` | string | (generated) | Agent display name |
| `CERTCTL_KEY_DIR` | string | /var/lib/certctl/keys | Local private key storage directory |
| `CERTCTL_AGENT_ID` | string | (env or generated) | Agent unique ID (mc-xxx prefix) |
| `CERTCTL_DISCOVERY_DIRS` | string | (empty) | Comma-separated directories for cert discovery |

#### MCP Server
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `CERTCTL_SERVER_URL` | string | http://localhost:8080 | Base URL of certctl server |
| `CERTCTL_API_KEY` | string | (required) | API key for authentication |

---

## Compliance Mapping Documentation

Mapping guides that document how certctl's features align with compliance frameworks. These are not certifications — they help auditors and evaluators assess how certctl supports their organization's compliance posture.

| Guide | Framework | Key Sections |
|-------|-----------|-------------|
| [SOC 2 Type II](compliance-soc2.md) | AICPA Trust Service Criteria | CC6 (logical access), CC7 (system operations), CC8 (change management), A1 (availability) |
| [PCI-DSS 4.0](compliance-pci-dss.md) | Payment Card Industry DSS | Req 3 (key management), Req 4 (data in transit), Req 8 (auth), Req 10 (audit logging) |
| [NIST SP 800-57](compliance-nist.md) | Key Management Guidelines | Key generation, storage, cryptoperiods, key states, algorithms, revocation |
| [Overview](compliance.md) | All three frameworks | Framework comparison, quick reference, V3 enhancement notes |

Each guide includes an evidence summary table mapping specific criteria to certctl API endpoints, configuration, and database evidence.

---

## Feature Matrix: V2 Free vs. V3 Paid (Roadmap)

| Feature | V2 | V3 (Paid) | Status |
|---------|----|-----------|-|
| Certificate lifecycle (create/renew/revoke) | ✓ | ✓ | Shipped v1.0+ |
| 4 issuer connectors (Local CA, ACME, step-ca, OpenSSL) | ✓ | ✓ | Shipped |
| 3 target connectors (NGINX, Apache, HAProxy) | ✓ | ✓ | Shipped |
| 6 notifier channels (Email, Webhook, Slack, Teams, PagerDuty, OpsGenie) | ✓ | ✓ | Shipped |
| Agent fleet + metadata | ✓ | ✓ | Shipped |
| Agent groups (dynamic + manual) | ✓ | ✓ | Shipped |
| Policies + violations | ✓ | ✓ | Shipped |
| Profiles + crypto constraints | ✓ | ✓ | Shipped |
| Revocation (RFC 5280, CRL, OCSP) | ✓ | ✓ | Shipped |
| Full web dashboard | ✓ | ✓ | Shipped |
| Observability (charts, metrics, stats) | ✓ | ✓ | Shipped |
| REST API (91 endpoints) | ✓ | ✓ | Shipped |
| MCP server (78 tools) | ✓ | ✓ | Shipped v2.1 |
| CLI tool (12 subcommands) | ✓ | ✓ | Shipped |
| Compliance mapping docs (SOC 2, PCI-DSS, NIST) | ✓ | ✓ | Shipped |
| Filesystem cert discovery (M18b) | ✓ | ✓ | Shipped |
| Network cert discovery (M21) | ✓ | ✓ | Shipped |
| Prometheus metrics (M22) | ✓ | ✓ | Shipped |
| Enhanced query API (sort, filter, cursor, fields) | ✓ | ✓ | Shipped |
| Immutable API audit log | ✓ | ✓ | Shipped |
| **OIDC/SSO auth** | ✗ | ✓ | Planned V3 |
| **RBAC (role-based access control)** | ✗ | ✓ | Planned V3 |
| **F5 BIG-IP implementation** | Stub | ✓ | Planned V3 |
| **IIS implementation** | Stub | ✓ | Planned V3 |
| **NATS event bus** | ✗ | ✓ | Planned V3 |
| **Real-time updates (SSE/WebSocket)** | ✗ | ✓ | Planned V3 |
| **Advanced search DSL** | ✗ | ✓ | Planned V3 |
| **Bulk operations** | ✓ | ✓ | M13 (free) |
| **Bulk revocation** | ✗ | ✓ | Planned V3 (paid) |
| **Certificate health scores** | ✗ | ✓ | Planned V3 |
| **Compliance scoring** | ✗ | ✓ | Planned V3 |
| **DigiCert issuer** | ✗ | ✓ | Planned V3 |
| **CT Log monitoring** | ✗ | ✓ | Planned V3 |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **API Endpoints** | 95 (under /api/v1/ + /.well-known/est/) |
| **Dashboard** | Full web GUI |
| **Issuer Connectors** | 4 (Local CA, ACME, step-ca, OpenSSL) |
| **Target Connectors** | 5 (3 impl: NGINX, Apache, HAProxy; 2 stubs: F5, IIS) |
| **Notifier Channels** | 6 (Email, Webhook, Slack, Teams, PagerDuty, OpsGenie) |
| **Job Types** | 4 (Issuance, Renewal, Deployment, Validation) |
| **Job States** | 7 (Pending, AwaitingCSR, AwaitingApproval, Running, Completed, Failed, Cancelled) |
| **Policy Rule Types** | 5 (AllowedIssuers, AllowedDomains, RequiredMetadata, AllowedEnvironments, RenewalLeadTime) |
| **Certificate States** | 8 (Pending, Active, Expiring, Expired, RenewalInProgress, Failed, Revoked, Archived) |
| **Revocation Reason Codes** | 8 (RFC 5280 compliant) |
| **Discovery Statuses** | 3 (Unmanaged, Managed, Dismissed) |
| **MCP Tools** | 76 (16 resource domains) |
| **CLI Subcommands** | 10 |
| **Database Tables** | 19 |
| **Test Suite** | 900+ tests (Go backend + frontend) |
| **Environment Variables** | 41+ configuration options |

