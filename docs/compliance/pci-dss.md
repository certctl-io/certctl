# PCI-DSS 4.0 Compliance Mapping

This guide maps certctl's existing capabilities to PCI-DSS 4.0 requirements relevant to TLS certificate and cryptographic key management. It is **not a compliance attestation** — a qualified security assessor (QSA) must evaluate your organization's complete control environment. Rather, this document helps you understand which PCI-DSS control objectives certctl supports and where operator responsibility lies.

Organizations subject to PCI-DSS typically need to demonstrate control over certificate issuance, renewal, rotation, revocation, and key management. Certctl automates the technical controls for certificate lifecycle; compliance depends on how you deploy, monitor, and audit it.

## Contents

1. [How to Use This Guide](#how-to-use-this-guide)
2. [Requirement 4: Protect Data in Transit](#requirement-4-protect-data-in-transit)
   - [4.2.1 — Strong Cryptography for Transmission](#421--strong-cryptography-for-transmission)
   - [4.2.2 — Certificate Inventory and Validation](#422--certificate-inventory-and-validation)
3. [Requirement 3: Protect Stored Cardholder Data (Key Management)](#requirement-3-protect-stored-cardholder-data-key-management)
   - [3.6 — Cryptographic Key Documentation](#36--cryptographic-key-documentation)
   - [3.7 — Key Lifecycle Procedures](#37--key-lifecycle-procedures)
4. [Requirement 8: Identify and Authenticate](#requirement-8-identify-and-authenticate)
   - [8.3 — Strong Authentication](#83--strong-authentication)
   - [8.6 — Application Account Management](#86--application-account-management)
5. [Requirement 10: Log and Monitor](#requirement-10-log-and-monitor)
   - [10.2 — Implement Automated Audit Logging](#102--implement-automated-audit-logging)
   - [10.3 — Protect Audit Trail](#103--protect-audit-trail)
   - [10.4 — Promptly Review and Address Audit Trail Exceptions](#104--promptly-review-and-address-audit-trail-exceptions)
   - [10.7 — Retain and Protect Audit Trail History](#107--retain-and-protect-audit-trail-history)
6. [Requirement 6: Develop and Maintain Secure Systems and Applications](#requirement-6-develop-and-maintain-secure-systems-and-applications)
   - [6.3.1 — Security Coding Practices](#631--security-coding-practices)
   - [6.5.10 — Broken Authentication and Cryptography Prevention](#6510--broken-authentication-and-cryptography-prevention)
7. [Requirement 7: Restrict Access by Business Need-to-Know](#requirement-7-restrict-access-by-business-need-to-know)
   - [7.2 — Implement Access Control](#72--implement-access-control)
8. [Evidence Summary Table](#evidence-summary-table)
9. [Operator Responsibilities](#operator-responsibilities)
10. [V3 Enhancements for PCI-DSS](#v3-enhancements-for-pci-dss)
11. [Next Steps for Compliance](#next-steps-for-compliance)
12. [Questions?](#questions)

## How to Use This Guide

Your QSA will request evidence that your certificate and key management systems meet specific PCI-DSS 4.0 requirements. For each applicable requirement, this guide identifies:

1. **Which certctl features support the control** — API endpoints, database tables, background processes
2. **What evidence you can produce** — audit logs, dashboard metrics, API queries, deployment configs
3. **Operator responsibilities** — what you must do outside certctl (policy, monitoring, access control)
4. **Status** — Available (v1.0 shipped), Planned (future release), or Operator Responsibility (outside scope)

---

## Requirement 4: Protect Data in Transit

**Objective**: Ensure strong cryptography is used to protect sensitive data during transmission.

### 4.2.1 — Strong Cryptography for Transmission

**Requirement**: Use appropriate and current cryptographic algorithms for all TLS and SSH connections protecting card data in transit.

**certctl Support**:
- **Automated TLS certificate lifecycle** — Certctl issues TLS certificates to NGINX, Apache HAProxy targets via `POST /api/v1/deployments`. Certificates include RSA 2048-bit and ECDSA P-256 key types (configurable per profile, M11a).
- **Control plane TLS enforcement** — All REST API endpoints served exclusively over HTTPS. Agent-to-server heartbeat and work polling use TLS. No plaintext protocol options.
- **Issuer connector key negotiation** — ACME v2 (Let's Encrypt, ZeroSSL) validates issuer cryptography. Local CA enforces RSA/ECDSA constraints. step-ca integration ensures Smallstep's cryptography standards.
- **Certificate profiles** (M11a) document allowed key types and minimum key sizes per environment (development, production, cardholder-network).

**Evidence You Can Provide**:
- Exported certificate inventory via `GET /api/v1/certificates` with key algorithm and size (serial JSON).
- Issued certificate details showing RSA 2048+ or ECDSA P-256 for all deployed certificates.
- Audit trail (`GET /api/v1/audit`) showing issuer connector selection and certificate profile assignment per certificate.
- Target deployment logs showing TLS certificate installation on NGINX/Apache/HAProxy.

**Operator Responsibility**:
- Configure certificate profiles for your environments with approved key algorithms.
- Audit cipher suite configuration on deployed targets (certctl deploys certs; you verify target TLS settings).
- Periodically review `CERTCTL_KEYGEN_MODE` — must be `agent` in production (never `server`).
- Monitor issuer connector configuration to ensure issuers meet your cryptography standards.

**Status**: **Available** (v1.0 shipped)

---

### 4.2.2 — Certificate Inventory and Validation

**Requirement**: Ensure all TLS/SSL certificates used for data transmission are valid, current, and meet required cryptographic standards.

**certctl Support**:

- **Managed Certificate Inventory** — Full CRUD API (`/api/v1/certificates`) with sortable, filterable list. Fields: common name, SANs, subject, issuer, serial number, key type/size, not-before/after dates, issuer ID, profile ID, owner, team, status (Active/Expiring/Expired/Revoked).

- **Filesystem Certificate Discovery** (M18b) — Agents scan configured directories (`CERTCTL_DISCOVERY_DIRS` env var) for existing PEM/DER certificates every 6 hours and on startup. Control plane deduplicates by SHA-256 fingerprint. Three triage statuses: Unmanaged (not managed by certctl), Managed (linked to a managed certificate), Dismissed (operator-marked as out-of-scope).
  - API endpoints:
    - `GET /api/v1/discovered-certificates?status=Unmanaged` — find orphaned certs
    - `GET /api/v1/discovery-summary` — aggregate counts by status
    - `POST /api/v1/discovered-certificates/{id}/claim` — link to managed certificate
    - `POST /api/v1/discovered-certificates/{id}/dismiss` — mark out-of-scope

- **Expiration Threshold Alerting** — Renewal policies support `alert_thresholds_days` (default 30, 14, 7, 0). Background scheduler evaluates daily; certificates transition to Expiring/Expired status automatically. Notifications sent to owners via email/webhook/Slack/Teams/PagerDuty.

- **Certificate Status Tracking** — Four statuses: Active (deployed, not yet expired), Expiring (within threshold, awaiting renewal), Expired (past not-after date), Revoked (revoked via RFC 5280 revocation API). Dashboard charts show status distribution.

- **Revocation Infrastructure** (M15a, M15b, M-006):
  - Revocation API: `POST /api/v1/certificates/{id}/revoke` with RFC 5280 reason codes
  - CRL endpoint: `GET /.well-known/pki/crl/{issuer_id}` — DER X.509 CRL, 24h validity, signed by issuing CA, served unauthenticated (RFC 5280 §5, RFC 8615, `Content-Type: application/pkix-crl`)
  - OCSP responder: `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` — DER-encoded OCSP response (good/revoked/unknown), served unauthenticated (RFC 6960, `Content-Type: application/ocsp-response`)
  - Bulk revocation (V2.2): `POST /api/v1/certificates/bulk-revoke` with filter criteria (profile, owner, agent, issuer) for fleet-wide incident response
  - Short-lived cert exemption: certs with TTL < 1 hour skip CRL/OCSP (expiry is sufficient revocation)

- **Stats API** (M14) — Real-time visibility:
  - `GET /api/v1/stats/summary` — total certs, by status, by issuer
  - `GET /api/v1/stats/expiration-timeline?days=90` — expiration distribution (weekly buckets)
  - `GET /api/v1/stats/job-trends?days=30` — renewal/issuance job success rates
  - `GET /api/v1/certificates` with `?sort=-notAfter&fields=id,commonName,notAfter,status` — sparse, sorted inventory

**Evidence You Can Provide**:
- Discovered certificate report: `GET /api/v1/discovered-certificates` JSON export showing all certs on systems, fingerprints, and status.
- Managed certificate inventory: `GET /api/v1/certificates` with filters (`?status=Expiring` for upcoming renewals).
- Expiration alert configuration: policy JSON showing `alert_thresholds_days` for each environment.
- CRL/OCSP availability proof: unauthenticated HTTP GET requests to `/.well-known/pki/crl/{issuer_id}` (DER, `application/pkix-crl`) and `/.well-known/pki/ocsp/{issuer_id}/{serial}` (DER, `application/ocsp-response`) with signed responses.
- Audit trail for certificate creation/renewal/revocation: `GET /api/v1/audit?type=certificate_issued,certificate_renewed,certificate_revoked`.
- Dashboard charts showing expiration timeline, renewal success trends, status distribution.

**Operator Responsibility**:
- Configure `CERTCTL_DISCOVERY_DIRS` on agents to scan all certificate storage locations (e.g., `/etc/nginx/certs`, `/etc/apache2/certs`, `/usr/local/share/ca-certificates`).
- Regularly triage discovered certificates: `GET /api/v1/discovered-certificates?status=Unmanaged`, claim or dismiss each.
- Set renewal policies for all certificate profiles with appropriate `alert_thresholds_days` (recommendation: 30, 14, 7, 0).
- Monitor expiration dashboard and respond to Expiring alerts before certificates expire.
- Verify that issued certificates meet your organization's cryptography standards (key type, key size, SANs).
- Test CRL/OCSP endpoints periodically to confirm they are reachable and signed correctly.

**Status**: **Available** (v1.0 shipped, discovery M18b, revocation M15a/M15b)

---

## Requirement 3: Protect Stored Cardholder Data (Key Management)

**Objective**: Render cardholder data unreadable anywhere it is stored; protect cryptographic keys used to encrypt data.

### 3.6 — Cryptographic Key Documentation

**Requirement**: Document and implement all key management processes and procedures covering generation, storage, archival, destruction, and change; protect cryptographic keys; and restrict access to keys to the minimum required.

**certctl Support**:

- **Certificate Profile Documentation** (M11a) — Named profiles define allowed key types, maximum TTL, and allowed EKUs per use case. Each profile is a documented policy:
  ```json
  {
    "id": "p-web-tls",
    "name": "Web TLS Production",
    "allowed_key_types": ["RSA_2048", "ECDSA_P256"],
    "max_ttl_seconds": 31536000,
    "require_sans": true,
    "description": "Production TLS certs for external web services"
  }
  ```

- **Owner and Team Tracking** (M11b) — Every certificate is assigned an owner (person + email) and optionally a team. This documents key responsibility and escalation paths.

- **Issuer Connector Specification** — Configuration and API endpoints document which CA and protocol issues each certificate:
  - `GET /api/v1/issuers/{id}` returns issuer type (local-ca, acme, step-ca, openssl), CA endpoint, authentication method, constraints
  - Each issuer type has documented key handling (e.g., Local CA loads CA key from `CERTCTL_CA_CERT_PATH`, step-ca via JWK provisioner)

- **Immutable Audit Trail** (M19) — Every certificate lifecycle event recorded in append-only `audit_events` table:
  - `certificate_issued` — when certificate created, by whom, issuer type, profile
  - `certificate_renewed` — when renewed, by whom, issuer
  - `certificate_revoked` — when revoked, by whom, RFC 5280 reason code
  - `certificate_deployed` — when deployed to target, by agent, target type
  - Query: `GET /api/v1/audit?resource_type=certificate&resource_id={cert_id}`

**Evidence You Can Provide**:
- Exported certificate profiles: `GET /api/v1/profiles` showing documented key types, max TTLs, constraints per environment.
- Certificate-to-owner mapping: `GET /api/v1/certificates` with owner/team fields.
- Issuer configuration audit: `GET /api/v1/issuers` showing CA endpoints, key storage paths, auth methods.
- Audit trail for a certificate: `GET /api/v1/audit?resource_type=certificate&resource_id={cert_id}` showing complete lifecycle.

**Operator Responsibility**:
- Define and document certificate profiles for each environment and use case.
- Assign owner and team to each certificate via API or dashboard.
- Document issuer connector configuration (CA endpoint, auth method, key storage location).
- Maintain baseline audit trail exports for compliance evidence.
- Establish certificate retirement policy (how long to retain audit records after certificate expiry/revocation).

**Status**: **Available** (v1.0 shipped)

---

### 3.7 — Key Lifecycle Procedures

**Requirement**: Generate, store, protect, access, and destroy cryptographic keys used to encrypt data in transit or at rest.

This requirement covers key generation, storage, rotation, and destruction. Certctl addresses the certificate/TLS key portion (not symmetric encryption keys used for cardholder data at rest — those are outside scope).

#### 3.7.1 — Key Generation

**Requirement**: Generate new keys using strong cryptography.

**certctl Support**:

- **Agent-Side Key Generation** (M8) — Production mode (default `CERTCTL_KEYGEN_MODE=agent`):
  - Agents generate ECDSA P-256 key pairs using `crypto/ecdsa` + `crypto/elliptic.P256()` + `crypto/rand` (cryptographically secure random).
  - Key generation happens **only on the agent**, never on the control plane.
  - Agent submits Certificate Signing Request (CSR) with public key to control plane via `POST /api/v1/agents/{id}/csr`.
  - Issued certificate is returned; private key remains on agent at `CERTCTL_KEY_DIR` (default `/var/lib/certctl/keys`).

- **Server-Side Fallback** (demo/development only) — `CERTCTL_KEYGEN_MODE=server`:
  - Control plane generates RSA 2048-bit or ECDSA P-256 keys using `crypto/rand` + `crypto/rsa`.
  - Server signs CSR and stores the private key in the certificate version record for agent deployment. **Security note:** In server keygen mode, the control plane holds private keys — this is why agent keygen mode is the recommended default for production.
  - **Must not be used in production.** Explicit warning logged: `server-side key generation enabled (CERTCTL_KEYGEN_MODE=server) — private keys touch control plane, demo only`

- **Issuer-Specific Key Negotiation**:
  - **ACME (Let's Encrypt, ZeroSSL)**: Let's Encrypt controls key types; certctl requests ECDSA P-256 by default.
  - **Local CA**: Supports RSA 2048+, ECDSA (P-256, P-384), PKCS#8 format. Key algorithm inherited from CA cert or specified via profile.
  - **step-ca**: Smallstep's provisioner defines key type; certctl respects server constraints.
  - **OpenSSL / Custom CA**: User-provided signing script; key type depends on CA backend.

**Evidence You Can Provide**:
- Deployment configuration: `CERTCTL_KEYGEN_MODE=agent` in production (verify in `docker-compose.yml`, Kubernetes manifests, or systemd units).
- Agent log excerpt showing key generation: Go `crypto/ecdsa.GenerateKey(elliptic.P256())` via agent process logs with CSR submission timestamp.
- Certificate CSR audit: `GET /api/v1/audit?type=certificate_issued` showing CSR fingerprint (SHA-256 hash of CSR PEM).
- Renewal job logs showing agent-submitted CSR, not server-generated key.

**Operator Responsibility**:
- **Enforce `CERTCTL_KEYGEN_MODE=agent` in all production deployments.** Never use `server` mode outside demos.
- Verify agent hardware is adequately isolated (crypto/rand relies on OS `/dev/urandom` quality).
- Monitor `CERTCTL_KEY_DIR` on agents for unauthorized file access (use OS-level file audit if available).
- Backup agent key directory (`/var/lib/certctl/keys`) as part of disaster recovery procedure.

**Status**: **Available** (v1.0 shipped)

#### 3.7.2 — Key Storage and Access Control

**Requirement**: Restrict cryptographic key access to the minimum required and protect keys from unauthorized access.

**certctl Support**:

- **Agent-Side Key Storage** (M8) — Private keys written to `CERTCTL_KEY_DIR` (default `/var/lib/certctl/keys`):
  - File permissions: `0600` (readable/writable by agent process owner only).
  - Filename convention: one file per certificate (e.g., `web-tls-prod.key`, `api-service.key`).
  - No key data passed over the network between agent and control plane (CSR only).
  - Keys used locally by agent to sign TLS handshakes, never transmitted to control plane or other systems.

- **Control Plane Key Storage** — Sensitive credentials managed via environment variables or `.env` files:
  - CA private key path: `CERTCTL_CA_CERT_PATH` + `CERTCTL_CA_KEY_PATH` (for Local CA sub-CA mode).
  - ACME account key: embedded in ACME issuer config (not stored separately; ACME library handles in memory).
  - step-ca provisioner key: `CERTCTL_STEPCA_KEY_PATH` env var (path to JWK private key file, loaded into memory during runtime).
  - API keys: `CERTCTL_API_KEY` (SHA-256 hashed in database, plaintext never stored).
  - Database credentials: `CERTCTL_DATABASE_URL` in `.env` file, not in source code.

- **Docker Compose Credential Management** — `.env` file (git-ignored) holds all secrets:
  ```bash
  CERTCTL_API_KEY=sk-test-...
  CERTCTL_DATABASE_URL=postgres://user:pass@db:5432/certctl
  CERTCTL_CA_KEY_PATH=/run/secrets/ca.key
  ```
  Credentials never in `docker-compose.yml` or Dockerfile.

- **Kubernetes Secrets** (operator responsibility) — Deploy control plane with:
  ```yaml
  env:
    - name: CERTCTL_DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: certctl-secrets
          key: database-url
    - name: CERTCTL_API_KEY
      valueFrom:
        secretKeyRef:
          name: certctl-secrets
          key: api-key
  ```

**Evidence You Can Provide**:
- Agent key directory listing (without keys): `ls -la /var/lib/certctl/keys` (shows file count, permissions, timestamps).
- Deployment manifest (`docker-compose.yml` or Kubernetes YAML) showing secrets via env var or Secret object (not inline).
- `.env` file (do not share contents, only confirm existence and git-ignore status).
- API key hash verification: `GET /api/v1/auth/check` with API key, verifying hash matching without plaintext exposure.

**Operator Responsibility**:
- **Store `.env` and credential files outside version control.** Verify `.gitignore` includes `.env`, `*.key`, `ca.key`, etc.
- **Restrict file system access to `/var/lib/certctl/keys` on agents** via OS-level permissions (Linux: `chmod 0700`, owned by agent user).
- **Limit CA key file read access** — `CERTCTL_CA_KEY_PATH` should be readable only by certctl server process (OS permissions).
- **Rotate API keys periodically** (recommendation: annually or when personnel changes). No audit trail for API key rotation (outside certctl scope).
- **Backup private key stores** (agent key dirs, CA key file) as part of disaster recovery. Encrypt backups at rest.
- **Monitor access logs** to `/var/lib/certctl/keys` and CA key file location (use OS audit or file integrity monitoring).

**Status**: **Available** (v1.0 shipped)

#### 3.7.3 — Key Rotation

**Requirement**: Rotate cryptographic keys upon expiration or compromise.

**certctl Support**:

- **Automated Certificate Renewal** — Renewal policies trigger certificate renewal automatically:
  - Background scheduler checks every 60 minutes (configurable via `CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL`).
  - For each policy, evaluates all managed certificates: if `(not-after - now) <= policy.renewal_threshold_days`, trigger renewal.
  - Renewal job created in AwaitingCSR state; agent receives work, generates new key pair, submits new CSR.
  - Issuer connector signs new CSR with new key; old key discarded by agent after new certificate installed.
  - New certificate deployed to target via deployment job.

- **Expiration-Based Rotation** — Certificate profiles (M11a) define `max_ttl_seconds` (e.g., 31536000 for 1 year, 3600 for short-lived certs):
  - Short-lived certificates (TTL < 1 hour) rotate every deployment cycle, providing defense-in-depth (RFC 5280 revocation not needed).
  - Longer-lived certs (90/180/365 days) rotated via renewal policy thresholds (30/14/7 day alerts).

- **Renewal Audit Trail** — Every renewal recorded:
  - `GET /api/v1/audit?type=certificate_renewed&resource_id={cert_id}` shows each renewal, old serial, new serial, issuer, actor.

**Evidence You Can Provide**:
- Renewal policy configuration: `GET /api/v1/policies` showing `renewal_threshold_days` and `alert_thresholds_days`.
- Renewal job history: `GET /api/v1/jobs?type=Renewal&status=Completed` with timestamp, before/after serial numbers.
- Certificate version history: `GET /api/v1/certificates/{id}/versions` showing all issued versions, dates, issuers.
- Audit trail: `GET /api/v1/audit?type=certificate_renewed` for trending and compliance reporting.

**Operator Responsibility**:
- **Define renewal policies for all certificate profiles** with appropriate thresholds (typically 30 days before expiration for 90+ day certs, more aggressive for shorter-lived).
- **Monitor renewal job success** via dashboard (M14 charts show renewal success trends) and alerts.
- **Investigate renewal failures** (stuck AwaitingCSR, issuer connectivity, deployment errors) promptly to avoid expired certificates.
- **Test renewal workflow in staging environment** before rolling out to production.
- **Document key rotation schedule** for your organization (renewal policy thresholds, approval workflows if AwaitingApproval).

**Status**: **Available** (v1.0 shipped)

#### 3.7.4 — Key Destruction

**Requirement**: Render cryptographic keys unreadable and unusable when they reach the end of their cryptographic lifetime.

**certctl Support**:

- **Certificate Revocation API** (M15a) — `POST /api/v1/certificates/{id}/revoke` with RFC 5280 reason codes:
  - `unspecified` — general revocation
  - `keyCompromise` — suspected key compromise
  - `caCompromise` — CA compromise
  - `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn` — lifecycle management
  - Revocation recorded in `certificate_revocations` table with timestamp and reason.
  - Issuer notified (best-effort; ACME lacks standard revocation, Local CA skips issuer step).
  - Revocation notifications sent to owner via email/webhook/Slack/Teams/PagerDuty.

- **CRL and OCSP Publication** (M15b, M-006) — Revoked certificates published in:
  - CRL: `GET /.well-known/pki/crl/{issuer_id}` (DER X.509 signed by CA, 24h validity, RFC 5280 §5 + RFC 8615, `Content-Type: application/pkix-crl`)
  - OCSP: `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` (returns revoked status for clients validating certificate chain, RFC 6960, `Content-Type: application/ocsp-response`)
  - Both endpoints are served unauthenticated so relying parties (browsers, TLS appliances) without certctl API keys can verify revocation — this is the RFC-compliant PKI model.
  - Clients checking certificate status via OCSP or CRL see revoked status within 24 hours.

- **Bulk Revocation for Incident Response** (V2.2) — `POST /api/v1/certificates/bulk-revoke` with filter criteria (profile, owner, agent, issuer) revokes all matching certificates in a single operation. PCI-DSS Req 4 requires rapid response to data transmission security incidents — bulk revocation enables operators to revoke an entire certificate set (e.g., all certs used by a compromised team or endpoint) in minutes rather than hours.

- **Private Key Destruction on Agent** — When certificate renewed or revoked:
  - Agent removes old private key file from `CERTCTL_KEY_DIR` when new certificate deployed.
  - Job status tracking confirms old key is no longer needed.
  - No audit trail of key deletion (private keys don't pass through control plane).

**Evidence You Can Provide**:
- Revocation requests: `GET /api/v1/audit?type=certificate_revoked` with RFC 5280 reason codes.
- CRL publication: HTTP GET `/.well-known/pki/crl/{issuer_id}` (unauthenticated) returns a DER X.509 CRL — parse with `openssl crl -inform der -noout -text` to show revoked serial numbers, reasons, and timestamps.
- OCSP responder validation: Query `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` (unauthenticated) for a known-revoked cert; response includes `revoked` status and can be parsed with `openssl ocsp` tooling.
- Audit trail: Certificate status transitions (Active → Revoked) recorded in `audit_events`.

**Operator Responsibility**:
- **Revoke certificates immediately upon key compromise suspicion** using reason code `keyCompromise`.
- **Revoke certificates at end of lifecycle** (host decommissioning, service sunset) using reason code `cessationOfOperation`.
- **Monitor CRL/OCSP availability** — ensure clients can check revocation status (test with TLS validator tools).
- **Establish certificate revocation procedure** (who can revoke, approval workflow if required, documentation).
- **Physically destroy backup private keys** (if offline backups are kept) when certificate is revoked or after archival period expires.
- **Test revocation workflow in staging** — issue test cert, revoke, verify OCSP/CRL reflects revocation within SLA.

**Status**: **Available** (v1.0 shipped)

---

## Requirement 8: Identify and Authenticate

**Objective**: Limit access to system components and cardholder data by business need-to-know, and authenticate and manage all access.

### 8.3 — Strong Authentication

**Requirement**: Authentication mechanisms must use strong cryptography and render authentication credentials (passwords, passphrases, keys) unreadable during transmission and storage.

**certctl Support**:

- **API Key Authentication** — All REST API endpoints require authentication (default):
  - Bearer token format: `Authorization: Bearer sk-...`
  - Key stored as SHA-256 hash in database (plaintext never persisted).
  - Comparison uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.
  - Configuration: `CERTCTL_AUTH_TYPE=api-key` (enforced by default, no opt-out without explicit env var).

- **GUI Authentication Context** — Web dashboard login flow:
  - Login page (`/login`) accepts API key entry.
  - AuthProvider context stores API key in session (localStorage in browser, sent in Authorization header for all API calls).
  - 401 Unauthorized responses trigger automatic redirect to login.
  - Logout button clears session.
  - No session server-side (stateless API).

- **Credential Transmission** — All API traffic over TLS:
  - HTTPS enforced at server level (no plaintext HTTP).
  - API key transmitted in Authorization header (not URL parameter, not cookie).
  - Browser to server: TLS.
  - Agent to server: TLS.
  - No credential logging (audit records the per-key actor `Name`, never the Bearer token; logs redact the `Authorization` header).

**Evidence You Can Provide**:
- API configuration: `CERTCTL_AUTH_TYPE=api-key` in deployment manifest.
- Key inventory: `CERTCTL_API_KEYS_NAMED` env var (format `name:key:admin,...`) — seeds the in-memory `NamedAPIKey{Name, Key, Admin}` struct at `internal/api/middleware/middleware.go:29`. Keys are constant-time-compared (`subtle.ConstantTimeCompare`) against the Bearer token. No database table stores them; protect the env var contents at rest via a secrets manager (Vault / AWS Secrets Manager / Kubernetes Secrets / Docker Secrets).
- API audit log: `GET /api/v1/audit?action=api_call` showing per-key actor names (`Name` field of matched `NamedAPIKey`) on every call, with zero plaintext or hashed key material recorded.
- TLS certificate on control plane: `openssl s_client -connect {server}:8443` showing valid certificate, TLS 1.2+, strong cipher.
- GUI login flow: browser network tab showing Authorization header (token value redacted in compliance report).

**Operator Responsibility**:
- **Issue API keys to users/systems** requiring API access (outside certctl; you maintain key registry).
- **Rotate API keys using zero-downtime rotation** — `CERTCTL_AUTH_SECRET` supports comma-separated keys (e.g., `new-key,old-key`). Add the new key, migrate clients, then remove the old key. Recommendation: rotate at least annually, or immediately when personnel changes.
- **Revoke API keys immediately** when user leaves or token is compromised (set `enabled=false` in API key management — not yet implemented in v1, owner must track manually).
- **Enforce strong TLS** on control plane: TLS 1.2+, modern ciphers (configure on reverse proxy or `CERTCTL_TLS_*` env vars if operator-controlled).
- **Protect `.env` and credential files** where API key is defined (restrict file system access, no version control).
- **Monitor API audit trail** for suspicious access patterns (many 401 errors, access from unexpected IPs, etc.).

**Status**: **Available** (v1.0 shipped)

### 8.6 — Application Account Management

**Requirement**: Users' system access must be restricted to the minimum level of application functions or data needed to perform duties. Application accounts (non-human) must use strong authentication.

**certctl Support**:

- **No Application Account Management in v1** — Certctl does not manage user accounts (no user directory, LDAP, OIDC).
  - All authentication via API key (service-to-service or human user with API key).
  - No per-user roles or permissions (that's V3 RBAC feature).
  - Single API key shared across team or one key per automation script (operator's responsibility to manage).

- **Credentials Not in Source Code** — Security hardening:
  - API keys via `CERTCTL_API_KEY` env var (not in `main.go`, Dockerfile, `docker-compose.yml`).
  - Database credentials via `CERTCTL_DATABASE_URL` in `.env` (git-ignored).
  - CA private key path via `CERTCTL_CA_CERT_PATH`/`CERTCTL_CA_KEY_PATH` (not inline).

- **Service Account Isolation** (planned for V3) — Future RBAC will support:
  - Automation script API keys with scoped permissions (e.g., read-only, renew-only, deploy-only).
  - OIDC/SSO for human users with fine-grained role assignment (admin, operator, viewer).
  - Audit trail showing which account/role performed each action.

**Evidence You Can Provide**:
- Deployment manifest (Dockerfile, docker-compose.yml) showing no hardcoded API keys, database credentials, or CA key paths.
- `.env` file existence (confirm via CI or compliance check, without sharing contents).
- `.gitignore` configuration showing `.env`, `*.key`, secrets excluded.
- Code review: grep `main.go`, `config.go` for `CERTCTL_API_KEY` — should only see env var reference, not hardcoded values.

**Operator Responsibility**:
- **Manage API keys externally** (issue, rotate, revoke).
- **Document who/what has API key access** (automation scripts, team members, third-party integrations).
- **Rotate application credentials** (API keys, database passwords) according to your organization's policy.
- **Segregate credentials** — one API key per automation script where possible, or use V3 RBAC scoping.
- **Monitor application account usage** via audit trail — `GET /api/v1/audit` filtered by action/actor.

**Status**: **Available in part** (v1.0: credentials out of source code). **Planned V3**: scoped API keys and RBAC.

---

## Requirement 10: Log and Monitor

**Objective**: Log and monitor access to network resources and cardholder data.

### 10.2 — Implement Automated Audit Logging

**Requirement**: Automatically log and monitor all access to system components and records containing cardholder data.

**certctl Support**:

- **Immutable API Audit Log** (M19) — Middleware captures every API call:
  - `audit_events` table (append-only, no UPDATE/DELETE):
    - `method`: HTTP method (GET, POST, PUT, DELETE)
    - `path`: API endpoint path only, excluding query parameters (e.g., `/api/v1/certificates` — query strings intentionally omitted to prevent sensitive data persistence in the append-only audit trail)
    - `actor`: authenticated user/service (extracted from API key or context)
    - `body_hash`: SHA-256 hash of request body (truncated to 16 chars, first 8 chars shown in logs)
    - `status_code`: HTTP response status (200, 201, 400, 401, 404, 500, etc.)
    - `latency_ms`: request duration in milliseconds
    - `timestamp`: RFC 3339 timestamp

- **Certificate Lifecycle Events** — Higher-level events logged separately:
  - `certificate_issued` — new certificate created, issuer, profile, profile ID
  - `certificate_renewed` — certificate renewed, old/new serial, renewal policy
  - `certificate_revoked` — certificate revoked, RFC 5280 reason code
  - `certificate_deployed` — certificate deployed to target, agent, target type
  - `certificate_validated` — validation job result (success/failure reason)

- **Job Lifecycle Events** — Job status transitions:
  - `job_created` — renewal/issuance/deployment/validation job created
  - `job_status_updated` — job state change (Pending → AwaitingCSR → Running → Completed/Failed)

- **Policy and Configuration Events** — Administrative changes:
  - `policy_created`, `policy_updated`, `policy_deleted` — renewal policy changes
  - `profile_created`, `profile_updated`, `profile_deleted` — certificate profile changes
  - `issuer_created`, `issuer_deleted` — CA connector registration changes

- **Excluded Paths** — Health/readiness probes not logged to reduce noise:
  - `GET /health` (excluded by default)
  - `GET /ready` (excluded by default)
  - Configurable via `CERTCTL_AUDIT_EXCLUDE_PATHS` env var

**Evidence You Can Provide**:
- Audit trail export: `GET /api/v1/audit` or manual database query, showing sample events with timestamp, actor, action, resource.
- API call audit log: Query `audit_events` table showing method, path, actor, status code for last 24-48 hours.
- Configuration changes: `GET /api/v1/audit?type=policy_created,policy_updated,issuer_created` showing who changed what and when.
- Certificate lifecycle: `GET /api/v1/audit?resource_type=certificate&resource_id={cert_id}` showing complete issuance → deployment → renewal/revocation history.

**Operator Responsibility**:
- **Enable audit logging** — it's on by default; verify `CERTCTL_AUDIT_EXCLUDE_PATHS` is not set to exclude certificate-related paths.
- **Monitor audit log growth** — `audit_events` table will grow with every API call. Recommend database maintenance (log rotation policy, archival after 90 days, etc.).
- **Export and archive audit logs** — periodically `SELECT * FROM audit_events WHERE timestamp > {date}` and export to secure storage (S3, syslog, SIEM).
- **Establish audit review procedure** — QSA may request sample of logs; have export process documented.
- **Test audit logging** — make API call, verify event appears in audit trail within seconds.

**Status**: **Available** (M19 shipped)

### 10.3 — Protect Audit Trail

**Requirement**: Promptly protect audit trail files from unauthorized modifications.

**certctl Support**:

- **Append-Only Database Design** — PostgreSQL triggers and constraints prevent modification:
  - `audit_events` table has no `UPDATE` or `DELETE` triggers.
  - Application code never executes UPDATE/DELETE on `audit_events`.
  - Primary key is `id` (serial); new events always INSERT.

- **Read-Only API Access** — Audit events accessible only via read (`GET /api/v1/audit`):
  - No `POST /api/v1/audit/{id}` endpoint (no creation from API).
  - No `PUT /api/v1/audit/{id}` endpoint (no modification).
  - No `DELETE /api/v1/audit/{id}` endpoint (no deletion).
  - Only control plane can record events (via internal service layer, not exposed API).

- **Database Access Control** (operator responsibility) — PostgreSQL user permissions:
  - `certctl` application user: INSERT, SELECT on `audit_events`.
  - `certctl_read_only` user (for compliance/audit team): SELECT only on `audit_events`.
  - `postgres` superuser: restricted to DBA operations, logged separately by PostgreSQL.

**Evidence You Can Provide**:
- Database schema: `\d audit_events` showing columns, primary key, no UPDATE/DELETE triggers.
- Application code review: `internal/service/audit.go` showing `RecordEvent(...)` as only INSERT operation.
- API endpoint audit: grep `internal/api/handler/audit*.go` or `internal/api/router/router.go` — no PUT/DELETE routes for events.
- PostgreSQL permissions: `psql -d certctl -c "\dp audit_events"` showing INSERT/SELECT grants only.

**Operator Responsibility**:
- **Restrict database access** — issue read-only PostgreSQL user for compliance/audit team (no write privileges).
- **Enable PostgreSQL query logging** — log all database connections and operations for DBA audit trail.
- **Backup audit logs** — regularly export `audit_events` to offsite storage (S3, archive tape, syslog aggregator) for long-term retention.
- **Monitor database modifications** — alert if any UPDATE/DELETE is attempted on `audit_events` (log-based alerting or PostgreSQL event triggers).
- **Encrypt audit exports** — if archiving to external storage, encrypt backups at rest.

**Status**: **Available** (v1.0 shipped)

### 10.4 — Promptly Review and Address Audit Trail Exceptions

**Requirement**: Promptly review audit logs and investigate exceptions/anomalies.

**certctl Support**:

- **Dashboard Charts** (M14) — Real-time observability:
  - **Renewal Success Trends** (30-day line chart) — shows job success rate; spikes in failures warrant investigation.
  - **Certificate Status Distribution** (donut chart) — shows Expiring/Expired counts; high Expired = missed renewals.
  - **Expiration Timeline** (90-day weekly heatmap) — shows upcoming expirations; bunching = renewal policy tuning needed.
  - **Issuance Rate** (30-day bar chart) — shows certificate creation/renewal activity; anomalies (zero issuances for weeks) indicate stopped automation.

- **Stats API** (M14) — Machine-readable trends:
  - `GET /api/v1/stats/job-trends?days=30` — renewal/issuance/deployment success/failure counts per day.
  - `GET /api/v1/stats/summary` — total certs, counts by status.
  - `GET /api/v1/stats/expiration-timeline?days=90` — expiration buckets for forecasting.

- **Agent Fleet Overview** (M14) — Agent health visibility:
  - Pie chart: agent status distribution (healthy, offline, error).
  - Version breakdown: agent versions in use (identify outdated agents).
  - Per-agent detail: last heartbeat timestamp, OS/architecture, IP address, recent jobs.

- **Alert Notifications** (M3, M16a) — Configurable escalation:
  - Email alerts: certificate approaching expiration, renewal failure, revocation notification.
  - Webhook: custom HTTP POST to your monitoring system (Slack, Teams, PagerDuty, OpsGenie, custom webhook).
  - **Retry & Dead-Letter Queue** (I-005) — Transient notifier failures (SMTP timeout, webhook 5xx) are retried with exponential backoff (`2^n` minutes capped at 1h, 5-attempt budget) before landing in the terminal `dead` status. Operators monitor DLQ depth via the `certctl_notification_dead_total` Prometheus counter and requeue via the Notifications page Dead letter tab once the underlying outage is resolved. Closes the pre-I-005 silent-drop gap where a single 5xx could lose a compliance-relevant alert without evidence.
  - Deduplication: one alert per threshold/certificate per day (avoid alert fatigue).

- **Audit Trail Filtering and Export** (M13) — Compliance reporting:
  - `GET /api/v1/audit?actor={user}&timestamp_after={date}` — filter audit log by actor, timestamp, type.
  - Export CSV/JSON via dashboard: audit page → select filters → "Export CSV" or "Export JSON".
  - Can export full audit trail for QSA review.

**Evidence You Can Provide**:
- Dashboard screenshots: expiration timeline, renewal success trends, status distribution.
- Job trend report: `GET /api/v1/stats/job-trends?days=90` showing success/failure rates.
- Agent fleet health: `GET /api/v1/agents` showing heartbeat status, version count distribution.
- Audit log sample: `GET /api/v1/audit?limit=100` showing certificate issuance/renewal/revocation activity.
- Alert configuration: screenshot of renewal policy `alert_thresholds_days` (30, 14, 7, 0) and notifier settings (email, Slack, etc.).

**Operator Responsibility**:
- **Review dashboard charts weekly** — look for anomalies (high Expired count, failure spike, renewal stalled).
- **Respond to alerts promptly** — expiration alert = investigate renewal (check job logs, issuer connectivity, agent heartbeat).
- **Set alert thresholds appropriately** — default 30/14/7/0 days is a starting point; adjust per your SLA and staffing.
- **Maintain alert distribution list** — ensure alerts reach the right on-call engineer/team.
- **Archive and review audit logs** — export monthly/quarterly for compliance trending (e.g., "all certificate changes last quarter").
- **Test alert delivery** — trigger a test renewal failure or manual revocation, verify alert is sent.

**Status**: **Available** (v1.0 shipped, M14 observable charts, M19 audit log)

### 10.7 — Retain and Protect Audit Trail History

**Requirement**: Retain audit trail history for at least one year and ensure it can be retrieved.

**certctl Support**:

- **Immutable Audit Trail** (M19) — `audit_events` table stores all API calls and certificate lifecycle events with timestamps.
- **No Automatic Purge** — Certctl does not delete audit events. They remain in PostgreSQL indefinitely.
- **Queryable History** — All events accessible via `GET /api/v1/audit` with time range, actor, resource filters.

**Evidence You Can Provide**:
- Database retention policy: confirm `audit_events` table has no DELETE triggers or maintenance jobs that purge events.
- Sample audit query: `SELECT COUNT(*) FROM audit_events WHERE timestamp > NOW() - INTERVAL '365 days'` showing one year+ of events.
- Export procedure: documented process for exporting audit logs to cold storage (S3, archive tape, syslog).

**Operator Responsibility**:
- **Configure PostgreSQL backup/retention** — certctl relies on database backups for audit trail protection.
  - Backup `audit_events` table daily or per your RPO/RTO.
  - Retain backups for at least 1 year (configure retention policy on backup system).
  - Test restore procedure annually.

- **Export and archive audit logs** — periodically export `SELECT * FROM audit_events WHERE timestamp > {start_date}` to offsite storage.
  - Recommendation: monthly exports to S3 with versioning enabled.
  - Encrypt exports at rest.
  - Retain archives for at least 3 years (adjust per your compliance requirements).

- **Monitor audit log growth** — `audit_events` table will grow ~1-5 MB/day depending on API call volume.
  - Estimate: 10,000 API calls/day = ~50 MB/month.
  - Plan PostgreSQL storage and backup capacity accordingly.

**Status**: **Available** (v1.0 shipped)

---

## Requirement 6: Develop and Maintain Secure Systems and Applications

**Objective**: Develop and maintain secure systems and applications.

### 6.3.1 — Security Coding Practices

**Requirement**: Develop all custom application code in accordance with secure coding practices and include authentication, access control, input validation, and error handling.

**certctl Support**:

- **Input Validation** — Centralized validators enforce strong input constraints:
  - Common name: max 253 chars, DNS-safe characters only, no leading/trailing hyphens.
  - CSR PEM: must be valid PEM format (regex validation).
  - Policy type: whitelist enum (Issuance, Renewal, Revocation, etc.).
  - API key: alphanumeric + hyphens only.
  - Implemented in `internal/domain/validation.go` and called from all handler layer inputs.

- **Error Handling** — No sensitive data leakage in error responses:
  - HTTP 500 errors return generic "Internal Server Error" message, not stack trace.
  - Database errors logged internally (structured slog), not exposed to client.
  - 404 errors do not reveal whether resource exists (consistent "Not Found" regardless of auth vs. not-found).

- **No Hardcoded Credentials** — All secrets via environment variables:
  - `CERTCTL_API_KEY`, `CERTCTL_DATABASE_URL`, `CERTCTL_CA_KEY_PATH` — env vars only.
  - Credentials not in `main.go`, Dockerfile, `docker-compose.yml`, or Git history.
  - `.env` file git-ignored and excluded from version control.

- **Dependency Management** — Go module pinning (`go.mod`):
  - All external dependencies pinned to specific versions.
  - No wildcard versions or `latest` tags.
  - CI runs `go mod verify` to detect tampering.

**Evidence You Can Provide**:
- Code review: `internal/domain/validation.go` showing input validation functions (Common name length, CSR PEM, policy type, etc.).
- Error handling audit: `internal/api/handler/certificates.go` showing HTTP error responses (no stack traces).
- Credentials in source code check: `grep -r "CERTCTL_API_KEY\|DATABASE_URL\|CA_KEY" cmd/ internal/ | grep -v ".env"` (should only show env var references, not values).
- `go.mod` review: no wildcard versions, all pinned.
- CI workflow: `.github/workflows/ci.yml` showing `go mod verify` step.

**Operator Responsibility**:
- **Review dependency updates** — keep Go version current, update certctl dependencies regularly (security patches).
- **Scan container images** — use Trivy, Clair, or similar to scan Docker images for known vulnerabilities.
- **Maintain secure coding practices** in any custom issuer/target connectors you deploy (scripts for OpenSSL, BASH/PowerShell for IIS/F5).

**Status**: **Available** (v1.0 shipped)

### 6.5.10 — Broken Authentication and Cryptography Prevention

**Requirement**: Prevent broken authentication and cryptography weaknesses.

**certctl Support**:

- **Authentication** — API key with SHA-256 hashing, constant-time comparison (`crypto/subtle.ConstantTimeCompare`).
- **Cryptography** — Go's `crypto/*` standard library (no weak ciphers). ECDSA P-256, RSA 2048+.
- **TLS** — HTTPS enforced (no plaintext HTTP endpoints).
- **No Sessions** — Stateless API (no session cookies, no session fixation risk).

**Status**: **Available** (v1.0 shipped)

---

## Requirement 7: Restrict Access by Business Need-to-Know

**Objective**: Limit access to system components and cardholder data by business need-to-know and ensure users are authenticated and authorized.

### 7.2 — Implement Access Control

**Requirement**: Ensure proper user identity management and implement access controls based on business need-to-know.

**certctl v1 Support** (limited):
- **Certificate Ownership** (M11b) — Each certificate assigned to owner (person + email) and optional team. Ownership is metadata; access control is not enforced at API level.
- **Agent Groups** (M11b) — Renewal policies target specific agent groups (OS, architecture, CIDR, version). Groups are used for policy targeting, not user access control.
- **Interactive Approval** (M11b) — `AwaitingApproval` job state allows manual approval/rejection of renewals (enforcement of business workflows, not user access control).

**certctl v3 Support** (planned):
- **OIDC/SSO** — Okta, Azure AD, Google integration. Users log in via identity provider.
- **Role-Based Access Control (RBAC)** — Three roles: admin (all operations), operator (issue/renew/deploy), viewer (read-only). Roles assigned via OIDC claims or group membership.
- **Profile/Owner Gating** — Operator can renew only certificates assigned to their team; viewer cannot modify anything.
- **Audit Trail Attribution** — Every action shows which user/role performed it.

**Evidence You Can Provide** (v1):
- Certificate ownership mapping: `GET /api/v1/certificates` showing owner, team fields (metadata only; access not controlled).
- Agent group targeting: `GET /api/v1/policies` showing `agent_group_id` field.
- Interactive approval workflow: job detail showing `AwaitingApproval` state, approve/reject endpoints in API docs.

**Operator Responsibility** (v1):
- **Manage API key distribution** externally — only issue API keys to authorized users/systems.
- **Implement reverse proxy auth** (Nginx, Apache, Okta proxy) in front of certctl to enforce OIDC/LDAP (outside certctl).
- **Plan for V3 RBAC** — budget for upgrade when finer-grained access control is needed.

**Planned** (V3):
- Upgrade to certctl Pro with OIDC/RBAC and per-role audit trail.

**Status**: **Available in part** (v1.0: ownership metadata, agent group targeting). **Planned V3**: OIDC/RBAC enforcement.

---

## Evidence Summary Table

| PCI-DSS Requirement | certctl Feature | API/UI Evidence | Database/Config | Audit Trail | Status |
|---|---|---|---|---|---|
| **4.2.1** Strong Crypto | TLS cert issuance, ACME/step-ca/Local CA, RSA 2048+/ECDSA P-256 | `GET /api/v1/certificates` (key_type, key_size) | Certificate profiles | `GET /api/v1/audit?type=certificate_issued` | Available |
| **4.2.2** Cert Inventory & Validation | Managed cert CRUD, discovery (M18b), expiration alerting, CRL/OCSP | `GET /api/v1/certificates`, `GET /api/v1/discovered-certificates`, `GET /.well-known/pki/crl/{issuer_id}`, `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` (both unauthenticated, RFC 5280 / RFC 6960) | `managed_certificates`, `discovered_certificates` tables | `GET /api/v1/audit?type=certificate_*` | Available |
| **3.6** Key Documentation | Profiles, owner/team tracking, issuer config, audit trail | `GET /api/v1/profiles`, `GET /api/v1/issuers`, certificate detail with owner/team | Profiles, certificate owner/team fields, issuer config | `GET /api/v1/audit?resource_type=certificate` | Available |
| **3.7.1** Key Generation | Agent-side ECDSA P-256, server keygen (demo only) | Agent logs, renewal job detail, CSR audit | `CERTCTL_KEYGEN_MODE=agent` (config), job_type=AwaitingCSR | `GET /api/v1/audit?type=certificate_issued` with CSR hash | Available |
| **3.7.2** Key Storage | Agent `/var/lib/certctl/keys` (0600), env var secrets, .env excluded | Deployment manifest (env var refs), agent key dir listing | `.env` file (git-ignored), `CERTCTL_KEY_DIR`, `CERTCTL_CA_KEY_PATH` | No API audit (keys off-platform) | Available |
| **3.7.3** Key Rotation | Auto renewal, expiration thresholds, renewal jobs | Dashboard renewal trends, `GET /api/v1/jobs?type=Renewal`, certificate versions | Renewal policies, certificate version history | `GET /api/v1/audit?type=certificate_renewed` | Available |
| **3.7.4** Key Destruction | Revocation API (RFC 5280), CRL/OCSP, private key cleanup | `POST /api/v1/certificates/{id}/revoke`, unauthenticated `GET /.well-known/pki/crl/{issuer_id}` and `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` | `certificate_revocations` table, CRL publication | `GET /api/v1/audit?type=certificate_revoked` | Available |
| **8.3** Strong Authentication | API key (SHA-256 hash, TLS), GUI login, 401 redirect | GUI login screenshot, API key auth header, TLS cert | API key hash in database | `GET /api/v1/audit` showing API calls | Available |
| **8.6** Acct Management | Credentials out of source, .env excluded, env var config | Code review (no hardcoded secrets), `.gitignore` check | Deployment manifests showing env var refs only | No account lifecycle audit (outside scope) | Available in part |
| **10.2** Audit Logging | API audit middleware (M19), certificate lifecycle events | `GET /api/v1/audit` with filter/pagination | `audit_events` table (every API call) | Real-time via API | Available |
| **10.3** Audit Protection | Append-only table design, read-only API, DB permissions | API endpoint audit (no PUT/DELETE on events), DB schema | `audit_events` table, PostgreSQL GRANT SELECT | Immutable by design | Available |
| **10.4** Review & Alert | Dashboard charts, stats API, notifier integrations | Dashboard (renewal trends, status pie, expiration heatmap), `GET /api/v1/stats/*` | Job results, alert config in policies | `GET /api/v1/audit?type=job_*` | Available |
| **10.7** Retention | 1+ year in PostgreSQL, export/archive procedures | Database query `SELECT COUNT(*) FROM audit_events WHERE timestamp > NOW() - INTERVAL '1 year'` | `audit_events` table retention (no auto-delete) | Manual export/archival (operator) | Available |
| **6.3.1** Secure Coding | Input validation, error handling, no hardcoded secrets, dependency pinning | Code review (validation.go, handlers), error responses | `go.mod` with pinned versions, `.gitignore` | GitHub Actions CI with `go mod verify` | Available |
| **7.2** Access Control | Ownership metadata, agent groups, interactive approval | `GET /api/v1/certificates` (owner/team), `GET /api/v1/agent-groups` | Certificate owner/team fields, agent group criteria | User identity from auth context | Available in part (V3: RBAC) |

---

## Operator Responsibilities

The following control objectives are **outside certctl's scope** and must be managed by your organization:

| Control Objective | Responsibility | Example Actions |
|---|---|---|
| **Network Segmentation** | Isolate certctl control plane from cardholder network | Place certctl on separate VLAN, firewall rules |
| **Physical Security** | Restrict access to servers/databases | Data center access controls, logging |
| **Personnel Screening** | Background checks for staff with access | HR/employment verification |
| **Access Control Enforcement** | User authentication & authorization outside API | Implement reverse proxy with OIDC (V3: use certctl Pro RBAC) |
| **Incident Response** | Procedures for certificate compromise or breach | Document key revocation process, alert escalation |
| **Disaster Recovery** | Backup and restore procedures | Database backup schedule, offsite replication |
| **Change Management** | Approval process for config/cert changes | CAB meetings, documented procedures |
| **Vulnerability Scanning** | ASV scanning, penetration testing, code review | Annual PCI-DSS penetration test |
| **Key Backup & Escrow** | Secure offline storage of CA private keys (if required) | Hardware security module (HSM) or encrypted vault |
| **Audit Log Retention** | Long-term archival and protection of audit logs | Export to S3/syslog, retain 3+ years |
| **QSA Engagement** | Schedule and coordination of compliance assessment | Annual audit with qualified security assessor |

---

## V3 Enhancements for PCI-DSS

Certctl v3 (Pro) adds paid features that strengthen PCI-DSS compliance posture:

| Feature | PCI-DSS Benefit |
|---|---|
| **OIDC/SSO Authentication** | Centralized identity management, audit integration with corporate directory |
| **Role-Based Access Control (RBAC)** | Least-privilege enforcement: admin, operator, viewer roles with profile/team gating |
| **Bulk Revocation by Profile/Owner/Agent** | Rapid incident response (revoke all certs in cardholder network in minutes) |
| **NATS Event Bus with JetStream Audit Streaming** | Real-time event streaming to SIEM (Splunk, ELK, Datadog) for centralized audit trail |
| **Certificate Health Scores** | Proactive risk identification (composite scoring: expiration proximity, rotation age, key strength) |
| **Advanced Search DSL** | Complex audit queries (POST /search with nested AND/OR, regex, field projection) for compliance reporting |
| **CT Log Monitoring** | Detect unauthorized certificate issuance (security vulnerability detection) |
| **DigiCert Issuer Connector** | Enterprise CA integration for compliance audits |

---

## Next Steps for Compliance

1. **Review this mapping with your QSA** — Confirm which requirements apply to your cardholder data environment.

2. **Configure certctl for your environment**:
   - Set `CERTCTL_KEYGEN_MODE=agent` in production.
   - Define certificate profiles with approved key types.
   - Configure renewal policies with appropriate thresholds (e.g., 30 days for 90-day certs).
   - Enable notifier integrations (email, Slack, PagerDuty) for alerts.
   - Plan `CERTCTL_DISCOVERY_DIRS` on agents to scan all certificate locations.

3. **Implement operator controls**:
   - Document certificate management procedures (issuance, renewal, revocation, archival).
   - Establish API key rotation schedule.
   - Set up audit log export and archival (monthly to S3, retain 1+ year).
   - Configure PostgreSQL backups (daily, 1+ year retention).
   - Plan incident response (who revokes certs, escalation process, timeline).

4. **Test compliance readiness**:
   - Trigger a test renewal and verify CRL/OCSP publication.
   - Export audit trail and verify it shows expected events.
   - Test revocation workflow and confirm OCSP reflects status within 24 hours.
   - Run discovery scan and verify unknown certs are detected and triaged.

5. **Prepare evidence for QSA**:
   - API endpoint documentation (OpenAPI spec: `api/openapi.yaml`).
   - Audit log sample (last 90 days of events).
   - Configuration export (profiles, policies, issuer/target definitions).
   - Deployment manifest (showing env var config, no hardcoded secrets).
   - Test certificates and CRL/OCSP query results.

6. **Plan for V3** (if RBAC/centralized audit required):
   - Evaluate certctl Pro for OIDC/SSO and NATS audit streaming.
   - Assess integration with existing identity provider (Okta, Azure AD, etc.).

---

## Questions?

For additional guidance on certctl features and PCI-DSS mapping:
- Review the [Architecture Guide](../reference/architecture.md) for system design.
- Check [Connectors Documentation](../reference/connectors/index.md) for issuer/target/notifier capabilities.
- Run the [Quick Start Guide](../getting-started/quickstart.md) to see features in action.
- Consult your QSA for final compliance determination.

**Last Updated**: March 24, 2026 (certctl v1.0 with M18b discovery and M19 audit logging)
