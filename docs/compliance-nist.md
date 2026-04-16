# NIST SP 800-57 Key Management Alignment

NIST SP 800-57 Part 1 Rev 5 (May 2020) is the authoritative US government guidance on cryptographic key management. This document maps certctl's implementation to its recommendations. certctl follows NIST guidance where applicable; this guide documents the alignment and identifies gaps for future roadmap planning.

## Contents

1. [Key Generation (Section 6.1)](#key-generation-section-61)
2. [Key Storage and Protection (Sections 6.3, 6.4)](#key-storage-and-protection-sections-63-64)
3. [Cryptoperiods (Section 5.3, Table 1)](#cryptoperiods-section-53-table-1)
4. [Key States and Transitions (Section 5.2)](#key-states-and-transitions-section-52)
5. [Algorithm Recommendations (Section 5.1, SP 800-131A)](#algorithm-recommendations-section-51-sp-800-131a)
6. [Key Distribution and Transport (Section 6.2)](#key-distribution-and-transport-section-62)
7. [Revocation and Compromise (NIST SP 800-57 Part 3)](#revocation-and-compromise-nist-sp-800-57-part-3)
8. [Alignment Summary Table](#alignment-summary-table)
9. [Gaps and Remediation Roadmap](#gaps-and-remediation-roadmap)
   - [V2 (Current)](#v2-current)
   - [V3 (Planned: 2026)](#v3-planned-2026)
   - [V5 (Planned: 2027+)](#v5-planned-2027)
   - [Post-Quantum (2027+)](#post-quantum-2027)
10. [References](#references)
11. [Questions or Corrections?](#questions-or-corrections)

## Key Generation (Section 6.1)

certctl generates certificate keys on agent infrastructure using Go's `crypto/rand` for entropy, backed by `/dev/urandom` on Linux and `CryptGenRandom` on Windows. Key generation happens as follows:

**Agent-Side Key Generation (Production Default)**
- Agents generate ECDSA P-256 key pairs per certificate using `crypto/ecdsa` + `crypto/elliptic` (Go stdlib)
- Key generation triggered by `AwaitingCSR` job state in renewal/issuance workflows
- Agent creates Certificate Signing Request (CSR) with `x509.CreateCertificateRequest`, signed with the agent's private key
- Only the CSR crosses the network to the control plane; private key material never leaves the agent
- Configuration: `CERTCTL_KEYGEN_MODE=agent` (default, production)

**Server-Side Key Generation (Demo Only)**
- Available for development and testing via `CERTCTL_KEYGEN_MODE=server`
- Explicitly logged as a warning at startup: "server-side key generation enabled (CERTCTL_KEYGEN_MODE=server) — private keys touch control plane, demo only"
- Docker Compose demo uses server mode for backward compatibility
- Not recommended for production; agent mode is the secure default

**Entropy Source**
- `crypto/rand` provides cryptographically secure random bytes
- On Linux: backed by `/dev/urandom` via `getrandom()` syscall
- On Windows: backed by `CryptGenRandom()` (now `BCryptGenRandom()`)
- Meets NIST SP 800-90B requirements for entropy generation

## Key Storage and Protection (Sections 6.3, 6.4)

certctl implements tiered key storage with different protection profiles based on key purpose.

**Agent Private Keys**
- Stored on agent filesystem at `CERTCTL_KEY_DIR` (default: `/var/lib/certctl/keys`)
- File permissions: 0600 (read/write by agent process only, no world/group access)
- One PEM file per certificate, organized by certificate ID
- Accessible only to the agent process; isolated from other processes
- For container deployments: use Docker volumes with restricted permissions (`-v /var/lib/certctl/keys:0600`)

**Issuing CA Keys (Local CA Connector)**
- Loaded from disk at server startup via `CERTCTL_CA_CERT_PATH` and `CERTCTL_CA_KEY_PATH` env vars
- Supports RSA (PKCS#1, PKCS#8) and ECDSA (SEC1, PKCS#8) key formats
- Validates certificate constraints before use:
  - `IsCA=true` flag present
  - `KeyUsageCertSign` extension set
  - Valid certificate chain (for sub-CA mode)
- Keys held in memory during server runtime (no on-disk caching after load)
- Cleared from memory only on server shutdown

**Sub-CA Mode (Enterprise Integration)**
- CA certificate and key signed by upstream enterprise root (e.g., Active Directory Certificate Services)
- Certctl acts as subordinate CA, inheriting issuer DN from upstream CA
- All issued certificates chain to enterprise trust anchor
- CA key protection inherits upstream root's key management practices
- Configured via: `CERTCTL_CA_CERT_PATH=/path/to/ca.crt` and `CERTCTL_CA_KEY_PATH=/path/to/ca.key`

**NIST Gap: HSM Storage**
NIST SP 800-57 Part 1 recommends Hardware Security Module (HSM) storage for high-value keys (CA signing keys). certctl V2 uses filesystem storage on the server. HSM support is planned for certctl Pro (V3), enabling integration with:
- AWS CloudHSM
- Azure Dedicated HSM
- Thales Luna, Gemalto SafeNet, YubiHSM (on-premises)
- PKCS#11-compatible devices

## Cryptoperiods (Section 5.3, Table 1)

NIST recommends cryptoperiods (key validity durations) based on key type and security requirements. certctl enforces cryptoperiods through certificate profiles and renewal policies.

**Certificate Profile Enforcement**
- Certificate profiles (M11a) define `max_ttl` constraint per enrollment profile
- All certificates issued through a profile cannot exceed the profile's max_ttl
- Profile configuration example:
  ```json
  {
    "id": "prof-web-prod",
    "name": "Production Web Certs",
    "max_ttl_seconds": 31536000,  // 1 year max
    "allowed_key_algorithms": ["ECDSA_P256"],
    "required_sans": ["example.com"]
  }
  ```

**Renewal Thresholds**
- Renewal policies with configurable `alert_thresholds_days`: `[30, 14, 7, 0]` (days before expiry)
- Background scheduler checks renewal eligibility every 1 hour
- Certificates transitioned to `Expiring` status at 30 days, `Expired` at 0 days
- Renewal workflow can be triggered manually or automatically

**NIST Cryptoperiod Recommendations vs certctl Implementation**

| Key Type | NIST Recommendation | certctl Implementation |
|----------|---------------------|------------------------|
| CA signing key | 3–10 years | Configured via CA certificate not-after date; inheritable from upstream CA in sub-CA mode |
| End-entity web server cert | 1–3 years (trending shorter) | Profile `max_ttl` configurable; ACME issuer typically 90 days; SC-081v3 mandating 47 days by 2029 |
| Code signing cert | 2–8 years | Profile enforcement via `max_ttl`; not primary certctl use case |
| Short-lived credentials | < 1 hour recommended | Profile TTL < 1 hour; exempt from CRL/OCSP (expiry is sufficient revocation); auto-expiry on scheduler tick |
| OCSP signing key | 1–2 years | Embedded OCSP responder uses issuing CA key (same period as issuer) or delegated signing cert |
| TLS/SSL interoperability cert | 1–2 years | Trending 1 year or less; certctl's ACME/sub-CA/step-ca issuers all support short periods |

## Key States and Transitions (Section 5.2)

NIST defines lifecycle states for keys: pre-activation, active, suspended, deactivated, compromised, and destroyed. certctl maps these to certificate and job states:

| NIST Key State | certctl Equivalent | Implementation |
|---|---|---|
| **Pre-activation** | `Pending` job state / `AwaitingCSR` | Job created but key not yet generated; awaiting agent CSR submission (agent-mode) or server keygen (demo mode) |
| **Active** | Certificate status `Active` | Cert deployed to targets and in use; within validity period (not before < now < not after) |
| **Suspended** | Job state `AwaitingApproval` | Interactive approval holds deployment job pending human review; resumes on approval or cancels on rejection |
| **Deactivated** | Certificate status `Expired` | Past not-after date; auto-transitioned by scheduler every 2 minutes; renewal eligible |
| **Compromised** | Certificate status `Revoked` | Issued via `POST /api/v1/certificates/{id}/revoke` with RFC 5280 revocation reason |
| **Destroyed** | Archived (implementation detail) | Operator responsibility; certctl retains all certs in audit trail for compliance; no destructive deletion API |

**State Transition Audit Trail**
All transitions logged to immutable `audit_events` table with:
- Event type (e.g., `certificate_revoked`, `renewal_job_completed`)
- Actor (authenticated user or agent ID)
- Timestamp (RFC3339)
- Resource (certificate ID)
- Reason (revocation reason code, approval reason, etc.)
- HTTP method, path, status (for API calls)

Example audit entry for revocation:
```json
{
  "id": "ae-2024-0615",
  "event_type": "certificate_revoked",
  "actor": "ops-alice@example.com",
  "timestamp": "2024-06-15T14:23:00Z",
  "resource_id": "cert-web-prod-2024",
  "resource_type": "certificate",
  "description": "Revoked: reason=keyCompromise",
  "body_hash": "sha256:a1b2c3d..."
}
```

## Algorithm Recommendations (Section 5.1, SP 800-131A)

NIST SP 800-131A Rev 2 (January 2024) categorizes cryptographic algorithms as Approved, Conditionally Approved, or Disallowed. certctl implements only NIST-approved algorithms:

| Algorithm | NIST Status | certctl Support | Notes |
|-----------|-------------|-----------------|-------|
| **ECDSA P-256** | Approved (128-bit security strength) | Default for agent-side keygen | Meets NIST curve requirements (FIPS 186-4) |
| **ECDSA P-384** | Approved (192-bit security strength) | Supported via profile configuration | Higher security margin; slower than P-256 |
| **ECDSA P-521** | Approved (256-bit security strength) | Supported via profile configuration | Rarely needed; overkill for TLS |
| **RSA 2048** | Approved minimum (112-bit security, transitioning) | Supported via all issuers | Deprecated path; migrate to 3072+ by 2030 per NIST |
| **RSA 3072** | Approved (128-bit security) | Supported via all issuers | Recommended minimum for long-term security |
| **RSA 4096** | Approved (192-bit security) | Supported via all issuers | Supported but slower; overkill for most TLS |
| **SHA-256** | Approved | Used throughout | CSR signing, certificate fingerprints, audit body hashing, CRL/OCSP signing |
| **SHA-384** | Approved (192-bit) | Supported where algorithm selection available | Used in some CA signing scenarios |
| **SHA-512** | Approved (256-bit) | Supported where algorithm selection available | Rarely needed; SHA-256 suffices for most use cases |
| **SHA-1** | Deprecated | Not used in certctl | Browsers reject SHA-1 certs; certctl never generates them |

**Algorithm Enforcement via Profiles**
Certificate profiles enforce allowed key algorithms:
```json
{
  "id": "prof-web-prod",
  "allowed_key_algorithms": ["ECDSA_P256", "ECDSA_P384", "RSA3072"]
}
```

**Post-Quantum Cryptography (Tracking)**
NIST has finalized PQC standards (FIPS 204, FIPS 205) in August 2024:
- **ML-KEM** (Kyber): Approved key encapsulation mechanism
- **ML-DSA** (Dilithium): Approved digital signature algorithm
- **SLH-DSA** (SPHINCS+): Approved stateless hash-based signature scheme

certctl will track NIST's PQC roadmap and plan integration when hybrid PQC+classical certificate formats reach browser/infrastructure support. Currently, pure PQC certificates are not widely interoperable.

## Key Distribution and Transport (Section 6.2)

NIST SP 800-57 Part 1 Section 6.2 addresses secure key distribution to minimize exposure during transit. certctl implements a zero-transmission-of-private-keys model:

**Private Key Distribution**
- Agent-side keygen model: Private keys never leave agent infrastructure
- CSR transmitted over HTTPS (TLS 1.2+) with mutual TLS optional
- API key authentication via `Authorization: Bearer <api-key>` header
- All API calls logged to immutable audit trail

**Signed Certificate Distribution**
- Certificates (public component) distributed via `GET /agents/{id}/work` over HTTPS
- Work endpoint enriches deployment jobs with certificate PEM and metadata
- Certificate PEM is idempotent (same cert always returns same bytes)

**Target Deployment**
- Deployment to targets via local filesystem write (NGINX, Apache, HAProxy)
- No network transmission of private keys to targets
- Agents read local private key from `CERTCTL_KEY_DIR` on deployment
- For appliances without agents (F5 BIG-IP, IIS), proxy agent pattern:
  - Proxy agent runs in same trust zone as appliance
  - Proxy agent holds target API credentials (iControl, WinRM)
  - Control plane never communicates with appliance directly
  - Deployment request includes certificate and proxy agent ID
  - Proxy agent executes deployment via appliance API

**Revocation Distribution**
- Certificate Revocation List (CRL) via `GET /api/v1/crl/{issuer_id}`
  - Returns DER-encoded X.509 CRL signed by issuing CA
  - 24-hour validity period
  - Includes all revoked serials, reasons, and revocation timestamps
  - Subject to URL caching; OCSP preferred for real-time revocation
- OCSP via `GET /api/v1/ocsp/{issuer_id}/{serial}`
  - Returns DER-encoded OCSP response (OCSPResponse ASN.1 structure)
  - Signed by issuing CA (or delegated OCSP signing cert)
  - Responds with good/revoked/unknown status
  - Real-time, more bandwidth-efficient than CRL polling

## Revocation and Compromise (NIST SP 800-57 Part 3)

NIST SP 800-57 Part 3 covers revocation (Section 2.5) when keys are suspected compromised or no longer needed. certctl implements comprehensive revocation infrastructure:

**Revocation API**
- Endpoint: `POST /api/v1/certificates/{id}/revoke`
- Request body:
  ```json
  {
    "reason": "keyCompromise",
    "reason_text": "Private key exposed in log file"
  }
  ```
- Supports all 8 RFC 5280 revocation reason codes:
  - `unspecified` — no specific reason provided
  - `keyCompromise` — private key suspected compromised
  - `caCompromise` — issuing CA key compromised
  - `affiliationChanged` — subject org/affiliation changed
  - `superseded` — cert superseded by newer cert
  - `cessationOfOperation` — key no longer in use
  - `certificateHold` — temporary hold (rarely used)
  - `privilegeWithdrawn` — subject authorization withdrawn

**Revocation Recording**
- Certificate status updated to `Revoked`
- Entry recorded in `certificate_revocations` table with:
  - Certificate serial number
  - Revocation timestamp
  - Revocation reason code
  - Issuer ID
- Idempotent (revoking an already-revoked cert is safe; returns 200 OK)

**Issuer Notification (Best-Effort)**
- Control plane calls `issuer.RevokeCertificate(ctx, serial, reason)` on issuing connector
- Failure does not block the revocation (async, logged, retried)
- Supported issuers:
  - Local CA: generates new CRL immediately
  - ACME: submits revocation to ACME server (RFC 8555 Section 7.6)
  - step-ca: calls `/revoke` API
  - OpenSSL: executes user-provided revocation script

**Revocation Notifications**
- Notifiers triggered after revocation recorded: Slack, Teams, PagerDuty, OpsGenie, email, webhook
- Message includes certificate common name, issuer, reason, actor, timestamp
- Delivery is asynchronous and retried on failure

**CRL and OCSP Distribution**
- CRL updated on every revocation (or scheduled refresh for non-issued revocations)
- OCSP responder queries revocation table in real-time
- Short-lived certificate exemption: certs with TTL < 1 hour skip CRL/OCSP (expiry is sufficient revocation)

**Bulk Revocation for Large-Scale Compromise Response** (V2.2) — NIST SP 800-57 Part 3 emphasizes rapid revocation when keys are compromised. `POST /api/v1/certificates/bulk-revoke` revokes all certificates matching filter criteria (profile, owner, agent, issuer) in a single operation. This enables operators to execute fleet-wide revocation for key compromise events affecting multiple certificates. Each bulk revocation creates individual jobs reusing the existing revocation pipeline, ensuring every certificate is recorded in the audit trail with the incident reason.

**Revocation Audit Trail**
All revocation events logged:
- Event type: `certificate_revoked` or `bulk_revocation_initiated` (for fleet operations)
- Actor: authenticated user or service
- Reason code: RFC 5280 enum (or incident justification for bulk operations)
- Timestamp: RFC3339
- Issuer notification status: success or error reason
- Filter criteria: profile_id, owner_id, agent_id, issuer_id (for bulk revocation)

## Alignment Summary Table

| NIST SP 800-57 Area | Status | Coverage | Notes |
|---|---|---|---|
| **Key Generation** | ✅ Aligned | 100% | Agent-side ECDSA P-256 using crypto/rand; server mode flagged as demo-only |
| **Key Storage** | ⚠️ Partially Aligned | 80% | Filesystem with 0600 perms; HSM support planned V3 Pro |
| **Cryptoperiods** | ✅ Aligned | 100% | Profile-enforced max_ttl; threshold-based renewal alerting |
| **Key States** | ✅ Aligned | 100% | Full lifecycle tracking with immutable audit trail |
| **Algorithms** | ✅ Aligned | 100% | NIST-approved algorithms only; post-quantum tracking in progress |
| **Key Distribution** | ✅ Aligned | 100% | Private keys never transmitted; CSR/cert over TLS; agent-local deployment |
| **Revocation** | ✅ Aligned | 100% | CRL, OCSP, all RFC 5280 reason codes; real-time updates |

## Gaps and Remediation Roadmap

### V2 (Current)
- [x] Agent-side key generation
- [x] Profile-enforced cryptoperiods
- [x] CRL and OCSP distribution
- [x] RFC 5280 revocation support
- [x] Immutable audit trail

### V2.2 (Planned: 2026)
- Bulk revocation by profile/owner/agent/issuer (fleet-level revocation for incident response)

### V3 (Planned: 2026)
- Role-based access control (limit revocation/approval to authorized operators)

### V3 Pro (Planned)
- HSM support for CA key storage and agent key storage (TPM 2.0, PKCS#11)
- FIPS 140-2/3 validated crypto module (BoringCrypto build or external FIPS library)
- Key destruction API (explicit secure erasure of agent keys)
- Key escrow / recovery mechanism (backup encrypted private keys for disaster recovery)

### Post-Quantum (2027+)
- ML-KEM and ML-DSA support when browser/TLS ecosystem supports hybrid certificates
- Migration path documentation (how to transition existing RSA certs to PQC)

## References

- NIST SP 800-57 Part 1 Rev 5 (May 2020): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- NIST SP 800-131A Rev 2 (January 2024): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
- FIPS 186-4 (Digital Signature Standard): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
- RFC 5280 (X.509 PKI Certificate and CRL Profile): https://tools.ietf.org/html/rfc5280
- RFC 8555 (Automatic Certificate Management Environment): https://tools.ietf.org/html/rfc8555
- NIST FIPS 204 (ML-DSA): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- NIST FIPS 205 (ML-KEM): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf

## Questions or Corrections?

This document reflects certctl's implementation as of March 2026. For the latest code, refer to:
- Key generation: `cmd/agent/main.go` (agent keygen) and `internal/service/renewal.go` (server keygen)
- Key storage: `internal/config/config.go` (CERTCTL_KEY_DIR, CERTCTL_CA_CERT_PATH)
- Revocation: `internal/service/revocation.go` and `internal/api/handler/certificates.go`
- Audit trail: `internal/api/middleware/audit.go`
