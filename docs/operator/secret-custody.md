# Secret custody — where private keys live in certctl

> Last reviewed: 2026-05-12

Use this when:
- You're sizing certctl against an internal security review or third-party
  diligence ("where do private keys live, and how are they protected at
  rest?").
- You're evaluating the file-on-disk vs HSM-vs-cloud-KMS roadmap before
  committing to a deployment topology.
- You need a single page that names every secret material on the control
  plane and on agents, plus the at-rest protection for each.

This document covers WHAT secrets exist, HOW they are stored, and the
THREAT MODEL we accept for each — it is not a hardening checklist. The
hardening levers (env-vars, file modes, encryption-key configuration) are
cross-referenced as you read through.

## The secrets that exist

| Material                        | Where it lives                                                                  | Protection at rest                                                                                                  | Closes when…                                                                       |
|---|---|---|---|
| Local CA private key            | File on the control-plane host (`CERTCTL_CA_KEY_PATH`)                          | Filesystem ACLs (operator-supplied path; mode 0600 recommended)                                                     | A `signer.PKCS11Driver` or `signer.CloudKMSDriver` ships (post-v2.1.0)             |
| Agent ECDSA P-256 private keys  | File on each agent host (default `/var/lib/certctl-agent/keys/`)                | Filesystem ACLs on the agent host. Never transmitted to the control plane.                                          | TPM / Secure Enclave drivers ship (no current roadmap entry)                       |
| OIDC client secret              | `oidc_providers.client_secret_enc` column (PostgreSQL)                          | AES-256-GCM v3 wire format, derived from `CERTCTL_CONFIG_ENCRYPTION_KEY` via PBKDF2-SHA256 600k rounds              | The encryption key is rotated via `internal/crypto` re-seal (see runbook below)    |
| Session signing key             | `auth_session_signing_keys` table (PostgreSQL)                                  | AES-256-GCM v3, same encryption-key passphrase as above                                                             | HSM/FIPS-validated signing-key driver lands (deferred to v3)                       |
| Break-glass credential          | `breakglass_credentials.password_hash` column (PostgreSQL)                      | Argon2id (m=64MiB, t=1, p=4) hash; never encrypted because we need constant-time comparison                         | Out of scope — Argon2id resists offline attack already                             |
| API-key bearer tokens           | `auth_api_keys.token_hash` column (PostgreSQL)                                  | SHA-256(token) only — the plaintext is shown to the operator once at create time and never persisted                | Out of scope                                                                       |
| CSR private keys mid-issuance   | Agent memory only, ephemeral                                                    | Never written to disk; never transmitted to the server (CSRs only)                                                  | Already closed                                                                     |
| Issuer-connector backend secrets | `issuers.encrypted_config` column (PostgreSQL) for `source='database'` rows    | AES-256-GCM v3; FAIL-CLOSED if `CERTCTL_CONFIG_ENCRYPTION_KEY` is unset (see "Env-seeded vs DB-seeded" below)        | Already closed for `source='database'`; `source='env'` carries an explicit carve-out |

The breakdown by row source matters and is the subject of the next
section. Read it before concluding that a plaintext column is a bug.

## Env-seeded vs DB-seeded configs

certctl supports two sources for issuer and target configurations:

- **`source='env'`** — built from process environment variables on every
  boot (`CERTCTL_CA_CERT_PATH`, `CERTCTL_CA_KEY_PATH`, `CERTCTL_ACME_DIRECTORY_URL`,
  `CERTCTL_STEPCA_URL`, etc. — see `internal/service/issuer.go::buildEnvVarSeeds`
  for the exact list). These rows are deterministically reconstructable from environment and
  exist primarily so the GUI has something to display and so audit logs
  can reference an issuer ID. The `config` column is intentionally
  plaintext for `source='env'` rows: the exact same bytes already live
  in the operator's Compose file / Helm values / systemd unit, so
  persisting them again to PostgreSQL adds no new disclosure surface.

- **`source='database'`** — created via the GUI or REST API write paths
  (`POST /api/v1/issuers`, etc.). These rows fail closed when
  `CERTCTL_CONFIG_ENCRYPTION_KEY` is not configured:
    - The HTTP handlers refuse the write with
      `crypto.ErrEncryptionKeyRequired`.
    - The server **refuses to start** if any `source='database'` row
      exists without the encryption key, to prevent retroactive
      plaintext exposure.

The startup guard is in `cmd/server/main.go` around the
`encryptionKey != ""` branch — it lists `source='database'` rows on every
boot and aborts if any are present without the key.

If you want every issuer/target row to be encrypted at rest unconditionally,
set `CERTCTL_CONFIG_ENCRYPTION_KEY` and use database-sourced
configurations exclusively (re-create env-seeded rows through the GUI
once the key is present).

## The signer abstraction

All CA private-key signing flows through
`internal/crypto/signer.Signer`, which embeds the stdlib `crypto.Signer`
and adds `Algorithm()`. Two drivers ship today:

- `signer.FileDriver` — the production default. Wraps the historical
  file-on-disk PEM flow without behavior change. **Heap-resident**:
  while certctl is running, the key bytes sit in the process's address
  space.
- `signer.MemoryDriver` — used in tests; never reaches production code
  paths.

The disk-exposure leg of the threat model is documented inline at the
top of `internal/connector/issuer/local/local.go` (the L-014 carve-out).
The mitigations on the FileDriver leg include:
- mode 0600 enforced on the key file at startup,
- the key directory is not served by any handler,
- the bytes are never logged or echoed in audit events,
- the server fails closed if it cannot read the key.

`FileDriver` does NOT mitigate "an attacker with read access to the
control-plane filesystem can recover the CA key." That mitigation lives
in a future `signer.PKCS11Driver` (hardware token) or
`signer.CloudKMSDriver` (AWS/GCP/Azure KMS). The interface exists; the
drivers do not ship yet. Both are post-v2.1.0 roadmap items — see
[`docs/reference/architecture.md`](../reference/architecture.md) for the
target topology.

If you need HSM-grade key custody today, you have two options:
1. Run certctl behind an enterprise issuer (Microsoft ADCS, EJBCA,
   Smallstep, ACME-public) and configure certctl's local CA as
   intermediate-only or disable it entirely. The issuer connector then
   sends every signing request to your existing hardware-rooted PKI.
2. Wait for the PKCS#11 driver. Track its status in
   [WORKSPACE-ROADMAP.md](../../WORKSPACE-ROADMAP.md).

## Config-encryption wire format

`internal/crypto/encryption.go` produces and reads three on-disk
formats. The read path accepts all three; the write path emits only
the newest:

| Version | Magic byte | Salt              | PBKDF2-SHA256 work factor | Status                                                            |
|---|---|---|---|---|
| v3      | `0x03`    | per-ciphertext 16B | 600,000                  | **Default for all writes** (OWASP 2024)                            |
| v2      | `0x02`    | per-ciphertext 16B | 100,000                  | Legacy read-only; superseded by v3                                 |
| v1      | none      | fixed 28B          | 100,000                  | Pre-M-8 legacy read-only; written before per-ciphertext-salt fix   |

The wire-format documentation is also in the `internal/crypto/encryption.go`
package comment.

### Forcing legacy blob upgrades

Re-sealing happens passively: any `UPDATE` against a row that contains a
v1 or v2 blob triggers a v3 rewrite the next time the field is set.
There is no in-place migration tool because re-sealing requires reading
the row through the same code path that performs the write, and any
operational path that touches the row (renaming an issuer in the GUI,
updating a target's endpoint, refreshing an OIDC provider's
client-secret) achieves this naturally.

If you want to FORCE re-sealing across the entire database, use the
runbook at
[`docs/operator/runbooks/config-encryption-upgrade.md`](runbooks/config-encryption-upgrade.md).
Recommended only if you suspect the encryption-key passphrase has
been exposed and have already rotated it (the runbook covers the
rotation order: set the new key, force re-seal, retire the old key
from the rotation pool).

## Roadmap (what is not yet closed)

Tracked in [`WORKSPACE-ROADMAP.md`](../../WORKSPACE-ROADMAP.md), not
maintained here to prevent drift:

- `signer.PKCS11Driver` for HSM-token-backed CA key custody.
- `signer.CloudKMSDriver` for AWS/GCP/Azure KMS-backed CA key custody.
- FIPS 140-3 mode for the entire control plane.
- HSM-backed session signing key (currently HMAC-SHA256 software keys).

If a buyer or auditor asks for "HSM support," the honest answer is:
the interface is there, the drivers are not, and an enterprise issuer
connector is the bridge until the drivers ship.

## Related reading

- [`docs/operator/security.md`](security.md) — the broader hardening
  checklist; covers TLS, RBAC, audit logging, network policy.
- [`docs/operator/auth-threat-model.md`](auth-threat-model.md) — the
  authentication-subsystem threat model. Item 5 ("HSM / FIPS-validated
  signing key for sessions") is the session-signing-key analog of this
  document's CA-key story.
- [`docs/reference/architecture.md`](../reference/architecture.md) §
  "Signer abstraction" — the diagram form of the FileDriver / future
  PKCS11Driver / CloudKMSDriver topology.
- [`internal/crypto/encryption.go`](../../internal/crypto/encryption.go)
  package comment — wire format authoritative reference.
- [`internal/connector/issuer/local/local.go`](../../internal/connector/issuer/local/local.go)
  L-014 carve-out — the load-bearing threat-model section for the
  FileDriver case.
