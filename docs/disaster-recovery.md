# Disaster recovery runbook

> **Status (this document):** Production hardening II Phase 10
> deliverable. Codifies the fail-safe behaviors that already exist in
> the codebase and the operator procedures for recovering from
> common failure modes. Nothing in this runbook requires new code —
> if a procedure here doesn't work as documented, that's a bug in
> docs (file an issue).

This runbook is the SOC 2 / PCI procurement-team deliverable: it tells
auditors and on-call operators what to do when a piece of certctl's
state corrupts, when a CA key needs rotation, or when Postgres needs
a point-in-time restore. Read it once when you set up certctl; print
the [DR checklist](#dr-checklist) and pin it near your on-call rotation.

## Contents

1. [Overview — what's already automatic](#overview)
2. [CRL cache recovery](#crl-cache-recovery)
3. [OCSP responder cert recovery](#ocsp-responder-cert-recovery)
4. [OCSP response cache recovery](#ocsp-response-cache-recovery)
5. [CA private-key rotation](#ca-private-key-rotation)
6. [Postgres restore](#postgres-restore)
7. [Trust-bundle reload semantics (SCEP / EST / Intune)](#trust-bundle-reload-semantics)
8. [DR checklist](#dr-checklist)

## Overview

certctl is engineered so most failure modes are auto-recoverable
without operator action. The fail-safes in the codebase:

- **CRL cache corruption** — the scheduler's `crlGenerationLoop`
  regenerates the CRL for every issuer on its tick (default 1h via
  `CERTCTL_CRL_GENERATION_INTERVAL`). A corrupt or missing
  `crl_cache` row causes the next HTTP fetch to fall through to the
  live-signing path; the scheduler then writes the fresh CRL back to
  cache.
- **OCSP responder cert missing** — `ensureOCSPResponder` lazily
  bootstraps the responder cert on the first OCSP request after a
  missing row. The CA-key signing operation is rare (only at
  bootstrap / 7-day rotation cycle), so this is fast even on a
  cold cache.
- **OCSP response cache corruption** — the read-through facade in
  `CAOperationsSvc.GetOCSPResponseWithNonce` falls through to live
  signing on cache miss + writes the fresh response back. Operators
  can `DELETE FROM ocsp_response_cache;` and the cache rebuilds
  organically as relying parties query.
- **Trust anchor reload after a half-rotation** — `TrustAnchorHolder`
  (used by SCEP/Intune + EST mTLS) keeps the OLD pool in place when
  a SIGHUP-triggered reload fails (parse error, expired cert). The
  GUI reload modal surfaces the typed error so the operator can
  correct the file and retry without taking the EST/SCEP endpoint
  down.

These fail-safes mean most of this runbook is "delete the corrupt
row + wait for the next tick" rather than "restore from backup +
manually re-issue." The runbook documents the full procedures
anyway because compliance auditors need to see them written down.

## CRL cache recovery

**Symptom:** `GET /.well-known/pki/crl/{issuer_id}` returns 500, or
the CRL it returns has the wrong revocations / wrong signature, or
parses as garbage.

**Diagnosis:**

```bash
# 1. Look at the cached row directly:
psql -c "SELECT issuer_id, length(crl_der), this_update, next_update,
                generated_at, generation_duration_ms, revoked_count
         FROM crl_cache WHERE issuer_id = 'iss-local';"

# 2. Look at recent generation events:
psql -c "SELECT started_at, succeeded, error, duration_ms
         FROM crl_generation_events
         WHERE issuer_id = 'iss-local'
         ORDER BY started_at DESC LIMIT 10;"
```

**Recovery:**

```bash
# Force regeneration on next request by deleting the cache row.
# The next HTTP fetch falls through to the live-signing path AND the
# next crlGenerationLoop tick (≤1h by default) writes a fresh row.
psql -c "DELETE FROM crl_cache WHERE issuer_id = 'iss-local';"

# Verify:
curl -sS --cacert /path/to/ca.crt \
    https://certctl.example.com:8443/.well-known/pki/crl/iss-local \
  | openssl crl -inform DER -noout -text \
  | head -20
```

**Worst case** — if the underlying revocation data in
`certificate_revocations` is also corrupt, restore Postgres
(see [Postgres restore](#postgres-restore)) and the CRL regenerates
from the restored data on the next tick.

## OCSP responder cert recovery

**Symptom:** OCSP requests return 500 with errors like "responder
not configured" or "failed to load responder key."

**Diagnosis:**

```bash
psql -c "SELECT issuer_id, cert_subject, not_before, not_after,
                created_at, key_path
         FROM ocsp_responder_certs
         WHERE issuer_id = 'iss-local';"

# Check the on-disk responder key file (path from the row above):
ls -la /etc/certctl/ocsp-responder-keys/iss-local.key
```

**Recovery:**

```bash
# Delete the responder row. The next OCSP request triggers
# ensureOCSPResponder which generates a fresh keypair, signs a new
# responder cert with the CA key (rare CA-key use), and persists
# the new row + the on-disk key file (mode 0600 enforced).
psql -c "DELETE FROM ocsp_responder_certs WHERE issuer_id = 'iss-local';"

# If the on-disk key file is also corrupt, delete it first:
rm -f /etc/certctl/ocsp-responder-keys/iss-local.key

# Trigger the bootstrap by issuing one OCSP request:
curl -sS --cacert /path/to/ca.crt \
    https://certctl.example.com:8443/.well-known/pki/ocsp/iss-local/00 \
  > /dev/null

# Verify the new row + file:
psql -c "SELECT * FROM ocsp_responder_certs WHERE issuer_id = 'iss-local';"
ls -la /etc/certctl/ocsp-responder-keys/iss-local.key
```

The new responder cert carries the same `id-pkix-ocsp-nocheck`
extension as the original (per RFC 6960 §4.2.2.2.1) so relying
parties accept it without recursing through OCSP for the responder
itself.

## OCSP response cache recovery

**Symptom:** an OCSP request returns a stale response (e.g. "good"
for a cert you just revoked). This usually means the
`InvalidateOnRevoke` wire failed to fire — see the warning logs from
`RevocationSvc.RevokeCertificateWithActor`.

**Recovery:**

```bash
# Delete the stale cache entry. The next OCSP request falls through
# to live signing which reads the now-current revocation_status.
psql -c "DELETE FROM ocsp_response_cache
         WHERE issuer_id = 'iss-local' AND serial_hex = 'deadbeef...';"

# Verify the next fetch returns "revoked":
curl -sS --cacert /path/to/ca.crt \
    https://certctl.example.com:8443/.well-known/pki/ocsp/iss-local/deadbeef... \
  | openssl ocsp -respin /dev/stdin -resp_text -CAfile /path/to/ca.crt \
  | grep "Cert Status"
```

For a fleet-wide invalidation (e.g. you rotated the CA key — see
next section), nuke the whole cache:

```bash
psql -c "TRUNCATE ocsp_response_cache;"
```

The cache rebuilds organically as relying parties query. There's no
service-degradation window because the live-sign fallback is always
available; only the per-request CPU cost goes up until the cache
warms back up.

## CA private-key rotation

**Symptom:** scheduled rotation cycle (annual or longer), or
emergency rotation due to suspected compromise.

This procedure rotates the CA private key for the local issuer.
After rotation, every existing cert chains to the OLD CA cert which
remains trusted by relying parties until its `notAfter` (typical
10y); newly-issued certs chain to the NEW CA cert.

**Procedure:**

1. **Backup the current CA cert + key.** The on-disk paths are
   `CERTCTL_CA_CERT_PATH` / `CERTCTL_CA_KEY_PATH` (typically
   `/etc/certctl/ca.crt` + `/etc/certctl/ca.key`). Copy both to
   a secure offline location with at least 2y retention (relying
   parties may still send OCSP requests against certs the OLD CA
   issued).
2. **Generate a new keypair + cert.** For self-signed mode:
   ```bash
   openssl ecparam -name prime256v1 -genkey -noout -out new-ca.key
   openssl req -x509 -key new-ca.key -days 3650 \
       -subj "/CN=certctl Local CA" -out new-ca.crt
   ```
   For sub-CA mode, generate a CSR and have your enterprise root
   sign it instead.
3. **Stop certctl.** `kill -TERM <pid>` or `docker stop certctl`.
4. **Move the new files into place + back up the old:**
   ```bash
   mv /etc/certctl/ca.crt /etc/certctl/ca.crt.old-rotated-20XX-XX-XX
   mv /etc/certctl/ca.key /etc/certctl/ca.key.old-rotated-20XX-XX-XX
   mv new-ca.crt /etc/certctl/ca.crt
   mv new-ca.key /etc/certctl/ca.key
   chmod 0600 /etc/certctl/ca.key
   ```
5. **Truncate the OCSP responder cert table** so the responder
   bootstrap re-fires against the new CA:
   ```bash
   psql -c "DELETE FROM ocsp_responder_certs;"
   ```
6. **Truncate the CRL cache** so the next `crlGenerationLoop` tick
   regenerates the CRL signed by the new CA:
   ```bash
   psql -c "TRUNCATE crl_cache;"
   ```
7. **Truncate the OCSP response cache** so future OCSP requests
   live-sign with the new CA's responder cert:
   ```bash
   psql -c "TRUNCATE ocsp_response_cache;"
   ```
8. **Start certctl.** The startup preflight loads the new CA cert +
   key. The next HTTP request bootstraps a new responder cert.
9. **Verify:**
   ```bash
   # Issue a test cert
   curl ... new-cert
   # Confirm chain to the new CA
   openssl x509 -in new-cert -noout -issuer
   ```

**Future:** when the HSM/PKCS#11 driver bundle (`cowork/hsm-pkcs11-
driver-prompt.md`) ships, this rotation procedure changes
substantially — the HSM-backed key never moves, only the cert wrap
rotates. The signer interface seam is the load-bearing prerequisite
for that.

## Postgres restore

certctl's full state lives in Postgres. The on-disk artifacts (CA
cert/key, RA cert/key for SCEP, responder keys for OCSP, trust
bundles for SCEP/Intune/EST mTLS) are operator-managed; everything
else is in DB rows.

**Restore procedure:**

1. Stop certctl. `kill -TERM <pid>` or `docker stop certctl`.
2. Restore the Postgres database from your point-in-time backup
   (`pg_restore` or your managed-DB equivalent).
3. Run any migrations newer than the backup's snapshot:
   ```bash
   migrate -path migrations/ -database "$DATABASE_URL" up
   ```
4. **Truncate the caches** that may now hold stale data referencing
   pre-restore rows:
   ```bash
   psql -c "TRUNCATE crl_cache;"
   psql -c "TRUNCATE ocsp_response_cache;"
   ```
5. Start certctl. The schedulers regenerate caches on their next
   ticks.

**Recoverable from DB only:** managed certificates, revocations,
audit log, jobs, agents, owners, teams, profiles, issuer/target/
notifier configs, scheduled tasks, network scan results.

**Operator-managed (NOT in DB):**
- CA cert + key (`CERTCTL_CA_CERT_PATH` / `CERTCTL_CA_KEY_PATH`)
- SCEP RA cert + key per profile
- OCSP responder keys per issuer (`CERTCTL_OCSP_RESPONDER_KEY_DIR`)
- SCEP/Intune trust anchor PEM bundles
- EST mTLS client CA trust bundles
- `CERTCTL_API_KEY`, `CERTCTL_AGENT_BOOTSTRAP_TOKEN`,
  `CERTCTL_CONFIG_ENCRYPTION_KEY`

Back these up out-of-band on the same cadence as your Postgres
backups. Without them, a restored DB is unusable.

## Trust-bundle reload semantics

This section codifies the fail-safe behavior that's already in code,
for compliance auditors who need to see the procedure documented.

**Pattern:** every trust-bundle holder (`internal/trustanchor.Holder`,
used by SCEP/Intune dispatcher + EST mTLS sibling route) implements
the same SIGHUP-equivalent reload semantics:

- A bad reload (parse error, expired cert, empty bundle) keeps the
  OLD pool in place. The endpoint stays up; the operator sees the
  typed error in the GUI Reload modal.
- The reload is atomic. There's no window where the holder is
  empty or pointing at a half-loaded bundle.
- In-flight requests use a snapshot taken at request-start. A
  request that crosses a SIGHUP uses the OLD pool — no mid-request
  validation drift.

**Operator workflow:**

1. Receive the new trust bundle (e.g., rotated Intune Connector
   signing cert, rotated EST mTLS client CA).
2. Overwrite the on-disk PEM file at the configured path.
3. Trigger reload via the GUI (`/scep` Profiles tab → Reload trust
   anchor; `/est` Profiles tab → same) OR send `kill -HUP <certctl-pid>`
   directly.
4. The Reload modal returns success or shows the typed error. On
   error, fix the file (`openssl x509 -in trust.pem -noout -text`
   to validate) and retry; the OLD pool stays in place between
   attempts.

## DR checklist

Print this. Pin it near your on-call rotation.

```
☐ Backups: Postgres backup runs nightly + retention ≥ 30 days
☐ Backups: CA cert + key offsite + retention ≥ NotAfter + 2y
☐ Backups: OCSP responder keys offsite (or accept rotate-from-CA on restore)
☐ Backups: Trust anchor PEMs offsite
☐ Backups: Operator-managed env vars (API_KEY, BOOTSTRAP_TOKEN,
  CONFIG_ENCRYPTION_KEY) in a separate secret manager

☐ Quarterly: dry-run a Postgres restore into a staging environment
☐ Quarterly: verify CA cert NotAfter > 1y
☐ Quarterly: rotate the OCSP responder cert (auto-handled by
  ensureOCSPResponder; verify the rotation actually fires by
  diffing the responder row's serial_number quarter-over-quarter)

☐ Annually: dry-run a full DR — restore Postgres + CA + responders
  into a clean environment + issue + revoke a test cert end-to-end
☐ Annually: rotate API_KEY, AGENT_BOOTSTRAP_TOKEN
☐ Every 5y: rotate the CA private key (see CA rotation section above)
```

## Related docs

- [`crl-ocsp.md`](crl-ocsp.md) — CRL/OCSP responder operator guide.
- [`tls.md`](tls.md) — control-plane TLS bootstrap.
- [`security.md`](security.md) — production-grade security posture.
- [`scep-intune.md`](scep-intune.md) — SCEP/Intune trust-anchor
  rotation specifics.
- [`est.md`](est.md) — EST mTLS trust-bundle rotation specifics.
