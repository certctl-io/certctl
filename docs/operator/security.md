# certctl Security Posture & Operator Guidance

This document collects the operator-facing security guidance that the source
code's per-finding comment blocks reference. Each section names the audit
finding it closes, the threat model, and the operator action required (if
any).

## OCSP responder availability

**Audit reference:** Bundle C / M-020. CWE-770 (uncontrolled resource
consumption); RFC 6960 (OCSP); RFC 7633 (Must-Staple).

certctl ships an OCSP responder at `/.well-known/pki/ocsp/{issuer_id}/{serial}`
that signs a fresh response per request. Pre-Bundle-C the unauth handler
chain had no rate limit, so an attacker could DoS the responder and force
fail-open relying parties to accept revoked certificates as valid. Bundle C
adds the same per-key rate limiter to the unauth chain that the authenticated
chain has used since Bundle B. Per-IP keying applies because OCSP traffic is
unauthenticated.

The rate limiter alone does not solve the underlying revocation-bypass risk.
**The architectural fix is for issued certificates to carry the OCSP
Must-Staple TLS Feature extension** (RFC 7633, OID 1.3.6.1.5.5.7.1.24). When
present, conforming TLS clients refuse to negotiate a session unless the
server staples a fresh signed OCSP response in the TLS handshake. This shifts
revocation enforcement from the client's discretion (which most fail-open by
default) to a hard requirement that the connection cannot complete without
proof of non-revocation.

### Operator action

For certificates issued to systems where revocation correctness matters:

1. **Configure the issuer profile to set `must-staple: true`.** Out-of-the-box
   profiles in `migrations/seed.sql` do not set this; operators add it at
   profile-creation time via the API or by editing seed data.
2. **Confirm the relying party honors the extension.** OpenSSL ≥ 1.1.0,
   Firefox, and Chrome 84+ all enforce Must-Staple. Older clients silently
   ignore it.
3. **Confirm the deployment target is configured for OCSP stapling** so the
   server can actually deliver the stapled response in the handshake.
   - **nginx:** `ssl_stapling on; ssl_stapling_verify on;`
   - **Apache:** `SSLUseStapling on`
   - **HAProxy:** `set ssl ocsp-response /path/to/response.der`
   - **Envoy:** `ocsp_staple_policy: must_staple`

### What this does NOT cover

- **CRL fallback.** Must-Staple does not affect CRL behavior. Operators with
  CRL-based relying parties should use the rate-limit + caching defense
  alone; there is no client-side equivalent to Must-Staple for CRLs.
- **Self-issued certs in air-gapped networks.** When the relying party
  cannot reach the OCSP responder at all (the threat model the audit
  cited), Must-Staple is the only mechanism that closes the bypass. CRL
  distribution similarly requires the relying party to fetch the CRL,
  which is also subject to the same network-availability concern.

## Postgres transport encryption

See [docs/database-tls.md](database-tls.md). Bundle B / M-018.

## Encryption at rest

Bundle B / M-001. PBKDF2-SHA256 at 600,000 rounds (OWASP 2024 Password
Storage Cheat Sheet floor) for the operator-supplied passphrase that
derives the AES-256-GCM key for sensitive config columns. v3 blob format
with a per-ciphertext random salt; v1/v2 read fallback for legacy rows.
See [internal/crypto/encryption.go](../internal/crypto/encryption.go) and
the accompanying tests for the format spec.

## Authentication surface

Bundle B / M-002. Two layers decide auth-exempt status:

1. **Router layer:** `internal/api/router/router.go::AuthExemptRouterRoutes`
   — the 4 endpoints registered via direct `r.mux.Handle` without going
   through the middleware chain (`/health`, `/ready`, `/api/v1/auth/info`,
   `/api/v1/version`).
2. **Dispatch layer:** `internal/api/router/router.go::AuthExemptDispatchPrefixes`
   — URL-prefix routing in `cmd/server/main.go::buildFinalHandler` for
   `/.well-known/pki/*`, `/.well-known/est/*`, and `/scep[/...]*`.

Both lists have AST-walking regression tests (`auth_exempt_test.go`) that
fail CI if a new bypass lands without an updating the documented constant.

## Per-user rate limiting

Bundle B / M-025. Authenticated callers are bucketed by API-key name;
unauthenticated callers (probes, OCSP relying parties, EST/SCEP enrollees)
are bucketed by source IP. `RPS` and `BurstSize` are per-key budgets.
`PerUserRPS` / `PerUserBurstSize` give authenticated clients a separate
budget when set non-zero.

## API key rotation

**Audit reference:** L-004. CWE-924 (improper enforcement of message integrity during transmission in a communication channel) — operator UX variant.

certctl's API keys are configured via the `CERTCTL_API_KEYS_NAMED` env var
(format `name1:key1,name2:key2:admin`) and parsed at startup into an
in-memory list. There is no DB-resident key store, no GUI, no `/api/v1/keys`
endpoint — the env var IS the key inventory.

Pre-Bundle-G the env var rejected duplicate names, so rotating a key
required: stop accepting OLDKEY → restart → roll NEWKEY out. Any client
polling against OLDKEY during the restart window hit a 401.

Bundle G adds a **double-key rotation window**: two entries can share a
name during the rollover, and both keys validate. Operators run the
rotation as:

1. **Generate the new key.** `openssl rand -hex 32` produces a 256-bit
   value with sufficient entropy.

2. **Append the new entry to `CERTCTL_API_KEYS_NAMED`** alongside the
   existing one:
   ```
   CERTCTL_API_KEYS_NAMED="alice:OLDKEY:admin,alice:NEWKEY:admin"
   ```
   Both entries MUST carry the same admin flag — startup fails loud if
   they don't (a non-admin shouldn't share an identity with an admin).

3. **Restart certctl.** A startup INFO log confirms the rotation window
   is active:
   ```
   INFO api-key rotation window active name=alice entries=2 see=docs/security.md::api-key-rotation
   ```

4. **Roll the new key out to all clients.** Both keys validate during
   this phase. Audit-trail actor + per-user rate-limit bucket stay
   consistent across the rollover (both entries produce the same
   `UserKey` context value, the shared name).

5. **Remove the old entry** from `CERTCTL_API_KEYS_NAMED`:
   ```
   CERTCTL_API_KEYS_NAMED="alice:NEWKEY:admin"
   ```

6. **Restart certctl.** OLDKEY now fails with 401. Rotation complete.

The rotation window has no operator-set timeout — it lasts for as long
as both entries are in the env var. Best practice is a 24-72h window
covering a full deploy cadence; if a client hasn't rolled to NEWKEY by
the end of step 4, extend the window before step 5.

### What the contract guarantees

- Two entries with the same `name`: **allowed** if both have the same
  `admin` flag.
- Two entries with the same `name` but mismatched admin: **rejected at
  startup** (privilege escalation guard).
- Two entries with the same `(name, key)` pair: **rejected at startup**
  (typo guard — rotation requires DIFFERENT keys under the same name).
- Single-entry steady state: unchanged from pre-Bundle-G behavior.

### What the contract does NOT do

- **No automatic expiration of OLDKEY.** The operator removes the entry
  in step 5; certctl doesn't track timestamps. A future enhancement
  could add a `rotated_at` annotation if operators ask for it.
- **No GUI / API for key management.** Keys are env-var only by design;
  building a key-management surface is a separate feature project.
- **No revocation list.** If a key leaks, the only path is to remove it
  from the env var and restart. That's appropriate for a small env-var
  inventory; it would not scale to a per-user-key-issued model.

## Reporting a vulnerability

Email `certctl@proton.me`. Coordinated disclosure preferred; we will
acknowledge within 72h.
