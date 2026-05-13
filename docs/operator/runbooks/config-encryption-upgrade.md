# Runbook: forcing config-encryption blob upgrades (v1/v2 → v3)

> Last reviewed: 2026-05-12

Use this when:
- You've rotated `CERTCTL_CONFIG_ENCRYPTION_KEY` and want every row in
  the database to be re-sealed under the new passphrase, not just the
  next ones to be touched.
- A v1- or v2-era encrypted blob existed in your database before you
  upgraded to a post-M-8 release and you want to retire the legacy
  read path's PBKDF2 work factor (100,000 rounds) in favor of the v3
  factor (600,000 rounds, OWASP 2024).
- You're preparing for an audit and want every at-rest encrypted blob
  to be on the same wire format.

Audience: a platform sysadmin who can run SQL against certctl's
PostgreSQL instance and exercise the GUI/REST API write paths.

For background on the v3 / v2 / v1 wire formats and the FileDriver vs
HSM threat model, read
[`docs/operator/secret-custody.md`](../secret-custody.md) first.

---

## Background: how the read fallback works

`internal/crypto/encryption.go::DecryptIfKeySet` reads three on-disk
formats in this order:

```
v3 (magic 0x03, per-ciphertext 16-byte salt, PBKDF2 600k) →
v2 (magic 0x02, per-ciphertext 16-byte salt, PBKDF2 100k) →
v1 (no magic, fixed 28-byte salt, PBKDF2 100k)
```

The fallback is AEAD-driven: if v3 decryption fails authentication, the
function tries v2; if v2 fails, v1. This is what keeps pre-M-8 v1 blobs
readable without an explicit migration.

`EncryptIfKeySet` always writes v3. As a result, any row that is
**re-written** through the normal application code path is silently
upgraded to v3 the moment it's persisted.

The implication: you do not need to "migrate" v1/v2 blobs for them to
keep working — only if you want the v1/v2 wire format physically gone
from your database.

## Procedure

### Step 1 — confirm the encryption key is set

Re-encryption obviously cannot run without a passphrase. Verify:

```bash
echo "${CERTCTL_CONFIG_ENCRYPTION_KEY:-NOT SET}" | sed -E 's/./*/g'
```

If the variable prints `NOT SET`, do not proceed — set the key in your
deployment manifest and restart the control plane first.

### Step 2 — identify which tables hold encrypted blobs

Encrypted columns in the v2.1.0 schema:

| Table              | Column                | Notes                                                                |
|---|---|---|
| `issuers`          | `encrypted_config`    | Only populated for `source='database'` rows (env-seeded rows are not encrypted) |
| `targets`          | `encrypted_config`    | Same source-based gating as issuers                                  |
| `oidc_providers`   | `client_secret_enc`   | OIDC client_secret                                                   |
| `auth_session_signing_keys` | `key_material_enc` | HMAC-SHA256 session-cookie signing key                          |

If your schema differs, derive the column list from the migration
folder:

```bash
grep -hE '_enc[ ,]|encrypted_config' migrations/*.up.sql | sort -u
```

### Step 3 — identify rows still on v1/v2

The magic byte of the blob distinguishes versions; v1 blobs start with
the random AES-GCM nonce (anything but `0x02` or `0x03` is definitely
v1), and v2 vs v3 is determined by the first byte:

```sql
-- Per-table version distribution (run against your live database)
SELECT
    SUBSTRING(encrypted_config FROM 1 FOR 1)::bytea AS magic,
    COUNT(*) AS rows
  FROM issuers
  WHERE encrypted_config IS NOT NULL
  GROUP BY magic;
```

Expected steady-state output is a single row with `magic = \x03`.
Any rows with `\x02` are v2; any rows with anything else are v1.

### Step 4 — force re-sealing

`UPDATE` the rows back to themselves through the normal application
write path. The cleanest way to do this is via the REST API or GUI,
not raw SQL — re-issuing the same `PUT /api/v1/issuers/:id` reads the
row, decrypts, then re-encrypts under v3 on the write back.

For an issuer named `iss-letsencrypt-prod`:

```bash
# Fetch then re-PUT the same body (CSRF + bearer token elided).
curl -sS https://certctl.example.com/api/v1/issuers/iss-letsencrypt-prod \
  -H "Authorization: Bearer $CERTCTL_API_KEY" \
  | jq '.' \
  | curl -sS -X PUT https://certctl.example.com/api/v1/issuers/iss-letsencrypt-prod \
      -H "Authorization: Bearer $CERTCTL_API_KEY" \
      -H "Content-Type: application/json" \
      --data-binary @-
```

Repeat for each row that the Step 3 query flagged as non-v3.

### Step 5 — verify

Re-run the Step 3 query. The output should now show only `magic =
\x03` rows.

## Special case: rotating the encryption-key passphrase

If your goal is to retire a possibly-compromised passphrase rather
than retire a legacy wire format, the order is:

1. Generate a new passphrase. Document it via your secret-management
   tool (HashiCorp Vault, AWS Secrets Manager, etc.).
2. Stop the control plane briefly so no rows are written under the
   stale passphrase during the transition window.
3. Run a one-shot decrypt-with-old / re-encrypt-with-new pass.
   certctl ships no built-in tool for this — see the open
   roadmap item below. The cleanest current approach is:
    - Start certctl with the OLD passphrase.
    - Read every encrypted column out to a JSON dump via the REST API.
    - Stop certctl. Update its env to the NEW passphrase. Restart.
    - PUT every row back from the JSON dump (the writes re-seal under
      the new passphrase).
4. Document the old passphrase as retired in your secret-management
   tool. Anyone with read access to a pre-rotation backup still needs
   it to decrypt that backup; the live database no longer needs it.

For most operators, simply rotating the passphrase and letting the
re-seal happen organically as rows are touched is acceptable — the
v3 wire format with PBKDF2 600k rounds makes offline brute-force
against the old passphrase computationally expensive.

## Open roadmap items

- Ship a built-in `certctl admin reseal --all` command that does Steps
  3 and 4 in one shot, with structured progress + audit logging.
  Tracked in [WORKSPACE-ROADMAP.md](../../WORKSPACE-ROADMAP.md).
- Surface per-table v1/v2/v3 distribution as a Prometheus gauge so
  alerting can fire on "rows on legacy format" drift.

## Related reading

- [`docs/operator/secret-custody.md`](../secret-custody.md) — the
  broader where-do-private-keys-live reference; this runbook is the
  procedural arm of that document.
- [`internal/crypto/encryption.go`](../../../internal/crypto/encryption.go)
  package comment — wire format authoritative reference.
