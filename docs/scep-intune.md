# Microsoft Intune SCEP enrollment via certctl

> **Status (this document):** Phase 11 of the SCEP RFC 8894 + Intune master
> bundle. The behavior described here is shipped on `master` and exercised
> end-to-end by `internal/api/handler/scep_intune_e2e_test.go`. The
> bundle is V2-free (community edition) — Conditional-Access compliance
> gating, native Microsoft Graph integration, and per-tenant trust
> anchors are documented under [Limitations](#limitations) as V3-Pro
> features.

## TL;DR

certctl is a **drop-in NDES replacement** for Microsoft Intune SCEP fleets.
Intune-managed devices keep using the existing Intune Certificate Connector;
only the SCEP server URL changes. certctl validates the Connector's
signed challenge using its installation signing cert (no Microsoft API
calls — the Connector already did that), binds the device claim to the
inbound CSR, and issues through whichever certctl issuer connector you
have configured (local CA, Vault, EJBCA, ADCS, etc.).

What you get over NDES:

- Per-profile SCEP endpoints (`/scep/corp` vs. `/scep/iot` etc.) so a
  single certctl deploy serves multiple device fleets with distinct
  challenge passwords + trust anchors.
- Audit log entries with the device GUID, claim subject, and CSR
  binding details — much better forensics than NDES + IIS logs.
- Trust anchor reload via `SIGHUP` (no service restart) when the
  Connector signing cert rotates.
- A built-in admin GUI tab (Intune Monitoring) showing per-profile
  enrollment counters, trust-anchor expiry countdowns, and the recent
  failures table.
- Per-device rate limit (sliding window log keyed by Subject + Issuer)
  that catches a compromised Connector signing key issuing many
  different valid challenges for the same device.

## Architecture

```
┌──────────────┐       ┌──────────────────────┐       ┌──────────────┐
│ Intune cloud │──────▶│ Intune Certificate   │──────▶│ certctl SCEP │
│              │       │ Connector            │       │ server       │
│ (Microsoft)  │       │ (customer infra)     │       │ (you)        │
└──────────────┘       └──────────────────────┘       └──────┬───────┘
                                                              │
                                                              ▼
                                                       ┌──────────────┐
                                                       │ issuer       │
                                                       │ connector    │
                                                       │ (local CA /  │
                                                       │  Vault /     │
                                                       │  EJBCA / …)  │
                                                       └──────────────┘
```

**certctl replaces NDES, not the Connector.** The Intune Certificate
Connector is the bridge between the Intune cloud and your on-prem PKI;
Microsoft installs and maintains it. What you replace is the
**Network Device Enrollment Service** (NDES) — the SCEP server
historically deployed on a Windows host, sitting between the Connector
and an Active Directory Certificate Services CA. certctl sits in
exactly that slot and speaks SCEP RFC 8894 to the Connector.

### What certctl validates per request

For every Intune-flavored SCEP request the dispatcher in
`internal/service/scep.go::dispatchIntuneChallenge` walks the
following gates in order. A failure on any gate produces a CertRep
PKIMessage with the documented `pkiStatus`/`failInfo` codes (per RFC
8894 §3.2.1.4.5) and increments the corresponding metric counter.

1. **Shape pre-check** — `looksIntuneShaped(challengePassword)`:
   length > 200 + exactly two dots. False positives are fine; false
   negatives on real Intune challenges would route them to the static
   compare and reject. The pre-check just decides whether to invoke
   the full validator.
2. **JWS signature** — `intune.ValidateChallenge` re-derives the
   signing input from the raw on-wire bytes (per RFC 7515 §3.1, NOT
   re-base64-encoded segments) and verifies against every cert in the
   trust anchor pool. Supports RS256 and ES256 (both fixed-width
   r||s and ASN.1-DER form). Explicitly rejects `alg=none` and
   HMAC algs.
3. **Version dispatch** — extracts the `version` claim from the
   payload prelude. v1 (current Connector format, no `version` key)
   routes to `unmarshalChallengeV1`. Future v2 plugs in a sibling
   parser without touching the validator.
4. **Time bounds** — `now ≥ iat AND now < exp`. Configurable cap on
   top via `INTUNE_CHALLENGE_VALIDITY` (defense-in-depth against a
   Connector that mints long-validity challenges).
5. **Audience pin** — `claim.aud == INTUNE_AUDIENCE` (skipped when
   `INTUNE_AUDIENCE` is empty for proxy/load-balancer scenarios).
6. **CSR binding** — `claim.DeviceMatchesCSR(csr)` checks
   set-equality between the claim's `device_name` / `san_dns` /
   `san_rfc822` / `san_upn` and the CSR's CN + SANs. Set-equality
   means the CSR carries EXACTLY the claim's values, no extras and
   no missing.
7. **Replay** — `intune.ReplayCache.CheckAndInsert` rejects
   duplicates within the configured TTL. Sized for 100k entries
   (covers a ~25 RPS Intune fleet's steady-state).
8. **Per-device rate limit** — sliding window log keyed by
   `(claim.Subject, claim.Issuer)`. Catches a compromised Connector
   issuing many DIFFERENT valid challenges for the same device. Default
   3 enrollments per 24h covers legitimate first-cert + recovery +
   post-wipe.
9. **Optional compliance check** — V3-Pro plug-in seam (nil-default
   no-op). When set, the gate calls Microsoft Graph's compliance API
   and short-circuits non-compliant devices with FAILURE+BadRequest.

A request that passes all nine gates flows to
`processEnrollment`, which builds the issuance request, calls the
configured issuer connector, and emits a CertRep PKIMessage with the
issued cert encrypted to the device's transient signing cert per RFC
8894 §3.3.2.

## Migration from NDES + EJBCA (or NDES + ADCS)

The migration plan below is conservative — install certctl alongside
your existing NDES so you can flip Intune profiles fleet-by-fleet
without a flag day. Validated against a fresh `docker compose up`
stack; the docker-compose.test.yml stack does not currently bake
Intune in (Phase 10.2 ships a hermetic in-process e2e test instead),
so the production validation step is a manual run-book item.

1. **Install certctl alongside existing NDES.** Stand up the certctl
   server on a separate host (or as a Kubernetes deployment) reachable
   from the Connector host. Use the existing operator-run-book in
   `docs/tls.md` for the TLS bootstrap.
2. **Configure a per-profile SCEP endpoint.** Pick a path id (e.g.
   `corp` — referenced as `<NAME>` below; the value gets uppercased
   for the env-var key and lowercased for the URL path) and set:

   ```
   CERTCTL_SCEP_ENABLED=true
   CERTCTL_SCEP_PROFILES=corp
   CERTCTL_SCEP_PROFILE_<NAME>_ISSUER_ID=iss-local           # or your existing issuer
   CERTCTL_SCEP_PROFILE_<NAME>_CHALLENGE_PASSWORD=<random>   # Intune still requires this
   CERTCTL_SCEP_PROFILE_<NAME>_RA_CERT_PATH=/etc/certctl/ra-corp.pem
   CERTCTL_SCEP_PROFILE_<NAME>_RA_KEY_PATH=/etc/certctl/ra-corp.key
   ```

   The endpoint will be served at `https://certctl.example.com/scep/corp`
   — the URL path uses the lowercased name and the env-var keys use
   the uppercased form. Concrete env-var name mappings are listed in
   [`features.md`](features.md).
3. **Extract the Intune Connector's signing cert.** On the Connector
   host (Windows), the Connector's installation creates a self-signed
   cert in the local machine's `Personal` cert store with subject
   `CN=Microsoft Intune Certificate Connector` (path documented by
   Microsoft — see Microsoft Learn link in the
   [Microsoft support statement](#microsoft-support-statement) below).
   Export the public cert (no private key) as a base64 `.cer` file.
4. **Configure the trust anchor.** Copy the `.cer` to the certctl host
   (or mount via your secret manager) and set:

   ```
   CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_ENABLED=true
   CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CONNECTOR_CERT_PATH=/etc/certctl/intune-corp.pem
   CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_AUDIENCE=https://certctl.example.com/scep/corp
   ```

   Restart certctl. The startup preflight refuses to boot if the
   trust anchor file is missing, unparseable, or contains an expired
   cert — failure is loud at boot rather than silent at request time.
5. **Configure the issuer connector.** If you're keeping EJBCA,
   point `CERTCTL_SCEP_PROFILE_<NAME>_ISSUER_ID` at your EJBCA issuer
   profile (see `docs/connectors.md`). For a clean cut-over to the
   built-in local CA, follow `docs/tls.md` to bootstrap a sub-CA cert.
6. **Migrate one Intune SCEP profile to certctl.** In the Intune
   admin center, edit the SCEP profile for a small canary device
   group and update the SCEP server URL to
   `https://certctl.example.com/scep/corp`. Push the profile and
   wait for the canary devices to rotate (24-48h).
7. **Verify enrollment.** Open the certctl admin GUI's
   [SCEP Intune Monitoring tab](#operational-monitoring) and watch
   the `success` counter tick on the `corp` profile card. The
   `recent failures` table surfaces any rejected enrollments with
   the exact reason (e.g. `signature_invalid`, `claim_mismatch`).
8. **Roll out the rest of the fleet.** Once the canary is clean,
   migrate the remaining Intune SCEP profiles in batches.
9. **Decommission NDES.** After all fleets are migrated and a few
   renewal cycles have completed cleanly, take down the NDES role
   and the IIS site. The existing certs continue to chain to your
   issuer; only the enrollment path changes.

## Intune SCEP profile fields → certctl behavior

The Intune admin center's SCEP profile editor exposes a fixed set of
fields. The mapping below is what each field controls relative to
certctl's behavior.

| Intune profile field         | certctl behavior                                                                                                                                                                                  |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Certificate type             | Treated as device or user; surfaces in the claim's `subject` field (device GUID vs. user UPN). certctl doesn't gate on type; the issuer's certificate profile decides.                            |
| Subject name format          | Drives the CSR's CN. The Intune Connector sets `claim.device_name` from this value; certctl's CSR-binding gate enforces equality.                                                                  |
| Subject alternative name     | Drives the CSR's SAN list. Intune supports DNS / RFC 822 / UPN; certctl's claim binding checks set-equality per dimension. Mismatches surface as `ErrClaimSANDNSMismatch` / `_SANRFC822Mismatch` / `_SANUPNMismatch`. |
| Certificate validity period  | Honored by the issuer connector. certctl caps via the per-profile `CertificateProfile.MaxTTLSeconds`; the smaller of the two wins.                                                                |
| Key storage provider         | Device-side concern (the Connector negotiates with the device's TPM / Software KSP). certctl never sees the device's private key — it only signs the CSR.                                          |
| Key usage / Extended key usage | Honored by the issuer connector via the bound `CertificateProfile.AllowedEKUs`. CSRs requesting an EKU outside the allowed set are rejected by the crypto-policy gate (`ValidateCSRAgainstProfile`). |
| Hash algorithm               | The CSR's signature hash (SHA-256 typical). The SCEP `GetCACaps` advertises SHA-256 + SHA-512; the device picks.                                                                                  |
| SCEP server URL              | The endpoint URL the Connector posts to. Set to `https://certctl.example.com/scep/<profile-name>`.                                                                                                |

## Trust anchor extraction

The Intune Certificate Connector self-signs an installation cert at
install time. To configure certctl, extract this cert (PUBLIC ONLY,
no private key) as PEM:

1. On the Connector host (Windows), open `certlm.msc` (Local Machine
   Certificate Manager).
2. Navigate to `Personal` → `Certificates`. Find the cert with
   subject `CN=Microsoft Intune Certificate Connector`.
3. Right-click → All Tasks → Export. Choose **No, do not export
   the private key**. Format: **Base-64 encoded X.509 (.CER)**.
4. Copy the resulting `.cer` file to the certctl host. Rename to
   `.pem` (the bytes are identical; certctl's PEM loader accepts
   either extension).
5. Set `CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CONNECTOR_CERT_PATH` to
   the file path.
6. If you have multiple Connectors in HA, repeat steps 1-3 on each
   and concatenate the PEM blocks into one bundle file.

When the operator rotates the Connector signing cert (typically once
every few years per Microsoft's Connector lifecycle), repeat the
extraction, overwrite the on-disk file, then send `SIGHUP` to the
certctl process. The trust holder swaps atomically; bad files (parse
error, expired cert) keep the OLD pool in place so a half-rotation
doesn't take Intune enrollment down.

## Troubleshooting

The dispatcher emits a typed metric label per failure mode plus a
matching audit-log entry. The table below maps the label to the most
common root cause and the operator action.

| Counter label       | Symptom                                                          | Root cause + fix                                                                                                                                                                                                  |
|----------------------|------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `signature_invalid`  | Every enrollment from a specific profile failing                 | Trust anchor mismatch — the Connector's signing cert was rotated and certctl wasn't reloaded. Re-extract the cert ([trust anchor extraction](#trust-anchor-extraction)), overwrite the file, send `SIGHUP`.        |
| `claim_mismatch`     | Some enrollments from one Intune SCEP profile failing            | The Intune SCEP profile's SAN config doesn't match what the device CSR actually has. Compare the `recent failures` table's claim row to the device's CSR; usually a SAN format mismatch (e.g. claim wants UPN, CSR has DNS). |
| `expired`            | All enrollments failing on a date boundary                       | Either clock skew between the Connector host and certctl (NTP both ends) OR the Connector's signing cert is past `NotAfter`. The certctl preflight catches an expired trust anchor at boot; check the Monitoring tab's expiry countdown. |
| `not_yet_valid`      | All enrollments failing                                          | Reverse clock skew (certctl's clock is BEHIND the Connector's). Sync via NTP.                                                                                                                                     |
| `wrong_audience`     | All enrollments from a profile failing                            | `INTUNE_AUDIENCE` doesn't match the URL the Connector is configured to call. Either fix `INTUNE_AUDIENCE` to match the operator URL, or unset it (defense-in-depth then disabled — the claim's exp + sig still gate). |
| `replay`             | Sporadic per-device failures, mostly during retries              | The device retried the SAME challenge after the first one failed. The replay cache TTL is `INTUNE_CHALLENGE_VALIDITY` (default 60m). Either widen the device's retry window (Intune-side) or shorten validity.    |
| `rate_limited`       | A specific device hitting `429`-equivalent failures              | The device exceeded `INTUNE_PER_DEVICE_RATE_LIMIT_24H` (default 3). If legitimate (post-wipe + recovery + first-cert all in 24h), bump the cap. If suspicious, this is the limiter doing its job — investigate the device. |
| `unknown_version`    | Sudden onset of failures across the entire fleet                  | Microsoft shipped a new Connector version with a `version` claim certctl doesn't understand. Open an issue on the certctl repo with the failing claim payload (anonymized); the parser dispatcher accepts new versions in ~30 LoC. |
| `malformed`          | Sporadic, low-volume                                              | Malformed challenge bytes — almost always a network proxy mangling the request body, or the Connector logging itself out mid-handshake. Capture a packet trace; the Connector should re-emit on the next device retry. |
| `compliance_failed`  | V3-Pro only                                                       | The pluggable compliance check returned non-compliant. The audit-log details carries the reason string from Microsoft Graph. V2 deployments never see this counter tick.                                          |

## Operational monitoring

The Phase 9 admin GUI surface (`/scep/intune`) shows:

- **Per-profile cards** — one card per SCEP profile, with the trust
  anchor expiry countdown badge:
  - `green` ≥ 30 days remaining
  - `amber` 7-30 days remaining (rotate soon)
  - `red` < 7 days remaining
  - `EXPIRED` past `NotAfter`
- **Live counters** — the per-status enrollment counts polled every
  30s. The order in the grid puts `success` first (vanity) and
  failure modes after.
- **Recent failures table** — the last 50 audit-log events with
  action `scep_pkcsreq_intune` or `scep_renewalreq_intune`, sorted
  by timestamp descending. Polled every 60s.
- **Trust anchor reload button** — confirms via modal then issues
  `POST /api/v1/admin/scep/intune/reload-trust` (the SIGHUP-equivalent).
  Bad reloads keep the OLD pool in place; the modal stays open with
  the underlying error so the operator can correct the file and retry.

Both admin endpoints (`GET /api/v1/admin/scep/intune/stats` and
`POST /api/v1/admin/scep/intune/reload-trust`) are M-008 admin-gated.
Non-admin Bearer callers get HTTP 403 + a clear message; the GUI
hides the page entirely for non-admin users (UX hint; server-side
enforcement is independent).

### Recommended alert thresholds

The counters are exposed in the GUI as snapshots; if you wrap them
in a Prometheus exporter (V3-Pro plug-in seam — V2 doesn't ship a
`/metrics` surface today), reasonable starting thresholds:

- `signature_invalid` rate > 0 for > 5 minutes → page on-call. The
  trust anchor is stale; the operator missed a SIGHUP after a
  Connector rotation.
- `claim_mismatch` rate > 0 sustained > 1 hour → notify (not page).
  An Intune SCEP profile is misconfigured; an admin needs to fix
  the SAN definition or the operator's CertificateProfile.
- `replay` rate climbing → notify. Either an aggressive retry policy
  on the device side OR active replay attempts. Cross-reference
  source IPs in the audit log.
- `rate_limited` for a single device > 1 per hour → notify. Either
  legitimate enrollment storm (post-wipe scenarios) or a compromised
  Connector signing key.
- Trust anchor `days_to_expiry` < 30 on any profile → notify; rotate
  the Connector's signing cert before the cliff.

## Limitations

This bundle is V2-free. The following capabilities are deferred to
V3-Pro:

- **Native Microsoft Graph integration.** certctl validates the
  Connector's signed challenge but doesn't call Microsoft's API
  directly — the Connector already did that. V3-Pro could ship a
  Graph client that pulls device-compliance state in addition to
  the challenge claim.
- **Conditional Access compliance gating.** The dispatcher exposes a
  nil-default `ComplianceCheck` hook. V3-Pro plugs in a Microsoft
  Graph compliance lookup before issuance; non-compliant devices
  fail with a typed `compliance_failed` failInfo.
- **Per-tenant trust anchors.** V2 has one trust anchor pool per
  SCEP profile; V3-Pro could support per-AAD-tenant anchor scoping
  for MSPs running shared certctl deployments across customers.
- **OCSP stapling at SCEP-response time.** The CertRep doesn't carry
  a stapled OCSP response today; certificate validators look up OCSP
  via the `id-pkix-ocsp` extension on the issued cert. V3-Pro could
  staple inline.
- **Auto-discovery of the Connector signing cert.** V2 requires the
  operator to extract the cert manually and configure the path.
  V3-Pro could pull from a Microsoft-published endpoint (with the
  appropriate trust constraints).

These deferrals are deliberate, not oversights. The V2 surface
covers every operationally-required path for a single-tenant
enterprise replacing NDES; V3-Pro adds the multi-tenant + native-API
features procurement teams sometimes ask for.

## Microsoft support statement

Microsoft documents the Intune Certificate Connector as
**RFC-8894-compliant** and supports its use against any RFC 8894
SCEP server. The relevant Microsoft Learn pages:

- [Intune Certificate Connector overview](https://learn.microsoft.com/en-us/mem/intune/protect/certificate-connector-overview) —
  documents the Connector's architecture and explicitly notes it
  speaks RFC-8894-compliant SCEP.
- [Use SCEP certificate profiles in Intune](https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure) —
  the operator-facing setup guide, with the SCEP server URL field
  the migration playbook above edits.
- [Validate setup of Intune Certificate Connector](https://learn.microsoft.com/en-us/mem/intune/protect/certificate-connector-install) —
  the install-validation checklist; useful when troubleshooting
  Connector-side failures vs. certctl-side failures.

certctl's role per Microsoft's framing: a third-party SCEP server
that the Connector posts to. Microsoft supports this topology; only
certctl's own RFC 8894 implementation is in scope for certctl
support. The end-to-end Connector → certctl → issuer flow is
exercised in `internal/api/handler/scep_intune_e2e_test.go` and
the golden-file fixtures in `internal/scep/intune/testdata/`.

## Related docs

- [`legacy-est-scep.md`](legacy-est-scep.md) — the per-profile SCEP
  setup guide + RFC 8894 reference + mTLS sibling route. Read this
  first if you're not already running certctl SCEP for non-Intune
  fleets.
- [`architecture.md`](architecture.md) — overall control-plane
  architecture; Security Model section calls out the Intune trust
  anchor as a sensitive operator-configured surface.
- [`features.md`](features.md) — every `CERTCTL_*` env var,
  including the per-profile `CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_*`
  family.
- [`tls.md`](tls.md) — TLS bootstrap for the certctl control plane;
  prerequisite for any production deploy.
