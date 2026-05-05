# SCEP Server (RFC 8894) — Protocol Reference

> Last reviewed: 2026-05-05

## What this is

certctl ships a native RFC 8894 SCEP server. This reference covers the
protocol surface: RA cert + key configuration, capability advertisement,
supported messageTypes, multi-profile dispatch, must-staple policy, mTLS
sibling routing, and Microsoft Intune dynamic-challenge dispatcher.

For Intune-specific deployment guidance (NDES replacement playbook,
Intune SCEP profile field mapping, troubleshooting matrix specific to
Intune deployments, Microsoft support statement), see
[`scep-intune.md`](scep-intune.md). For the legacy-client TLS 1.2
reverse-proxy runbook, see
[`docs/operator/legacy-clients-tls-1.2.md`](../../operator/legacy-clients-tls-1.2.md).

## How it works

Prior to the RFC 8894 native implementation, certctl's SCEP server parsed
`PKCS#7 SignedData` and treated the encapsulated content as a raw
`PKCS#10 CSR` (the file-internal "MVP" path). That worked for lightweight
MDM agents but failed against ChromeOS and most production MDM clients
which expect full RFC 8894 wire format: `SignedData` wrapping an
`EnvelopedData` encrypting the CSR to the RA cert's public key, with
`signerInfo` POPO over the auth-attrs.

The new RFC 8894 path runs FIRST; on any parse failure it falls through
to the legacy MVP raw-CSR path so existing operators see no behavior
change for their lightweight clients.

## Required: RA cert + key

The RFC 8894 path requires a Registration Authority cert + key pair.
Clients encrypt their CSR to the RA cert's public key (RFC 8894 §3.2.2);
the certctl server uses the RA key to decrypt and to sign the outbound
CertRep PKIMessage signerInfo (RFC 8894 §3.3.2).

| Env var | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_SCEP_RA_CERT_PATH` | (none) | Path to PEM-encoded RA certificate. **Required when `CERTCTL_SCEP_ENABLED=true`.** |
| `CERTCTL_SCEP_RA_KEY_PATH` | (none) | Path to PEM-encoded RA private key matching `CERTCTL_SCEP_RA_CERT_PATH`. File MUST be mode `0600` (preflight refuses world-readable). |

Generate the RA pair (any RSA-2048+ or ECDSA-P256+ pair signed by your
root or sub-CA works):

```bash
# RSA-2048 RA pair, valid 1 year, signed by your root.
openssl req -new -newkey rsa:2048 -nodes -keyout ra.key -out ra.csr \
  -subj "/CN=corp-ca-RA"
openssl x509 -req -in ra.csr -days 365 \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -extfile <(printf "extendedKeyUsage=emailProtection,1.3.6.1.5.5.7.3.4") \
  -out ra.crt

chmod 0600 ra.key       # required — preflight rejects world-readable keys
chmod 0644 ra.crt
mv ra.key ra.crt /etc/certctl/scep/

export CERTCTL_SCEP_ENABLED=true
export CERTCTL_SCEP_RA_CERT_PATH=/etc/certctl/scep/ra.crt
export CERTCTL_SCEP_RA_KEY_PATH=/etc/certctl/scep/ra.key
export CERTCTL_SCEP_CHALLENGE_PASSWORD=$(openssl rand -hex 32)
```

The startup preflight in `cmd/server/main.go::preflightSCEPRACertKey`
validates: file existence, key file mode 0600, cert/key match, cert
non-expired, RSA-or-ECDSA public-key algorithm. Failures `os.Exit(1)`
with a structured log line identifying the offending profile.

## Capability advertisement (`GetCACaps`)

```
POSTPKIOperation
SHA-256
SHA-512
AES
SCEPStandard
Renewal
```

ChromeOS specifically looks for `POSTPKIOperation` (non-base64 POST),
`AES` (the now-implemented CBC content encryption), `SCEPStandard` (RFC
8894 conformance), and `Renewal` (RenewalReq messageType-17 support).
Older Cisco IOS clients also accept `SHA-256` and `SHA-512` per RFC 8894
§3.5.2.

## Supported messageTypes

| Type | RFC 8894 § | Behavior |
| --- | --- | --- |
| `PKCSReq` (19) | §3.3.1 | Initial enrollment. Signer cert is the device's transient self-signed key. |
| `RenewalReq` (17) | §3.3.1.2 | Re-enrollment. Signer cert MUST be a previously-issued cert from this issuer; service-side `verifyRenewalSignerCertChain` enforces. |
| `GetCertInitial` (20) | §3.3.3 | Polling for pending requests. v1 returns `FAILURE+badCertID` because deferred-issuance isn't supported (every PKCSReq either succeeds or fails synchronously). |
| `CertRep` (3) | §3.3.2 | Server response — never inbound. |

## MVP backward-compatibility path

Lightweight clients that send a stripped `SignedData` containing a raw
CSR (no `EnvelopedData` wrapper, no `signerInfo` POPO) keep working: the
handler tries the RFC 8894 path FIRST; on any parse failure it falls
through to the legacy `extractCSRFromPKCS7` path. The legacy path uses
the CSR's `challengePassword` attribute the same way as the RFC 8894
path. Operators with existing lightweight-client deploys see zero
behavior change.

## Multi-profile dispatch (`/scep/<pathID>`)

Real enterprise deploys run multiple SCEP endpoints from one certctl
instance — corp-laptop CA, IoT CA, server CA — each with its own
issuer + RA pair + challenge password. Configure via the indexed env-var
form: set `CERTCTL_SCEP_PROFILES=corp,iot,server` (a comma-separated list
of profile names), then for each name supply the per-profile env-vars
prefixed with `CERTCTL_SCEP_PROFILE_<NAME>_` followed by the suffix
keys `_ISSUER_ID`, `_PROFILE_ID`, `_CHALLENGE_PASSWORD`, `_RA_CERT_PATH`,
`_RA_KEY_PATH`. The `<NAME>` token resolves to the upper-cased profile
name from the list. Each profile is independently validated at startup;
per-profile failures log the offending PathID.

The router exposes `/scep/corp`, `/scep/iot`, `/scep/server`. The legacy
`/scep` root remains for the single-profile flat-env-var case (when
`CERTCTL_SCEP_PROFILES` is unset). Per-profile preflight validates each
RA pair independently; failures log the offending PathID.

## ChromeOS Admin Console pointer

In Google Admin Console → Devices → Networks → Certificates, register
certctl's `/scep[/<pathID>]` URL as the SCEP server. Enter the challenge
password from `CERTCTL_SCEP_CHALLENGE_PASSWORD` (or per-profile
`CERTCTL_SCEP_PROFILE_<NAME>_CHALLENGE_PASSWORD`). ChromeOS pulls
`GetCACert` first to retrieve the RA cert, then enrolls via
PKIOperation.

## RA cert rotation

The RA cert is loaded once at startup and persisted in the handler's
struct field; rotation requires a server restart (mirrors the
`CERTCTL_SERVER_TLS_CERT_PATH` precedent in `cmd/server/tls.go`). The
recommended cadence is annual rotation with a 30-day overlap during
which both old + new RA certs are listed in `GetCACert`'s response (set
the cert chain accordingly in your sub-CA hierarchy).

## Must-staple per-profile policy (RFC 7633)

When a `CertificateProfile` has `MustStaple = true`, the local issuer
adds the `id-pe-tlsfeature` extension (OID `1.3.6.1.5.5.7.1.24`,
non-critical, value `SEQUENCE OF INTEGER {5}`) to every issued cert.
Browsers + modern TLS libraries that see this extension fail-closed on
missing OCSP stapling responses — defense against revocation-bypass via
OCSP blackholing.

**Default policy:** `false`. Operators opt in once they've confirmed the
TLS reverse proxy / load balancer staples OCSP responses. NGINX,
HAProxy, Envoy all support stapling but it requires explicit config —
turning must-staple on without verifying the TLS path will hard-fail
browsers.

Recommended for: Intune-deployed device certs (modern TLS clients);
SCEP profiles serving general / legacy clients (ChromeOS, IoT) should
stay `false` until the TLS path is verified.

## mTLS sibling route (Phase 6.5, opt-in)

SCEP is documented as application-layer-auth — the challenge password
is the authentication boundary per RFC 8894 §3.2. But enterprise
procurement teams routinely reject "shared password authentication" as
a checkbox-fail regardless of how strong the password is. The clean
answer: a **sibling** route at `/scep-mtls/<pathID>` that requires
client-cert auth at the handler layer AND ALSO accepts the challenge
password (defense in depth, not replacement). Devices present a
bootstrap cert from a trusted CA (e.g. a manufacturing-time cert),
then SCEP-enroll for their long-lived cert. Same model Apple's MDM and
Cisco's BRSKI use.

**Opt in per profile** by setting two env vars:

```
CERTCTL_SCEP_PROFILE_<NAME>_MTLS_ENABLED=true
CERTCTL_SCEP_PROFILE_<NAME>_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH=/etc/certctl/scep/<name>-bootstrap-cas.pem
```

The trust bundle is a PEM file containing the bootstrap-CA certs the
operator allows to enroll. Operators with multiple bootstrap CAs
concatenate them. The startup preflight
(`cmd/server/main.go::preflightSCEPMTLSTrustBundle`) validates: file
exists, parses as PEM, contains ≥1 cert, none expired. Failures
`os.Exit(1)` with a structured log identifying the offending PathID.

**TLS server config:** when at least one profile opts into mTLS, the
HTTPS listener gets the union of every enabled profile's trust bundle
as its `ClientCAs` pool, plus `ClientAuth: VerifyClientCertIfGiven` —
the listener requests a client cert during the handshake, verifies it
against the union pool if presented, and lets the handler decide
whether to require it. This means the SAME listener serves both
`/scep[/<pathID>]` (no client cert required) and `/scep-mtls/<pathID>`
(cert required). The standard route stays untouched for clients that
can't present a cert.

**Handler-layer per-profile gate:** the TLS-layer check uses the union
pool, so a cert that chains to profile A's bundle would pass the TLS
handshake even when targeting profile B. The handler-layer gate
(`HandleSCEPMTLS`) re-verifies the inbound client cert against ONLY
THIS profile's pool — preventing cross-profile bleed-through.

**Auth chain on the mTLS sibling route:**

1. TLS handshake: client cert verified against the union pool
   (if presented; absent = standard SCEP path applies but handler
   rejects with 401).
2. Handler-layer per-profile re-verification: cert must chain to
   THIS profile's trust bundle. Mismatch = 401.
3. Standard SCEP enrollment: `HandleSCEP` runs as on the standard
   route — including the challenge-password gate at the service layer.

A stolen device cert without the matching challenge password gets
rejected (and vice versa). Both layers are independently required.

**Operator workflow** for migrating from challenge-password-only to
challenge+mTLS:

1. Generate a bootstrap CA + issue a bootstrap cert per device (out
   of band — typically manufacturing-time, MDM-pushed, or a separate
   PKI flow).
2. Distribute the trust bundle to certctl as the
   `_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH`.
3. Set `_MTLS_ENABLED=true` for the profile, restart certctl.
4. Devices now have TWO valid enrollment URLs:
   `/scep/<pathID>` (challenge-password-only, legacy) and
   `/scep-mtls/<pathID>` (cert + challenge, new).
5. Roll out config to fleet that switches devices to the new URL.
6. Once the fleet has migrated, remove `_CHALLENGE_PASSWORD` from the
   profile (Validate() will keep the gate when MTLSEnabled=true so
   the password requirement doesn't go away — the password is still
   the application-layer auth boundary).

## Microsoft Intune dynamic-challenge dispatcher (Phase 8, opt-in)

When SCEP sits behind the Microsoft Intune Certificate Connector, devices
present an Intune-issued signed challenge (a JWT-like blob over a JSON
claim payload) instead of the static `_CHALLENGE_PASSWORD`. Phase 8 wires
a per-profile dispatcher that validates these signed challenges against
the Connector's signing-cert trust anchor and binds the asserted device
identity to the inbound CSR. Static challenge passwords still work as a
fallback so heterogeneous fleets (some Intune-enrolled, some not) keep
working.

**Per-profile env vars** (all default to off; legacy/static-only profiles
need no changes):

```
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_ENABLED=true
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CONNECTOR_CERT_PATH=/etc/certctl/intune-corp.pem
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_AUDIENCE=https://certctl.example.com/scep/corp
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CHALLENGE_VALIDITY=60m
CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_PER_DEVICE_RATE_LIMIT_24H=3
```

**Trust-anchor extraction:** the operator extracts the Connector
installation's signing cert (from the Connector's certificate store on
the Windows host running the Connector — Microsoft does not publish a
direct download) and writes a PEM bundle to the configured path.
Multiple Connectors in HA = concatenate their certs.

**Trust-anchor reload:** the holder re-reads the bundle on `SIGHUP` (the
same signal that rotates the server's TLS cert). A bad reload (parse
error, expired cert) keeps the OLD pool in place — operators get a
recoverable failure window rather than a service-down. Rotate the file
on disk, then `kill -HUP <certctl-pid>` to apply with no restart.

**Replay protection:** in-memory cache of seen challenge nonces with TTL
= `_CHALLENGE_VALIDITY` (default 60m). Sized for 100k entries, which
covers a ~25 RPS Intune fleet's steady-state. The same challenge
submitted twice within the TTL is rejected with `ErrChallengeReplay`.

**Per-device rate limit:** sliding-window-log limiter keyed by
`(claim.Subject, claim.Issuer)`. Default 3 enrollments per 24h covers
legitimate first-cert + recovery + post-wipe re-enrollment but blocks a
compromised Connector signing key from issuing many DIFFERENT valid
challenges for the same device. Set the var to `0` to disable.

**Audit + observability:** Intune enrollments emit
`audit_event.action="scep_pkcsreq_intune"` (or
`"scep_renewalreq_intune"`) so operators can grep the audit log to count
Intune-vs-static enrollments. Per-failure-mode reason flows into the log
line; the metric label set is `success / signature_invalid / expired /
not_yet_valid / wrong_audience / replay / rate_limited / claim_mismatch
/ unknown_version / malformed`.

**Compliance-state hook (V3-Pro plug-in seam):** a nil-default
`ComplianceCheck` field on `SCEPService` lets a future Pro module plug
in a Microsoft Graph compliance API call between challenge validation
and certificate issuance. V2 ships the seam (one struct field + one
setter + one nil-guarded call site) so Pro is plug-in code, not a
dispatcher refactor.

**Mixed-mode (recommended):** keep `_CHALLENGE_PASSWORD` set even when
Intune is enabled. Devices that don't go through Intune (manual
enrollment, on-prem MDM bridges) continue to enroll via the static path;
the dispatcher routes Intune-shaped challenges (length > 200 + exactly
two dots) to the validator and falls through to the static compare
otherwise.

## Operational notes

- **Audit:** every enrollment emits an `audit_event` row with action
  `scep_pkcsreq` (initial) or `scep_renewalreq` (renewal); operators
  can grep the audit log to distinguish. Intune-dispatched enrollments
  use `scep_pkcsreq_intune` and `scep_renewalreq_intune` respectively.
- **Body-size cap:** `http.MaxBytesReader` middleware caps request
  bodies at `CERTCTL_MAX_BODY_SIZE` (default 1MB); SCEP PKIMessages are
  typically <50KB so the default cap is generous.
- **HTTPS-only:** the SCEP endpoint inherits the TLS-1.3-pinned control
  plane; there is no plaintext fallback. Legacy clients that only speak
  TLS 1.2 use the reverse-proxy bridge documented at
  [`docs/operator/legacy-clients-tls-1.2.md`](../../operator/legacy-clients-tls-1.2.md).
- **For Microsoft Intune deployments,** see [`scep-intune.md`](scep-intune.md) —
  architecture, NDES-replacement migration playbook, Intune SCEP profile
  field mapping, trust-anchor extraction recipe, troubleshooting matrix,
  operational monitoring, V3-Pro deferrals, and the Microsoft support
  statement (with Microsoft Learn URLs procurement teams ask for).
- **For per-profile SCEP observability** (RA cert expiry countdown,
  mTLS sibling-route status, challenge-password-set indicator, and
  the full SCEP audit log filter), the admin GUI page lives at `/scep`
  with three tabs: **Profiles** (default), **Intune Monitoring**,
  **Recent Activity**. See the operational-monitoring section in
  [`scep-intune.md`](scep-intune.md) for the Intune-specific tab.

## Related docs

- [`scep-intune.md`](scep-intune.md) — Microsoft Intune deployment guide
- [`est.md`](est.md) — EST RFC 7030 server reference
- [`docs/operator/legacy-clients-tls-1.2.md`](../../operator/legacy-clients-tls-1.2.md) — TLS 1.2 reverse-proxy runbook for legacy SCEP clients
- [`docs/reference/architecture.md`](../architecture.md) — system design including SCEP server placement
