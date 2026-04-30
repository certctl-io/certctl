# EST (RFC 7030) — Operator Guide

> **Status (this document):** EST RFC 7030 hardening master bundle Phases
> 1–11 shipped on `master`; this guide is the Phase-12 deliverable
> against the bundle. Every behavior described here is exercised by the
> tests at `internal/api/handler/est*_test.go`,
> `internal/service/est*_test.go`, and (for the libest interop layer)
> `deploy/test/est_e2e_test.go` under `//go:build integration`. The
> bundle is **V2-free**; per-tenant CA isolation, Conditional-Access
> compliance gating, and EST cert-bound usage analytics are documented
> as V3-Pro deferrals in [V3-Pro deferrals](#v3-pro-deferrals).

## Contents

1. [Concepts](#concepts)
2. [Quick start](#quick-start)
3. [Multi-profile dispatch](#multi-profile-dispatch)
4. [Authentication modes](#authentication-modes)
5. [RFC 9266 channel binding](#rfc-9266-channel-binding)
6. [WiFi / 802.1X recipe (FreeRADIUS)](#wifi--8021x-recipe-freeradius)
7. [IoT bootstrap recipe](#iot-bootstrap-recipe)
8. [`serverkeygen` for resource-constrained devices](#serverkeygen-for-resource-constrained-devices)
9. [HSM-backed CA signing for EST](#hsm-backed-ca-signing-for-est)
10. [Operator GUI (EST Admin tabs)](#operator-gui-est-admin-tabs)
11. [CLI + MCP tools](#cli--mcp-tools)
12. [Renewal: device-driven model](#renewal-device-driven-model)
13. [Troubleshooting matrix](#troubleshooting-matrix)
14. [TLS 1.2 reverse-proxy runbook](#tls-12-reverse-proxy-runbook)
15. [Threat model](#threat-model)
16. [V3-Pro deferrals](#v3-pro-deferrals)
17. [Appendix A: libest reference client](#appendix-a-libest-reference-client)
18. [Appendix B: RFC 7030 wire-format quirks](#appendix-b-rfc-7030-wire-format-quirks)
19. [Related docs](#related-docs)

## Concepts

EST (RFC 7030) is the IETF-standardized successor to SCEP for device
enrollment over HTTPS. certctl ships a native EST server that handles
all six RFC 7030 endpoints — `cacerts`, `simpleenroll`,
`simplereenroll`, `csrattrs`, `serverkeygen`, and (proxy-pass)
`fullcmc` — out of a single binary, with per-profile dispatch so a
single deploy can serve multiple device fleets from the same control
plane.

**EST is a handler-level protocol, not a connector.** The
`ESTHandler` parses the wire format, enforces auth, and delegates
issuance to whichever `IssuerConnector` the profile binds. EST does
not replace your CA — it sits in front of the local CA, Vault PKI,
EJBCA, ADCS, step-ca, or anything else certctl already knows how to
issue against. Devices submit a CSR; certctl validates, gates, signs,
and returns a PKCS#7 certs-only response.

**Two enrollment models, one server.**

- **Host enrollment** — a long-lived device or laptop boots, generates
  its own keypair locally, and enrolls via `simpleenroll` (initial)
  then `simplereenroll` (renewal) over the device's TLS-pinned
  channel. Private keys never leave the device.
- **User enrollment** — a network supplicant (corporate WiFi, VPN
  client) drives `simpleenroll` against certctl on behalf of the user
  identity. The CSR carries the user UPN as a SAN; the FreeRADIUS or
  VPN policy gates session establishment on cert validity.

**Profile-driven policy.** Every EST profile carries its own:

- Issuer binding (`CERTCTL_EST_PROFILE_<NAME>_ISSUER_ID`)
- Optional `CertificateProfile` (`_PROFILE_ID`) that constrains
  allowed key algorithms, key sizes, EKUs, SANs, max TTL, and
  must-staple
- Auth mode mix: mTLS only, HTTP Basic only, both, or none (for
  back-compat with anonymous deploys — strongly discouraged)
- Optional RFC 9266 `tls-exporter` channel binding
- Optional per-(CN, sourceIP) sliding-window rate limit
- Optional server-side keygen

The per-profile family is documented exhaustively in
[`features.md`](features.md).

**Multi-profile dispatch.** `CERTCTL_EST_PROFILES=corp,iot,wifi`
publishes three independent endpoint groups under
`/.well-known/est/<pathID>/`. Each profile's auth, trust anchor, and
issuer binding is isolated; a compromise of one profile's enrollment
password does not affect any other profile.

## Quick start

The five-minute single-profile setup runs EST anonymously over
HTTPS-only. **Use this only on a private network during evaluation;**
production deploys MUST set an auth mode (see
[Authentication modes](#authentication-modes)).

1. Have certctl running with TLS configured per [`tls.md`](tls.md).
   The control plane listens on `:8443`; EST shares the same listener
   under `/.well-known/est/`.
2. Set the legacy single-profile env vars in your compose file or
   Helm values:

   ```
   CERTCTL_EST_ENABLED=true
   CERTCTL_EST_ISSUER_ID=iss-local
   ```

3. Restart certctl. The startup log line `EST server enabled` should
   surface; the routes `/.well-known/est/{cacerts,simpleenroll,simplereenroll,csrattrs}`
   are now live.
4. Ground-truth check from a client host:

   ```bash
   curl -sS --cacert /path/to/ca.crt \
        https://certctl.example.com:8443/.well-known/est/cacerts \
     | base64 -d | openssl pkcs7 -inform DER -print_certs -noout
   ```

   You should see your CA cert subject and `NotAfter`. This is the
   `/cacerts` endpoint serving the PKCS#7 SignedData certs-only
   response per RFC 7030 §4.1.

5. Generate a CSR and enroll:

   ```bash
   openssl ecparam -name prime256v1 -genkey -noout -out device.key
   openssl req -new -key device.key -subj "/CN=device-001.example.com" -out device.csr
   curl -sS --cacert /path/to/ca.crt \
        -H "Content-Type: application/pkcs10" \
        --data-binary @<(openssl req -in device.csr -outform DER | base64 -w0) \
        https://certctl.example.com:8443/.well-known/est/simpleenroll \
     | base64 -d | openssl pkcs7 -inform DER -print_certs > device.crt
   ```

   The response is a PKCS#7 certs-only blob; the issued cert lands in
   `device.crt`.

If the curl fails with a TLS error, walk through [`tls.md`](tls.md);
the EST handler relies on the same listener as the REST API and
SHARES NO TRUST POLICY with the legacy plaintext :8080 of pre-v2.2
deploys (which was removed when the HTTPS-only policy landed).

## Multi-profile dispatch

A single certctl binary publishes one EST endpoint group per name in
`CERTCTL_EST_PROFILES`. Set the comma-separated list, then a matching
set of `CERTCTL_EST_PROFILE_<NAME>_*` env vars per profile:

```
CERTCTL_EST_ENABLED=true
CERTCTL_EST_PROFILES=corp,iot,wifi

# per-profile config — `<NAME>` placeholder gets replaced by the
# uppercased name from the list (so "corp" → CORP, "iot" → IOT,
# "wifi" → WIFI). The URL path uses the lowercased form.
CERTCTL_EST_PROFILE_<NAME>_ISSUER_ID=iss-local
CERTCTL_EST_PROFILE_<NAME>_PROFILE_ID=cp-corp-laptops
CERTCTL_EST_PROFILE_<NAME>_ENROLLMENT_PASSWORD=<random>
CERTCTL_EST_PROFILE_<NAME>_ALLOWED_AUTH_MODES=basic
```

This publishes:

- `/.well-known/est/corp/{cacerts,simpleenroll,simplereenroll,csrattrs,serverkeygen}`
- `/.well-known/est/iot/...`
- `/.well-known/est/wifi/...`

Each profile is independently validated at startup (see
`internal/config/config.go::Validate`). Per-profile failures log the
offending PathID and refuse the boot. The legacy single-profile
shape (`CERTCTL_EST_ENABLED` + `CERTCTL_EST_ISSUER_ID` without
`CERTCTL_EST_PROFILES`) continues to work — the back-compat shim in
`loadESTProfilesFromEnv` synthesises a single profile bound to the
empty PathID, which the router serves at `/.well-known/est/` (no
path component).

PathID rules (enforced at boot):

- Lowercased ASCII `[a-z0-9-]+` only, no leading/trailing hyphen.
- Distinct PathIDs per profile (no duplicates).
- Reserved name `est` rejected (would collide with the legacy root).

Mirrors the SCEP `CERTCTL_SCEP_PROFILES` family from the SCEP RFC
8894 master bundle — see [`legacy-est-scep.md`](legacy-est-scep.md)
for the SCEP equivalent.

## Authentication modes

certctl supports three EST authentication topologies per profile,
mixed and matched via `CERTCTL_EST_PROFILE_<NAME>_ALLOWED_AUTH_MODES`:

| Mode    | Endpoint                                  | When to use                                                                                                                                       |
|---------|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `mtls`  | `/.well-known/est-mtls/<pathID>/...`      | The device already has a bootstrap cert (factory-provisioned, previous-cert renewal, or out-of-band onboarding). Enterprise procurement teams almost always require this for production fleets — shared-password auth is a checkbox-fail regardless of password strength. |
| `basic` | `/.well-known/est/<pathID>/...`           | First-cert bootstrap when no prior cert exists. The `_ENROLLMENT_PASSWORD` is a per-profile shared secret; constant-time comparison via `crypto/subtle.ConstantTimeCompare`. Pair with the source-IP failed-auth rate limit (see below). |
| both    | both routes published                     | Migration window: existing devices renew via mTLS, new devices bootstrap via Basic. Same profile config, just both routes registered.            |
| (empty) | `/.well-known/est/<pathID>/...`           | Anonymous; no auth required at the EST layer. Back-compat for pre-Phase-1 deploys. Hardened-deployment best practice is to set this explicitly to `basic` or `mtls` — a future bundle may flip the default. |

Per-profile cross-check enforced at boot:

- `mtls` in the list requires `_MTLS_ENABLED=true` AND
  `_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH` non-empty.
- `basic` in the list requires `_ENROLLMENT_PASSWORD` non-empty.
- Unknown auth modes refused at boot with the offending token in the
  error message.

**Source-IP failed-auth rate limit.** When `_ENROLLMENT_PASSWORD` is
set and the Basic-auth gate trips, the handler increments a sliding-
window counter keyed on the source IP. After 10 consecutive failures
in an hour, the source is locked out (HTTP 429-equivalent failure
code) for the rest of the window. The limiter is process-local
(50k-IP cap, sliding 1h window — defaults; tunable in a follow-up).
This is independent of the per-(CN, sourceIP) per-principal limiter
discussed under [Renewal](#renewal-device-driven-model).

## RFC 9266 channel binding

When `CERTCTL_EST_PROFILE_<NAME>_CHANNEL_BINDING_REQUIRED=true`, the
EST handler enforces RFC 9266 `tls-exporter` channel binding. The
client must include an `id-aa-channelBindings` attribute in the CSR
whose value matches the server's
`r.TLS.ConnectionState().ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)`
output, computed independently at request time.

What this defends against: an attacker that bridges two TLS
connections (one client → attacker, another attacker → certctl) and
forwards the device's CSR through the attacker's TLS session. Without
channel binding, certctl sees a valid CSR submitted over a TLS
session authenticated by the attacker's cert; with channel binding,
the CSR's binding bytes only match if the CSR was signed against
THIS TLS session's exporter material.

Failure mode mapping:

| Server-side error                  | HTTP status | Meaning                                                                                                              |
|-------------------------------------|-------------|----------------------------------------------------------------------------------------------------------------------|
| `ErrChannelBindingMissing`         | 400         | `_CHANNEL_BINDING_REQUIRED=true` but the CSR's attribute is absent. Bad client config (or a non-RFC-9266 EST client). |
| `ErrChannelBindingMismatch`        | 409         | Attribute present but doesn't match the live exporter — MITM signal. Treat as a security event, log the source IP.   |
| `ErrChannelBindingNotTLS13`        | 426         | Client connected over TLS 1.2 — `tls-exporter` requires TLS 1.3. Upgrade client OR rely on the TLS-1.2 reverse-proxy runbook. |

Cross-check at boot: setting `_CHANNEL_BINDING_REQUIRED=true` on a
profile with `_MTLS_ENABLED=false` is refused — channel binding is
meaningful only when mTLS is in use (otherwise the binding has no
client identity to bind to).

**libest support.** Cisco libest v3.0+ supports the RFC 9266
`--tls-exporter` flag. Older builds (commonly distros' packaged
versions through 2024) do not; per-profile opt-out via leaving the
env var `false` is the migration path. The libest sidecar in
`deploy/test/libest/Dockerfile` builds v3.2.0-2 from source and
includes the flag.

## WiFi / 802.1X recipe (FreeRADIUS)

This recipe stands up an EAP-TLS-authenticated corporate WiFi network
where certctl issues every device certificate via EST. End-to-end
flow:

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│ Laptop /    │ EAP  │ WiFi access      │ Radius│ FreeRADIUS  │
│ supplicant  │─────▶│ point (NAS)      │──────▶│ (validate   │
│ (wpa_       │      │                  │      │  cert chain)│
│  supplicant │      └──────────────────┘      └──────┬──────┘
│  / iwd /    │                                       │
│  Apple WiFi)│                                       │ trusts
└──────┬──────┘                                       ▼
       │ EST (one-time, then renewal)         ┌─────────────┐
       │ /simpleenroll, /simplereenroll       │ certctl CA  │
       └────────────────────────────────────▶│ (EST profile│
                                              │  "wifi")    │
                                              └─────────────┘
```

### certctl-side: EST profile config for 802.1X

```
CERTCTL_EST_ENABLED=true
CERTCTL_EST_PROFILES=wifi
CERTCTL_EST_PROFILE_<NAME>_ISSUER_ID=iss-local
CERTCTL_EST_PROFILE_<NAME>_PROFILE_ID=cp-wifi-eap-tls
CERTCTL_EST_PROFILE_<NAME>_MTLS_ENABLED=true
CERTCTL_EST_PROFILE_<NAME>_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH=/etc/certctl/wifi-bootstrap-ca.pem
CERTCTL_EST_PROFILE_<NAME>_ALLOWED_AUTH_MODES=mtls
CERTCTL_EST_PROFILE_<NAME>_CHANNEL_BINDING_REQUIRED=true
CERTCTL_EST_PROFILE_<NAME>_RATE_LIMIT_PER_PRINCIPAL_24H=3
```

The matching `CertificateProfile` (`cp-wifi-eap-tls`) configured via
the API or GUI:

- `AllowedKeyAlgorithms`: ECDSA P-256 (covers Apple, Android, modern
  laptop supplicants) plus optional RSA 2048+ for legacy clients.
- `AllowedEKUs`: `clientAuth` only (`1.3.6.1.5.5.7.3.2`). Drops
  `serverAuth` so a device cert can't be reused as a TLS server cert.
  EAP-TLS requires `clientAuth`; FreeRADIUS will reject certs without
  it when `eap_chain_check_eku` is on.
- `RequiredCSRAttributes`: `["deviceSerialNumber"]` so the device's
  serial appears in the issued cert (operators correlate WiFi grants
  back to inventory).
- `MaxTTLSeconds`: 31536000 (1 year). Long enough for laptop fleets
  that don't renew daily; short enough to limit the cert's blast
  radius on key compromise.

### Device-side: drive `simpleenroll` from the supplicant

For Linux/embedded laptops:

```bash
# Bootstrap once (factory bootstrap cert presented over mTLS):
openssl ecparam -name prime256v1 -genkey -noout -out /etc/wifi/eap.key
openssl req -new -key /etc/wifi/eap.key \
    -subj "/CN=laptop-001/serialNumber=ABC123" \
    -out /etc/wifi/eap.csr
curl -sS --cacert /etc/certctl/ca.crt \
    --cert /etc/wifi/bootstrap.crt \
    --key  /etc/wifi/bootstrap.key \
    -H "Content-Type: application/pkcs10" \
    --data-binary @<(openssl req -in /etc/wifi/eap.csr -outform DER | base64 -w0) \
    https://certctl.example.com:8443/.well-known/est-mtls/wifi/simpleenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs > /etc/wifi/eap.crt

# Renewal cycle (cron, 10 days before NotAfter):
curl -sS --cacert /etc/certctl/ca.crt \
    --cert /etc/wifi/eap.crt \
    --key  /etc/wifi/eap.key \
    -H "Content-Type: application/pkcs10" \
    --data-binary @<(openssl req -new -key /etc/wifi/eap.key -subj "/CN=laptop-001" -outform DER | base64 -w0) \
    https://certctl.example.com:8443/.well-known/est-mtls/wifi/simplereenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs > /etc/wifi/eap.crt.new && \
  mv /etc/wifi/eap.crt.new /etc/wifi/eap.crt
```

For Apple-managed devices the equivalent flow is wrapped by an MDM
profile that drives EST. For ChromeOS the Admin Console SCEP profile
remains the easier path until Google's EST support stabilises (track
the [SCEP+ChromeOS guide](legacy-est-scep.md#scep-rfc-8894-native-implementation-post-2026-04-29)).

### FreeRADIUS-side: EAP-TLS configuration

In `mods-available/eap`:

```
eap {
    default_eap_type = tls
    tls-config tls-common {
        # The CA bundle that signed certctl's EST-issued device certs.
        # Save the certctl issuer's CA chain to this path; the
        # FreeRADIUS daemon reloads on HUP.
        ca_file = /etc/freeradius/certs/certctl-ca.pem

        # Server cert presented to the supplicant for tunnel TLS.
        # Separate cert chain — FreeRADIUS's own cert, NOT a certctl-
        # issued client cert.
        certificate_file = /etc/freeradius/certs/freeradius-server.pem
        private_key_file = /etc/freeradius/certs/freeradius-server.key

        # Validate the supplicant's cert chain to certctl-ca.pem.
        check_cert_issuer = "/CN=certctl-corp-ca"

        # Pin the supplicant's EKU to clientAuth.
        check_cert_cn = "%{User-Name}"
    }
    tls {
        tls = tls-common
    }
}
```

The matching `sites-available/default` authorize block invokes
`eap` and rejects on cert-chain failure. CRL/OCSP validation against
certctl's CRL endpoint (`/.well-known/pki/crls/<issuerID>.crl`) is
configured under `tls-common.crl_dir` — see [`crl-ocsp.md`](crl-ocsp.md)
for the certctl-side CRL distribution endpoint and refresh cadence.

### End-to-end flow

1. Laptop boots, supplicant starts EAP-TLS handshake against the AP.
2. AP forwards the EAP frames to FreeRADIUS over RADIUS.
3. FreeRADIUS validates the supplicant cert chain against
   `certctl-ca.pem`, checks revocation against the certctl CRL, and
   pins the EKU to `clientAuth`.
4. On valid cert, FreeRADIUS returns Access-Accept; the AP grants
   network access.
5. ~10 days before the cert's `NotAfter`, the device's renewal cron
   hits `simplereenroll` over the EXISTING mTLS-authenticated session
   — no operator interaction.

What can go wrong (operator playbook):

| Symptom                                | Diagnostic                                                       | Fix                                                                                            |
|----------------------------------------|------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| Supplicant rejected at TLS handshake   | `tcpdump` on AP shows TLS-1.2 hello                              | Update supplicant to TLS 1.3 OR ensure FreeRADIUS's cert is signed under a chain it trusts.   |
| FreeRADIUS rejects with "expired CRL"  | `freeradius -X` log surfaces stale CRL                           | certctl regenerates per-issuer CRLs hourly (see [`crl-ocsp.md`](crl-ocsp.md)); tighten `crl_dir` reload cadence in FreeRADIUS. |
| Renewal fails with HTTP 429            | certctl audit log shows `est_rate_limited` for this device       | Per-(CN, sourceIP) limit tripped; either widen `_RATE_LIMIT_PER_PRINCIPAL_24H` or investigate why the device is renewing >3x/24h. |
| Renewal fails with HTTP 401            | certctl audit log shows `est_auth_failed_mtls`                   | Bootstrap cert chain doesn't trace to `_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH`. Re-issue or rotate.  |
| Sustained `est_auth_failed_basic` from one IP | certctl audit log + IP reverse lookup                       | Likely brute-force; the source-IP limiter will lock the IP after 10 fails/hr. Block at firewall.|

## IoT bootstrap recipe

Long-running devices in the field — sensors, gateways, kiosks —
typically follow this lifecycle:

1. **Factory provisioning** — bake one of:
   - A **bootstrap enrollment password** into the device firmware
     (per-fleet shared secret; pair with the source-IP rate limit)
   - A **factory-installed bootstrap cert** signed by the operator's
     factory CA, suitable for mTLS on first enroll
2. **First boot** — device generates an ECDSA P-256 keypair locally,
   builds a CSR with its serial in `deviceSerialNumber`, and POSTs to
   `/.well-known/est/<pathID>/simpleenroll` (with HTTP Basic) or
   `/.well-known/est-mtls/<pathID>/simpleenroll` (with the bootstrap
   cert). On success, the device persists the issued cert and the
   bootstrap material can be discarded.
3. **Steady state** — device drives `simplereenroll` over the
   issued cert's mTLS session ~10–25% before `NotAfter`. The
   re-enrollment uses the issued cert as the client cert; no shared
   secrets in the renewal path.
4. **Compromise / decommission** — operator hits the bulk-revoke
   endpoint:

   ```bash
   curl -sS -X POST \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $CERTCTL_API_KEY" \
       --cacert /path/to/ca.crt \
       https://certctl.example.com:8443/api/v1/est/certificates/bulk-revoke \
       -d '{"reason":"keyCompromise","profile_id":"cp-iot-sensors"}'
   ```

   The endpoint is M-008 admin-gated; non-admin Bearer callers receive
   HTTP 403. Source is auto-pinned to `EST` server-side, so the
   operation only revokes EST-issued certs even if the criteria match
   non-EST sources too. The CRL/OCSP responder picks up the revocations
   on the next refresh cycle (`CERTCTL_CRL_GENERATION_INTERVAL`,
   default 1h) — see [`crl-ocsp.md`](crl-ocsp.md).

**Recommended cert lifetimes for IoT.** Set `MaxTTLSeconds = 7776000`
(90 days) on the IoT `CertificateProfile`. Long enough to absorb
multi-day network outages without losing the device; short enough to
limit exposure on key compromise (combined with bulk revoke + CRL
refresh, the worst-case window is `1h + crl_refresh_interval` from
revocation to relying-party rejection).

**Renewal trigger ratio for IoT.** Set the device's renewal cron to
fire at 25% remaining lifetime — that gives ~22 days of buffer for a
device that's offline at expiry-time to reconnect, retry, and
re-enroll before the cert hard-expires. Mirrors the renewal-trigger
ratio for laptops at 50% (laptops are online more often, so the
buffer can be tighter relative to lifetime).

## `serverkeygen` for resource-constrained devices

RFC 7030 §4.4 lets the server generate the keypair on behalf of the
client when the device lacks a hardware RNG — typical of ultra-low-
power IoT or embedded modules without a TRNG. certctl supports this
via `CERTCTL_EST_PROFILE_<NAME>_SERVERKEYGEN_ENABLED=true`.

Wire format: `POST /.well-known/est/<pathID>/serverkeygen` with the
device's CSR as the request body. The handler:

1. Parses the CSR; the CSR's pubkey is treated as the **recipient
   key** for CMS EnvelopedData wrapping (RFC 7030 §4.4.2). The CSR's
   pubkey must support keyTrans (RSA-only at this revision; ECDH
   defer to a follow-up bundle) — non-RSA CSRs return HTTP 400 with
   `ErrServerKeygenRequiresKeyEncipherment`.
2. Resolves the per-profile key algorithm from
   `CertificateProfile.AllowedKeyAlgorithms` (default RSA-2048).
3. Generates a fresh keypair in process memory.
4. Re-builds the CSR with the server-generated pubkey (so the issuer
   sees a CSR that matches the cert it's signing).
5. Runs the existing issuer pipeline.
6. Marshals the private key as PKCS#8 DER, then wraps it in CMS
   EnvelopedData encrypted to the device's CSR pubkey via AES-256-CBC
   with a per-call random IV.
7. Returns the response as `multipart/mixed` per RFC 7030 §4.4.2:
   first part is the cert chain (PKCS#7), second part is the
   EnvelopedData blob (`application/pkcs8`).
8. **Zeroizes** the plaintext key + PKCS#8 bytes before return —
   `internal/service/est.go::zeroizeKey` + `zeroizeBytes`. The
   private key never persists to disk on the certctl side.

Cross-check at boot: setting `_SERVERKEYGEN_ENABLED=true` on a
profile with empty `_PROFILE_ID` is refused — server-keygen needs a
`CertificateProfile` to pin `AllowedKeyAlgorithms` (the server has
to decide what key to generate, and a profile-less default would be
arbitrary).

**Security caveats.**

- **Trust transitivity.** Server-keygen breaks the cardinal property
  of agent-based key management: that the private key never leaves
  the device. The CMS wrap protects the key in transit, but the
  device still trusts certctl with the key material at generation
  time. Use only when the device cannot generate its own keypair —
  not as a convenience.
- **Heap residency window.** The plaintext key lives in process heap
  between generation and CMS encryption. The zeroize step closes the
  obvious leakage leg, but a Go runtime that GC-relocates the buffer
  before zeroize fires could leave a copy. The threat-model carve-out
  is documented in [Threat model](#threat-model); use HSM-backed
  signing for highest-assurance fleets.
- **No audit-log trail of the key bytes.** The audit row records
  the issuance (cert serial, subject, issuer) but never the key
  bytes; the operator cannot recover a key after issuance. This is
  by design — the key bytes only exist for the duration of the
  request.

## HSM-backed CA signing for EST

EST signs certs using whatever issuer connector the profile binds.
The `internal/crypto/signer/` interface (post-2026-04-28) means a
future HSM/PKCS#11 driver bundle (parking-lot at
`cowork/hsm-pkcs11-driver-prompt.md`) plugs in transparently — the
EST handler doesn't change. EST-issued certs benefit from HSM-backed
signing automatically once the HSM bundle ships and the operator
swaps the local issuer's `FileDriver` for a `PKCS11Driver`.

For deploys that need HSM-backed CA signing today, use the local
issuer's `FileDriver` with the CA key on a read-only TPM-protected
tmpfs; the L-014 file-on-disk threat-model carve-out in
`internal/connector/issuer/local/local.go` documents the
defense-in-depth steps.

## Operator GUI (EST Admin tabs)

The EST Admin surface lives at `/est` (route `web/src/main.tsx`,
nav link `web/src/components/Layout.tsx::EST Admin`). The page is
admin-gated at the top level — non-admin Bearer callers see an
"Admin access required" banner, and the underlying admin endpoints
(`/api/v1/admin/est/*`) are M-008 protected server-side independently.

Three tabs:

- **Profiles** (default) — per-profile lean cards with auth-mode
  badges, mTLS trust-anchor expiry countdown (green ≥30d / amber
  7–30d / red <7d / EXPIRED), the 12-cell live counter grid (every
  `est_*` failure mode), and a "Reload trust anchor" modal that
  hits `POST /api/v1/admin/est/reload-trust` (the SIGHUP-equivalent;
  bad reloads keep the OLD pool in place per the
  [Threat model](#threat-model) reload semantics).
- **Recent Activity** — merges the four EST audit-action prefixes
  (`est_simple_enroll`, `est_simple_reenroll`, `est_server_keygen`,
  `est_auth_failed`) across four parallel queries with chip filters
  (All / Enrollment / Re-enrollment / ServerKeygen / AuthFailure).
  Polled every 60s.
- **Trust Bundle** — per-mTLS-profile cert subjects + expiries
  surfaced from the trust holder snapshot. Used during rotation:
  operator extracts the new bundle, overwrites the on-disk file,
  hits Reload, then reloads this tab to confirm the new subjects.

All three admin endpoints (`GET /api/v1/admin/est/profiles`,
`POST /api/v1/admin/est/reload-trust`, plus the audit-query merge in
the GUI) are M-008 admin-gated. The page itself hides (UX hint) and
the server-side gate enforces (security boundary).

## CLI + MCP tools

The `certctl-cli est` subcommand family (`internal/cli/est.go`):

```
certctl-cli est cacerts        --profile <name>
certctl-cli est csrattrs       --profile <name>
certctl-cli est enroll         --profile <name> --csr <path|-> [--out <path>]
certctl-cli est reenroll       --profile <name> --csr <path|-> [--out <path>]
certctl-cli est serverkeygen   --profile <name> --csr <path>   --out <prefix>
certctl-cli est test           --profile <name>
```

`--profile` is the lowercased PathID (matches the URL path). Empty
profile string maps to the legacy `/.well-known/est/` root — use only
during a back-compat migration. Server-keygen writes
`<prefix>.cert.pem` plus `<prefix>.key.enveloped` (the EnvelopedData
blob, decryptable with `openssl smime`).

The MCP server (`internal/mcp/tools_est.go`) exposes six tools that
mirror the CLI surface for AI-orchestrated workflows:

- `est_list_profiles` — every configured EST profile + its auth modes
  + counters
- `est_admin_stats` — alias of the above; matches the
  `scep_admin_stats` naming convention
- `est_get_cacerts` — base64 PKCS#7 cert chain
- `est_get_csrattrs` — base64 DER attributes blob (per-profile when
  `RequiredCSRAttributes` is set)
- `est_enroll` — body carries the CSR PEM; returns the issued cert
- `est_reenroll` — same but uses the previous-cert mTLS path

All six are gated by the standard MCP Bearer auth + the page-level
admin gate where applicable (`est_list_profiles`, `est_admin_stats`).

## Renewal: device-driven model

RFC 7030 §4.2.2 mandates the renewal model: the **device** decides
when to renew and drives `simplereenroll` over its existing cert.
There is no server-initiated push — certctl never reaches out to a
device fleet to force renewal.

Practical implications:

- A device offline at expiry-time **loses its cert**. Mitigation:
  pick a renewal-trigger ratio with enough buffer (50% remaining
  lifetime for laptops, 25% for IoT — see
  [IoT bootstrap recipe](#iot-bootstrap-recipe)). On chronically
  offline fleets, lengthen `MaxTTLSeconds`.
- The "operator wants to push renewal" case is handled via the
  notification webhook surface (`internal/connector/notifier/webhook/`)
  — operator publishes an event on a topic the device fleet
  subscribes to (or the operator's MDM picks up); the device's MDM
  agent triggers the renewal cron out-of-band. certctl emits a
  `cert.expiring_soon` event on the standard 30/7/1-day pre-expiry
  schedule (`internal/scheduler/scheduler.go::expiryNotificationLoop`).
- Per-(CN, sourceIP) sliding-window cap keeps a misbehaving device
  from hammering the server. Default is `0` (disabled, back-compat);
  production deploys set `3` per `CERTCTL_EST_PROFILE_<NAME>_RATE_LIMIT_PER_PRINCIPAL_24H`.
  Mirrors the SCEP/Intune per-device limit pattern from
  [`scep-intune.md`](scep-intune.md).

## Troubleshooting matrix

The handler emits a typed audit-action code per failure mode. Filter
the GUI Recent Activity tab on the action prefix to find the
offending requests, and use the table below to map back to root
cause + fix.

| Audit action                         | Symptom                                                                 | Root cause + fix                                                                                                                                                                                                                          |
|--------------------------------------|-------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `est_simple_enroll_success`          | (success counter)                                                       | No action needed.                                                                                                                                                                                                                          |
| `est_simple_enroll_failed`           | An enrollment failed — the bare `_failed` codes give the typed reason   | The audit row's `details` carries the inner reason; cross-reference one of the rows below.                                                                                                                                                |
| `est_simple_reenroll_success`        | (success counter)                                                       | No action needed.                                                                                                                                                                                                                          |
| `est_simple_reenroll_failed`         | A renewal failed                                                        | Same as `est_simple_enroll_failed`; cross-reference inner reason.                                                                                                                                                                          |
| `est_server_keygen_success`          | (success counter)                                                       | No action needed.                                                                                                                                                                                                                          |
| `est_server_keygen_failed`           | Server-keygen failed                                                    | Most common: device CSR carries a non-RSA pubkey (the keyTrans wrap requires RSA at this revision). Switch the device to an RSA CSR or wait for ECDH support.                                                                              |
| `est_auth_failed_basic`              | HTTP Basic gate tripped                                                 | Wrong password OR the password env var rotated and the device wasn't re-provisioned. Watch the source-IP for sustained failures — the limiter locks out after 10 fails/hr.                                                                  |
| `est_auth_failed_mtls`               | mTLS gate tripped                                                       | Client cert doesn't chain to the trust anchor OR the cert is past `NotAfter` OR the cert presented is for a different EST profile (cross-profile bleed defense). Check `details.subject` against `_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH`.       |
| `est_auth_failed_channel_binding`    | RFC 9266 channel-binding gate tripped                                   | One of: missing `id-aa-channelBindings` attribute on the CSR (libest <v3.0); mismatch (MITM signal — log + escalate); TLS 1.2 client (channel binding requires TLS 1.3). Map the inner error to the [channel-binding table](#rfc-9266-channel-binding). |
| `est_rate_limited`                   | Per-(CN, sourceIP) cap tripped                                          | If legitimate (recovery + first-cert + post-wipe in 24h), bump `_RATE_LIMIT_PER_PRINCIPAL_24H`. If suspicious, the limiter is doing its job — investigate the device.                                                                       |
| `est_csr_policy_violation`           | CSR violates the bound `CertificateProfile` rules                       | Inner detail names the dimension (key alg, key size, EKU, SAN, max TTL). Either fix the device CSR or relax the policy — never silently accept.                                                                                          |
| `est_bulk_revoke`                    | Operator-initiated bulk revoke                                          | Audit-only signal; no failure. Cross-reference the operator's identity in `details.actor`.                                                                                                                                                |
| `est_trust_anchor_reloaded`          | Operator-initiated SIGHUP-equivalent reload                             | Audit-only signal; no failure. Failed reloads do NOT emit this code (the OLD pool stays in place; check the GUI Reload modal's error message + the `details.path_id`).                                                                    |

The bare action codes (without the `_success`/`_failed` suffix) are
also emitted for back-compat with the GUI activity-tab filter chips
which match by exact-string `startsWith()` — the split-emit pattern
preserves both the legacy-grep and the new typed-counter use cases.
See `internal/service/est_audit_actions.go` for the constant
definitions; the per-action emission sites are in
`internal/service/est.go::processEnrollment`.

## TLS 1.2 reverse-proxy runbook

Some embedded EST clients only speak TLS 1.2 — older OpenWRT routers,
some industrial PLCs, IoT firmware that can't be field-upgraded.
certctl's control plane is TLS 1.3 only (pinned at
`cmd/server/tls.go::buildServerTLSConfig`). The migration path is the
TLS 1.2 reverse-proxy pattern documented in
[`legacy-est-scep.md`](legacy-est-scep.md):

- nginx / HAProxy terminates TLS 1.2 from the legacy client
- Forwards the EST request body unchanged to certctl on TLS 1.3
- Optionally forwards the client cert via `X-SSL-Client-Cert` for the
  proxy-side mTLS trust pin

Important caveat: **RFC 9266 channel binding cannot work through a
reverse proxy.** The channel binding bytes are derived from the
client↔proxy TLS session, NOT the proxy↔certctl session. Disable
`_CHANNEL_BINDING_REQUIRED` for profiles that serve via the proxy
runbook.

## Threat model

The EST hardening bundle's threat model rests on these load-bearing
properties; deviations need explicit operator awareness:

- **Trust anchor reload is fail-safe.** A SIGHUP that hits a
  half-rotated bundle (parse error, expired cert) keeps the OLD pool
  in place. The validator never accepts an unparseable bundle. The
  GUI reload modal surfaces the error so the operator can correct
  the file and retry without taking the EST endpoint down.
- **Per-profile counter isolation.** Each ESTService instance has
  its own `estCounterTab` (sync/atomic-backed). A future shared-
  counter refactor would fail at the compile-time pointer-identity
  check in `internal/service/est_profile_counter_isolation_test.go`.
  This means the Recent Activity tab's per-profile filter is a real
  filter, not a fan-out display of one shared counter.
- **mTLS cross-profile bleed is blocked.** A client cert presented
  to profile A's mTLS endpoint must chain to A's trust bundle, not
  any other profile's. The per-handler re-verify enforces this even
  when both profiles share a TLS listener union pool (see
  `cmd/server/tls.go::buildServerTLSConfigWithMTLS`).
- **Source-IP failed-Basic limiter is process-local.** The 10/hr
  cap is enforced in-process; a load-balanced multi-pod deploy where
  request distribution is round-robin can amplify the effective
  per-IP rate by the pod count. Mitigation: use sticky-source-IP
  load balancing for `/.well-known/est/` if this is in scope.
- **Server-keygen has a heap-residency window.** The plaintext
  private key lives in process memory between generation and CMS
  EnvelopedData encryption. The zeroize step closes the obvious
  leakage leg, but a GC-relocation between generation and zeroize
  could leave a copy. Use HSM-backed signing for highest-assurance
  fleets where this matters.
- **HTTP Basic password is in-process only.** Stored in
  `ESTHandler.basicPassword`, never logged, never written to disk by
  certctl. Operators ARE responsible for the env-var injection path
  (Helm secret, Docker secret, Vault) — see `tls.md` for the
  recommended secret-mount conventions.
- **The legacy unauthenticated default exists for back-compat.**
  Pre-Phase-1 deploys had no `_ALLOWED_AUTH_MODES` env var; the
  default is empty (anonymous) so existing deploys continue to work.
  A future bundle MAY flip the default to require explicit opt-in;
  production deploys should set `_ALLOWED_AUTH_MODES` explicitly
  today regardless.

## V3-Pro deferrals

These capabilities are deferred to V3-Pro (paid tier). They're not
oversights — they're the natural follow-on bundles after v2.X.0 GA:

- **Conditional Access / device-posture gating.** The per-profile
  ESTService exposes a nil-default compliance-hook seam (mirrors the
  SCEP/Intune `ComplianceCheck` pattern). V3-Pro plugs in a
  Microsoft Graph or other posture-check callback before issuance;
  non-compliant devices fail with a typed `est_compliance_failed`
  reason.
- **Multi-tenant CA isolation.** V2 has one trust anchor pool per
  EST profile and one issuer binding. V3-Pro ships per-tenant root
  + per-tenant audit isolation for MSPs running shared certctl
  deployments across customers.
- **EST cert-bound usage analytics.** Forward device-side handshake
  logs into certctl for cert-bound session analytics. V3-Pro (or
  delegate to a real session-management product like Teleport for
  TLS sessions).
- **EST-cert-manager-style controller for K8s host fleets.**
  External-issuer pattern that lets cert-manager use certctl's EST
  server as a backend. Parking-lot per `WORKSPACE-ROADMAP.md::Cloud
  and Kubernetes`.
- **Standalone `certctl-est` CLI binary.** All EST ops route through
  the certctl server in V2; a standalone binary that an operator can
  run on a laptop without the full server (similar to the SCEP probe
  deferred CLI binary). V2 ships the `certctl-cli est` subcommand
  family which solves the same operator workflow at a lower
  packaging cost.
- **`fullcmc` (RFC 7030 §4.3) implementation.** Rare in practice;
  only Cisco IOS and a few financial-PKI vendors use it. Defer
  until a customer asks.

## Appendix A: libest reference client

certctl's CI exercises the EST endpoints against Cisco's libest
reference implementation via the sidecar at
`deploy/test/libest/Dockerfile`. The build reproduces v3.2.0-2 from
source on `debian:bookworm-slim` (digest-pinned per the H-001 guard).

To reproduce locally:

```bash
# From the repo root.
docker compose --profile est-e2e -f deploy/docker-compose.test.yml build libest-client
docker compose --profile est-e2e -f deploy/docker-compose.test.yml up -d libest-client
docker exec -it certctl-libest-client estclient --help
```

The integration test suite (`deploy/test/est_e2e_test.go`, build
tag `integration`) drives the live certctl server through the
sidecar via `docker exec` for these scenarios:

- `TestEST_LibESTClient_Enrollment_Integration` — `cacerts`
  → `simpleenroll` → cert assertion
- `TestEST_LibESTClient_MTLSEnrollment_Integration` — mTLS sibling
  route
- `TestEST_LibESTClient_ServerKeygen_Integration` — RFC 7030 §4.4
  multipart/mixed
- `TestEST_LibESTClient_RateLimited_Integration` — exhausts the
  per-principal cap and asserts the 429-shaped error
- `TestEST_LibESTClient_ChannelBinding_Integration` — RFC 9266
  `--tls-exporter` (skipped when libest build lacks the flag)

Run the suite via `INTEGRATION=1 go test -tags integration ./deploy/test/... -run EST`.

## Appendix B: RFC 7030 wire-format quirks

certctl's EST handler ships with quirk-tolerance for documented EST
client populations. The fixtures + unit tests live at
`internal/api/handler/cisco_ios_quirks_test.go` +
`internal/api/handler/testdata/cisco_ios_*.txt`.

| Vendor / version            | Quirk                                                            | certctl behavior                                                                                                                                                            |
|-----------------------------|------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Cisco IOS 15.x              | Some images send the CSR as `application/x-pem-file` (not the spec'd `application/pkcs10`) | The handler dispatches on the body prefix (`-----BEGIN`) rather than the Content-Type header — accepted as PEM-encoded PKCS#10.                                              |
| Cisco IOS 16.x              | Trailing newlines on the base64 body (variable count)            | `strings.TrimSpace` pass before base64 decode; bodies tolerated regardless of trailing whitespace.                                                                          |
| Apple MDM (some firmware)   | CRLF line wrapping inside the base64 body                        | `base64.StdEncoding` handles both LF and CRLF.                                                                                                                              |
| OpenWRT (older builds)      | TLS 1.2 only                                                     | Use the [TLS 1.2 reverse-proxy runbook](#tls-12-reverse-proxy-runbook); disable channel binding for affected profiles.                                                      |
| libest <v3.0                | No RFC 9266 `--tls-exporter` flag                                | Set `_CHANNEL_BINDING_REQUIRED=false` for affected profiles; the server still validates everything else.                                                                    |

If you find a new wire-format quirk in a real device, file an issue
with a base64 dump of the failing request — we'll add a fixture +
the matching tolerance pass.

## Related docs

- [`legacy-est-scep.md`](legacy-est-scep.md) — TLS 1.2 reverse-proxy
  runbook + the SCEP RFC 8894 native implementation parallels.
- [`scep-intune.md`](scep-intune.md) — the SCEP/Intune master bundle
  that established the multi-profile dispatch + admin GUI + golden
  fixture patterns this EST bundle mirrors.
- [`crl-ocsp.md`](crl-ocsp.md) — the per-issuer CRL distribution
  endpoint and OCSP responder that EST-issued certs are revoked
  through.
- [`features.md`](features.md) — every `CERTCTL_*` env var,
  including the per-profile `CERTCTL_EST_PROFILE_<NAME>_*` family
  documented here.
- [`architecture.md`](architecture.md) — overall control-plane
  architecture; EST Server section + Security Model trust-anchor
  rotation discussion.
- [`tls.md`](tls.md) — TLS bootstrap for the certctl control plane;
  prerequisite for any production EST deploy.
- [`connectors.md`](connectors.md) — issuer connectors that EST
  delegates to.
