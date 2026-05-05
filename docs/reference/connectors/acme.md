# ACME Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the outbound ACME v2 issuer
> connector (certctl as an ACME *client*). For the inbound ACME
> server (certctl as an ACME *server*), see
> [acme-server.md](../protocols/acme-server.md). For the
> connector-development context (interface contract, registry,
> ports/adapters), see the [connector index](index.md).

## Overview

The ACME connector implements the full ACME v2 protocol (RFC 8555)
using Go's `golang.org/x/crypto/acme` package. It supports three
challenge methods and ARI (RFC 9773) for renewal-window negotiation.

Compatible CAs include Let's Encrypt, ZeroSSL, Sectigo, Buypass,
Google Trust Services, SSL.com, and any other RFC 8555 ACME
implementation. step-ca's ACME directory is also compatible if you
prefer ACME over the native step-ca connector.

Implementation lives at `internal/connector/issuer/acme/`.

## When to use this connector

Use the ACME connector when:

- You need public-trust certificates (Let's Encrypt, ZeroSSL,
  Sectigo via ACME, Google Trust Services, SSL.com).
- You want certctl to drive renewal lifecycle on top of the ACME
  CA's free or paid issuance.
- You want one tool that covers both internal PKI (Local, Vault,
  step-ca) and public-trust ACME issuance.

Look elsewhere when:

- You need OV / EV certificates and your CA doesn't expose them
  via ACME — use the DigiCert or Sectigo SCM REST connectors.
- You're standing up internal-only PKI and don't want to operate
  ACME challenge infrastructure — use Local CA or Vault PKI for a
  simpler synchronous path.

## Challenge methods

### HTTP-01 (default)

A built-in temporary HTTP server starts on demand during
certificate issuance. The domain being validated must resolve to
the machine running the connector, and the configured HTTP port
must be reachable from the internet.

```json
{
  "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "email": "admin@example.com",
  "http_port": 80
}
```

### DNS-01 (for wildcards)

Creates DNS TXT records via user-provided scripts. Required for
wildcard certificates (`*.example.com`) and hosts that can't serve
HTTP on port 80. The connector invokes external scripts to create
and clean up `_acme-challenge` TXT records, making it compatible
with any DNS provider (Cloudflare, Route53, Azure DNS, etc.).

```json
{
  "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "email": "admin@example.com",
  "challenge_type": "dns-01",
  "dns_present_script": "/etc/certctl/dns/create-record.sh",
  "dns_cleanup_script": "/etc/certctl/dns/delete-record.sh",
  "dns_propagation_wait": 30
}
```

DNS hook scripts receive these environment variables:

- `CERTCTL_DNS_DOMAIN` — domain being validated
- `CERTCTL_DNS_FQDN` — full record name (`_acme-challenge.<domain>`
  for dns-01, `_validation-persist.<domain>` for dns-persist-01)
- `CERTCTL_DNS_VALUE` — TXT record value
- `CERTCTL_DNS_TOKEN` — ACME challenge token

The present script must create the TXT record and exit 0; the
cleanup script removes it (dns-01 only).

### DNS-PERSIST-01 (standing record)

Creates a one-time persistent TXT record at
`_validation-persist.<domain>` containing the CA's issuer domain
and your ACME account URI. Once set, this record authorizes
unlimited future certificate issuances without per-renewal DNS
updates. Based on
[draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/)
and CA/Browser Forum ballot SC-088v3.

If the CA doesn't offer dns-persist-01 yet, the connector falls
back to dns-01 automatically.

```json
{
  "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "email": "admin@example.com",
  "challenge_type": "dns-persist-01",
  "dns_present_script": "/etc/certctl/dns/create-record.sh",
  "dns_persist_issuer_domain": "letsencrypt.org",
  "dns_propagation_wait": 30
}
```

The present script creates a TXT record at
`_validation-persist.<domain>` with the value
`letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<your-id>`.
This record is permanent — no cleanup script is needed.

## ACME Renewal Information (ARI, RFC 9773)

Instead of using fixed renewal thresholds (e.g. renew 30 days
before expiry), certctl can ask the CA when it should renew.
Enable with `CERTCTL_ACME_ARI_ENABLED=true`.

The ARI protocol lets the CA specify a `suggestedWindow` (start
and end times) for when you should renew — useful for distributing
load during maintenance windows or coordinating mass-revocation
scenarios. Cert ID is computed as `base64url(SHA-256(DER cert))`.

If the CA doesn't support ARI (404 response), certctl
automatically falls back to threshold-based renewal with no
operator intervention required.

## External Account Binding (EAB)

ZeroSSL, Google Trust Services, and SSL.com require EAB for ACME
account registration. For most CAs, get your EAB credentials from
the CA's dashboard and provide them via `eab_kid` and `eab_hmac`.
The HMAC key must be base64url-encoded (no padding). CAs that
don't require EAB (Let's Encrypt, Buypass) ignore these fields.

```json
{
  "directory_url": "https://acme.zerossl.com/v2/DV90",
  "email": "admin@example.com",
  "eab_kid": "your-zerossl-eab-kid",
  "eab_hmac": "your-zerossl-eab-hmac-base64url"
}
```

### ZeroSSL auto-EAB

When the directory URL points to ZeroSSL and no EAB credentials
are provided, certctl automatically fetches them from ZeroSSL's
public API (`api.zerossl.com/acme/eab-credentials-email`) using
your configured email address. No dashboard visit required — just
set the directory URL and email. Same approach used by Caddy and
acme.sh.

```json
{
  "directory_url": "https://acme.zerossl.com/v2/DV90",
  "email": "admin@example.com"
}
```

## Certificate profiles (Let's Encrypt, GA January 2026)

Let's Encrypt supports ACME certificate profile selection. Set
`CERTCTL_ACME_PROFILE=shortlived` to request 6-day certificates —
ideal for ephemeral workloads where short validity substitutes for
revocation. The `tlsserver` profile produces standard TLS
certificates. When the profile field is empty (default), the CA
uses its default profile.

## Environment variables

- `CERTCTL_ACME_DIRECTORY_URL` — ACME directory URL
- `CERTCTL_ACME_EMAIL` — Contact email for account registration
- `CERTCTL_ACME_EAB_KID` — External Account Binding Key ID
- `CERTCTL_ACME_EAB_HMAC` — External Account Binding HMAC key
  (base64url-encoded)
- `CERTCTL_ACME_CHALLENGE_TYPE` — `http-01` (default), `dns-01`,
  or `dns-persist-01`
- `CERTCTL_ACME_DNS_PRESENT_SCRIPT` — Path to DNS record creation
  script
- `CERTCTL_ACME_DNS_CLEANUP_SCRIPT` — Path to DNS record cleanup
  script (dns-01 only)
- `CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN` — CA issuer domain for
  persistent record (dns-persist-01 only)
- `CERTCTL_ACME_PROFILE` — Certificate profile for the newOrder
  request

## Revocation by serial number (Top-10 fix #7)

RFC 8555 §7.6 requires the certificate DER bytes (not just the
serial) on the revoke wire — but a CLM platform's job is to
abstract over that limitation. Operators routinely have only the
serial in hand: the original PEM was lost, the private key was
rotated, the operator clicked "revoke" in the GUI based on a row
in the certs list.

certctl's ACME
`RevokeCertificate(ctx, RevocationRequest{Serial: ...})` looks the
serial up in the local cert store
(`certificate_versions.pem_chain`), decodes the leaf-cert PEM into
DER, and calls the ACME revoke endpoint with
`(accountKey, der, reasonCode)` — RFC 8555 §7.6 case 1,
"revocation request signed with account key". This works because
the same account key issued the cert, so authority is intrinsic.

The cert version must exist in the local store: this means the
cert was issued through certctl, not imported. If
`GetVersionBySerial` returns `sql.ErrNoRows`, the connector
returns an actionable error pointing at the local-store
requirement. Revoke-by-serial is therefore only available for
ACME certs that certctl issued.

Reason codes follow RFC 5280 §5.3.1: nil reason maps to
`unspecified` (0), and the connector accepts the canonical
camelCase form (`keyCompromise`, `cACompromise`,
`affiliationChanged`, `superseded`, `cessationOfOperation`,
`certificateHold`, `removeFromCRL`, `privilegeWithdrawn`,
`aACompromise`) plus underscore_lower and ALL_CAPS_UNDERSCORE
variants. An unknown reason returns an error rather than silently
demoting to `unspecified` — operators rely on the reason for
audit reporting.

## Related docs

- [ACME server](../protocols/acme-server.md) — certctl *as* an ACME server (the inverse direction)
- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [migration/acme-from-cert-manager.md](../../migration/acme-from-cert-manager.md) — point cert-manager at certctl's ACME server
- [migration/acme-from-traefik.md](../../migration/acme-from-traefik.md) — point Traefik at certctl's ACME server
