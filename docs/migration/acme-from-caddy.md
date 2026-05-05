# Caddy Integration Walkthrough

> Last reviewed: 2026-05-05

> **Use this walkthrough when** you're already running Caddy 2.7+ and
> want it to ACME-issue from certctl (your internal CA, your private
> PKI, or a local sub-CA chained under an enterprise root) instead of
> Let's Encrypt. The Caddyfile changes are minimal; the load-bearing
> piece is trusting certctl's bootstrap CA so Caddy's ACME client can
> talk to certctl over HTTPS.

End-to-end recipe for issuing certs from a certctl-server deployment
through Caddy 2.7+. Target audience: operator running Caddy on a VM
or container who wants Caddy to ACME-issue from certctl instead of
Let's Encrypt.

## Prereqs

- A reachable certctl-server with `CERTCTL_ACME_SERVER_ENABLED=true`
  and at least one profile whose `acme_auth_mode` is set. Profile
  setup is identical to the cert-manager walkthrough — see
  [`docs/acme-cert-manager-walkthrough.md`](./acme-from-cert-manager.md)
  Step 2.
- Caddy 2.7.x or later. `caddy version` should show 2.7.0+.
- Network reachability: Caddy → certctl-server's HTTPS listener (port
  8443 by default).
- The certctl bootstrap CA, in PEM form, captured for the trust
  configuration below. Capture exactly the same way as the cert-manager
  walkthrough Step 3 — use `cat deploy/test/certs/ca.crt`.

## Step 1 — Configure Caddy

Caddy's ACME issuer is configured per-site (or globally) via the
`acme_ca` directive in a Caddyfile, or via the `tls.acme_ca` field
in JSON config. The directive points at the directory URL:

```
{
  email ops@example.com
}

example.com {
  tls {
    acme_ca https://certctl.example.com:8443/acme/profile/prof-test/directory
    issuer acme
  }
  reverse_proxy localhost:8080
}
```

Notes:

- `acme_ca` must point at the directory URL (ending in `/directory`),
  not just the base. Caddy uses the directory document to discover
  the new-account / new-order URLs, exactly the same way cert-manager
  does.
- `issuer acme` is the default; included here for clarity. Caddy can
  also be configured with `issuer zerossl` or `issuer internal`; for
  certctl integration, `acme` is the correct issuer.
- Caddy auto-discovers `tls-alpn-01` first when port 443 is bound to
  Caddy, then falls back to HTTP-01. For `trust_authenticated` mode
  profiles, both work without solver round-trips.

## Step 2 — Trust the certctl bootstrap CA

Caddy validates the certctl-server's TLS chain before any ACME call,
the same way cert-manager does. Two options for trust:

### Option A — OS trust store (preferred for VMs)

```
sudo cp deploy/test/certs/ca.crt /usr/local/share/ca-certificates/certctl-bootstrap.crt
sudo update-ca-certificates
sudo systemctl restart caddy
```

Caddy honors the system trust store via the Go runtime's
`crypto/x509` defaults. After `update-ca-certificates`, Caddy's HTTPS
client trusts certctl's self-signed root and the directory call
succeeds.

### Option B — Caddy `tls.cas` (for containerized deployments)

```
{
  pki {
    ca certctl_bootstrap {
      root_cert_file /etc/caddy/certctl-bootstrap.crt
    }
  }
}

example.com {
  tls {
    acme_ca https://certctl.example.com:8443/acme/profile/prof-test/directory
    ca certctl_bootstrap
    issuer acme
  }
  reverse_proxy localhost:8080
}
```

The `pki.ca` block registers a named CA Caddy can reference; the
`tls.ca certctl_bootstrap` line in the site block scopes that trust
to ACME calls for this site only. This is the right pattern for
multi-tenant Caddy deployments where some sites trust certctl + others
don't.

## Step 3 — Reload Caddy

```
caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy reloads atomically; in-flight requests complete on the old
config while new requests use the new ACME issuer. On the next
`example.com` request, Caddy hits certctl's directory URL, registers
an account, submits a new-order, and finalizes — typically completing
in under 5 seconds for `trust_authenticated` mode.

## Step 4 — Verify

```
caddy list-certificates
# example.com (issuer=certctl.example.com): CN=example.com, valid until 2026-06-30
```

The cert is in Caddy's certificate cache (`$XDG_DATA_HOME/caddy/certificates/`
by default). Inspect:

```
openssl x509 -in ~/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt -noout -subject -issuer -dates
# subject= CN=example.com
# issuer= CN=certctl test internal CA
```

(Path layout is Caddy-version-dependent; check `caddy environ` for the
canonical data dir.)

On the certctl side, the operator's audit log captures the issuance
event:

```
psql -c "SELECT actor, action, resource_id FROM audit_events
         WHERE actor LIKE 'acme:%' ORDER BY created_at DESC LIMIT 5;"
```

## Common failure modes

- **Caddy logs `tls: failed to verify certificate: x509: certificate
  signed by unknown authority`** → certctl bootstrap CA is not in
  Caddy's trust path. Re-do Step 2; verify with `curl --cacert
  /etc/caddy/certctl-bootstrap.crt https://certctl.example.com:8443/acme/profile/prof-test/directory`.
- **Caddy logs `urn:ietf:params:acme:error:rateLimited`** → certctl
  per-account orders/hour limit hit (default 100/hr). Tune via
  `CERTCTL_ACME_SERVER_RATE_LIMIT_ORDERS_PER_HOUR` if you have
  legitimately high throughput.
- **Caddy logs `urn:ietf:params:acme:error:rejectedIdentifier`** →
  the SAN list includes an identifier the certctl profile policy
  rejects. Cross-reference [`docs/acme-server.md` § Troubleshooting](../reference/protocols/acme-server.md#certificate-readyfalse-with-rejectedidentifier).
- **`badNonce` in Caddy logs** → clock skew or multi-replica certctl
  without sticky sessions; same fix as the cert-manager walkthrough.

## Cleanup

```
caddy stop
# remove the certctl-specific block from your Caddyfile
sudo systemctl reload caddy
# Optional: delete cached certs from the certctl directory namespace.
rm -rf ~/.local/share/caddy/certificates/certctl.example.com-*
```

## See also

- [`docs/acme-server.md`](../reference/protocols/acme-server.md) — canonical reference.
- [`docs/acme-cert-manager-walkthrough.md`](./acme-from-cert-manager.md) —
  K8s-native equivalent.
- [Caddy upstream ACME docs](https://caddyserver.com/docs/automatic-https#acme-issuer)
  — verify behavior pinned here against Caddy 2.7.x semantics.
