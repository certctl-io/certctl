# Postfix / Dovecot Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Postfix / Dovecot mail server
> TLS connector. For the connector-development context (interface
> contract, registry, atomic deploy primitive shared across all
> targets), see the [connector index](index.md).

## Overview

A dual-mode mail-server TLS connector. Writes certificate, key, and
chain files to configured paths and reloads the mail service. The
`mode` field selects between Postfix MTA and Dovecot IMAP/POP3,
which determines default file paths and reload commands.

This connector pairs with certctl's S/MIME certificate support
(email protection EKU, email SAN routing) for a complete email
infrastructure story — TLS for transport encryption, S/MIME for
end-to-end message signing and encryption.

Implementation lives at `internal/connector/target/postfix/`.

## When to use this connector

Use the Postfix / Dovecot connector when:

- You operate a self-hosted mail server (Postfix as MTA, Dovecot
  as IMAPS/POP3S) and want certctl to rotate the TLS material in
  place.
- You want validate-before-reload behaviour to keep a bad cert
  config from taking down mail.

Look elsewhere when:

- You're running a mail provider (Google Workspace, Microsoft 365)
  — the provider rotates certs internally.
- Your MTA is something else (Exim, Sendmail) — these don't have
  built-in connectors yet; use a [generic file-based
  target](index.md#target-connector) by hand or commission a
  custom adapter.

## Configuration

### Postfix mode

```json
{
  "mode": "postfix",
  "cert_path": "/etc/postfix/certs/cert.pem",
  "key_path": "/etc/postfix/certs/key.pem",
  "chain_path": "/etc/postfix/certs/chain.pem",
  "reload_command": "postfix reload",
  "validate_command": "postfix check"
}
```

### Dovecot mode

```json
{
  "mode": "dovecot",
  "cert_path": "/etc/dovecot/certs/cert.pem",
  "key_path": "/etc/dovecot/certs/key.pem",
  "chain_path": "/etc/dovecot/certs/chain.pem",
  "reload_command": "doveadm reload",
  "validate_command": "doveconf -n"
}
```

### Field reference

| Field | Default (Postfix) | Default (Dovecot) | Description |
|---|---|---|---|
| `mode` | `postfix` | `dovecot` | Service mode — determines defaults |
| `cert_path` | `/etc/postfix/certs/cert.pem` | `/etc/dovecot/certs/cert.pem` | Path for certificate file |
| `key_path` | `/etc/postfix/certs/key.pem` | `/etc/dovecot/certs/key.pem` | Path for private key (0600 permissions) |
| `chain_path` | (empty) | (empty) | If set, chain written separately; otherwise appended to cert |
| `reload_command` | `postfix reload` | `doveadm reload` | Command to reload the mail service |
| `validate_command` | `postfix check` | `doveconf -n` | Optional config validation before reload |

All commands are validated against shell injection via
`validation.ValidateShellCommand()`. File permissions: cert /
chain 0644, key 0600.

## Choosing Mode=postfix vs Mode=dovecot

Both modes share the same Go connector code (atomic-write,
PreCommit/PostCommit hooks, post-deploy verify, rollback), so the
rollback contract is identical across modes. The mode flag just
swaps the daemon-specific defaults.

`mode: postfix` is also the **default when `mode` is unset**.

### Hosts running BOTH Postfix and Dovecot

The common mail-server pattern. Configure **two separate targets**
in the certctl control plane, one per daemon. Each gets its own
cert path, its own validate / reload command, and its own
optional verify endpoint. The cert + key bytes can be identical
across the two targets if your mail server uses the same TLS
material for both daemons (which many do); certctl does not
deduplicate the deploys, but the byte-equal cert hits the
SHA-256 idempotency short-circuit on subsequent renewals when
the target paths haven't changed.

### Sharing a single cert file across daemons via symlink

Works fine with the connector — the atomic-write path's
`os.Rename` follows symlinks. Configure both targets to point at
the same canonical path, or have one target's `cert_path`
symlink into the other's. Operators who want byte-deduplication
should rely on this approach rather than asking certctl to
coordinate it.

## Daemon-specific quirks

### Postfix STARTTLS (port 25)

Typically requires the cert to chain to a public root for
receiving mail from arbitrary external MTAs that validate
SMTP-side server certs. If you're deploying a self-signed cert
from `iss-local`, configure the receiving Postfix accordingly
(e.g. `smtpd_use_tls=yes` + `smtpd_tls_security_level=may` for
opportunistic TLS so external senders that don't validate
continue to deliver).

### Dovecot IMAPS (port 993)

Typically client-facing — the chain you ship matters more here
because IMAPS clients (Thunderbird, Outlook) actively validate.
Set `chain_path` if your certificate chain is supplied
separately; when `chain_path` is unset, the connector appends the
chain bytes to `cert_path`.

### No shared TLS session cache

Postfix and Dovecot do not share a TLS session cache by default.
Both reload independently, so a cert renewal that updates both
targets via certctl requires both reloads to succeed before
clients re-handshake. The two targets are fully independent in
the certctl scheduler — one reload failing rolls back that
target only.

## Post-deploy verify

Operator-supplied via `post_deploy_verify` (`enabled` +
`endpoint` + `timeout`) — the connector does NOT bake in a
per-mode default port. Operators that opt in should set
`endpoint` to their daemon's listener (e.g. `mail.example.com:25`
for Postfix STARTTLS, `mail.example.com:993` for Dovecot IMAPS).

## Test pins

Bundle 11 (commit `88e8881`) added end-to-end tests for
`Mode=dovecot`:

- `TestPostfix_Atomic_DovecotMode_HappyPath` — confirms
  `applyDefaults` populates the dovecot validate + reload
  commands AND the deploy threads them through to `runValidate`
  + `runReload`.
- `TestPostfix_Atomic_DovecotMode_VerifyFails_Rollback` —
  confirms the rollback path under `Mode=dovecot` restores
  pre-deploy cert + key bytes byte-exact.

The `Mode=postfix` branch has equivalent test coverage in the
same file (see `TestPostfix_HappyPath`,
`TestPostfix_VerifyMismatch_Rollback`,
`TestPostfix_ReloadFails_Rollback`).

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [NGINX](nginx.md) — comparable file-based deploy with explicit reload
- [Apache](apache.md) — comparable file-based deploy with `apachectl configtest`
