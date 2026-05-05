# OpenSSL / Custom CA Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the script-based OpenSSL /
> Custom CA issuer connector. For the connector-development context
> (interface contract, registry, ports/adapters), see the
> [connector index](index.md).

## Overview

Script-based issuer connector for organizations with existing CA
tooling. Delegates certificate signing, revocation, and CRL
generation to user-provided shell scripts. The connector `exec`s
the script for every certificate lifecycle operation; the script
runs as the certctl-server user with that user's full filesystem
and network access.

This is the highest-flexibility, highest-trust connector in
certctl. It exists to integrate with arbitrary CLI-driven CAs that
don't have a Go SDK — at the cost of a wider attack surface than
any other issuer.

Implementation lives at `internal/connector/issuer/openssl/`.

## When to use this connector

Use the OpenSSL / Custom CA connector when:

- Your CA is a CLI tool (BoringSSL, custom OpenSSL wrapper,
  hardware-CA controller, internal CA with no published SDK) and
  no Go-native adapter exists.
- You're prepared to operate the script with the same care as any
  privileged binary on the host (review every line, lock the path
  ownership and mode, audit invocations).

Look elsewhere when:

- A Go-native adapter exists for your CA (Vault, DigiCert,
  Sectigo, ACME, AWS ACM PCA, Google CAS, EJBCA, Entrust,
  GlobalSign, step-ca). Use the native adapter — narrower attack
  surface, no shell-out exposure.
- You're in a compliance environment (PCI-DSS Level 1, FedRAMP
  High, HIPAA-regulated PHI handling) where shell-out attack
  surfaces are formally disallowed.
- You're running multi-tenant certctl-server where tenant-A's
  script can affect tenant-B's certificates.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `CERTCTL_OPENSSL_SIGN_SCRIPT` | Yes | Script that receives CSR on stdin and outputs signed PEM cert on stdout |
| `CERTCTL_OPENSSL_REVOKE_SCRIPT` | No | Script to revoke a certificate (receives serial number as argument) |
| `CERTCTL_OPENSSL_CRL_SCRIPT` | No | Script that outputs DER-encoded CRL on stdout |
| `CERTCTL_OPENSSL_TIMEOUT_SECONDS` | No | Script execution timeout (default 30s) |

The sign script receives the CSR PEM on stdin and outputs the
signed certificate PEM on stdout. The connector parses the
certificate to extract serial number, validity dates, and chain
information.

Before shell execution, serial numbers are validated as hex-only
(`^[0-9a-fA-F]+$`) and revocation reason codes are validated
against the RFC 5280 specification to prevent argv injection. Both
checks live in `internal/validation/command.go`.

## Threat model

certctl's OpenSSL adapter is a deliberate trade between
flexibility and attack surface. Top-10 fix #6 of the 2026-05-03
issuer-coverage audit captured the threat model in detail; the
short version is below.

### What the adapter accepts

- A trusted operator pointing at a trusted script that lives in a
  trusted filesystem location (`/usr/local/bin/`,
  `/opt/<vendor>/bin/`, etc.) with appropriate ownership
  (root-owned, mode 0755) and a clear audit trail
  (filesystem-monitored, version-controlled).
- Env-var inheritance from the certctl-server process. Operators
  must NOT export sensitive credentials (Vault tokens, API keys
  for OTHER systems) into certctl-server's environment — or, if
  they must, must accept that those credentials are visible to the
  issuance script. The connector does not whitelist or strip env
  vars before fork.
- The hex-only serial-number filter and the RFC 5280 reason-code
  allow-list as defenses against argv injection. They are NOT
  defenses against a malicious script.

### What the adapter does NOT accept

- A script path under operator-writable filesystem (`/tmp`,
  `/var/tmp`, `~`) where a non-root user can swap the binary
  mid-flight. **Symlink attack:** a non-root user with write
  access to the directory replaces the script with a symlink to
  `/etc/shadow` or `/root/.ssh/authorized_keys`; certctl-server
  reads (or in the worst case writes via a malicious script)
  those files.
- Untrusted script content. The script can do anything the
  certctl-server user can — modify state outside `/etc/certctl/`,
  exfiltrate data, write SSH keys to enable persistence.
  Operators MUST review every script line before deploying.
- A multi-tenant host where multiple operators deploy scripts
  under the same certctl-server. Process-level isolation isn't
  enforced; one operator's script can read another's working
  files (the temp CSR/cert files the connector writes to
  `os.TempDir()` are mode 0600 but are visible by name to anyone
  who can list the directory).

## Mitigations operators can layer on

- **Run certctl-server under a dedicated unprivileged user**
  (e.g. `certctl:certctl`). The systemd unit ships with
  `User=certctl` by default — keep it that way.
- **Pin the script path to a root-owned mode-0755 binary**
  (`/usr/local/bin/issue-cert.sh`, root:root, 0755). Add a
  filesystem audit rule (`auditctl -w /usr/local/bin/issue-cert.sh
  -p wa -k certctl-script`) so any write attempt to the script is
  logged.
- **Set a per-call timeout via `CERTCTL_OPENSSL_TIMEOUT_SECONDS`**
  (default 30s). The connector wires this through
  `exec.CommandContext` so a hung script is killed at the
  wall-clock budget. Production operators should set it to the
  upper bound of legitimate issuance time — anything longer is a
  runaway.
- **Sanitise the certctl-server environment.** systemd's
  `Environment=` directive lets operators allow-list which env
  vars certctl-server (and therefore the script) sees.
  Default-deny is the safe posture; the connector itself does NOT
  scrub envs before fork.
- **Use a chroot or container.** systemd's `RootDirectory=` or
  running certctl-server in a container limits the filesystem the
  script can touch.
- **Audit the script's behaviour.** A wrapper script that logs
  every invocation's argv + env-snapshot + exit code to a
  separate audit log gives operators a forensic trail.
- **Per-call concurrency bound.** The renewal scheduler's
  `CERTCTL_RENEWAL_CONCURRENCY` (Bundle L closure) bounds
  scheduled traffic; ad-hoc `POST /api/v1/certificates` traffic
  isn't bounded. For high-volume environments, layer a
  reverse-proxy rate limit (NGINX, HAProxy) in front of the API.

## V3-Pro forward path

The hardened OpenSSL adapter (chroot/container by default,
env-var allow-list at the adapter layer, signed-script-binary
verification, audit-log-on-every-invocation, per-call concurrency
bound shared with the API surface) is V3-Pro work. Tracking:
`cowork/WORKSPACE-ROADMAP.md` (search "OpenSSL hardened mode").

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [Local CA issuer](local-ca.md) — Go-native alternative when the CA can be run as a sub-CA under certctl
- [Vault PKI](vault.md), [EJBCA](ejbca.md), [DigiCert](digicert.md) — Go-native alternatives for common CA stacks
