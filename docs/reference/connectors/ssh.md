# SSH (Agentless) Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the SSH agentless target
> connector. For the connector-development context (interface
> contract, registry, atomic deploy primitive shared across all
> targets), see the [connector index](index.md).

## Overview

The SSH connector enables agentless certificate deployment to any
Linux/Unix server via SSH/SFTP. Instead of installing the certctl
agent binary on every target, a single "proxy agent" in the same
network zone deploys certificates to remote servers over SSH.

This is ideal for environments where installing agents on every
server is impractical — air-gapped servers, legacy fleets, or
brownfield environments where agent installation requires change-
control tickets per host.

Implementation lives at `internal/connector/target/ssh/`.

## When to use this connector

Use the SSH connector when:

- Installing the certctl agent on every target is impractical or
  politically expensive.
- The agent-to-target network path is operator-controlled.
- You're deploying to known, registered infrastructure where the
  operator implicitly trusts the host (you're already shipping it
  a TLS cert).

Look elsewhere when:

- You're deploying across the public internet to dynamic /
  multi-tenant hosts. The connector accepts any host key
  (`InsecureIgnoreHostKey`); MITM resistance requires the
  mitigations below.
- Your environment has strict regulatory MITM-resistance
  requirements (PCI-DSS Level 1, FedRAMP High). The inline-comment
  "out of scope" framing on host-key acceptance doesn't satisfy
  auditors who want documented host-key verification at the
  connector level.

## Configuration

### Key authentication (recommended)

```json
{
  "host": "web-server.internal",
  "port": 22,
  "user": "certctl",
  "auth_method": "key",
  "private_key_path": "/home/certctl/.ssh/id_ed25519",
  "cert_path": "/etc/ssl/certs/cert.pem",
  "key_path": "/etc/ssl/private/key.pem",
  "chain_path": "/etc/ssl/certs/chain.pem",
  "reload_command": "systemctl reload nginx",
  "timeout": 30
}
```

### Password authentication

```json
{
  "host": "legacy-server.internal",
  "user": "deploy",
  "auth_method": "password",
  "password": "s3cret",
  "cert_path": "/etc/ssl/cert.pem",
  "key_path": "/etc/ssl/key.pem",
  "reload_command": "systemctl reload apache2"
}
```

### Field reference

| Field | Default | Description |
|---|---|---|
| `host` | (required) | SSH hostname or IP address |
| `port` | 22 | SSH port |
| `user` | (required) | SSH username |
| `auth_method` | `"key"` | `"key"` or `"password"` |
| `private_key_path` | — | Path to SSH private key file (key auth) |
| `private_key` | — | Inline SSH private key PEM (alternative to path) |
| `password` | — | SSH password (password auth) |
| `passphrase` | — | Passphrase for encrypted private keys |
| `cert_path` | (required) | Remote path for certificate file |
| `key_path` | (required) | Remote path for private key file |
| `chain_path` | — | Remote path for chain file (if empty, chain appended to cert) |
| `cert_mode` | `"0644"` | File permissions for cert (octal) |
| `key_mode` | `"0600"` | File permissions for private key (octal) |
| `reload_command` | — | Command to execute after deployment |
| `timeout` | 30 | SSH connection timeout in seconds |

## Security baseline

- **Key-based authentication is recommended** over password
  authentication. Encrypted private keys are supported via
  `passphrase`.
- **Reload commands are validated against shell injection** (same
  validation as Postfix/Dovecot connectors).
- **Host field is regex-validated** to prevent shell metacharacters.
- **Private keys are written with 0600 permissions** by default.
- **Host key verification is intentionally skipped.** See the
  threat model below.

## Operator playbook: SSH host-key verification

certctl's SSH connector dials each target with
`HostKeyCallback: ssh.InsecureIgnoreHostKey()`, meaning **the
connector accepts any server host key without comparison against
`known_hosts`**. This is a documented design choice, not an
oversight.

### Why the connector accepts any host key

- certctl deploys to operator-configured target infrastructure.
  Each target is registered explicitly in the control plane with
  hostname + auth credentials + cert/key paths; the operator
  implicitly trusts the host they're deploying to (otherwise why
  give it a TLS cert).
- Mirrors the same posture certctl applies to the network scanner
  (`InsecureSkipVerify` for cert-monitoring TLS handshakes) and
  the F5 connector (`Insecure` flag for self-signed BIG-IP
  management interfaces).
- Avoids a heavyweight per-target `known_hosts` management layer
  that would shift complexity onto operators with no
  proportional security gain when the network model is
  "operator-configured infrastructure on operator-controlled
  network".

### Threat model the design accepts

- A passive eavesdropper on the agent-to-target link. SSH's
  transport encryption still applies — host-key acceptance
  affects MITM vulnerability, not on-the-wire confidentiality.
- A MITM attacker on the agent-to-target link who can intercept
  the SSH TCP handshake AND has positioned themselves on a
  hostname the operator has registered as a deploy target.
  Layered authentication (per-target SSH keys with strong
  passphrases stored at the agent) limits the blast radius — the
  MITM gets one target's cert+key payload, not the agent's
  broader credentials.

### Threat model the design does NOT accept

- Deploying across the public internet to a host whose IP
  rotates (e.g. ephemeral cloud instances behind a load balancer
  that doesn't pin SSH host keys). In that scenario,
  `InsecureIgnoreHostKey` opens an MITM window during IP
  rotation — register a `known_hosts` file path or use SSH
  certificates (below) instead.
- Multi-tenant networks where another tenant could plausibly
  impersonate the target host. certctl's design assumes
  operator-controlled network paths.

### Mitigations operators can layer on

- **`known_hosts` enforcement**: implement a custom `SSHClient`
  (the connector's `SSHClient` interface accepts injected clients
  via `NewWithClient`) whose `Connect` method builds an
  `ssh.ClientConfig` with `HostKeyCallback` set to
  `knownhosts.New("/path/to/known_hosts")` from
  `golang.org/x/crypto/ssh/knownhosts`.
- **SSH certificate authentication**: use OpenSSH 5.4+ host
  certificates signed by an organizational CA. Configure the
  agent's `known_hosts` CA pinning via `@cert-authority` lines so
  any host presenting a certificate signed by the CA is trusted,
  regardless of IP rotation.
- **Network segmentation**: run the certctl agent on the same
  private network segment as its targets; require VPN tunnels
  for cross-network deploys; use bastion hosts with their own
  host-key validation.
- **Per-target SSH keys**: rotate the agent's SSH credentials
  per target so a successful MITM compromise is bounded to that
  one target's cert+key, not the agent's broader credential set.

### V3-Pro forward path

The operator-managed `known_hosts` integration (config field +
`HostKeyCallback` plumbing + per-target root-of-trust enforcement)
is documented as V3-Pro work. Tracking:
`WORKSPACE-ROADMAP.md` (search for "SSH known_hosts").

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [F5 BIG-IP](f5.md) — comparable proxy-agent target where the agent doesn't run on the appliance itself
- [Kubernetes Secrets](k8s.md) — agent-in-cluster alternative when the targets are workloads rather than VMs
