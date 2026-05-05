# Java Keystore (JKS / PKCS#12) Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the Java Keystore target
> connector. For the connector-development context (interface
> contract, registry, atomic deploy primitive shared across all
> targets), see the [connector index](index.md).

## Overview

The Java Keystore connector deploys certificates to JKS or
PKCS#12 keystores via the `keytool` CLI. This enables TLS cert
deployment for Tomcat, Jetty, Kafka, Elasticsearch, and any
JVM-based service.

Flow: PEM → temp PKCS#12 → `keytool -importkeystore` into the
target keystore. The flow is engineered for atomicity and
rollback, not just convenience.

Implementation lives at `internal/connector/target/javakeystore/`.

## When to use this connector

Use the Java Keystore connector when:

- The target is a JVM-based service (Tomcat, Jetty, Kafka,
  Elasticsearch, ZooKeeper) that reads TLS material from a
  keystore file.
- You need PKCS#12 or JKS format support; the connector handles
  both.

Look elsewhere when:

- The JVM service has been re-fronted with a non-Java reverse
  proxy (NGINX, HAProxy) that handles TLS termination — deploy
  to the proxy instead.
- The service uses PKCS#11 or a hardware token rather than a
  keystore file — that's outside this connector's scope.

## Configuration

```json
{
  "keystore_path": "/opt/tomcat/conf/keystore.p12",
  "keystore_password": "changeit",
  "keystore_type": "PKCS12",
  "alias": "server",
  "reload_command": "systemctl restart tomcat"
}
```

| Field | Default | Description |
|---|---|---|
| `keystore_path` | (required) | Absolute path to the keystore file |
| `keystore_password` | (required) | Keystore password |
| `keystore_type` | `"PKCS12"` | `"PKCS12"` or `"JKS"` |
| `alias` | `"server"` | Key entry alias in the keystore |
| `reload_command` | — | Optional command to run after keystore update |
| `create_keystore` | `true` | Create keystore if it doesn't exist |
| `keytool_path` | `"keytool"` | Override keytool binary path |
| `backup_retention` | `3` | Number of `.certctl-bak.<unix-nanos>.p12` snapshot files to keep after a successful deploy. `0` means use the default of 3; `-1` opts out of pruning entirely. |
| `backup_dir` | `dirname(keystore_path)` | Override directory where rollback snapshots are written and pruned from. Defaults to the keystore's own directory so snapshots land on the same filesystem. |

## Atomic-rollback contract (Bundle 8)

The deploy flow is **snapshot → delete → import → reload**.

Before the irreversible `keytool -delete` step (which removes the
existing alias from the keystore), the connector runs `keytool
-exportkeystore` to write a sibling `.certctl-bak.<unix-nanos>.p12`
file containing the prior alias.

If the subsequent `keytool -importkeystore` fails for any reason,
the rollback path runs `keytool -delete` (best-effort cleanup of
any partial alias the failed import created) followed by
`keytool -importkeystore` from the snapshot PFX, restoring the
keystore to its pre-deploy state.

If both the import AND the rollback fail, the connector returns
an operator-actionable wrapped error containing both error
strings AND the snapshot path so the operator can manually
`keytool -importkeystore` from the `.p12` file to recover.

Successful deploys prune older `.certctl-bak.*.p12` files beyond
the configured `backup_retention` count; pruning sorts by file
ModTime and removes the oldest entries first. Operators that wire
their own archival/rotation logic can opt out via
`backup_retention: -1`.

First-time deploys (no keystore file exists at the configured
path) skip the snapshot phase entirely — there's nothing to roll
back to. The same is true for "alias-not-present-in-existing-
keystore" deploys: `keytool -exportkeystore` returns "alias does
not exist" which the connector recognises as a normal first-
time-on-existing-keystore signal, not an outage.

## Operator playbook: keytool argv password exposure

Java's `keytool` accepts the keystore password via the
`-storepass` argv flag — there is no stdin or file-based password
mode in OpenJDK keytool. While the keytool subprocess is running,
the password is visible in `ps(1)` output to any user on the same
host who can read `/proc/<pid>/cmdline`. **This is a standard
keytool limitation, not a certctl-specific issue**, but operators
in regulated environments should know about it.

### What this means in practice

- The password is visible for the duration of each keytool
  invocation (typically <1s on modern hardware; the connector
  runs 2-4 keytool calls per deploy: snapshot, optional
  pre-import delete, import, optional rollback).
- A local user with shell access on the agent host who polls
  `ps -ef` aggressively can capture the password.
- The exposure is local to the agent host; remote attackers
  without shell access cannot see it.
- The same applies to the snapshot's transient `-deststorepass`
  (which mirrors the operator's keystore password by design —
  see "Why the snapshot reuses the keystore password" below).

### Mitigations

Layer one or more depending on threat model:

- **Restrict shell access to the agent host.** Only the certctl
  agent's service account should have a login shell. Other admins
  SSH to a bastion that doesn't host the agent.
- **Use Linux user namespaces or AppArmor** to deny `ps`-
  visibility into the keytool subprocess for non-root users.
  systemd's `ProtectKernelTunables=yes` + `ProtectProc=invisible`
  (kernel 5.8+) hides `/proc/<pid>` from non-owner users.
- **Run the certctl agent in a single-purpose container** so only
  the agent's processes are visible to anyone who execs into the
  container. The host's `ps` doesn't see container internals if
  proper PID-namespace isolation is configured.
- **Rotate the keystore password post-deployment.** For
  high-security environments where the brief exposure is
  unacceptable, the rotation can itself be automated via a
  post-deploy hook running `keytool -storepasswd`. The certctl
  `reload_command` is the natural place for this; just be aware
  the new password must be propagated to whatever service reads
  the keystore (Tomcat's `server.xml`, Kafka's
  `kafka.properties`, etc.).
- **For FIPS environments**, use the `BCFKS` (BouncyCastle FIPS)
  keystore type which supports stronger password-derivation. Same
  argv-exposure caveat applies; the keystore-format change
  doesn't affect how keytool receives the password.

For a fundamentally different password-handling model, switch to
a non-Java target (e.g. PEM-on-disk via the SSH connector + a
JCA-shim like `tomcat-native` reading PEMs directly) or a
PKCS#11 keystore (where the password is supplied to the cryptoki
library, not via argv).

### Why the snapshot reuses the keystore password

The snapshot's `keytool -exportkeystore` writes a PKCS#12 file
under a `-deststorepass`. The connector reuses the operator's
`keystore_password` for this rather than generating a separate
transient password. Two reasons:

1. The operator already trusts the connector with this secret,
   so the surface area doesn't grow.
2. The rollback's matching `keytool -importkeystore` needs to
   know the password too, and threading a second random
   password through the in-memory state machine adds complexity
   (and another argv-exposure window) for no security gain.

If you rotate the keystore password between deploys, the
rollback may fail to read the snapshot — keep stale
`.certctl-bak.*.p12` files on disk until the rotation completes,
and clean them up manually if rotation invalidates them.

## Security baseline

- Reload commands validated against shell injection via
  `validation.ValidateShellCommand()`.
- Alias validated against injection (alphanumeric, hyphens,
  underscores only).
- Path traversal prevention on keystore path.
- Transient PKCS#12 temp file cleaned up after import (even on
  error).

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [Windows Certificate Store](wincertstore.md) — comparable cert-store deploy on Windows
- [SSH agentless](ssh.md) — alternative when the JVM target is reachable via SSH and you'd rather drop PEM files than maintain a keystore
