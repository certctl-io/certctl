# certctl CLI

> Last reviewed: 2026-05-05

`certctl-cli` is the command-line interface to certctl. It wraps the REST API as terminal commands so operators and CI/CD pipelines can drive certctl without writing curl invocations.

## Install

```bash
go install github.com/certctl-io/certctl/cmd/cli@latest
```

The binary lands at `$GOBIN/cli` (or `$HOME/go/bin/cli` if `GOBIN` is unset). Rename to `certctl-cli` if you prefer.

## Configure

The CLI reads three environment variables:

```bash
export CERTCTL_SERVER_URL=https://localhost:8443
export CERTCTL_API_KEY=your-api-key
export CERTCTL_SERVER_CA_BUNDLE_PATH=/path/to/ca.crt
```

Or pass them per-invocation:

```bash
certctl-cli --server https://localhost:8443 --api-key your-key --ca-bundle ca.crt certs list
```

For local development against a self-signed bootstrap cert, `--insecure` skips TLS verification. **Never set this in production.**

## Command groups

The CLI is organized by resource:

```
certctl-cli certs    [list|get|renew|revoke]
certctl-cli agents   [list|get]
certctl-cli jobs     [list|get|cancel]
certctl-cli import   [bulk PEM import]
certctl-cli est      [enroll|reenroll]
certctl-cli status   [server health + summary stats]
certctl-cli version  [CLI + server version]
```

## Common workflows

### List + filter certificates

```bash
# All certs
certctl-cli certs list

# Filter by environment
certctl-cli certs list --env production

# JSON output (default is table)
certctl-cli certs list --format json

# Sort + paginate
certctl-cli certs list --sort -expires_at --limit 50

# Time-range filter (RFC 3339)
certctl-cli certs list --expires-before 2026-06-01T00:00:00Z

# Sparse fields — only return the columns you need
certctl-cli certs list --fields id,common_name,expires_at,status
```

### Trigger renewal

```bash
certctl-cli certs renew mc-api-prod
# Returns the job id; track with: certctl-cli jobs get <job-id>
```

### Revoke

```bash
# Single revoke
certctl-cli certs revoke mc-api-prod --reason keyCompromise

# Bulk revoke by filter
certctl-cli certs revoke --profile prof-deprecated --reason superseded
certctl-cli certs revoke --team t-payments --reason cessationOfOperation
certctl-cli certs revoke --issuer iss-old-vault --reason cACompromise
```

Reason codes are the canonical RFC 5280 §5.3.1 set: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`. Anything else returns an error.

### Bulk import

```bash
# Import a directory of PEMs
certctl-cli import /etc/letsencrypt/live/

# Import a single concatenated bundle
certctl-cli import certs.pem
```

Each cert lands in the inventory as `Unmanaged` (per the discovery model). Triage from the dashboard or via `certctl-cli certs claim <id>` once you've decided to actively manage it.

### EST enrollment

```bash
# Enroll a new device cert via EST simpleenroll
certctl-cli est enroll --csr device.csr --output device.crt

# Re-enroll (renew) an existing device cert
certctl-cli est reenroll --csr device.csr --client-cert device.crt --client-key device.key
```

### Server status

```bash
certctl-cli status
# Health: ok
# Total certificates: 145
# Expiring (30d): 12
# Active jobs: 3
# Pending renewals: 8
```

## Output formats

- `--format table` (default) — human-readable terminal output
- `--format json` — JSON for piping into `jq`, scripts, dashboards

The CLI is built with Go's standard library only — no external dependencies. The binary is small (~10MB) and statically linked.

## Wiring into CI/CD

Common pattern: a CI step that issues a cert from your internal CA, deploys it via certctl, and verifies the deploy:

```bash
certctl-cli certs renew mc-api-prod --wait
certctl-cli jobs get $(certctl-cli certs renew mc-api-prod --json | jq -r '.job_id') --wait
certctl-cli certs get mc-api-prod --json | jq -r '.expires_at'
```

The `--wait` flag blocks until the job reaches a terminal state (Completed / Failed / Cancelled), which is what CI scripts actually need.

## Related docs

- [`docs/reference/api.md`](api.md) — the OpenAPI 3.1 spec the CLI wraps
- [`docs/reference/mcp.md`](mcp.md) — the MCP server that exposes the same surface to AI assistants
- [`docs/contributor/qa-prerequisites.md`](../contributor/qa-prerequisites.md) — local environment setup before the CLI can talk to a server
