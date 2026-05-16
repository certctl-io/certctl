# MCP ↔ REST API parity coverage

> Last reviewed: 2026-05-16

## What this file is

This is the canonical record of which certctl REST routes are exposed
as MCP (Model Context Protocol) tools, plus the explicit allowlist of
routes that are intentionally NOT exposed. The companion CI guard
`scripts/ci-guards/mcp-coverage-parity.sh` fails the build if a new
REST route lands without either an MCP tool wrapping it or an
explicit allowlist entry justifying the exclusion.

Before ARCH-004 (Sprint 4, 2026-05-16) the README said *"the full REST
API is exposed as MCP tools"* with no published coverage data. That
wording was an overclaim — see the audit trail in `git log --grep='ARCH-004'`.

## Current numbers

Re-derive at any time:

```bash
# REST routes registered by the router
grep -cE '^\s*r\.Register\(' internal/api/router/router.go

# MCP tools registered (counts gomcp.AddTool call sites)
grep -rcE 'gomcp\.AddTool' internal/mcp/ --include='*.go' \
  | grep -v '_test.go' | awk -F: '{s+=$2} END{print s}'
```

At the most recent verification (2026-05-16): **221 routes / 162 tools**.

## Coverage categories

The gap between routes and tools is intentional and falls into four
named exclusion categories. Adding a new REST route in any of these
categories does NOT require a paired MCP tool — but it DOES require
an allowlist entry in the CI guard.

### 1. Protocol-conformance endpoints

Routes that implement a wire protocol an automated client (cert-manager,
certbot, lego, MS Intune, EST devices, OCSP responders, CRL fetchers)
talks to directly. These are not human-driven API calls; the MCP
"natural language → tool call" model doesn't fit them. The MCP server
SHOULD NOT wrap these because exposing them would invite operators to
ask an AI agent to "renew the cert via ACME" when the right answer is
"the ACME client your existing infra already runs handles that."

- `/acme/*` — RFC 8555 + RFC 9773 (ACME server)
- `/scep/*` — RFC 8894 (SCEP server, MS Intune)
- `/.well-known/est/*` — RFC 7030 (EST server)
- `/ocsp` — RFC 6960 (OCSP responder)
- `/.well-known/pki/crl/*` — RFC 5280 CRL distribution

### 2. Browser-only auth flow endpoints

OIDC SSO + CSRF + bootstrap routes that exist solely for the GUI's
session establishment dance. An MCP client should authenticate via
the same API-key Bearer path the REST callers use; exposing the
browser flow as a tool would be incoherent.

- `/auth/oidc/login`
- `/auth/oidc/callback`
- `/auth/oidc/back-channel-logout`
- `POST /api/v1/auth/bootstrap` (one-shot day-0 admin)
- `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`
- `GET /api/v1/auth/csrf`

### 3. Liveness / readiness / version

Out of scope for natural-language workflows.

- `/health`
- `/ready`
- `/api/v1/version`

### 4. Streaming / binary download endpoints

The MCP tool contract is request → response JSON. Binary streaming
and chunked transfer don't fit the shape and would force lossy
encoding (base64-wrapped JSON blobs) the operator wouldn't actually
use through an AI assistant.

- `GET /api/v1/certificates/{id}/download` — raw PEM
- `GET /api/v1/certificates/{id}/chain` — chain PEM
- `GET /api/v1/intermediate-cas/{id}/cert` — raw cert
- `GET /api/v1/metrics/prometheus` — Prometheus text format

## How to add a new route

1. Add the route in `internal/api/router/router.go`.
2. Decide: should an AI assistant be able to invoke this?
   - **Yes** → add a matching `gomcp.AddTool` call in `internal/mcp/`.
   - **No** → confirm the route fits one of the four exclusion
     categories above AND add an entry to the allowlist in
     `scripts/ci-guards/mcp-coverage-parity.sh`.
3. The CI guard will fail until either branch is satisfied.

If the route doesn't fit any of the four categories and you don't
want it in MCP for another reason, name a fifth category in this
file and update the CI guard. The list is meant to grow with the
product, not contain it.

## Why this matters

certctl is sold to operators who'll use AI assistants to drive it.
"Most of the REST API" is a meaningful coverage claim; "the full REST
API" was not. Diligence reviewers and operators evaluating MCP-driven
workflows need the explicit gap surface — both to plan their
automation around the gap and to spot when the gap drifts.
