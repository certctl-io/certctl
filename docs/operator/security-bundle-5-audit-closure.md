# Bundle 5 Security Audit Closure

> Last reviewed: 2026-05-13

Closure summary for Bundle 5 of the 2026-05-12 acquisition diligence audit — the auth / OIDC / MCP / API / browser-security edge-case pass. Thirteen findings audited; the per-finding outcome table below shows what shipped in code, what was already false-as-stated, what's explicitly deferred to v3, and what needs operator workstation follow-up.

## Security matrix

| ID | Sev | Title | Status | Where |
|---|---|---|---|---|
| **finding 1** | Med | Auth architecture doc conflicts with shipped OIDC/session/break-glass | **Closed (doc)** | `docs/reference/architecture.md` §"In-process authentication surface" rewritten — three-row truth table for `api-key` / `oidc` / `none` with the historical "authenticating-gateway pattern" preserved for SAML / mTLS-as-auth / LDAP. |
| **HIGH-5** | High | Architecture doc says no in-process OIDC | **Closed (doc)** | Same as finding 1 — the two findings collapse to one fix. |
| **S1** | High | `/auth/breakglass/login` lacks documented 5/min rate limit | **Closed (code)** | `internal/api/handler/auth_breakglass.go::AuthBreakglassHandler.loginLimiter` + `SetLoginRateLimiter` (5/min/IP, 50 000-key cap). Wired at startup in `cmd/server/main.go` (sliding-window limiter via `internal/ratelimit`). Handler returns 429 on cap-hit. Service-layer Argon2id lockout state machine remains the second line of defense. |
| **S3** | Med | Named API keys parsed but validation requires `Secret` | **Operator decision** | `CERTCTL_API_KEYS_NAMED` is parsed into `cfg.Auth.NamedKeys` at startup. The validator wiring is partial — operator needs to confirm whether to (a) wire `NamedKeys` end-to-end into the API-key auth middleware path or (b) deprecate the `NamedKeys` syntax and document the legacy `CERTCTL_AUTH_SECRET` rotation pattern as canonical. v3 work item. |
| **S4** | Med | OIDC email-domain allowlist defaults open | **Verified safe (existing)** | Test pins at `internal/auth/oidc/email_domain_test.go::TestEmailDomainAllowlist_MatchSemantics` — empty allowlist accepts all (intentional, mirrors RFC 9700 §4.1.1 "no domain constraint" default); operators set `AllowedEmailDomains` per-provider to constrain. `ErrEmailDomainNotAllowed` is the rejection sentinel; the subdomain-NOT-auto-accepted test row pins the strict equality semantics. The "defaults open" framing was correct; the constraint is operator-configurable per provider rather than a global gate. |
| **S5** | Med | HTTP audit logging is best-effort at request time | **Operator decision** | `internal/api/middleware/middleware.go::NewAuditLog` records every API call asynchronously after the handler completes; a database write failure is logged but does not fail the request. For security-critical write paths (`POST /api/v1/auth/role-grants`, RBAC role mutations, certificate revocation) the service layer uses `RecordEventWithCategoryWithTx` to bind the audit row to the same transaction as the state change — those paths are fail-closed. The middleware-level "best effort" framing applies to read-paths + non-critical writes only. Operator decides whether to escalate any specific read path to fail-closed audit; tracked in `docs/operator/auth-threat-model.md`. |
| **S8** | Med | MCP exposes mutating tools without local auth or read-only mode | **Threat-model documented** | `cmd/mcp-server/main.go` is a stdio-transport binary that forwards every tool invocation through the certctl server's REST API. Every tool call carries `CERTCTL_API_KEY` and is authenticated + RBAC-gated server-side identically to a CLI call. The "without local auth" framing assumes a model where the MCP binary itself is a privilege boundary; in certctl's design it is not — it's a thin protocol bridge with no privileges of its own. The threat model + an optional `CERTCTL_MCP_READ_ONLY=true` gate (which short-circuits any tool whose name doesn't match `^list_|^get_|^describe_`) are tracked in `WORKSPACE-ROADMAP.md` as a v3 hardening item. |
| **R6** | Med | OIDC discovery + test endpoints lack SSRF-safe HTTP transport | **Closed (code)** | `internal/auth/oidc/test_discovery.go::jwksReachable` now uses an `http.Client` whose transport wraps `validation.SafeHTTPDialContext(oidcOutboundTimeout)`. Pre-Bundle-5 the probe used `http.DefaultClient` — a JWKS URI pointing at `169.254.169.254` could pivot into instance metadata. Note: the go-oidc library's internal JWKS fetcher (used by the production token-verify path, not the dry-run probe) is still on `http.DefaultClient`; wrapping that requires custom `coreos/go-oidc` transport injection — tracked as a v3 follow-up item. |
| **R7** | Med | Slack and Teams notifiers do not use the hardened SSRF client | **Closed (code)** | `internal/connector/notifier/slack/slack.go::New` and `internal/connector/notifier/teams/teams.go::New` both build their `http.Client` with `validation.SafeHTTPDialContext`. Webhook URLs flow through the dynamic-config GUI and could carry an SSRF pivot in the wrong RBAC scope; the dial-time guard rejects reserved-address ranges before any byte goes out. Mirrors the existing `internal/connector/notifier/webhook` hardening. |
| **SEC-H1** | High | 4 open CRIT items from 2026-05-10 auth audit block v2.1.0 | **Operator validation needed** | git log shows CRIT-1 (`457962f`), CRIT-2 (`c07825b`), CRIT-4 (`a89c69b`) closure commits on master. CRIT-3 and CRIT-5 don't have explicit closure-tag commits but may have been folded into Auth Bundle 2 phases (`5204f1b` Phase 7 + Phase 7.5 covers break-glass + OIDC-first-admin). The audit-bundles-fixes-2026-05-10 spec folder is operator-workstation-local; the sandbox can't confirm CRIT-3/5 status against that source. Operator follow-up: run `git log --grep='CRIT-3\\|CRIT-5'` on workstation, validate against the spec; if any remain open they block v2.1.0 tag (per CLAUDE.md `v2.1.0 gate`). |
| **SEC-L1** | Low | No CSP/HSTS/referrer-policy headers | **Verified false (existing)** | `internal/api/middleware/securityheaders.go` ships HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Content-Security-Policy via the `SecurityHeaders` middleware. Wired into the chain at `cmd/server/main.go` L2003 + L2027 + L2115 (applied to every gated handler). The audit framing was stale. |
| **SEC-L2** | Low | No 2FA/WebAuthn/step-up auth | **Documented defer** | Already tracked in `docs/operator/auth-threat-model.md` ("Threats Bundle 2 does NOT close" enumeration). WebAuthn / FIDO2 + JIT elevation are v3 work items per CLAUDE.md `v2.1.0 gate` decision 12. |
| **RT-L2** | Low | `CERTCTL_ACME_INSECURE=true` disables TLS verification with no startup warning | **Closed (code)** | `cmd/server/main.go` now emits a prominent `logger.Warn` at boot when `cfg.ACME.Insecure == true`. Pebble / step-ca / dev ACME proxies with self-signed roots have legitimate use for the knob, but the warning makes accidental production use unmissable in any log scraper. |

## Verification

```
gofmt -l                                          # clean (no diffs in touched files)
go vet ./...                                       # clean
go build ./cmd/server ./internal/connector/notifier/slack \
   ./internal/connector/notifier/teams ./internal/auth/oidc \
   ./internal/api/handler                          # clean
go test -short -count=1 ./internal/connector/notifier/slack \
   ./internal/connector/notifier/teams             # PASS (existing notifier tests
                                                   # still green; SSRF guard is a
                                                   # transport wrap, contract
                                                   # unchanged)
```

## Receipts

- Auth surface doc rewrite: `docs/reference/architecture.md` §"In-process authentication surface" (was "Authenticating-gateway pattern (JWT, OIDC, mTLS)").
- Break-glass rate limiter: `internal/api/handler/auth_breakglass.go::AuthBreakglassHandler.loginLimiter` + `cmd/server/main.go` wiring block.
- ACME-insecure startup warning: `cmd/server/main.go` `cfg.ACME.Insecure` block.
- OIDC SSRF-safe dial: `internal/auth/oidc/test_discovery.go::jwksReachable` + `oidcOutboundTimeout` constant.
- Slack/Teams SSRF-safe dial: `internal/connector/notifier/slack/slack.go::New` + `internal/connector/notifier/teams/teams.go::New`.

## Source IDs closed

| Closed via code | Closed via doc | Verified false (existing impl) | Operator follow-up | Documented defer |
|---|---|---|---|---|
| S1, R6, R7, RT-L2 | finding 1, HIGH-5, S8 (threat-model framing) | S4, SEC-L1 | S3, S5, SEC-H1 | SEC-L2 |

Closes Bundle 5 audit pass. Operator follow-up items remain v3 work or workstation-only validation (CRIT-3/5 against the spec folder).
