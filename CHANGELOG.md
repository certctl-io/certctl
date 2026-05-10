# Changelog

## v2.1.0 — Auth Bundle 1: RBAC primitive ⚠️

> **SECURITY: AUDIT YOUR API KEYS.**
>
> Bundle 1 ships role-based authorization. Every existing API key
> configured via `CERTCTL_API_KEYS_NAMED` (or the legacy
> `CERTCTL_AUTH_SECRET`) is mapped to the **r-admin role on the first
> upgrade boot** so existing automation keeps working unchanged. Most
> keys do NOT need full admin power; downgrade them before tagging
> the next release.
>
> Recommended post-upgrade flow:
>
> ```bash
> # 1. List every key with its current role:
> certctl-cli auth keys list
>
> # 2. Walk an interactive prompt that downgrades each key:
> certctl-cli auth keys scope-down
>
> # 3. Or get a heuristic suggestion based on 30 days of audit history:
> certctl-cli auth keys scope-down --suggest
> certctl-cli auth keys scope-down --suggest --apply   # applies the suggestion
>
> # 4. Or drive scope-down from a JSON config (Helm post-upgrade hook):
> certctl-cli auth keys scope-down --non-interactive ./scope-down.json
> ```
>
> The synthetic `actor-demo-anon` actor (used when
> `CERTCTL_AUTH_TYPE=none` is configured) is system-managed and
> excluded from the prompt loop.

What else changed in v2.1.0:

- **RBAC primitive shipped.** `tenants`, `roles`, `permissions`,
  `role_permissions`, `actor_roles` tables (migration 000029); 33-permission
  canonical catalogue; 7 default roles (`admin`, `operator`, `viewer`,
  `agent`, `mcp`, `cli`, `auditor`); per-handler permission gates via
  `auth.RequirePermission` middleware (replaces the legacy
  `IsAdmin` boolean check on the 5 admin-only handlers).
- **Day-0 admin bootstrap.** Set `CERTCTL_BOOTSTRAP_TOKEN` on a fresh
  deploy and POST a single curl call against `/api/v1/auth/bootstrap` to
  mint the first admin API key; one-shot, never logged, and locks
  closed once any admin actor exists. Migration 000031 ships the
  `api_keys` table that stores the SHA-256 hash; the plaintext is
  shown in the response body once and never persisted.
- **Auditor role split.** New `auditor` role holds only `audit.read`
  + `audit.export`. Compliance reviewers can read the audit trail
  without holding mutation power. Migration 000032 adds
  `audit_events.event_category` so auditors can filter to
  authentication-related events specifically.
- **`/v1/auth/check` enrichment.** Response now includes the actor's
  standing roles and effective permissions, so the GUI gates
  affordances from a single fetch on app boot.
- **Approval-bypass closure.** Edits to a profile that has (or
  would have) `RequiresApproval=true` now route through the
  `ApprovalService` two-person integrity gate (Phase 9). Migration
  000033 adds `approval_kind` + `payload` to
  `issuance_approval_requests` so cert-issuance and profile-edit
  approvals share the same workflow. Same-actor self-approve is
  rejected with `ErrApproveBySameActor` for both kinds. Closes the
  flip-flop loophole where an admin could disable approval, mutate,
  re-enable. Documented at
  [`docs/reference/profiles.md`](docs/reference/profiles.md).
- **GUI: Roles / API Keys / Auth Settings / Approvals queue.**
  Four new pages under `/auth/*` consume `/v1/auth/me` for
  permission-aware rendering. The Approvals queue blocks
  self-approve at the client layer (Approve/Reject buttons hidden
  when requested_by == current actor_id) on top of the server-side
  enforcement. AuditPage gains a category filter (cert_lifecycle /
  auth / config) for the auditor view.
- **MCP server gains 12 RBAC tools.** Operators driving certctl
  from Claude / VS Code / any MCP client get parity with the GUI
  + CLI. Each tool routes through the same HTTP handler; permission
  gates fire server-side.
- **OpenAPI catalogues every new route.** Every Bundle 1 endpoint
  ships with an `operationId`; the parity test guards against drift.
- **Coverage gates.** `internal/auth/` and `internal/service/auth/`
  now have ≥85% coverage floors in `.github/coverage-thresholds.yml`.
  The 12-path negative-test list from the Bundle 1 prompt is
  fully covered (path #12 deferred with in-tree TODO).
- **Protocol-endpoint allowlist pinned at three layers.** The
  middleware bypass (`auth.IsProtocolEndpoint`), the router-level
  `AuthExemptRouterRoutes` constant, and a new
  `phase12_protocol_allowlist_test.go` AST scan all guard against
  accidentally wrapping ACME / SCEP / EST / OCSP / CRL routes in
  `rbacGate`.
- **Bundle 2 (OIDC + sessions) starts after Bundle 1 lands on
  master.** Roadmap entry remains in `cowork/auth-bundle-2-prompt.md`.

Migration ordering, idempotency, and downgrade are documented in
[`docs/migration/api-keys-to-rbac.md`](docs/migration/api-keys-to-rbac.md).
The threat model + compliance mapping live at
[`docs/operator/auth-threat-model.md`](docs/operator/auth-threat-model.md).
Day-2 RBAC operations live at
[`docs/operator/rbac.md`](docs/operator/rbac.md).

## v2.0.68 — Image registry path changed ⚠️

> **Image registry path changed.** Starting this release, container images publish to `ghcr.io/certctl-io/certctl-server` and `ghcr.io/certctl-io/certctl-agent`. Existing pulls from `ghcr.io/shankar0123/certctl-{server,agent}:<tag>` continue to work for previously-published tags (the registry never deletes images), but the `:latest` tag at the old path stops moving forward at this release. Update your `docker pull` paths, `docker-compose.yml` `image:` keys, or Helm `image.repository` values to receive future updates. Old `git clone` / `git push` / install-script / API URLs continue to redirect forever — only the container-registry path changed.

This is the only operator-action-required change in v2.0.68. Other changes in this release are cosmetic URL refreshes after the GitHub-org transfer from `shankar0123/certctl` to `certctl-io/certctl` (HTTP redirects mean no other operator action is required) plus an internal contextcheck lint fix in the agent. Full commit list is on the [GitHub release page](https://github.com/certctl-io/certctl/releases/tag/v2.0.68).

---

certctl no longer maintains a hand-edited per-version changelog. Per-release
notes are auto-generated from commit messages between consecutive tags.

**Where to find what changed in a given release:**

- **[GitHub Releases](https://github.com/certctl-io/certctl/releases)** — every
  tag has an auto-generated "What's Changed" section pulled from the commits
  between that tag and the previous one, plus per-release supply-chain
  verification instructions (Cosign / SLSA / SBOM).
- **`git log <prev-tag>..<this-tag> --oneline`** — same content, locally.

**Why no hand-edited CHANGELOG.md:**

certctl is solo-developed and pushes directly to master. Maintaining a
hand-edited CHANGELOG meant the file drifted (entries piled into
`[unreleased]` and never got promoted to per-version sections when tags were
cut). A stale CHANGELOG is worse than no CHANGELOG — it signals abandoned
maintenance to security-conscious operators doing diligence.

The auto-generated release notes work here because commit messages follow a
descriptive convention: `<area>: <summary>` with a longer body for non-trivial
changes (see `git log v2.0.50..HEAD` for the established pattern). Anyone
reading the GitHub Releases page can see exactly what landed in each version
without depending on the author to manually update a separate file.

**For the historical record:** earlier versions (pre-v2.2.0 and the [2.2.0]
tag itself) had a hand-edited CHANGELOG. That content is preserved in
[git history](https://github.com/certctl-io/certctl/blob/v2.2.0/CHANGELOG.md)
at the v2.2.0 tag.
