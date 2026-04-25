# Changelog

All notable changes to certctl are documented in this file. Dates use ISO 8601. Versions follow [Semantic Versioning](https://semver.org/).

## [unreleased] — 2026-04-25

### H-1: Security hardening trio — closed end-to-end

> Three 2026-04-24 audit findings (all P2) that together complete the HTTPS-Everywhere security baseline. The audit flagged: (1) the unauth surface (EST RFC 7030, SCEP, PKI CRL/OCSP, /health, /ready) accepted arbitrary-size request bodies because the `noAuthHandler` middleware chain was missing the `bodyLimitMiddleware` that the authed `apiHandler` chain has; (2) zero security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) were emitted on any response — enabling clickjacking, MIME-sniffing, and untrusted-origin resource loads against the dashboard and API; (3) `CERTCTL_CONFIG_ENCRYPTION_KEY` was accepted with any non-empty value, including a single character — PBKDF2-SHA256 with 100k rounds does not compensate for low-entropy passphrases at scale (CWE-916 / CWE-329).

### Breaking Changes

**Operators with low-entropy `CERTCTL_CONFIG_ENCRYPTION_KEY` will fail to start after upgrade.** Pre-H-1 the field accepted any non-empty string. Post-H-1 it requires ≥32 bytes (e.g. `openssl rand -base64 32`). The startup error names the offending env var, the actual length, the required minimum, and the canonical generation command. Empty (`""`) remains accepted — the existing fail-closed sentinel `crypto.ErrEncryptionKeyRequired` triggers downstream when an empty key tries to encrypt or decrypt. Operators using a short passphrase must rotate before the upgrade.

### Added

- **`internal/api/middleware/securityheaders.go`** (new) — `SecurityHeaders` middleware applies HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and a conservative Content-Security-Policy on every response. Defaults via `SecurityHeadersDefaults()` are: `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer-when-downgrade`, and `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'`. Operators behind a customising reverse proxy can override per-header by setting any field of the config struct to the empty string (omits that header).
- **`bodyLimitMiddleware` wired into `noAuthHandler`** in `cmd/server/main.go`. Same default cap (1 MB, configurable via `CERTCTL_MAX_BODY_SIZE`), same 413 response on overflow. Pre-H-1 only the authed surface had this protection.
- **`securityHeadersMiddleware` wired into BOTH chains** (`middlewareStack` for authed routes; `noAuthHandler` for unauth routes). Applied before the audit middleware so headers reach 4xx/5xx responses too — critical for security posture (an attacker probing for misconfiguration sees the same headers on a 401 as on a 200).
- **`CERTCTL_CONFIG_ENCRYPTION_KEY` length validation** in `internal/config/config.go::Validate()` — rejects keys shorter than 32 bytes with a structured error naming the actual length, the required minimum, and the canonical generation command. Empty keys remain accepted (downstream fail-closed sentinel handles it).
- **Tests:** `internal/api/middleware/securityheaders_test.go` (4 cases — defaults present, empty disables single header, override applied, headers on 4xx/5xx). `internal/config/config_test.go` adds 5 cases for the encryption-key length check (empty accepted, 1-byte rejected, 31-byte rejected at boundary, 32-byte accepted, 44-byte realistic operator key accepted).

### Audit findings closed

- `cat-s5-4936a1cf0118` (P2, EST/SCEP/PKI unauth endpoints bypass `http.MaxBytesReader`)
- `cat-s11-missing_security_headers` (P2, no CSP / HSTS / X-Frame-Options on responses)
- `cat-r-encryption_key_no_length_validation` (P2, encryption key accepted with zero entropy validation)

### Known follow-ups (deferred from H-1 scope)

A weak-key dictionary check (reject `password123`, common ASCII patterns) is deferred — adds operational friction with low marginal entropy gain at the 32-byte minimum. CSP `'unsafe-inline'` for styles is required because Tailwind via Vite injects per-component `<style>` blocks at build time; removing it would require an HTML report or component refactor outside H-1 scope. A `Permissions-Policy` (formerly Feature-Policy) header is not in the H-1 baseline because the dashboard uses no advanced browser APIs (camera, microphone, geolocation); deferred until a real consumer needs it.

### D-2: TS ↔ Go type drift cluster — closed end-to-end

> The 2026-04-24 coverage-gap audit flagged five `diff-05x06-*` findings — every one a TypeScript-vs-Go shape mismatch where the on-wire JSON the backend emits and the TS interface in `web/src/api/types.ts` had drifted apart. D-1 master closed the same pattern for `Certificate` (cat-f-ae0d06b6588f, 5 phantom fields trimmed, plus the cat-f-cert_detail_page_key_render_fallback render-site fix). D-2 closes it for the remaining five entities: Agent, Target, DiscoveredCertificate, Issuer, and Notification. The audit's blunt rule "stricter side is the contract" decides the per-entity verdict — for TS phantoms (fields declared on TS, never emitted by Go) the Go side wins and TS gets trimmed; for TS-missing fields (emitted by Go, absent from TS) the Go side still wins and TS gets the addition. Pre-D-2 the failure modes were: phantom fields silently rendered `'—'` at consumer sites (e.g. AgentDetailPage's "Capabilities" + "Tags" sections always rendered empty; IssuersPage rendered `'Unknown'` for every issuer; NotificationsPage's `n.message || n.subject` fallback always fell through), and missing fields forced `(target as any).retired_at` escapes that lost type-checking. Verify-only side task: Certificate / ManagedCertificate confirmed clean since D-1.

### Breaking Changes

None on the wire. The JSON the backend emits is byte-identical pre/post-D-2 — D-2 is purely TS-side reconciliation. The interface shapes change in ways that are TypeScript compile errors at consumer sites that read trimmed phantoms (intentionally — that's the closure mechanism) but no operator-visible behaviour shifts.

### Added

- `Target` interface gains `retired_at?: string | null` and `retired_reason?: string | null` (mirrors the Agent retirement-fields shape and the Go-side `internal/domain/connector.go::DeploymentTarget` I-004 model). An Agent retire cascades to all associated Targets per `service.RetireAgent → repository.RetireTarget`; the GUI can now type-check the retired-state surfacing without `(target as any).retired_at` escapes.
- `DiscoveredCertificate` interface gains `pem_data?: string`. The Go-side struct (`internal/domain/discovery.go::DiscoveredCertificate.PEMData`, `omitempty`) emits this field on the wire — populated by the agent filesystem scanner, the cloud-secret-manager connectors, and the repo SELECT. Optional because Go uses `omitempty`. Consumers can now reach the raw PEM with type-checked code.
- **CI regression guardrail extension** in `.github/workflows/ci.yml` (renamed `Forbidden StatusBadge dead-key + TS phantom-field regression guard (D-1 + D-2)`) — adds three new awk-windowed greps over the Agent / Issuer / Notification interfaces in `types.ts` that fail the build if any of the trimmed phantom fields reappear. The Agent regex `\b(last_heartbeat|capabilities|tags|created_at|updated_at)\b` is paired with a `grep -v 'last_heartbeat_at'` filter to avoid false positives on the legitimate Go-emitted heartbeat field.

### Removed

- `Agent` interface — 5 phantom fields trimmed: `last_heartbeat`, `capabilities`, `tags`, `created_at`, `updated_at`. None emitted by `internal/domain/connector.go::Agent`. Two had real consumers in `AgentDetailPage.tsx` (capabilities + tags sections) — both were removed because their guards always evaluated false. The "Updated" InfoRow that read `agent.updated_at` was also dropped (Go has no equivalent timestamp on Agent). `last_heartbeat_at` flipped from required to optional to match Go's `*time.Time omitempty`.
- `Issuer` interface — phantom `status: string` removed. Go has only `Enabled bool`. Both `IssuersPage.tsx::issuerStatus` and `IssuerDetailPage.tsx::issuerStatus` rewritten to compute `i.enabled ? 'Enabled' : 'Disabled'` exclusively (the pre-D-2 fallback `issuer.status || 'Unknown'` always rendered 'Unknown').
- `Notification` interface — phantom `subject?: string` removed. The dead `{n.message || n.subject}` fallback at `NotificationsPage.tsx:241` was simplified to `{n.message}`. Test mocks in `NotificationsPage.test.tsx` no longer set the field.

### Audit findings closed

- diff-05x06-7cdf4e78ae24 (P2, Agent TS↔Go drift)
- diff-05x06-2044a46f4dd0 (P2, Target TS↔DeploymentTarget Go drift)
- diff-05x06-85ab6b98a2f7 (P2, DiscoveredCertificate TS↔Go drift)
- diff-05x06-97fab8783a5c (P2, Issuer TS↔Go drift)
- diff-05x06-caba9eb3620e (P2, Notification TS↔NotificationEvent Go drift)
- diff-05x06-af18a8d7ef41 (P2, Certificate / ManagedCertificate) — verified no residual drift since D-1; no edit required

### Known follow-ups (deferred from D-2 scope)

A richer Issuer status view that derives from `enabled × test_status` (instead of `enabled` alone) is deferred — a UX scope decision, not a contract drift, and the existing `test_status: 'untested' | 'success' | 'failed'` field is already on the TS interface for whoever picks up that work. Real Agent metadata fields (capabilities advertised at heartbeat time, operator-applied tags) are deferred — D-2 removed the false UI affordance; if/when the product wants real fields, re-introduce in `AgentDetailPage` in the same commit that ships the Go-side change. The `DiscoveredCertificate.pem_data` LIST-response performance optimization (gate emission on the per-id detail path, since pem_data is kilobytes per row) is deferred as a separate backend change — D-2 only closed the contract drift.

### B-1: Orphan-CRUD client functions + RenewalPolicy GUI gap — closed end-to-end

> The 2026-04-24 coverage-gap audit flagged a cluster of operator-blocking GUI omissions: six client.ts `update*` functions (`updateOwner`, `updateTeam`, `updateAgentGroup`, `updateIssuer`, `updateProfile`, plus the full `*RenewalPolicy` CRUD trio) had backend handlers, OpenAPI operations, and exported TypeScript fetchers — but zero page consumers. Operators wanting to fix a typo in an owner's email, rename a team, retarget an agent group's match rules, or edit a renewal-policy field were forced to either delete-and-recreate (losing FK history and audit-trail continuity) or open a `psql` session against the production database directly. The audit's blunt summary: "every backend feature ships with its GUI surface" — a load-bearing CLAUDE.md invariant — was being violated for five operator-facing entities. B-1 closes that violation by wiring per-page Edit modals onto five existing pages, adding a brand-new `RenewalPoliciesPage` for the rp-* CRUD surface, and deleting one dead duplicate (`exportCertificatePEM`) so the public client surface area stops growing without consumers.

### Breaking Changes

None. All five existing pages keep their Create + Delete affordances unchanged; Edit is purely additive. `RenewalPoliciesPage` is a new route at `/renewal-policies` and a new sidebar nav item slotted between Policies and Profiles. The `exportCertificatePEM` helper had zero consumers in `web/`, MCP, CLI, and tests at the time of removal — operators using `downloadCertificatePEM` (the actual call site in `CertificateDetailPage`) are unaffected.

### Added

- **`web/src/pages/RenewalPoliciesPage.tsx`** — a new full-CRUD page for the `rp-*` renewal-policy table. Surfaces a 7-column DataTable (Policy / Renewal Window / Auto / Retries / Alert Thresholds / Created / Actions) with Create, Edit, and Delete affordances. A shared `PolicyFormModal` powers both Create and Edit (the form shape is identical) covering the full domain field set: `name`, `renewal_window_days`, `auto_renew`, `max_retries`, `retry_interval_seconds`, `alert_thresholds_days[]`. The thresholds input parses comma-separated integers (`30, 14, 7, 0`) into the array shape the backend expects. Delete surfaces `repository.ErrRenewalPolicyInUse` (409 from the backend when a policy still has `managed_certificates.renewal_policy_id` references) via an explicit alert so the operator can re-target the dependent certs to a different policy before deletion. Wired into `web/src/main.tsx` routing and `web/src/components/Layout.tsx` sidebar nav.
- **EditOwnerModal** in `web/src/pages/OwnersPage.tsx` — pre-populates from the editing owner via `useEffect`, calls `updateOwner(id, {name, email, team_id})`, mirrors the Create modal's TanStack-Query mutation/invalidation pattern.
- **EditTeamModal** in `web/src/pages/TeamsPage.tsx` — same shape, fields `name`/`description`.
- **EditAgentGroupModal** in `web/src/pages/AgentGroupsPage.tsx` — covers the full match-rule set (`name`, `description`, `match_os`, `match_architecture`, `match_ip_cidr`, `match_version`, `enabled`).
- **EditIssuerModal** in `web/src/pages/IssuersPage.tsx` — deliberately rename-only. The `type` field is shown but disabled, the existing `config` blob (which includes credentials for ACME, ADCS, ZeroSSL, etc.) is forwarded untouched, and only `name` is editable. Footer note: "To change issuer type or rotate credentials, delete and recreate." This trades scope for safety — the audit's destructive-rename complaint is closed without surfacing a credential-edit attack surface that has not been threat-modeled.
- **EditProfileModal** in `web/src/pages/ProfilesPage.tsx` — same rename-only shape. Forwards full `Partial<CertificateProfile>` with policy fields (`allowed_key_algorithms`, `max_ttl_seconds`, `allowed_ekus`, etc.) preserved untouched. Footer note about deferred policy-field editing.
- **CI regression guardrail** in `.github/workflows/ci.yml` (`Forbidden orphan-CRUD client function regression guard (B-1)`) — grep-fails the build if any of the eight previously-orphan client functions (`updateOwner`, `updateTeam`, `updateAgentGroup`, `updateIssuer`, `updateProfile`, `createRenewalPolicy`, `updateRenewalPolicy`, `deleteRenewalPolicy`) loses its non-test consumer under `web/src/pages/`. Also blocks resurrection of the deleted `exportCertificatePEM` function. Verified locally on the post-fix tree (passes — all 8 fns have ≥2 consumers); fires against synthetic regressions (delete the Edit modal → guardrail fires the next CI run).

### Removed

- `web/src/api/client.ts::exportCertificatePEM` — closes `cat-b-9b97ffb35ef7`. The function returned `{cert_pem, chain_pem, full_pem}` JSON but had zero consumers across `web/`, MCP, CLI, and tests; `downloadCertificatePEM` (the blob-download path consumed by `CertificateDetailPage`) covers all real call sites. Test references in `web/src/api/client.test.ts` and `client.error.test.ts` were also removed. The CI guardrail blocks resurrection without an accompanying page consumer.

### Audit findings closed

- `cat-b-31ceb6aaa9f1` (P1, `updateOwner`/`updateTeam`/`updateAgentGroup` orphan)
- `cat-b-7a34f893a8f9` (P1, `updateIssuer`/`updateProfile` orphan, rename-only closure)
- `cat-b-4631ca092bee` (P1, RenewalPolicy CRUD orphan — new RenewalPoliciesPage)
- `cat-b-9b97ffb35ef7` (P3, `exportCertificatePEM` dead duplicate)

### Known follow-ups (deferred from B-1 scope)

A fuller `EditIssuerModal` with explicit credential-rotation flow is deferred — that needs an explicit threat model (rotation reuse window, audit-trail granularity, in-flight CSR cancellation), and the audit's destructive-rename complaint is closed by rename-only Edit alone. Likewise an `EditProfileModal` with policy-field editing (max-TTL, allowed EKUs, allowed key algorithms) is deferred because policy edits affect the `enforce_certificate_policy` evaluator's semantics for already-issued certs and warrant their own scope. Per-page Vitest coverage for the new Edit modals is deferred — the CI grep guardrail catches the same regression vector ("page lost its `update*` fn consumer") at lower cost than five new test files.

### L-1: Client-side bulk-action loops — closed end-to-end

> The certctl dashboard's busiest screen (`CertificatesPage.tsx`) had two bulk-action workflows that looped per-cert HTTP calls. Selecting 100 certs and clicking "Renew" issued 100 sequential `POST /api/v1/certificates/{id}/renew` requests; "Reassign owner" issued 100 sequential `PUT /api/v1/certificates/{id}` requests. Each round-trip carried ~50–200 ms of Auth → audit-log → handler → service → repo → DB → audit-write → response, so a 100-cert bulk action was a 5–20-second wedge during which the operator stared at a progress bar. The bulk-revoke endpoint (`POST /api/v1/certificates/bulk-revoke`) already shipped in v2.0.x as the canonical pattern for this; L-1 ports that exact shape to bulk-renew (P1) and bulk-reassign (P2). One backend round-trip; one audit event for the entire operation; per-cert success/skip/error counts in a single response envelope. Bundled with two new MCP tools and an OpenAPI spec update so non-GUI callers (CLI / MCP / blackbox probes) can use the same endpoints.

### Breaking Changes

None. Both endpoints are additive; the per-cert `POST /certificates/{id}/renew` and `PUT /certificates/{id}` paths remain available and unchanged. The frontend implementation switches from looping to single-call, but operators with custom GUIs hitting the per-cert endpoints continue to work.

### Added

- **`POST /api/v1/certificates/bulk-renew`** — enqueues a renewal job for every matching managed certificate. Supports criteria-mode (`{profile_id, owner_id, agent_id, issuer_id, team_id}`) and explicit-IDs mode (`{certificate_ids}`). Mirrors `BulkRevokeCriteria` field-for-field (sans the RFC-5280 reason code). Returns `{total_matched, total_enqueued, total_skipped, total_failed, enqueued_jobs[], errors[]}`. NOT admin-gated — bulk renewal is non-destructive (worst case it kicks off some redundant ACME orders). Status filter: certs in `Archived/Revoked/Expired/RenewalInProgress` are silent-skipped (TotalSkipped++) rather than returned as errors. Implementation: `internal/domain/bulk_renewal.go`, `internal/service/bulk_renewal.go`, `internal/api/handler/bulk_renewal.go`.
- **`POST /api/v1/certificates/bulk-reassign`** — updates `owner_id` (required) and `team_id` (optional) on every cert in `certificate_ids`. Skips certs already owned by the target (silent no-op surfaced as `total_skipped`). Validates the target `owner_id` upfront — a non-existent owner returns 400 (via the typed `service.ErrBulkReassignOwnerNotFound` sentinel) before any cert is touched. NOT admin-gated. Implementation: `internal/domain/bulk_reassignment.go`, `internal/service/bulk_reassignment.go`, `internal/api/handler/bulk_reassignment.go`.
- **MCP tools `certctl_bulk_renew_certificates` and `certctl_bulk_reassign_certificates`** in `internal/mcp/tools.go` + `internal/mcp/types.go`. Mirror the existing `certctl_bulk_revoke_certificates` shape so MCP consumers have a uniform bulk-action surface.
- **OpenAPI schemas** `BulkRenewRequest`, `BulkRenewResult`, `BulkEnqueuedJob`, `BulkReassignRequest`, `BulkReassignResult` plus the two new operations with shared envelope semantics.
- **Frontend client functions** `bulkRenewCertificates(criteria)` and `bulkReassignCertificates(request)` in `web/src/api/client.ts` with full TS types for both request and response envelopes.
- **Service-layer regression tests** for both new services (`internal/service/bulk_renewal_test.go` + `internal/service/bulk_reassignment_test.go`): happy path, criteria-mode, status-skip semantics (RenewalInProgress / Revoked / Archived for renew; already-owned for reassign), empty-criteria rejection, partial-failure tolerance, single-bulk-audit-event contract.
- **Handler-layer regression tests** (`internal/api/handler/bulk_renewal_handler_test.go` + `internal/api/handler/bulk_reassignment_handler_test.go`): happy path, empty-body 400, wrong-method 405, actor attribution from `middleware.GetUser`, owner-not-found-sentinel-→-400 mapping for reassign, generic-service-error-→-500.
- **Domain-layer JSON-shape tests** pinning the wire contract for `BulkRenewalResult` / `BulkReassignmentResult` / `BulkOperationError`.
- **CI regression guardrail** in `.github/workflows/ci.yml` (`Forbidden client-side bulk-action loop regression guard (L-1)`) — grep-fails the build if `for(...) await triggerRenewal(...)` or `for(...) await updateCertificate(...)` reappears in `web/src/pages/CertificatesPage.tsx`. Verified: passes against the post-fix tree, fires against synthetic regressions.

### Changed

- **`web/src/pages/CertificatesPage.tsx::handleBulkRenewal`** — rewritten from N-call loop to a single `bulkRenewCertificates({ certificate_ids })` call. Result envelope drives the progress UI (matched / enqueued / skipped / failed counts).
- **`web/src/pages/CertificatesPage.tsx::handleReassign`** (in the reassign modal) — same shape: single `bulkReassignCertificates({ certificate_ids, owner_id })` call. First-error message surfaced when `total_failed > 0`.
- **`internal/api/router/router.go`** — three bulk-* routes (revoke / renew / reassign) registered together as a block before the per-cert `{id}` routes; `HandlerRegistry` gains `BulkRenewal` and `BulkReassignment` fields.
- **`cmd/server/main.go`** — constructs `BulkRenewalService` (threads `cfg.Keygen.Mode` so bulk-renew jobs land in the same initial status as single-cert `TriggerRenewal`) and `BulkReassignmentService` alongside the existing `BulkRevocationService`.

### Performance impact

100-cert bulk-renew workflow goes from ~10 s of sequential per-cert HTTP (worst case) to a single ~100 ms call — roughly 99% latency reduction on the canonical operator workflow. Server-side resource use also drops: one Auth pass, one audit event, one criteria-resolution query, instead of N of each.

### Closed audit findings

- `cat-l-fa0c1ac07ab5` (P1, primary) — bulk renew client-side sequential loop
- `cat-l-8a1fb258a38a` (P2) — bulk owner-reassign client-side sequential loop

### Known follow-ups (deferred from L-1 scope)

- `cat-b-31ceb6aaa9f1` (P1, `updateOwner`/`updateTeam`/`updateAgentGroup` orphan) — different shape; the fix is "wire up the existing PUT endpoints to the GUI", not "add a bulk endpoint".
- `cat-k-e85d1099b2d7` (P2, CertificatesPage no pagination UI) — same page; criteria-mode bulk-renew (`{owner_id: 'o-alice'}`) means an operator can already "renew all of Alice's certs" without paginating, but pagination is still wanted for the table view.
- `cat-i-b0924b6675f8` (P1, MCP missing `claim`/`dismiss`/`acknowledge`) — L-1 added two new MCP tools but does NOT close that finding.

### D-1: StatusBadge enum drift + Certificate phantom fields — closed end-to-end

> The dashboard silently lied in five places. Agents in the `Degraded` state (the only Go-side AgentStatus that means "needs operator attention") rendered as default neutral grey because StatusBadge mapped `Stale` (a key Go has never emitted) to yellow and let the real `Degraded` value fall through to the dictionary default. Dead-letter notifications (`status: 'dead'`, retries exhausted) rendered as default neutral, visually equated with `read` (operator-acknowledged). The Certificate badge map carried a `PendingIssuance` key that no Go enum value ever emits — dead key, latent confusion vector. CertificateDetailPage's Key Algorithm and Key Size rows always rendered `—` even when the data was a single fetch away, because the lookup went through `cert.key_algorithm` directly — and the underlying `Certificate` TypeScript interface declared five optional fields (`serial_number`, `fingerprint_sha256`, `key_algorithm`, `key_size`, `issued_at`) that Go's `ManagedCertificate` has never carried (those values live on `CertificateVersion`). Five findings, two files, one frontend rebuild. Pre-D-1 the only reason this didn't trip a regression suite was that the regression suite never asserted "every Go-emitted enum value gets a non-default StatusBadge class" — D-1 fixes the visual lies and adds a 38-case Vitest property test that walks every Go enum and pins the contract.

### Breaking Changes

- **`Certificate` TypeScript interface no longer declares `serial_number?`, `fingerprint_sha256?`, `key_algorithm?`, `key_size?`, or `issued_at?`.** The Go `ManagedCertificate` (`internal/domain/certificate.go`) has never emitted these fields on list responses; they live on `CertificateVersion` and are reachable via `getCertificateVersions(id)`. Pre-D-5 (the cat-f phantom-fields finding) the optional declarations made `cert.X` always-undefined on lists, and downstream consumers silently rendered `—` for every cert. Post-D-5 a `cert.X` access for any of the five fields is a TypeScript compile error, forcing every consumer to acknowledge the version-fallback pattern. The OpenAPI `ManagedCertificate` schema was already correct — only the TS type was drifted.
- **StatusBadge no longer maps `Stale` (Agent) or `PendingIssuance` (Certificate).** Both were dead keys — no Go enum value emits them. Operators with custom CSS hooked off `.badge-warning` for `Stale` will see the same color come back via the new `Degraded` mapping (same class), but JS/TS code that switches on the literal `'Stale'` will need to switch on `'Degraded'` instead. The `PendingIssuance` deletion has no documented downstream consumer.

### Added

- **`web/src/components/StatusBadge.tsx`: `Degraded` (Agent) → `badge-warning` and `dead` (Notification) → `badge-danger`.** First mappings restore the color contract for the two real Go-side values that previously fell through to the dictionary default. The `Degraded` mapping cross-references `internal/domain/connector.go::AgentStatusDegraded`; the `dead` mapping cross-references `internal/domain/notification.go::NotificationStatusDead`.
- **`web/src/components/StatusBadge.test.tsx`: 38-case Vitest property test.** Iterates every Go-side enum value (`AgentStatus`, `CertificateStatus`, `JobStatus`, `NotificationStatus`, `DiscoveryStatus`, `HealthStatus`) plus the two frontend-synthesized `Enabled`/`Disabled` labels, asserts every value gets a non-default class (or, for the five intentionally-neutral terminal values like `Archived`/`Cancelled`/`read`, an explicit `badge badge-neutral`). Includes negative assertions on the deleted `Stale` and `PendingIssuance` keys (must fall through to neutral) and specific UX-correctness assertions on the operator-attention semantics (`dead` → danger, `Degraded` → warning).
- **`web/src/api/types.test.ts`: D-5 Certificate phantom-fields trim regression.** A `Certificate` literal construction pinned post-trim, plus a sibling `CertificateVersion` literal pinning that the trimmed fields still live on the version envelope. The `tsc --noEmit` gate in CI is the primary enforcement; the test is the documentation of intent.
- **CI regression guardrail in `.github/workflows/ci.yml` (`Forbidden StatusBadge dead-key + Certificate phantom-field regression guard (D-1)`).** Two grep blocks: (1) catches `Stale: 'badge-...'` or `PendingIssuance: 'badge-...'` in `web/src/components/StatusBadge.tsx`; (2) uses an awk-scoped window over the `export interface Certificate {` block in `web/src/api/types.ts` to catch any of the five phantom fields reappearing — explicitly excludes the `CertificateVersion` block which legitimately carries them. Verified locally on the post-fix tree (passes) and against synthetic regressions (each fires the guardrail).

### Changed

- **`web/src/pages/CertificateDetailPage.tsx`: Key Algorithm and Key Size rows now read from `latestVersion?.key_algorithm` / `latestVersion?.key_size`.** Mirrors the existing `latestVersion` fallback used for `serial_number` and `fingerprint_sha256` earlier in the same file. Pre-D-4 these rows accessed `cert.key_algorithm` and `cert.key_size` directly — both phantom fields per D-5 — so the rows always rendered `—`. The same file's `serial_number` / `fingerprint_sha256` / `issued_at` derivations were also simplified to drop the now-impossible `cert.X || latestVersion?.X` cert-side leg.
- **`web/src/components/StatusBadge.tsx` adds a leading docblock** naming the Go-side source-of-truth file for every status family it maps (`AgentStatus`, `CertificateStatus`, `JobStatus`, `NotificationStatus`, `DiscoveryStatus`, `HealthStatus`) and pointing at the property test as the regression vector for future enum changes.
- **`api/openapi.yaml::ManagedCertificate`** gets a leading comment cross-referencing the D-5 closure and explaining why per-issuance fields legitimately don't appear here (they live on `CertificateVersion`). Schema property list unchanged — the OpenAPI spec was already correct.

### Closed audit findings

- `cat-d-359e92c20cbf` (P1 primary) — Agent: `Stale` dead key + `Degraded` neutral fallthrough
- `cat-d-9f4c8e4a91f1` (P2) — Notification: `dead` missing
- `cat-d-1447e04732e7` (P3) — Certificate: `PendingIssuance` dead key
- `cat-f-cert_detail_page_key_render_fallback` (P2) — render-site uses `cert.key_algorithm` directly
- `cat-f-ae0d06b6588f` (P2) — Certificate TS phantom fields (root cause)

### Known follow-ups (deferred from D-1 scope)

The audit's broader type-drift cluster (`diff-05x06-7cdf4e78ae24` Agent TS, `diff-05x06-2044a46f4dd0` DeploymentTarget TS, `diff-05x06-caba9eb3620e` Notification TS, `diff-05x06-85ab6b98a2f7` DiscoveredCertificate TS, `diff-05x06-97fab8783a5c` Issuer TS) is out of D-1 scope. Recon for those is per-type field-by-field diff Go ↔ TS — codegen-shaped, not edit-shaped — and warrants its own D-2 master prompt.

### U-3: GitHub #10 reopened — fresh-clone first-up postgres init failure (P1) — closed end-to-end

> Operator `mikeakasully` cloned v2.0.50 fresh, ran the canonical quickstart `docker compose -f deploy/docker-compose.yml up -d --build`, and postgres reported `unhealthy` indefinitely; dependent containers (certctl-server, certctl-agent) never started. Root cause: the deploy compose stack mounted both a hand-curated subset of `migrations/*.up.sql` and `seed.sql` into postgres `/docker-entrypoint-initdb.d/`. Postgres applied them at initdb time. Once `seed.sql` referenced columns added by migrations *after* the mounted cutoff (e.g., `policy_rules.severity` from migration 000013, which the mount list never included), initdb crashed mid-seed and the container loop wedged. Two sources of truth — the mount list and the in-tree migration ladder — diverged the moment a seed-touching migration shipped, and the only thing that fixed it was hand-editing the compose file every release. The U-3 closure removes the dual source: postgres now boots empty and the server applies the entire migration ladder + seed at startup via `RunMigrations` + `RunSeed`. Same pattern Helm has used since day one. Bundled with four ride-along audit findings whose fixes are in adjacent code (column rename, missing column, dropped orphan columns, new build-identity endpoint) so operators take the schema-change pain only once.

### Breaking Changes

- **`deploy/docker-compose.yml` postgres no longer initdb-mounts the migration files or `seed.sql`.** Operators running on a populated `postgres_data` volume from a pre-U-3 release see no behavioral change (the schema is already in place; `RunMigrations` is `IF NOT EXISTS` and `RunSeed` is `ON CONFLICT DO NOTHING`). Operators running on a *fresh* clone now rely on the server to apply both — which is the bug fix. There is no rollback path other than re-introducing the dual-source-of-truth hazard. See `internal/repository/postgres/db.go::RunSeed` for the runtime contract.
- **`migrations/000017_db_coupling_cleanup.up.sql` renames `renewal_policies.retry_interval_minutes` → `retry_interval_seconds`.** The column always held seconds; the column name lied (`cat-o-retry_interval_unit_mismatch`). Operators running raw SQL against the old name need to update their queries. The Go layer (`internal/repository/postgres/renewal_policy.go`) is updated in lockstep so the in-tree code path is unaffected.
- **`migrations/000017_db_coupling_cleanup.up.sql` drops `network_scan_targets.health_check_enabled` and `network_scan_targets.health_check_interval_seconds`.** These columns were declared by a long-ago migration but never wired into Go code (`cat-o-health_check_column_orphans`) — schema noise that confused operators reading raw SQL. Anyone with custom dashboards selecting those columns will break.
- **The compose demo overlay (`deploy/docker-compose.demo.yml`) no longer initdb-mounts `seed_demo.sql`.** It now sets `CERTCTL_DEMO_SEED=true` and the server applies the demo seed at boot via `RunDemoSeed` after baseline migrations + seed.sql are in place. Same single-source-of-truth pattern as the production path.

### Added

- **Migration `000017_db_coupling_cleanup`** (up + down). Bundles three schema changes in idempotent SQL: (1) rename `renewal_policies.retry_interval_minutes` → `retry_interval_seconds` (DO $$ guard so re-application is safe), (2) add `notification_events.created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, (3) drop the orphan `network_scan_targets.health_check_*` columns. Reduces operator-visible "schema-change releases" from four to one.
- **`internal/repository/postgres.RunSeed`** — runtime equivalent of the deleted initdb mount for `seed.sql`. Called from `cmd/server/main.go` immediately after `RunMigrations`. Idempotent (every INSERT in the shipped seed uses `ON CONFLICT (id) DO NOTHING`); missing-file is a no-op so operators with custom packaging that strips the seed don't break.
- **`internal/repository/postgres.RunDemoSeed`** + **`config.DatabaseConfig.DemoSeed`** + **`CERTCTL_DEMO_SEED` env var.** Replaces the deleted `seed_demo.sql` initdb mount. The compose demo overlay sets `CERTCTL_DEMO_SEED=true` and the server applies the demo seed after baseline. Same idempotency contract as the baseline path. Default-off so a vanilla deploy never lands fake-history rows.
- **`GET /api/v1/version` endpoint** + **`internal/api/handler.VersionHandler`**. Returns `{version, commit, modified, build_time, go_version}` from `runtime/debug.ReadBuildInfo()` with ldflags-supplied `Version` taking priority. Wired through the no-auth dispatch in `cmd/server/main.go` so probes and rollout systems can read build identity without Bearer credentials. Audit middleware excludes the path so rollout polls don't dominate the audit trail. Closes `cat-u-no_version_endpoint`.
- **`notification_events.created_at` column** is now populated by `NotificationRepository.Create` (with a `time.Now()` fallback when the caller leaves it zero) and read back by `scanNotification`. Pre-U-3 the JSON API serialised `0001-01-01T00:00:00Z` — closes `cat-o-notification_created_at_dead_field`.
- **Five regression tests** for the U-3 contract: `TestRunSeed_AppliesIdempotently`, `TestRunSeed_MissingFileIsNoOp`, `TestRunDemoSeed_AppliesIdempotently`, `TestMigration000017_RetryIntervalRename`, `TestMigration000017_NotificationCreatedAt`, `TestMigration000017_HealthCheckOrphansDropped`, plus `TestNotificationRepository_CreatedAt_IsPersisted` / `TestNotificationRepository_CreatedAt_DefaultsToNow` for the round-trip. All testcontainers-gated (skipped under `-short`). Three handler-layer unit tests pin `/api/v1/version` (`TestVersion_ReturnsBuildInfo`, `TestVersion_RejectsNonGet`, `TestVersion_LdflagsOverride`).
- **CI regression guardrail** in `.github/workflows/ci.yml` (`Forbidden migration mount in compose initdb (U-3)`) — grep-fails the build if any `migrations/.*\.sql` or `seed.*\.sql` file is re-mounted into `/docker-entrypoint-initdb.d` in any compose file. Catches future drift before a fresh-clone operator hits it.

### Changed

- **`deploy/docker-compose.yml`** + **`deploy/docker-compose.test.yml`** — postgres `volumes:` no longer mount migrations or seed files; postgres healthcheck gains `start_period: 30s`; certctl-server healthcheck gains `start_period: 30s` to absorb the runtime migration + seed application window on first boot.
- **`deploy/docker-compose.demo.yml`** — replaces the `seed_demo.sql` initdb mount with the `CERTCTL_DEMO_SEED=true` env var on `certctl-server`.
- **`migrations/seed.sql`** — `INSERT INTO renewal_policies` updated to use the new `retry_interval_seconds` column name (lockstep with migration 000017).
- **`internal/repository/postgres/renewal_policy.go`** — column references updated to `retry_interval_seconds` across SELECT, INSERT, and UPDATE sites (lockstep with migration 000017).

### Closed audit findings

- `cat-u-seed_initdb_schema_drift` (P1, primary U-3 finding)
- `cat-o-retry_interval_unit_mismatch` (P1)
- `cat-o-notification_created_at_dead_field` (P2)
- `cat-o-health_check_column_orphans` (P1)
- `cat-u-no_version_endpoint` (P2)

### G-1: JWT silent auth downgrade — closed end-to-end

> Pre-G-1 the config validator accepted `CERTCTL_AUTH_TYPE=jwt` and the startup log faithfully echoed `"authentication enabled" "type"="jwt"`. Reasonable people read that and concluded JWT was on. It wasn't. The auth-middleware wiring at `cmd/server/main.go` unconditionally routed every request through the api-key bearer middleware regardless of `cfg.Auth.Type`. So `CERTCTL_AUTH_TYPE=jwt` quietly compared incoming `Authorization: Bearer <something>` against whatever string the operator put in `CERTCTL_AUTH_SECRET` — real JWT clients got 401, and operators who treated `CERTCTL_AUTH_SECRET` as a *signing* secret (because they thought they were configuring JWT) had effectively handed an attacker an api-key. A security finding masquerading as a config option. We chose to remove the option rather than ship JWT middleware — the audit-recommended structural fix that closes the hazard. Operators who actually need JWT/OIDC front certctl with an authenticating gateway (oauth2-proxy / Envoy `ext_authz` / Traefik `ForwardAuth` / Pomerium / Authelia) and run the upstream certctl with `CERTCTL_AUTH_TYPE=none`. The same pattern works on docker-compose and Helm.

### Breaking Changes

- **`CERTCTL_AUTH_TYPE=jwt` is no longer accepted.** Pre-G-1 the value was silently downgraded to api-key middleware. Post-G-1 the server fails at startup with a dedicated diagnostic naming the authenticating-gateway pattern. Operators with this in their env block must either switch to `api-key` (if they were de facto using api-key auth all along — same Bearer token continues to work) or switch to `none` and front certctl with an oauth2-proxy / Envoy / Traefik / Pomerium gateway. See [`docs/upgrade-to-v2-jwt-removal.md`](docs/upgrade-to-v2-jwt-removal.md).
- **Helm chart `server.auth.type=jwt` now fails at `helm install` / `helm upgrade` template time.** New `certctl.validateAuthType` template helper runs on every template that depends on `.Values.server.auth.type` (`server-deployment.yaml`, `server-configmap.yaml`, `server-secret.yaml`) and fails the render with a pointer at the gateway-fronting pattern.
- **OpenAPI spec `auth_type` enum no longer includes `jwt`.** API consumers checking `/api/v1/auth/info` against the spec will see a smaller enum.

### Removed

- Documented references to JWT in the certctl auth surface (config docblocks, middleware/health-handler comments, `.env.example`, `docs/architecture.md` middleware-stack bullet). Connector-level JWT references (Google OAuth2 service-account JWT in `internal/connector/discovery/gcpsm/`, `internal/connector/issuer/googlecas/`; step-ca's provisioner one-time-token JWT in `internal/connector/issuer/stepca/`) are unrelated and untouched — those are external-protocol uses, not certctl's own auth shape.

### Added

- **`config.AuthType` typed alias** with `AuthTypeAPIKey` / `AuthTypeNone` exported constants. Single source of truth for the allowed set across the validator, the runtime defense-in-depth switch in `main.go`, and the helm chart's `validateAuthType` helper.
- **`config.ValidAuthTypes()`** helper returning the complete allowed set; pinned by a property test (`TestValidAuthTypesDoesNotContainJWT`) that fails the build if `"jwt"` is ever re-added to the slice.
- **Defense-in-depth runtime guard** in `cmd/server/main.go` immediately after `config.Load()` — a `switch config.AuthType(cfg.Auth.Type)` that exits 1 if the validator was bypassed (test harness, alt config loader, env-var rebinding).
- **`certctl.validateAuthType` Helm template helper** mirroring the existing `certctl.tls.required` pattern. Fails template render on any `server.auth.type` outside `{api-key, none}`.
- **`docs/architecture.md` "Authenticating-gateway pattern (JWT, OIDC, mTLS)"** section explaining the design rationale for the narrow in-process auth surface and listing oauth2-proxy / Envoy `ext_authz` / Traefik `ForwardAuth` / Pomerium / Authelia / Caddy `forward_auth` / Apache `mod_auth_openidc` / nginx `auth_request` as the standard fronting options.
- **`docs/upgrade-to-v2-jwt-removal.md`** migration guide. Same shape as `docs/upgrade-to-tls.md`. Walks through the dedicated startup error, both recovery paths (`api-key` vs gateway-fronting), a complete docker-compose oauth2-proxy walkthrough, Traefik ForwardAuth and Envoy `ext_authz` patterns, and rollback posture.
- **`deploy/helm/certctl/README.md`** "JWT / OIDC via authenticating gateway" section with a Kubernetes-flavored oauth2-proxy + certctl walkthrough.
- **CI regression guardrail** in `.github/workflows/ci.yml` (`Forbidden auth-type literal regression guard (G-1)`) — grep-fails the build if `"jwt"` appears as an auth-type literal in production code or spec. Connector packages exempt (legitimate external-protocol uses).
- **Negative test coverage** in `internal/config/config_test.go`: `TestValidate_JWTAuth_RejectedDedicated` (two table rows pinning that the dedicated G-1 error fires regardless of whether `Secret` is set), `TestValidAuthTypesDoesNotContainJWT` (property-level guard), `TestValidAuthTypesIsExactly_APIKey_None` (allowed-set contract), `TestValidate_GenericInvalidAuthType` (pins that other invalid values still surface the generic invalid-auth-type error, so the dedicated G-1 path doesn't accidentally swallow non-jwt typos).

### Changed

- `internal/api/middleware/middleware.go::AuthConfig.Type` field comment now references the typed `config.AuthType` constants instead of an inline string enumeration.
- `internal/api/handler/health.go::HealthHandler.AuthType` field comment same treatment.
- `internal/api/handler/health_test.go` — the prior `TestAuthInfo_ReturnsAuthType_JWT` (which asserted the handler echoed `"jwt"`, baking the silent-downgrade lie into the regression suite) is removed; the pre-existing `TestAuthInfo_ReturnsAuthType_APIKey` continues to cover the api-key happy path.
- Auth-disabled startup log in `main.go` now points operators at the authenticating-gateway pattern explicitly.

### U-2: Dockerfile HEALTHCHECK protocol mismatch — closed end-to-end

> Pre-U-2 the published `ghcr.io/shankar0123/certctl-server` image shipped with `HEALTHCHECK CMD curl -f http://localhost:8443/health`. The server has been HTTPS-only since the v2.2 HTTPS-Everywhere milestone (`cmd/server/main.go::ListenAndServeTLS`, no plaintext fallback, TLS 1.3 pinned), so the probe failed every interval and Docker marked the container `unhealthy` indefinitely. Operators inside docker-compose / Helm / the example stacks were unaffected — compose overrides the HEALTHCHECK with `--cacert + https://`, Helm uses explicit `httpGet` probes that ignore Docker's HEALTHCHECK, and every example compose file overrides with `curl -sfk https://localhost:8443/health`. But anyone running bare `docker run` / Docker Swarm / Nomad / ECS — exactly the "I just pulled the published image" path — saw permanent `unhealthy` status and (depending on orchestrator policy) a restart-loop. Recon for U-2 also surfaced two adjacent bugs from the same v2.2 milestone gap: the Helm chart's `readinessProbe.httpGet.path` pointed at `/readyz`, a route the server doesn't register (only `/health` and `/ready` are wired and bypass the auth middleware), so K8s readiness probes were getting 404/auth-rejection and pods stayed `NotReady`; and the agent image had no HEALTHCHECK at all (the compose override called `pgrep -f certctl-agent` against an image that didn't ship `procps` — latent always-fail). All three are closed in this commit.

### Fixed

- **`Dockerfile` HEALTHCHECK now speaks HTTPS.** Bare `docker run` / Swarm / Nomad / ECS users no longer see `unhealthy` forever. The probe uses `curl -fsk https://localhost:8443/health` — `-k` (insecure) is acceptable because the probe is localhost-to-localhost: the same process serving the cert is being probed; the probe never traverses a network. Compose / Helm / examples already perform full cert-chain validation and are unaffected.
- **Helm `server.readinessProbe.httpGet.path` corrected from `/readyz` to `/ready`.** The `/readyz` path was never registered as a no-auth route (see `internal/api/router/router.go:81` and `cmd/server/main.go:920`), so K8s readiness probes received 401 (api-key auth rejection) or 404 (when auth was disabled). Pods previously failed to report Ready under most realistic Helm deployments. Liveness probe path (`/health`) was already correct and is unchanged.
- **`docs/connectors.md` curl examples** (15 sites) updated from `http://localhost:8443/...` to `https://localhost:8443/...` with a one-time `--cacert "$CA"` extraction note matching the existing pattern in `docs/quickstart.md`. Pre-U-2 these examples silently failed against the HTTPS listener.

### Added

- **`Dockerfile.agent` HEALTHCHECK** — `pgrep -f certctl-agent` process-presence check (the agent has no HTTP listener; presence is the right primitive). Bare-`docker run` agents now report health-status the same way compose-managed ones do. Also adds `procps` to the runtime image so `pgrep` is actually available — pre-U-2 the docker-compose override at `deploy/docker-compose.yml:173` called `pgrep -f certctl-agent` against an image that lacked it (latent always-fail; container was reported unhealthy in compose too, just rarely noticed because nothing acted on the signal).
- **`deploy/test/healthcheck_test.go`** (`//go:build integration`) — image-level integration tests. `TestPublishedServerImage_HealthcheckSpecUsesHTTPS` builds the server image, inspects `Config.Healthcheck.Test` via `docker inspect`, and asserts the array contains `https://localhost:8443/health` and `-k`, and does NOT contain `http://localhost:8443/health` (negative regression contract). `TestPublishedAgentImage_HealthcheckSpecExists` builds the agent image and asserts the HEALTHCHECK uses `pgrep` against `certctl-agent`. Both tests `t.Skip` cleanly when docker isn't available (sandbox / CI without docker-in-docker). A third runtime test (`TestPublishedServerImage_HealthcheckTransitionsToHealthy`) is a `t.Skip` placeholder until the harness wires a sidecar postgres for image-level smoke — documented honestly so the next refactor adopts it instead of rediscovering the gap.
- **CI regression guardrail** in `.github/workflows/ci.yml` (`Forbidden plaintext HEALTHCHECK regression guard (U-2)`) — grep-fails the build if any `Dockerfile*` carries `HEALTHCHECK.*http://` or `curl -f http://localhost:8443/health`. Comments exempt; the `docs/upgrade-to-tls.md:182` post-cutover invariant string (which deliberately documents the expected-failure shape) is out of the guardrail's scope because the guardrail only scans Dockerfiles.

### Changed

- `Dockerfile` final-stage HEALTHCHECK lines now carry a long-form docblock explaining the `-k` design choice, the published-image vs compose vs Helm vs examples coverage matrix, and cross-references to the audit closure + the integration test.
- `Dockerfile.agent` runtime stage adds `procps` to the apk install so the new HEALTHCHECK and the existing compose override both have a working `pgrep`.
- `deploy/helm/certctl/values.yaml` server probes block now carries an explanatory comment naming the registered probe routes (`/health`, `/ready`) and the U-2 closure rationale for the `/readyz` → `/ready` correction.

## [2.2.0] — 2026-04-19

### HTTPS Everywhere — The Irony

> certctl manages other teams' certificates. Until v2.2, it didn't terminate TLS on its own control plane. We treated the server as an internal service sitting behind whatever TLS-terminating infrastructure the operator already owned — reverse proxies, Kubernetes Ingress controllers, service mesh sidecars. Working through an EST coverage-gap audit surfaced this as a credibility problem we wanted to fix head-on: a cert-lifecycle product should ship with HTTPS by default. This release flips that. Self-signed bootstrap for docker-compose demos, operator-supplied Secret for Helm (with optional cert-manager integration), and a one-step cutover with no backward-compat bridge. Out-of-date agents will fail at the TLS handshake layer on upgrade; the upgrade guide walks operators through the roll.

### Breaking Changes

- **HTTPS-only control plane. The plaintext HTTP listener is gone.** There is no `CERTCTL_TLS_ENABLED=false` escape hatch and no `:8080` fallback. Operators who were running certctl behind their own TLS terminator must either (a) continue doing so and let the downstream TLS terminator talk to certctl's HTTPS listener, or (b) bring their own cert/key and terminate on certctl directly. Either path requires config changes — see `docs/upgrade-to-tls.md` for a one-step cutover.
- **Agents reject `CERTCTL_SERVER_URL=http://...` at startup.** This is a pre-flight config validation failure with a fail-loud diagnostic pointing at `docs/upgrade-to-tls.md`. Not a TCP-refused, not a TLS-handshake-error — the agent will not even attempt the network call. Every agent deployment must be reconfigured before upgrading the server.
- **CLI and MCP clients require `https://` URLs.** Same pre-flight rejection of plaintext schemes.
- **TLS 1.2 is not supported. TLS 1.3 only.** The server's `tls.Config.MinVersion` is pinned to `tls.VersionTLS13`. Any client still negotiating TLS 1.2 will fail at the handshake. Modern curl, Go stdlib, browsers, and Kubernetes tooling all default to 1.3-capable; legacy clients may need an upgrade.
- **Helm chart requires a TLS source.** `helm install` without one of `server.tls.existingSecret`, `server.tls.certManager.enabled`, or (for eval only) `server.tls.selfSigned.enabled` fails at template time with a diagnostic pointing at `docs/tls.md`. There is no default-to-plaintext path.

### Added

- **Self-signed bootstrap for Docker Compose demos.** A `certctl-tls-init` init container runs before the server on first boot, generates a SAN-valid self-signed cert into `deploy/test/certs/`, and exits. The server mounts the resulting cert/key. Every curl in the demo stack pins against `./deploy/test/certs/ca.crt` with `--cacert`.
- **Helm chart TLS provisioning — three modes.** Operator-supplied Secret (`server.tls.existingSecret`), cert-manager integration (`server.tls.certManager.enabled` with issuer selection), or self-signed (`server.tls.selfSigned.enabled` — eval only, not supported for production). Chart templates enforce exactly one is active.
- **Hot-reload of TLS cert/key on `SIGHUP`.** Overwrite the cert/key on disk, send `SIGHUP` to the server PID, watch the `slog.Info("tls.reload", ...)` log line, and new TLS connections use the new cert. Failure during reload is logged and does not crash the server; the previous cert remains in use.
- **Agent CA-bundle env vars.** `CERTCTL_SERVER_CA_BUNDLE_PATH` points at a PEM file the agent's HTTP client will trust. `CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY` disables verification (development only — the agent logs a loud warning at startup). `install-agent.sh` writes both as commented template lines into the generated `agent.env`.
- **Integration test suite runs over HTTPS.** `go test -tags=integration ./deploy/test/...` stands up the full Compose stack, extracts the self-signed CA bundle, and exercises every certctl API over `https://localhost:8443`. All 34 subtests green.
- **`docs/tls.md`** — cert provisioning patterns: bring-your-own Secret, cert-manager, self-signed bootstrap, SAN requirements, rotation workflows, SIGHUP reload semantics, troubleshooting.
- **`docs/upgrade-to-tls.md`** — one-step cutover guide for existing v2.1 operators. Walks through the agent fleet roll, Helm upgrade sequencing, downgrade-is-not-supported warnings, and cert-provisioning decision tree.

### Changed

- `cmd/server/main.go` now calls `http.Server.ListenAndServeTLS(certFile, keyFile)`. The plaintext `ListenAndServe` code path is deleted — `grep -rn "ListenAndServe[^T]" cmd/ internal/` returns zero hits.
- All documentation curls (`docs/testing-guide.md`, `docs/quickstart.md`, `deploy/helm/INSTALLATION.md`, `deploy/helm/DEPLOYMENT_GUIDE.md`, `deploy/ENVIRONMENTS.md`, `docs/openapi.md`, migration guides, example READMEs) use `https://localhost:8443` and `--cacert` against the demo stack's bundle.
- OpenAPI spec (`api/openapi.yaml`) `servers` blocks default to `https://localhost:8443`.

### Security

- TLS 1.3 pinned via `tls.Config.MinVersion = tls.VersionTLS13`.
- Plaintext HTTP listener removed entirely — no port 8080, no `Upgrade-Insecure-Requests`, no HSTS-required redirect dance. There is only one port: 8443, TLS 1.3.
- `grep -rn "http://" cmd/ internal/` returns zero hits outside test fixtures and the agent-side URL-scheme rejection error message.

### Upgrade Notes

Read `docs/upgrade-to-tls.md` before upgrading. The short version:

1. Pick a TLS source — bring-your-own cert, cert-manager, or self-signed bootstrap.
2. Upgrade the server with TLS configured. First boot over HTTPS.
3. Roll the agent fleet: set `CERTCTL_SERVER_URL=https://...` and, if using a private CA, `CERTCTL_SERVER_CA_BUNDLE_PATH`. Old agents will fail loud at startup — expected.
4. Roll CLI/MCP clients the same way.

There is no backward-compat bridge. There is no dual-listener mode. The cutover is one step.
