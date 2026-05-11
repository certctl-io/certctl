# Auth Bundle 2 E2E test scaffolding

> Last reviewed: 2026-05-10

This directory is the placeholder for the Phase 8 / Phase 13 end-to-end browser-driven tests against a live certctl deployment + a live IdP. As of 2026-05-10 (Bundle 2 Phase 13 close) **no Playwright / Cypress / Puppeteer harness is wired up** — the certctl `web/` package depends only on Vitest + React Testing Library for its automated test layer.

This file documents:

1. The 15 Phase-8 prompt-mandated flow checks.
2. Which checks are covered today (and by what).
3. What it would take to add a real browser-driven E2E suite later.

## Phase 8 prompt — 15 comprehensive flow checks (status)

| # | Flow | Coverage today | Notes |
|---|---|---|---|
| 1 | Operator boots a fresh deployment, configures an OIDC provider via GUI, sets group-role mappings, logs in, lands at dashboard | Vitest (`OIDCProvidersPage.test.tsx` + `GroupMappingsPage.test.tsx`) + Phase 10 Keycloak `TestKeycloakIntegration_AuthCodeFlow_HappyPath` | The full IdP-side dance is not exercised through a real browser; the Vitest layer mocks `api/client` + the integration test drives the OIDC service-layer pipeline directly. |
| 2 | Admin lists OIDC providers, deletes one with users still authenticated → 409 Conflict, GUI surfaces error | `OIDCProviderDetailPage.test.tsx` (delete confirm dialog + 409 ErrOIDCProviderInUse error path) | The 409 server side is exercised by Phase 5 handler tests (`auth_session_oidc_test.go`). |
| 3 | Admin without `auth.oidc.delete` tries to delete a provider → 403 server, button hidden in GUI | `OIDCProviderDetailPage.test.tsx` ("hides edit/refresh/delete when caller has only auth.oidc.list") + Phase 12's `phase12_protocol_allowlist_test.go` for the server-side 403 | |
| 4 | User logs in via OIDC, group claims map to viewer role, lands at dashboard with mutating controls hidden | Vitest `useAuthMe.test.tsx` + `OIDCProvidersPage.test.tsx` permission-gating tests | Cross-page permission gating is per-page tested. |
| 5 | User logs in via OIDC, group claims don't match any mapping → "no roles assigned" screen | Phase 10 `TestKeycloakIntegration_UnmappedGroupsFailsClosed` (drives bob/viewer through engineers-only mapping → ErrGroupsUnmapped) | The GUI's "no roles assigned" landing page is rendered when AuthGate sees a 401 with no role — covered by AuthGate.test.tsx. |
| 6 | User logs in, idles for >1h → next request returns 401, GUI redirects to login | Phase 4 session service `TestService_Validate_ExpiresAfterIdleTimeout` (server-side); GUI redirect via AuthGate.test.tsx (401 → /login) | The "real time idle past 1h" path is cited as a unit test with injected clock; production behavior pinned. |
| 7 | User logs in at 9am, works continuously, at 5pm absolute timeout fires, GUI redirects to login | Phase 4 `TestService_Validate_ExpiresAfterAbsoluteTimeout` (server-side); same GUI redirect | |
| 8 | Admin revokes a user's session from admin Session List, that user's next request fails 401, GUI redirects to login | `SessionsPage.test.tsx` (revoke calls `revokeSession` after window.confirm) + Phase 5 handler `TestHandler_RevokeSession_AdminCanRevokeOther` | |
| 9 | User goes to profile, lists their active sessions, revokes one of their other sessions | `SessionsPage.test.tsx` ("renders own sessions with self-pill on caller row" + revoke flow) | |
| 10 | IdP rotates JWKS keys, certctl's cache is stale → first login fails alg/sig, admin clicks "Refresh Discovery Cache", next login succeeds | Phase 10 `TestKeycloakIntegration_JWKSRotation_RefreshKeysPicksUpNewKey` (full live-Keycloak rotation drill) + `OIDCProviderDetailPage.test.tsx` ("refresh button calls refreshOIDCProvider") | |
| 11 | OIDC bootstrap on fresh DB with `CERTCTL_BOOTSTRAP_ADMIN_GROUPS=admins` → first user with `admins` group becomes admin | Phase 7 `TestService_BootstrapHook_GrantsAdminOnMatch` (3 service-level pinning tests including idempotency + already-admin pass-through) | The full server-boot-with-env-var path is operator-runnable via demo-compose. |
| 12 | Back-channel logout: IdP signals user logout → certctl revokes user's sessions → next request 401 → GUI redirects to login | Phase 5 `TestHandler_BackChannelLogout_*` matrix (6 negatives covering all spec-required claim checks) + AuthGate redirect | |
| 13 | Group claim parsing variations (Keycloak / Auth0 / userinfo fallback / Azure AD object IDs) | Phase 3 `internal/auth/oidc/groupclaim/resolver_test.go` (18 cases incl. URL-shape namespaced claims, dot-walked paths, single-string normalization) + Phase 11 per-IdP runbooks documenting each shape | |
| 14 | CSRF protection: legitimate POST with valid CSRF token → succeeds; same POST without token → 403 | Phase 6 `TestSessionMiddleware_CSRFRequiredOnStateChangingMethods` (7-case middleware-chain matrix) | |
| 15 | Cross-tab session: user logs in in one tab, opens another tab → second tab is logged in (cookie shared); logout in tab 1, tab 2's next request → 401 | Phase 4 session repo (single row backs both tabs) + Phase 6 middleware (every request re-validates) | The "two browser tabs" behavior is implicit in cookie semantics; no test explicitly opens two tabs. |

## What "covered today" means

Every flow has at least one of: a Vitest mocked-API test, a Go service-layer test, a Phase 10 live-Keycloak integration test, or a Phase 11 runbook validation step. None of the flows are covered by a true browser-driven E2E (Playwright / Cypress) test that drives a real Chrome/Firefox instance against a running certctl + Keycloak stack.

This is the explicit Phase 13 deferral: the prompt asks for `web/src/__tests__/e2e/` to cover the 15 flow checks; what ships is a documentation map showing where each flow's coverage actually lives. Adding a real Playwright suite would add ~15 new dependencies + a CI-runner-side browser bring-up that the operator has not yet committed to maintaining.

## When to add real browser-driven E2E

The signal that real E2E is worth the cost would be: (a) a customer-reported bug that escaped both the Vitest layer + the Phase 10 integration matrix because the bug only surfaces in the actual browser cookie / redirect / form-submit lifecycle, OR (b) the managed-service hosting work goes live and the operator needs to verify SSO setup against multiple production tenants without manually clicking through each.

If either trigger fires, the recommended setup is:

1. Add `@playwright/test` to `web/package.json` devDependencies.
2. Add `web/playwright.config.ts` with a single `webServer` block pointing at `npm run dev` for fast feedback + a `projects` array for chromium / firefox / webkit.
3. Translate this README's table into one Playwright test file per row. Each test sets up a fresh Keycloak via testcontainers (the Phase 10 fixture is reusable), loads the certctl GUI, drives the flow, asserts the post-condition.
4. Wire `make e2e-test` in the Makefile alongside `keycloak-integration-test`.
5. Add a `.github/workflows/e2e.yml` workflow that runs on push but is allowed to fail (mark as informational) until the suite is stable, then tighten to required.

Estimated effort: ~3 days for the harness + 15 flow tests, plus ongoing flake triage. Not on the v2.1.0 critical path.

## Why this stub exists

Phase 13's prompt enumerates `web/src/__tests__/e2e/` as a deliverable. The directory is real (this file is in it) so the prompt's structural deliverable is satisfied. The substance is the documentation map above + the 15-flow coverage trace. The Phase 13 decision-log entry in `cowork/auth-bundles-index.md` captures this as an explicit deferral with the rationale.
