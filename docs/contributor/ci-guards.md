# CI guards

> Last reviewed: 2026-05-12

CI guards are small scripts (shell + Python) and Go tests that pin invariants the v2 audit history showed are easy to lose. Each one runs on every push, fails the build on regression with a useful error message, and produces no output on the happy path. The canonical source is `scripts/ci-guards/` for shell guards and `internal/ciparity/` for Go-based parity tests.

This page lives at `docs/contributor/ci-guards.md` and is the entry point for contributors who want to understand why a CI step is red, how to add a new guard, or where the allowlist for a given guard lives. The exhaustive list of shell guards is at `scripts/ci-guards/README.md`; this doc explains the categories + the discipline.

## Why guards exist

Two failure modes the v2 audit cycle surfaced repeatedly:

The codebase grew faster than the docs and config could keep up. Env vars got added without consumers; OpenAPI ops were registered without router routes; docs went stale; a migration broke on cold-DB without any test catching it. Each one of those classes has a one-time-fix _per-instance_ pattern (re-read the doc, wire the env var) and a structural _per-class_ pattern (write a guard that fails the next time it happens). CI guards are the second.

The team grew. Reviewers had to remember what each commit author had forgotten. CI guards externalize the institutional knowledge into checks — the build refuses to ship the lying field, the stale doc, the broken migration. New contributors don't need to know the audit history.

## Categories

The guards fall into four buckets, organized by what they pin:

### Code-shape guards

Catch defects in source files BEFORE they ship. Examples: `G-3-env-docs-drift.sh` (no env var defined-but-undocumented or documented-but-undefined), `complete-path-config-coverage.sh` (every env var has a non-config consumer), `T-1-frontend-page-coverage.sh` (every new GUI page has a sibling test file).

### Contract-parity guards

Catch drift across the four product surfaces — OpenAPI spec, HTTP router, MCP tool catalogue, CLI verb dispatcher. The router ↔ OpenAPI pin lives at `internal/api/router/openapi_parity_test.go::TestRouter_OpenAPIParity`. The MCP + CLI sweep lives at `internal/ciparity/surface_parity_test.go` (post-v2.1.0 anti-rot item 2). One hard gate: the MCP tool count cannot regress below `mcpBaselineFloor`. The CLI parity sweep is informational until the CLI surface stabilizes.

### Build / dependency guards

`H-001-bare-from.sh` (Dockerfile pin to `@sha256:`), `digest-validity.sh` (every digest actually resolves on the registry), `M-012-no-root-user.sh` (no Dockerfile ends as root), `bundle-8-*.sh` (frontend XSS / reverse-tabnabbing surface). These come out of specific audits and pin the closure.

### Operational guards

`doc-rot-detector.sh` (every doc reviewed within 120 days) pins the operational reality, not the source shape.

The cold-DB compose smoke (wipe postgres volume, bring stack up cold, issue/renew/revoke, audit-row check) lives directly in `.github/workflows/ci.yml::cold-db-compose-smoke` — not as a script. It is intentionally not operator-runnable: the gate's value is that CI owns the cold-DB state, the operator never has to remember to run it. Master branch-protection enforces the job as a required check; that is the manual action, and it happens once.

## When the build is red

Find the failing step in the GitHub Actions UI. Every guard's output starts with the guard's own identifier and ends with one of:

`::error::<one-line description of the regression>` followed by 2-4 remediation paths. The fastest path: read the remediation list, pick the option that fits, fix.

`exit 1` without an `::error::` annotation — likely an `set -e` trap on an internal command. Re-run with `bash -x scripts/ci-guards/<id>.sh` locally to see where it died.

If a guard is fundamentally wrong (e.g., refactor moved the code it scans), update the guard in the same PR that triggered the failure. Don't add a one-off allowlist to silence a real bug.

## Adding a new guard

The discipline in five steps. The first three are non-negotiable; the last two are courtesy.

Drop a new `<id>.sh` in `scripts/ci-guards/` with a head-comment block that names the bug class, lists the audit finding (if any) it closes, and explains the failure mode. Mirror the shape of an existing guard — `G-3-env-docs-drift.sh` and `digest-validity.sh` are the canonical bash+Python and pure-bash examples.

Use `set -e` early; use `::error::` annotations on regression; exit 0 with one happy-path confirmation line. Take no arguments, require no env vars. The CI loop iterates every `*.sh` without args.

Write the allowlist file alongside (`<id>-exceptions.yaml`) with the shape `- path: ... / - name: ... + justification + expires`. Make `expires` a required field — every exception has a hard expiration date, typically 90 days out.

Verify on a deliberately broken state: introduce the regression, confirm the guard fires with a useful message, revert, confirm green. Capture the negative-test output in your PR description.

Add a row to `scripts/ci-guards/README.md`. The CI loop auto-picks up the new file — no `ci.yml` edit required, unless the guard needs Docker (in which case it gets its own dedicated job; see `cold-db-compose-smoke` for the pattern).

## Discipline: the allowlist trap

Allowlists are dangerous. They start as a small concession ("this one env var is documented for an external script, not consumed by Go code") and become a junk drawer of unverified exemptions that mask real defects. The discipline that keeps that from happening:

Every entry MUST carry a `justification:` field with a one-line reason. "Tech debt" is not a reason; "documented contract surface consumed by the ACME DNS-01 helper script — see `deploy/test/acme/dns01-export.sh`" is.

Every entry MUST carry an `expires:` field with a hard date, typically 90 days out. The guards reject entries past their expiration. When an entry expires, the only paths forward are (a) close the underlying gap so the entry is no longer needed, (b) re-justify with a fresh expiration. Both force a real review.

If you're adding more than one entry to an allowlist in a single PR, that's a smell — usually the underlying class needs a small refactor, not three allowlist rows.

## Where the bundles live

The `Audit-Closes:` commit trailer convention (post-v2.1.0 anti-rot item 4) is the cross-reference between audit findings and the commits that closed them. Re-derive the closure history of any audit with:

    git log --grep='Audit-Closes: <audit-id>'

The audit folder structure under `cowork/` (workspace-local; not in this repo) carries the per-audit RESULTS.md + findings.yaml. CLAUDE.md's "Audit closures" subsection is the current-state index of which audits are open vs closed.

## Related

The exhaustive guard list — `scripts/ci-guards/README.md`.
The CI pipeline architecture — `docs/contributor/ci-pipeline.md`.
The QA test suite — `docs/contributor/qa-test-suite.md`.
