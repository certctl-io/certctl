# `scripts/ci-guards/` — Regression-guard scripts

Each `<id>.sh` script in this directory pins one closed audit finding from
regressing. CI runs the full set on every push via the
`Regression guards` step in `.github/workflows/ci.yml`. Operators can
run any script locally:

```bash
bash scripts/ci-guards/G-3-env-docs-drift.sh
```

## Contract

Every script in this directory MUST:

1. Be exit-code 0 on a clean repo (no regression present).
2. Be exit-code non-zero on regression, with a `::error::` annotation
   prefix so PR reviewers see the failing line in the GitHub Actions UI.
3. **Be runnable from repo root via `bash scripts/ci-guards/<id>.sh`
   with NO arguments and NO env-var requirements.** The CI loop step
   (`for g in scripts/ci-guards/*.sh; do bash "$g"; done`) iterates
   every `.sh` here without args; any script that requires an arg or
   env var WILL fail in that loop.
4. Carry a head-comment block matching the in-source justification
   from the original ci.yml entry: the audit-finding reference, the
   closure rationale, the exempt-surface list (if any).
5. Use `set -e` early to fail-fast on internal command errors.
6. Produce no output on the happy path beyond a final
   `echo "<id>: clean."` confirmation line.

### Helpers vs guards

Scripts that consume input artifacts (a test-output log, a
`coverage.out` file) or env vars (`PR_NUMBER`, `GH_TOKEN`) are
HELPERS, not guards. They live in `scripts/`, NOT `scripts/ci-guards/`.

Current helpers:
- `scripts/vendor-e2e-skip-check.sh` — consumes `test-output.log`
  arg from the deploy-vendor-e2e job
- `scripts/coverage-pr-comment.sh` — consumes `coverage.out` +
  `PR_NUMBER` + `GH_TOKEN` env from the go-build-and-test job
- `scripts/check-coverage-thresholds.sh` — consumes `coverage.out`
  + `.github/coverage-thresholds.yml`
- `scripts/qa-doc-part-count.sh` + `scripts/qa-doc-seed-count.sh` —
  invoked via `make verify-docs` pre-tag, not in CI

## Adding a new guard

1. Drop a new `<id>.sh` in this directory with the head-comment block
   describing the audit finding it closes.
2. Make it executable: `chmod +x scripts/ci-guards/<id>.sh`.
3. Verify it fails on a deliberate regression and passes on clean repo.
4. CI auto-picks up new scripts via the `for g in scripts/ci-guards/*.sh`
   loop in the `Regression guards` step — no ci.yml change required.

## The 20 guards in this directory

| ID | Finding | Catches |
|---|---|---|
| `G-1-jwt-auth-literal` | G-1 JWT silent auth downgrade | `"jwt"` literal in additive auth-type surfaces |
| `L-001-insecure-skip-verify` | L-001 unjustified InsecureSkipVerify | `InsecureSkipVerify: true` without `//nolint:gosec` |
| `H-001-bare-from` | H-001 (CWE-829) tag-swap attack | Bare `FROM` line without `@sha256` digest pin |
| `M-012-no-root-user` | M-012 (CWE-250) container-as-root | Dockerfile missing terminal `USER <non-root>` |
| `H-009-readme-jwt` | H-009 README JWT advertising | README.md re-introducing JWT-as-supported claim |
| `G-2-api-key-hash-json` | G-2 cat-s5-apikey_leak | `api_key_hash` in JSON-emitting surface |
| `U-2-plaintext-healthcheck` | U-2 healthcheck protocol mismatch | Plaintext `http://` in HEALTHCHECK directive |
| `U-3-migration-mount` | U-3 seed initdb schema drift | Migration file mounted into postgres initdb |
| `D-1-D-2-statusbadge-phantom` | D-1 + D-2 dead keys + TS phantoms | StatusBadge dead keys + 5 Certificate / 5 Agent / 1 Issuer / 1 Notification phantom fields |
| `L-1-bulk-action-loop` | L-1 client-side bulk loops | `for ... await triggerRenewal/updateCertificate` in CertificatesPage |
| `B-1-orphan-crud` | B-1 orphan-CRUD client fns | 8 update/create/delete fns lose their page consumer |
| `S-2-strings-contains-err` | S-2 brittle error-dispatch | `strings.Contains(err.Error(), "not found"\|"violates foreign key")` in handlers |
| `G-3-env-docs-drift` | G-3 env-var docs drift | `CERTCTL_*` env var defined OR documented but not both |
| `test-naming-convention` | I-001-extended | `func TestXxx` (lowercase first letter) — Go silently skips |
| `S-1-hardcoded-source-counts` | S-1 stale numeric prose | Hardcoded "N issuer connectors" / "N MCP tools" in README + docs |
| `P-1-documented-orphan-fns` | P-1 documented orphans | 16 read-fn names removed from client.ts exports |
| `T-1-frontend-page-coverage` | T-1 untested frontend pages | New page in `web/src/pages/` without sibling `.test.tsx` and not on the deferred allowlist |
| `bundle-8-L-015-target-blank-rel-noopener` | L-015 (CWE-1022) reverse-tabnabbing | `target="_blank"` without `rel="noopener noreferrer"` |
| `bundle-8-L-019-dangerously-set-inner-html` | L-019 (CWE-79) XSS | `dangerouslySetInnerHTML` outside `safeHtml.ts` |
| `bundle-8-M-009-bare-usemutation` | M-009 + M-029 mutation contract | Bare `useMutation()` outside `useTrackedMutation` wrapper |

## Guards explicitly NOT here

- **`QA-doc Part-count drift`** + **`QA-doc seed-count drift`** — these
  protect docs-the-operator-reads, not anything the product depends on.
  Moved to `make verify-docs` (operator runs pre-tag, not on every push).
  See `cowork/ci-pipeline-cleanup-prompt.md` Phase 11.

## Running the full set locally

```bash
for g in scripts/ci-guards/*.sh; do
  echo "=== $(basename "$g") ==="
  bash "$g" || echo "  FAILED"
done
```
