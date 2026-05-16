# loadtest-artifacts/

> Last reviewed: 2026-05-16

Long-term archive of k6 load-test results from the `loadtest` GitHub
Actions workflow. TEST-005 closure (Sprint 5, 2026-05-16) introduces
this directory as the committed home for captures the operator
chooses to retain past GitHub's 90-day artifact-retention window.

## What lands here

After a `loadtest` workflow_dispatch run, follow the procedure in
[`docs/operator/scale-baseline-2026-Q2.md`](../../../docs/operator/scale-baseline-2026-Q2.md#capture-procedure):

1. Download the three matrix-leg artifacts from the workflow page.
2. Update the latest-capture table in the baseline doc with the
   extracted percentiles.
3. Commit the raw artifacts you want long-term-retained here, named:

   ```
   2026-Q2-bulk-renewal-<run-id>.tar.gz
   2026-Q2-acme-burst-<run-id>.tar.gz
   2026-Q2-agent-storm-<run-id>.tar.gz
   ```

4. If any single archive exceeds 100 MB, route it through `git lfs`
   (configured at repo root via `.gitattributes`).

## Why commit artifacts rather than rely on GHA retention

- **GitHub Actions retains workflow artifacts for 90 days by default.**
  Acquisition-diligence reviewers looking at scale evidence months
  later get a 404 unless we keep the raw NDJSON in tree.
- **Reproducibility.** Pinning the k6 NDJSON to a SHA makes it
  cheap to re-derive percentiles with a different filter (e.g.
  "p99 excluding the warmup ramp's first 30 seconds") without
  re-running the workflow.

## What does NOT belong here

- **Per-PR ephemeral runs.** The `loadtest` workflow runs on
  workflow_dispatch + weekly cron; per-PR runs would be too noisy
  and aren't retained.
- **Production-environment captures.** These artifacts are the
  ubuntu-latest reference baseline. An operator capturing their
  production-environment scale should put the artifacts in their
  own observability platform — committing them here would imply
  "this is what certctl's reference numbers are" which it isn't.
- **Manual k6 captures from a developer's laptop.** Same rationale
  as the visual-regression snapshot runbook
  ([`docs/operator/runbooks/e2e-snapshot-update.md`](../../../docs/operator/runbooks/e2e-snapshot-update.md))
  — only the CI environment produces canonical numbers.
