# Runbook: regenerating Playwright visual-regression snapshots

> Last reviewed: 2026-05-16

Use this when:

- You've intentionally changed UI shape (added a column, restyled a
  banner, replaced an icon set) and the next `Frontend E2E` CI run
  fails with `Screenshot comparison failed:` errors on multiple
  `04-visual-regression.spec.ts` cases.
- A deterministic-but-platform-specific font-rendering difference
  emerges (Linux runner vs your Mac dev box) and you want to refresh
  baselines from the canonical CI environment.

TEST-003 closure (Sprint 5, 2026-05-16) flipped the workflow from
`continue-on-error: true` to `false`. Pre-fix you could ignore a
red E2E run and ship anyway. Post-fix the run blocks the merge, so
any change that legitimately moves pixels needs the snapshot bump
captured here.

Do NOT use this to make a real visual regression disappear. The
snapshots are version-controlled evidence — if a pixel diff fires
unexpectedly, investigate the rendering change before bumping.

## What "snapshots" means here

`web/playwright/04-visual-regression.spec.ts` calls
`toHaveScreenshot()`. Playwright stores the canonical PNG at
`web/playwright/04-visual-regression.spec.ts-snapshots/<test-name>-<browser>-<platform>.png`
on first run. Subsequent runs compare pixel-by-pixel against that
file. We commit the PNGs to git so the CI runner and local dev
share a single source of truth.

Two failure modes the diff is designed to catch:

- **Intentional UI change.** You added a new field to the Targets
  table. The screenshot now has an extra column. The baseline
  doesn't. Pixel diff fires — this is the "operator updates
  baselines" path documented below.
- **Regression.** A CSS change inadvertently shifted spacing.
  Investigate before regenerating; don't paper over the diff.

## Standard bump (one or two affected tests)

1. Run the E2E suite locally with the update flag against the
   same Linux runner image Playwright uses:

   ```bash
   cd web
   npx playwright test 04-visual-regression.spec.ts --update-snapshots
   ```

   If you're on macOS, run it through Docker against the same image
   the workflow uses (`mcr.microsoft.com/playwright`); font
   rendering differs between platforms and Linux baselines must
   come from a Linux source.

2. Inspect every regenerated PNG:

   ```bash
   git status web/playwright/*.spec.ts-snapshots/
   git diff --stat web/playwright/*.spec.ts-snapshots/
   ```

   PNG diffs in `git diff` are unhelpful — open the files in any
   image viewer and confirm the change matches your intent.

3. Commit the snapshots alongside the source change in the same
   PR:

   ```bash
   git add web/playwright/*.spec.ts-snapshots/
   git commit -m "chore(e2e): refresh visual snapshots after <change>"
   ```

4. Push and confirm CI's E2E job greens out.

## Mass bump (font upgrade, framework migration)

Use the workflow's `workflow_dispatch` input to regenerate from
CI's canonical environment:

1. Go to `Actions` → `Frontend E2E` → `Run workflow`.
2. Set `update_snapshots: true`.
3. The workflow runs Playwright with `--update-snapshots`, then
   commits + pushes the regenerated PNGs to a feature branch
   `playwright/snapshot-update-<run-id>`.
4. Open a PR from that branch to master. Review the PNG diffs in
   the PR view (GitHub renders image diffs side-by-side for
   committed PNGs).
5. Merge.

## What NOT to do

- Don't regenerate snapshots from a developer's local machine and
  push them as the canonical baseline. The Linux runner's font
  hinting differs from macOS / Windows, so the baselines must come
  from the same image the CI workflow runs.
- Don't add `--update-snapshots` to the always-run e2e step in
  `.github/workflows/e2e.yml`. That's how snapshot regressions
  become invisible — every diff gets accepted, every PR ships
  fine, and the visual-regression layer becomes decorative.
- Don't bump snapshots in a "fix typo" PR. Every PNG change is
  an architectural decision; pair it with the source change that
  justifies it.
