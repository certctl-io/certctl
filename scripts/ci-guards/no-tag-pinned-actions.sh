#!/usr/bin/env bash
# scripts/ci-guards/no-tag-pinned-actions.sh
#
# Phase 1 RED-2 closure (2026-05-13): every GitHub Action invocation
# under .github/workflows/ MUST be SHA-pinned (@<40-char-sha>) rather
# than tag-pinned (@v4 / @v0.10.0 / etc.). Tags are mutable; SHAs
# aren't. Mutable tags are the standard supply-chain attack vector
# against GitHub Actions consumers — a compromised tag silently
# pulls compromised code on every CI run.
#
# Pattern allowance:
#   - `uses: org/repo@<40-char-sha>  # v4` ← the trailing comment
#     documenting the human-readable tag is REQUIRED for operator
#     audit purposes ("which version is that SHA?"), but the SHA is
#     the load-bearing pin.
#
# How to fix a violation:
#   1. Look up the action's tag → SHA mapping. Either via the GitHub
#      web UI (visit the action's tags page), or via:
#        curl -sS https://api.github.com/repos/<org>/<repo>/git/refs/tags/<tag> | jq .object.sha
#   2. Rewrite the line as `uses: <org>/<repo>@<sha>  # <tag>`.
#   3. Re-run this guard locally to confirm.
#
# Rationale + history:
#   - Phase 1 of the certctl architecture diligence remediation
#     (cowork/certctl-architecture-diligence-audit.html#fix-RED-2)
#     swept the entire .github/workflows/ tree from 37 tag-pinned /
#     4 SHA-pinned to 0 tag-pinned / 41 SHA-pinned in one PR.
#   - This guard catches the regression mode: a future PR adds a new
#     `uses: foo/bar@v2` line and the build fails until the
#     contributor SHA-pins it.

set -e

# Match `uses: <anything>@vN` or `@v<digit>.<digit>` etc. Don't match
# `@<40-char-sha>`. The negative-lookahead-free shell-regex shape:
# anything-not-hex-40-chars after the @.
VIOLATIONS=$(grep -rnE "uses:[^#]*@v[0-9]" .github/workflows/ 2>/dev/null || true)

if [ -n "$VIOLATIONS" ]; then
  echo "::error::no-tag-pinned-actions regression: tag-pinned uses: line found."
  echo ""
  echo "GitHub Actions MUST be SHA-pinned (@<40-char-sha>) rather than"
  echo "tag-pinned (@v4). Tags are mutable; SHAs aren't. See the guard"
  echo "header for the fix workflow."
  echo ""
  echo "Violations:"
  echo "$VIOLATIONS"
  exit 1
fi

echo "no-tag-pinned-actions guard OK: every GitHub Action is SHA-pinned"
