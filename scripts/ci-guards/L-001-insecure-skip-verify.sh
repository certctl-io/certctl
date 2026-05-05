#!/usr/bin/env bash
# scripts/ci-guards/L-001-insecure-skip-verify.sh
#
# L-001 audited every production InsecureSkipVerify=true call site
# and documented the justification per site in docs/operator/tls.md. This
# script grep-fails the build if any new `InsecureSkipVerify: true`
# lands in a non-test Go file without a `//nolint:gosec` comment
# carrying the justification. Test files (_test.go) are exempt.
# Updating the documented surface goes through the docs/operator/tls.md
# table — net-new sites must be reasoned about before merge.

set -e
# Find every "InsecureSkipVerify: true" or "InsecureSkipVerify = true"
# in a non-test .go file. Then for each, check the same line OR the
# immediately preceding line for `//nolint:gosec`.
BAD=""
while IFS= read -r match; do
  file=$(echo "$match" | cut -d: -f1)
  line=$(echo "$match" | cut -d: -f2)
  same=$(sed -n "${line}p" "$file" 2>/dev/null)
  prev=$(sed -n "$((line - 1))p" "$file" 2>/dev/null)
  if echo "$same $prev" | grep -q 'nolint:gosec'; then
    continue
  fi
  BAD="$BAD\n$match"
done < <(grep -rnE 'InsecureSkipVerify:\s*true|InsecureSkipVerify\s*=\s*true' \
           --include='*.go' \
           --exclude='*_test.go' \
           . || true)
if [ -n "$BAD" ]; then
  echo "::error::L-001 regression: new InsecureSkipVerify=true site without //nolint:gosec justification:"
  echo -e "$BAD"
  echo ""
  echo "Add a //nolint:gosec comment with justification on the same"
  echo "or preceding line, AND add a row to the docs/operator/tls.md table."
  exit 1
fi
echo "L-001 insecure-skip-verify: clean."
