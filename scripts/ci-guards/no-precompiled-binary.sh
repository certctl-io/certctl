#!/usr/bin/env bash
# scripts/ci-guards/no-precompiled-binary.sh
#
# Phase 1 RED-1 closure (2026-05-13): no precompiled binary (ELF /
# Mach-O / PE) should ever be tracked in the repo. The original
# Phase 1 trigger was `deploy/test/f5-mock-icontrol/f5-mock-icontrol`
# — an 8.6 MB ARM64 ELF that lived in git alongside the Go source
# that builds it. The Dockerfile for that fixture already runs
# `go build` from source inside the container, so the tracked
# binary was vestigial. Deleting it cost nothing; tracking it cost
# 8.6 MB per clone forever.
#
# This guard scans every TRACKED file (i.e. what an external clone
# sees, not what's in the operator's working tree) and uses `file(1)`
# to detect compiled executables. Any hit fails the build with a
# clear pointer to the right fix.
#
# Allowlist:
#   - PNG / JPG / PDF / SVG / GIF / WebP — image assets are not
#     binaries in the supply-chain sense even though `file` reports
#     them as "executable" in some encodings.
#   - Specific large fixtures that legitimately need to be tracked
#     (e.g. canonical certificate test vectors). Add to the
#     allowlist with a rationale comment.
#
# Mirror of the B6-no-private-keys-in-tree.sh pattern.

set -e

# What `file(1)` outputs we treat as a binary smell. ELF / Mach-O /
# PE / Java class / WebAssembly all qualify. Image / archive / text
# formats do NOT.
BAD_TYPES='ELF|Mach-O|PE32|PE32\+|compiled Java class|WebAssembly'

VIOLATIONS=$(git ls-files -z \
  | xargs -0 file --brief --separator='|' --print0 2>/dev/null \
  | tr '\0' '\n' \
  | grep -E "$BAD_TYPES" \
  | grep -vE '^$' \
  || true)

if [ -n "$VIOLATIONS" ]; then
  echo "::error::no-precompiled-binary regression: tracked executable file(s) found:"
  echo ""
  echo "$VIOLATIONS"
  echo ""
  echo "Precompiled binaries must not be tracked. If this is a test"
  echo "fixture, route the build through a Dockerfile / Makefile target"
  echo "that rebuilds from source. If it is a legitimate exception,"
  echo "add the path to the allowlist in scripts/ci-guards/no-precompiled-binary.sh"
  echo "with a rationale comment."
  exit 1
fi

echo "no-precompiled-binary guard OK: no tracked ELF / Mach-O / PE / class / wasm binaries"
