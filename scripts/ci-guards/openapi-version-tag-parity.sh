#!/usr/bin/env bash
# scripts/ci-guards/openapi-version-tag-parity.sh
#
# ARCH-001-A closure (Sprint 5, 2026-05-16). The hand-written
# api/openapi.yaml carries an info.version that historically drifted
# from the actual git-tag-shipping cadence (was "2.0.0" against a
# v2.1.7 latest tag). External consumers reading the spec for their
# generated clients have no signal which release shipped it.
#
# Fix: the guard reads info.version from openapi.yaml and the latest
# `v*` git tag from the repo. If they don't match, fail. Bump
# info.version in the same commit that runs `git tag -a v* ...`
# at release time.
#
# Edge cases handled:
#   - Shallow CI clones: actions/checkout fetches no tags by default.
#     The guard falls back to the GitHub API when local tags are
#     unavailable, mirroring CLAUDE.md's ground-truth-against-the-API
#     pattern. CI sets fetch-tags: true on the checkout step (per the
#     workflow update that lands alongside this guard) so local-tag
#     reads work reliably.
#   - Pre-first-tag: skip with a notice if no v* tag exists yet.

set -e

YAML="api/openapi.yaml"
if [ ! -f "$YAML" ]; then
  echo "::error::openapi-version-tag-parity: $YAML not found"
  exit 1
fi

# Extract info.version from openapi.yaml. The version is at top level
# under `info:`. Use a minimal awk state machine instead of pulling
# yq into the CI dep graph.
spec_version=$(awk '
  /^info:/        { in_info = 1; next }
  /^[a-zA-Z]/     { in_info = 0 }
  in_info && /^[[:space:]]+version:/ {
    sub(/.*version:[[:space:]]*/, "")
    sub(/[[:space:]]*#.*$/, "")
    gsub(/^[[:space:]]+|[[:space:]]+$/, "")
    print
    exit
  }' "$YAML")

if [ -z "$spec_version" ]; then
  echo "::error file=${YAML}::openapi-version-tag-parity: could not parse info.version. Expected a `version: x.y.z` line under `info:`."
  exit 1
fi

# Resolve the latest tag locally. Fall back to the GitHub API if the
# checkout is shallow + tag-less (CLAUDE.md ground-truth pattern).
latest_tag=$(git tag --sort=-v:refname 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
if [ -z "$latest_tag" ]; then
  echo "openapi-version-tag-parity: no local v* tag found; falling back to api.github.com/.../tags"
  latest_tag=$(curl -sS https://api.github.com/repos/certctl-io/certctl/tags 2>/dev/null \
    | grep -oE '"name": *"v[0-9]+\.[0-9]+\.[0-9]+"' \
    | head -1 \
    | sed -E 's/.*"v/v/; s/".*//')
fi
if [ -z "$latest_tag" ]; then
  echo "openapi-version-tag-parity: no v* tag anywhere yet — skipping (pre-first-release)."
  exit 0
fi

# Strip the leading 'v' from the tag for comparison.
tag_version="${latest_tag#v}"

if [ "$spec_version" != "$tag_version" ]; then
  echo "::error file=${YAML}::openapi-version-tag-parity: info.version=${spec_version} does NOT match latest tag ${latest_tag}."
  echo "  Bump $YAML info.version to ${tag_version} in the same commit that ships the release,"
  echo "  OR if a release commit is in flight, tag it first then re-run CI."
  exit 1
fi

echo "openapi-version-tag-parity: clean (info.version=${spec_version} matches latest tag ${latest_tag})."
