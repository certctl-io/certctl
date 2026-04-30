#!/usr/bin/env bash
# scripts/ci-guards/digest-validity.sh
#
# Verify every @sha256:<digest> reference in deploy/**/*.{yml,Dockerfile*}
# actually resolves on its registry. H-001 only checks for digest
# presence; this catches fabricated or stale digests.
#
# Per ci-pipeline-cleanup bundle Phase 7. The bug class this catches:
# Bundle II shipped 11 fabricated digests that passed H-001's
# regex-only check and failed `docker pull` in CI.
#
# Real registries supported:
#   - Docker Hub library/* and non-library (auth.docker.io)
#   - ghcr.io (lscr.io alias for linuxserver/*)
#   - mcr.microsoft.com (no auth required for public images;
#     Windows IIS image needs the manifest.v2 single-image digest,
#     not the multi-arch list digest)

set -e

# Find every digest reference in compose files + Dockerfiles
mapfile -t REFS < <(
  grep -rEho '[a-z0-9./-]+:[a-z0-9.-]+@sha256:[a-f0-9]{64}' \
    deploy/ Dockerfile* deploy/test/*/Dockerfile 2>/dev/null \
    | sort -u
)

if [ ${#REFS[@]} -eq 0 ]; then
  echo "No @sha256 refs found — nothing to verify."
  exit 0
fi

fail=0
for ref in "${REFS[@]}"; do
  digest="${ref##*@}"
  imgtag="${ref%@*}"
  tag="${imgtag##*:}"
  img="${imgtag%:*}"

  # Determine registry + auth flow.
  if [[ "$img" =~ ^lscr\.io/ ]]; then
    img="${img#lscr.io/}"
    registry="ghcr.io"
    auth_url="https://ghcr.io/token?scope=repository:${img}:pull"
  elif [[ "$img" =~ ^mcr\.microsoft\.com/ ]]; then
    img="${img#mcr.microsoft.com/}"
    registry="mcr.microsoft.com"
    auth_url=""
  elif [[ "$img" == */* ]]; then
    # Non-library Docker Hub (e.g., envoyproxy/envoy, boky/postfix)
    registry="registry-1.docker.io"
    auth_url="https://auth.docker.io/token?service=registry.docker.io&scope=repository:${img}:pull"
  else
    # Library Docker Hub (e.g., httpd, golang)
    img="library/$img"
    registry="registry-1.docker.io"
    auth_url="https://auth.docker.io/token?service=registry.docker.io&scope=repository:${img}:pull"
  fi

  # Get auth token if needed.
  auth_header=""
  if [ -n "$auth_url" ]; then
    tok=$(curl -sS "$auth_url" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null)
    if [ -z "$tok" ]; then
      echo "::error::Failed to get auth token for $registry / $img"
      fail=1
      continue
    fi
    auth_header="Authorization: Bearer $tok"
  fi

  # HEAD the manifest by digest.
  if [ -n "$auth_header" ]; then
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -H "$auth_header" \
      -H "Accept: application/vnd.oci.image.index.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      "https://${registry}/v2/${img}/manifests/${digest}")
  else
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -H "Accept: application/vnd.oci.image.index.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      "https://${registry}/v2/${img}/manifests/${digest}")
  fi

  if [ "$code" != "200" ]; then
    echo "::error::digest does not resolve: ${ref}"
    echo "  registry: $registry"
    echo "  image:    $img"
    echo "  digest:   $digest"
    echo "  HTTP:     $code"
    fail=1
  else
    echo "OK  $ref"
  fi
done

[ $fail -eq 0 ] || exit 1
echo ""
echo "digest-validity: clean — all ${#REFS[@]} digest references resolve."
