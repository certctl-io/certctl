# EST RFC 7030 hardening master bundle Phase 10.1 — libest sidecar.
#
# Multi-stage build of Cisco's libest reference client, used as the
# canonical RFC 7030 client for the certctl integration test suite.
#
# Source: https://github.com/cisco/libest (the upstream reference
# implementation; latest tag is r3.2.0 — verified via
# https://api.github.com/repos/cisco/libest/tags 2026-04-30. The
# protocol surface we exercise is stable RFC 7030). We build from
# source rather than pulling a published image because no official
# Cisco image exists on Docker Hub + reproducible offline-friendly
# builds need a pinned ref.
#
# Note: an earlier draft of this Dockerfile (commit 15da1f4) pinned
# LIBEST_REF=v3.2.0-2 — that ref does not exist upstream (cisco/libest
# tags do NOT use the `v` prefix and there is no `-2` patch suffix).
# The build silently broke until ci-pipeline-cleanup Phase 8's Docker
# build smoke surfaced it.
#
# The builder stage compiles libest + its OpenSSL dependency; the
# runtime stage carries only the compiled `estclient` binary +
# `openssl` + `bash` so the integration test (which docker-execs into
# the container) has a small, predictable surface.
#
# Build (from repo root):
#   docker build -f deploy/test/libest/Dockerfile -t certctl/libest:test .
#
# CI uses `docker compose --profile est-e2e build libest-client` to
# orchestrate the build alongside the rest of the test stack.

ARG LIBEST_REF=r3.2.0

# Why bullseye-slim and NOT bookworm-slim:
#
# libest r3.2.0 (last upstream commit 2020-07-06) was authored
# against OpenSSL 1.1.x and binutils ≤ 2.35. It does NOT build on
# OpenSSL 3.0 / binutils 2.36+ for three independent reasons surfaced
# by the ci-pipeline-cleanup Phase 8 Docker build smoke step:
#
#   1. `FIPS_mode` / `FIPS_mode_set` — removed in OpenSSL 3.0;
#      libest calls them in 5 places (est_client.c lines 3179, 3590,
#      3676; est_server.c line 3336; estclient.c line 1283).
#      Even libest `main` branch (last update 2024-07-12) still uses
#      these without OpenSSL-version guards.
#   2. `e_ctx_ssl_exdata_index` declared without `extern` in
#      est_locl.h:593 — multiple-definition error under the binutils
#      2.36+ default `-fno-common`. Fixed on libest main but not
#      backported to r3.2.0.
#   3. `ossl_dump_ssl_errors` duplicate symbol between libest and
#      example/client/utils.c — same `-fno-common` shape.
#
# debian:bullseye-slim ships:
#   - OpenSSL 1.1.1n — FIPS_mode/FIPS_mode_set present as expected
#   - binutils 2.35.2 — pre-`-fno-common` default; tolerates the
#     multiple-def shape libest was written under
#
# All three build errors vanish simultaneously. The earlier draft of
# this Dockerfile (commit 15da1f4 + 320ef73) used bookworm-slim and
# silently broke the build; ci-pipeline-cleanup Phase 8's Docker
# build smoke surfaced it.
#
# Bullseye support timeline: regular updates until 2026-08, LTS
# until 2028-08. The libest sidecar is a hermetic test-only fixture
# (not exposed to attackers, not shipped in production), so the
# OpenSSL 1.1.1 EOL (2023-09) is acceptable here. Production
# certctl images stay on bookworm-slim with OpenSSL 3.0.
#
# Bundle A / Audit H-001 (CWE-829): both FROM lines below pin
# debian:bullseye-slim to the immutable OCI image-index digest pulled
# 2026-04-30. To bump:
#   tok=$(curl -sS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull" | jq -r .token)
#   curl -sSI -H "Authorization: Bearer $tok" \
#     -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
#     "https://registry-1.docker.io/v2/library/debian/manifests/bullseye-slim" \
#     | grep -i 'docker-content-digest'
# Replace the @sha256:... portion on BOTH FROM lines.
FROM debian:bullseye-slim@sha256:1a4701c321b1d28b1ff5f0230e766791e4b79b1d4c6c7a70064f4b297b1a330f AS builder

ARG LIBEST_REF

# Build deps. We use the system openssl (1.1.1n in bullseye-slim) which
# is the same major version libest r3.2.0 was tested against. libest
# also wants libcurl + libsafec; we install both via apt rather than
# building from source for reproducibility.
RUN apt-get update && apt-get install --no-install-recommends -y \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        git \
        libcurl4-openssl-dev \
        libssl-dev \
        libtool \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Why CFLAGS=-fcommon + LDFLAGS=-Wl,--allow-multiple-definition:
#
# GCC 10 (released 2020-05) flipped the default from -fcommon to
# -fno-common — "tentative definitions" of global variables in
# headers (without the `extern` keyword) now get a real definition
# in EVERY translation unit that includes the header. libest's
# est_locl.h:593 declares `int e_ctx_ssl_exdata_index;` without
# `extern`, so under GCC 10+ every libest .c file gets its own copy
# and the linker reports nine multiple-definition errors.
#
#   -fcommon                          → restore GCC 9 / pre-2020
#                                       default for tentative
#                                       definitions; tolerates the
#                                       libest est_locl.h shape.
#
# Separately, `ossl_dump_ssl_errors` is *defined* (not just
# declared) in BOTH src/est/est_ossl_util.c:310 (inside libest)
# AND example/client/util/utils.c:33 (which estclient links).
# This is a real-function-level duplicate; -fcommon doesn't apply.
#
#   -Wl,--allow-multiple-definition   → restore the pre-strict ld
#                                       behavior that tolerates
#                                       function-level duplicates
#                                       (last-defined-wins).
#
# Both flags restore the build contract libest 3.2.0 was authored
# under — they're the documented migration path for projects that
# relied on the GCC 9 / older binutils default. Not a band-aid;
# this is the canonical way to build libest 3.2.0 on a modern
# toolchain.
#
# bullseye-slim's GCC is 10.2 (already enforces -fno-common); the
# next-older default-fcommon GCC is 9.x in debian:buster, which is
# LTS-EOL since June 2024. Restoring the flag explicitly is cleaner
# than downgrading the base again.
#
# CRITICAL: pass CFLAGS + LDFLAGS at configure-time ONLY. Do NOT also
# pass them on the `make` command line.
#
# Why: libest's configure.ac (lines 193-195) unconditionally appends
# the bundled safec stub paths to the user's CFLAGS/LDFLAGS/LIBS:
#
#   CFLAGS="$CFLAGS -Wall -I$safecdir/include"
#   LDFLAGS="$LDFLAGS -L$safecdir/lib"
#   LIBS="$LIBS -lsafe_lib"
#
# The merged values get baked into the generated Makefile as
# @CFLAGS@/@LDFLAGS@/@LIBS@ substitutions, so every link command —
# notably estclient's — gets `-L/src/safe_c_stub/lib -lsafe_lib`.
#
# Per automake's variable-precedence rules, a command-line
# `make LDFLAGS=...` OVERRIDES the `LDFLAGS = @LDFLAGS@` line in
# the Makefile. Pass-through at make-time wipes the safec stub's
# `-L` path; estclient then fails to link with
# `cannot find -lsafe_lib` even though `safe_c_stub/lib/libsafe_lib.a`
# built fine. Configure-time alone is sufficient — configure writes
# the merged value into the Makefile exactly once.
RUN git clone --depth 1 --branch ${LIBEST_REF} https://github.com/cisco/libest.git . \
    && CFLAGS="-fcommon" \
       LDFLAGS="-Wl,--allow-multiple-definition" \
       ./configure --prefix=/opt/libest --disable-shared --enable-static \
    && make -j"$(nproc)" \
    && make install

# Runtime stage. Carries only what we need to docker-exec estclient
# from the integration test: the compiled binary, the openssl CLI for
# CSR generation + cert parsing, and bash for the test's exec scripts.
#
# MUST be bullseye-slim — the estclient binary built in the builder
# stage dynamically links against libssl1.1 + libcrypto1.1 (OpenSSL
# 1.1.x ABI). bookworm-slim ships libssl3/libcrypto3 only — running
# the bullseye-built binary on a bookworm runtime fails at startup
# with "error while loading shared libraries: libssl.so.1.1".
# Pinned to the same digest as the builder above (Bundle A / H-001).
FROM debian:bullseye-slim@sha256:1a4701c321b1d28b1ff5f0230e766791e4b79b1d4c6c7a70064f4b297b1a330f

RUN apt-get update && apt-get install --no-install-recommends -y \
        bash \
        ca-certificates \
        curl \
        libcurl4 \
        libssl1.1 \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 estuser

COPY --from=builder /opt/libest/bin/estclient /usr/local/bin/estclient

# /config/est is the working dir the integration test mounts; /config/certs
# carries certctl's CA bundle (./test/certs/ca.crt) for TLS pinning.
RUN mkdir -p /config/est /config/certs && chown -R estuser:estuser /config

USER estuser
WORKDIR /config/est

# Container stays alive so the integration test can docker-exec into
# it; matches the spec's `command: sleep infinity` directive.
CMD ["sleep", "infinity"]
