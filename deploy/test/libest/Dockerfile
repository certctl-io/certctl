# EST RFC 7030 hardening master bundle Phase 10.1 — libest sidecar.
#
# Multi-stage build of Cisco's libest reference client, used as the
# canonical RFC 7030 client for the certctl integration test suite.
#
# Source: https://github.com/cisco/libest (the upstream reference
# implementation; last tag 3.2.0-2 from 2018, but the protocol surface
# we exercise is stable RFC 7030). We build from source rather than
# pulling a published image because no official Cisco image exists on
# Docker Hub + reproducible offline-friendly builds need a pinned ref.
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

ARG LIBEST_REF=v3.2.0-2

FROM debian:bookworm-slim AS builder

ARG LIBEST_REF

# Build deps. We use the system openssl (1.1.1n in bookworm-slim) which
# is the same major version libest 3.2.0-2 was tested against. libest
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

RUN git clone --depth 1 --branch ${LIBEST_REF} https://github.com/cisco/libest.git . \
    && ./configure --prefix=/opt/libest --disable-shared --enable-static \
    && make -j"$(nproc)" \
    && make install

# Runtime stage. Carries only what we need to docker-exec estclient
# from the integration test: the compiled binary, the openssl CLI for
# CSR generation + cert parsing, and bash for the test's exec scripts.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install --no-install-recommends -y \
        bash \
        ca-certificates \
        curl \
        libcurl4 \
        libssl3 \
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
