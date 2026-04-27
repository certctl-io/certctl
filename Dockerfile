# Multi-stage build for certctl server
#
# Bundle A / Audit H-001 (CWE-829): every FROM line is pinned to an
# immutable digest in addition to the human-readable tag. The tag is
# advisory; the digest is what Docker actually pulls. A registry-side
# tag swap (the documented prior-art for tag-only pulls being unsafe)
# can no longer change the build.
#
# Bump procedure (operator):
#   1. Quarterly cadence (or sooner if a CVE lands on a base image).
#   2. For each FROM:
#        docker pull <image>:<tag>
#        docker manifest inspect <image>:<tag> | grep -m1 digest
#      OR via Docker Hub Registry API:
#        curl -sSL https://hub.docker.com/v2/repositories/library/<image>/tags/<tag> \
#          | jq -r .digest
#   3. Replace the @sha256:... portion of the FROM line.
#   4. Run `docker build` locally + verify CI.
#   5. Commit with the bump procedure cited in the message body.
#
# The CI step "Forbidden bare FROM regression guard (H-001)" rejects
# any future commit that lands a FROM without an @sha256 pin.

# Stage 1: Build frontend
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS frontend

# Proxy propagation (M-4, Issue #9) — defaulted to empty so un-proxied builds
# behave identically to the pre-fix tree. When `HTTP_PROXY`/`HTTPS_PROXY`/
# `NO_PROXY` are forwarded via `docker build --build-arg` (or compose
# `build.args`), they are re-exported as ENV with both upper- and lower-case
# names because npm/apk/curl read the lowercase variants while Go, Node, and
# most HTTP libraries read the uppercase ones.
ARG HTTP_PROXY=
ARG HTTPS_PROXY=
ARG NO_PROXY=
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY}

WORKDIR /app/web

COPY web/ .
# Bundle A / Audit M-014: explicit retry loop for `npm ci`. Pre-bundle
# this was `npm ci || npm ci && tsc && build` — the bash precedence is
# `A || (B && C && D)` so the second `npm ci` only ran on the failure
# path of the first, but the `tsc && build` chain only ran on the
# success path of the second. Net effect: a transient registry blip
# turned the build into a silent skip of the production step.
#
# New shape: a deterministic 3-attempt retry with 5-second backoff and
# an explicit `[ -d node_modules ]` post-check so a silent failure is
# impossible.
RUN for i in 1 2 3; do \
        npm ci --include=dev && break; \
        echo "npm ci attempt $i failed; sleeping 5s before retry"; \
        sleep 5; \
    done && \
    [ -d node_modules ] || (echo "ERROR: npm ci failed after 3 attempts; node_modules missing" && exit 1) && \
    node_modules/.bin/tsc --version && \
    npm run build

# Stage 2: Build Go binary
FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder

# Proxy propagation (M-4, Issue #9) — see Stage 1 rationale.
ARG HTTP_PROXY=
ARG HTTPS_PROXY=
ARG NO_PROXY=
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY}

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build server binary (use TARGETARCH for multi-platform support)
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s" \
    -o bin/server \
    ./cmd/server

# Stage 3: Runtime
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

RUN apk add --no-cache ca-certificates tzdata curl

RUN addgroup -g 1000 certctl && \
    adduser -D -u 1000 -G certctl certctl

WORKDIR /app

COPY --from=builder /app/bin/server .
COPY --chown=certctl:certctl migrations/ ./migrations/
COPY --from=frontend --chown=certctl:certctl /app/web/dist/ ./web/dist/

RUN chown -R certctl:certctl /app

USER certctl

EXPOSE 8443

# Image-level HEALTHCHECK for bare `docker run` / Docker Swarm / Nomad / ECS.
#
# U-2 (P1, cat-u-healthcheck_protocol_mismatch): pre-U-2 this probe used
# `curl -f http://localhost:8443/health`, which always failed against the
# HTTPS-only listener (HTTPS-Everywhere milestone, v2.2 / tag v2.0.47 —
# `cmd/server/main.go::ListenAndServeTLS`, no plaintext fallback, TLS 1.3
# pinned). Operators outside docker-compose / Helm saw permanent
# `unhealthy` status and a restart-loop the first time they pulled the
# image. The compose stack overrides this HEALTHCHECK with `--cacert` to
# the bootstrap CA bundle (deploy/docker-compose.yml:126); the Helm chart
# uses explicit `httpGet` probes with `scheme: HTTPS` and ignores Docker's
# HEALTHCHECK; every example compose file in `examples/*/docker-compose.yml`
# overrides with `curl -sfk https://localhost:8443/health`. This image-
# level probe is for the bare-`docker run` consumer ONLY.
#
# `-k` (insecure) is acceptable here because the probe is localhost-to-
# localhost: the same process serving the cert is being probed; the probe
# never traverses a network. Pinning a `--cacert` is not viable for the
# published image because the bootstrap cert is per-deploy (generated into
# the `certs` named volume on first up; operator-supplied via Helm's
# `existingSecret` or cert-manager). Compose / Helm / examples already
# perform full cert-chain validation and are unaffected.
#
# CI grep guardrail at .github/workflows/ci.yml ("Forbidden plaintext
# HEALTHCHECK regression guard (U-2)") blocks reintroduction of the
# `http://` shape. Image-level integration test in
# deploy/test/healthcheck_test.go pins the contract end-to-end.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
    CMD curl -fsk https://localhost:8443/health || exit 1

ENTRYPOINT ["/app/server"]
