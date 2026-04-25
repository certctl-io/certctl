# Multi-stage build for certctl server

# Stage 1: Build frontend
FROM node:20-alpine AS frontend

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
RUN npm ci --include=dev || npm ci --include=dev && \
    node_modules/.bin/tsc --version && \
    npm run build

# Stage 2: Build Go binary
FROM golang:1.25-alpine AS builder

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
FROM alpine:3.19

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
