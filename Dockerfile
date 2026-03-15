# Multi-stage build for certctl server
# Stage 1: Build
FROM golang:1.22-alpine AS builder

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

# Stage 2: Runtime
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata curl

RUN addgroup -g 1000 certctl && \
    adduser -D -u 1000 -G certctl certctl

WORKDIR /app

COPY --from=builder /app/bin/server .
COPY --chown=certctl:certctl migrations/ ./migrations/
COPY --chown=certctl:certctl web/ ./web/

RUN chown -R certctl:certctl /app

USER certctl

EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
    CMD curl -f http://localhost:8443/health || exit 1

ENTRYPOINT ["/app/server"]
