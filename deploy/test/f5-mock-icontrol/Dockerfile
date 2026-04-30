# f5-mock-icontrol sidecar: in-tree Go server implementing the
# subset of F5 iControl REST that the certctl F5 connector exercises.
# Used by the deploy-hardening II Phase 10 vendor-edge tests as a
# CI-friendly alternative to a real F5 BIG-IP appliance.
#
# Per H-001 guard: every FROM is digest-pinned. Operator re-pins
# quarterly per docs/deployment-vendor-matrix.md.

# golang:1.25.9-bookworm digest pinned per H-001.
FROM golang:1.25.9-bookworm@sha256:a3a4d83e8e83bf9bb6bf6c5e41bcde5a8e8e1d8e6b9cbcd3b9e7c5d4e7f9c1d5 AS builder
WORKDIR /src
COPY deploy/test/f5-mock-icontrol/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/f5-mock-icontrol .

# debian:bookworm-slim digest pinned per H-001 (matches libest sidecar).
FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252
RUN useradd --create-home --shell /bin/bash mockf5
COPY --from=builder /out/f5-mock-icontrol /usr/local/bin/f5-mock-icontrol
USER mockf5
EXPOSE 443 8080
ENTRYPOINT ["/usr/local/bin/f5-mock-icontrol"]
