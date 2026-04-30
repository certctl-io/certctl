# f5-mock-icontrol sidecar: in-tree Go server implementing the
# subset of F5 iControl REST that the certctl F5 connector exercises.
# Used by the deploy-hardening II Phase 10 vendor-edge tests as a
# CI-friendly alternative to a real F5 BIG-IP appliance.
#
# Per H-001 guard: every FROM is digest-pinned. Operator re-pins
# quarterly per docs/deployment-vendor-matrix.md.

# golang:1.25.9-bookworm digest pinned per H-001.
FROM golang:1.25.9-bookworm@sha256:1a1408bf8d2d3077f9508880caf0e8bb0fde195fe3c890e7ea480dfb66dc7827 AS builder
WORKDIR /src
COPY deploy/test/f5-mock-icontrol/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/f5-mock-icontrol .

# debian:bookworm-slim digest pinned per H-001 (matches libest sidecar).
FROM debian:bookworm-slim@sha256:5a2a80d11944804c01b8619bc967e31801ec39bf3257ab80b91070eb23625644
RUN useradd --create-home --shell /bin/bash mockf5
COPY --from=builder /out/f5-mock-icontrol /usr/local/bin/f5-mock-icontrol
USER mockf5
EXPOSE 443 8080
ENTRYPOINT ["/usr/local/bin/f5-mock-icontrol"]
