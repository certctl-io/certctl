// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

// Package observability is the optional OpenTelemetry seed.
// Acquisition-audit DEPL-006 closure (Sprint 6 ACQ, 2026-05-16).
//
// What this package does
// ======================
//
// Init wires up an OTLP/HTTP tracer provider when
// CERTCTL_OTEL_ENABLED=true and registers it as the global
// otel.SetTracerProvider. The returned shutdown function MUST be
// deferred by the caller (typically cmd/server/main.go) so in-
// flight spans flush before process exit.
//
// When CERTCTL_OTEL_ENABLED is unset or false (the default), Init
// returns a no-op shutdown and does NOT register a tracer provider.
// The global otel.GetTracerProvider() therefore returns the SDK's
// noop provider; any spans created by future-instrumented code
// paths are silently discarded with no allocation cost. Zero
// behavior change for operators who don't opt in.
//
// What this package does NOT do
// =============================
//
//   - No span instrumentation is added anywhere in the certctl code
//     base by this commit. The DEPL-006 audit finding is closed by
//     standing up the surface (initializer + config wiring + dep
//     promotion); per-handler / per-query / per-connector spans are
//     tracked as a v2.3 roadmap follow-up.
//
//   - The hand-rolled Prometheus exposition handler at
//     internal/api/handler/metrics.go::GetPrometheusMetrics is
//     intentionally untouched. OTel is additive — operators with
//     Prometheus continue to scrape the existing endpoint; operators
//     with an OTel collector can opt in by setting CERTCTL_OTEL_ENABLED
//     and OTEL_EXPORTER_OTLP_ENDPOINT.
//
// Transport choice
// ================
//
// The exporter uses OTLP/HTTP (proto-binary over HTTPS), not OTLP/gRPC.
// Both are valid OTel transports and downstream collectors accept
// either. OTLP/HTTP is chosen here to keep certctl's dependency
// surface narrow — gRPC pulls in google.golang.org/grpc +
// google.golang.org/genproto/* which materially expand the binary
// size and the supply-chain attack surface for a feature that today
// emits zero spans. Operators with a gRPC-only collector can wrap
// their collector with an OTel-collector tee or run the
// collector's OTLP/HTTP receiver alongside. If gRPC-direct
// becomes a real ask, swapping the exporter is a single-import
// change.
//
// Env vars
// ========
//
//	CERTCTL_OTEL_ENABLED          — gate (default false).
//	OTEL_EXPORTER_OTLP_ENDPOINT   — standard OTel env var; HTTP URL.
//	                                Default (per OTel spec):
//	                                http://localhost:4318.
//	OTEL_EXPORTER_OTLP_HEADERS    — standard OTel env var; auth
//	                                header pairs for the collector.
//	OTEL_SERVICE_NAME             — overrides the default
//	                                "certctl-server" resource label.
//
// All standard OTEL_* env vars the SDK consumes are honored
// automatically — this Init does not re-implement them.
package observability

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
)

// Config is the operator-facing config surface for the OTel seed.
// Plumbed in from internal/config/config.go::ObservabilityConfig at
// boot. The single field is Enabled — service name + endpoint +
// headers + protocol flow through the standard OTEL_* env vars
// honored directly by the OTel SDK (resource.WithFromEnv +
// otlptracehttp.New), no certctl-specific re-implementation.
type Config struct {
	// Enabled gates the whole subsystem. When false, Init returns a
	// no-op shutdown and registers nothing. CERTCTL_OTEL_ENABLED.
	Enabled bool
}

// Init initializes OpenTelemetry tracing if cfg.Enabled is true.
//
// The returned shutdown function flushes the in-flight span batcher
// and tears the tracer provider down. The caller MUST defer it
// before process exit; without the shutdown, the last batch of
// spans is lost.
//
// When disabled, Init returns a no-op shutdown that always succeeds.
// Callers can therefore unconditionally defer the returned function
// without branching on cfg.Enabled.
//
// The OTLP HTTP client created here connects lazily — Init does
// NOT block on the collector being reachable. An unreachable
// collector surfaces as failed export attempts in the SDK's
// internal error log, NOT as a boot-time error. This is intentional:
// observability MUST NOT block process startup.
func Init(ctx context.Context, cfg Config) (shutdown func(context.Context) error, err error) {
	if !cfg.Enabled {
		return noopShutdown, nil
	}

	// resource.WithFromEnv picks up OTEL_RESOURCE_ATTRIBUTES and
	// OTEL_SERVICE_NAME from the environment — operators override
	// service.name without code changes. WithProcess adds process.*
	// attributes (PID, runtime info). The default service.name
	// "certctl-server" applies only when OTEL_SERVICE_NAME is unset.
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("certctl-server")),
		resource.WithFromEnv(),
		resource.WithProcess(),
	)
	if err != nil {
		return nil, fmt.Errorf("observability: resource.New: %w", err)
	}

	// otlptracehttp.New honors the standard OTel env vars:
	// OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS,
	// OTEL_EXPORTER_OTLP_INSECURE, OTEL_EXPORTER_OTLP_TIMEOUT,
	// OTEL_EXPORTER_OTLP_PROTOCOL. The HTTP client connects lazily;
	// New returns nil error even if the collector is unreachable.
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("observability: otlptracehttp.New: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// noopShutdown is the disabled-mode return — always succeeds. Kept
// as a package-level var so we don't allocate a fresh closure on
// every disabled Init call.
var noopShutdown = func(context.Context) error { return nil }
