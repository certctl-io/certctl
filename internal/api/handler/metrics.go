package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
)

// MetricsService defines the service interface for metrics collection.
type MetricsService interface {
	GetDashboardSummary(ctx context.Context) (interface{}, error)
}

// CounterSnapshotter is the minimum surface MetricsHandler consumes
// from a counter table for the Prometheus exposer. The OCSPCounters
// type in internal/service satisfies this; future per-area counter
// tabs (CRL, cert-export, EST, SCEP, Intune) plug in the same way.
//
// Production hardening II Phase 8.
type CounterSnapshotter interface {
	Snapshot() map[string]uint64
}

// DeploySnapshotEntry is the per-target-type tuple emitted by the
// deploy package's counter table. Avoids importing the service
// package's DeploySnapshot directly so the handler stays
// dependency-light (the interface uses primitives only).
//
// Phase 10 of the deploy-hardening I master bundle.
type DeploySnapshotEntry struct {
	TargetType       string
	AttemptsSuccess  uint64
	AttemptsFailure  uint64
	ValidateFailures uint64
	ReloadFailures   uint64
	PostVerifyFails  uint64
	RollbackRestored uint64
	RollbackAlsoFail uint64
	IdempotentSkips  uint64
}

// DeployCounterSnapshotter is the surface MetricsHandler consumes
// for the per-target-type deploy counters. The DeployCounters type
// in internal/service satisfies this via an adapter.
type DeployCounterSnapshotter interface {
	Snapshot() []DeploySnapshotEntry
}

// MetricsHandler handles HTTP requests for metrics.
// Supports both JSON format (GET /api/v1/metrics) and Prometheus exposition format
// (GET /api/v1/metrics/prometheus) for integration with Prometheus, Grafana, Datadog, etc.
type MetricsHandler struct {
	svc           MetricsService
	serverStarted time.Time
	// Production hardening II Phase 8 — per-area counter snapshotters.
	// nil values omit the corresponding metric block; cmd/server/main.go
	// wires the instances at startup. The naming convention is
	// certctl_<area>_<label>_total per frozen decision 0.10.
	ocspCounters CounterSnapshotter
	// Phase 10 (deploy-hardening I) — per-target-type deploy counters.
	deployCounters DeployCounterSnapshotter
}

// NewMetricsHandler creates a new MetricsHandler with a service dependency.
// serverStarted is used to calculate uptime_seconds.
func NewMetricsHandler(svc MetricsService, serverStarted time.Time) MetricsHandler {
	return MetricsHandler{
		svc:           svc,
		serverStarted: serverStarted,
	}
}

// SetOCSPCounters wires the OCSP counter table for the per-area
// metric block in the Prometheus exposition. nil disables the block.
// Production hardening II Phase 8.
func (h *MetricsHandler) SetOCSPCounters(c CounterSnapshotter) {
	h.ocspCounters = c
}

// SetDeployCounters wires the per-target-type deploy counter table
// for the Prometheus exposition. nil disables the block. Phase 10
// of the deploy-hardening I master bundle.
func (h *MetricsHandler) SetDeployCounters(c DeployCounterSnapshotter) {
	h.deployCounters = c
}

// MetricsResponse represents the JSON metrics response for V2.
type MetricsResponse struct {
	Gauge   MetricsGauge   `json:"gauge"`
	Counter MetricsCounter `json:"counter"`
	Uptime  UptimeMetric   `json:"uptime"`
}

// MetricsGauge represents gauge metrics (point-in-time values).
type MetricsGauge struct {
	CertificateTotal        int64 `json:"certificate_total"`
	CertificateActive       int64 `json:"certificate_active"`
	CertificateExpiringSoon int64 `json:"certificate_expiring_soon"` // Within 30d
	CertificateExpired      int64 `json:"certificate_expired"`
	CertificateRevoked      int64 `json:"certificate_revoked"`
	AgentTotal              int64 `json:"agent_total"`
	AgentOnline             int64 `json:"agent_online"`
	JobPending              int64 `json:"job_pending"`
}

// MetricsCounter represents counter metrics (cumulative values).
type MetricsCounter struct {
	JobCompletedTotal int64 `json:"job_completed_total"`
	JobFailedTotal    int64 `json:"job_failed_total"`
	// NotificationsDeadTotal is a point-in-time count of notifications in the
	// dead-letter queue (status="dead"), exposed here with the _total suffix
	// to match Prometheus DB-snapshot counter convention (same semantics as
	// JobFailedTotal and JobCompletedTotal — see metrics.md). I-005 DLQ
	// observability gate.
	NotificationsDeadTotal int64 `json:"notifications_dead_total"`
}

// UptimeMetric represents server uptime information.
type UptimeMetric struct {
	UptimeSeconds int64     `json:"uptime_seconds"`
	ServerStarted time.Time `json:"server_started"`
	MeasuredAt    time.Time `json:"measured_at"`
}

// GetMetrics returns JSON metrics (aggregated from dashboard summary).
// GET /api/v1/metrics
func (h MetricsHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	summary, err := h.svc.GetDashboardSummary(r.Context())
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to collect metrics", requestID)
		return
	}

	// Extract fields from summary via JSON round-trip (avoids cross-package type assertion)
	jsonBytes, err := json.Marshal(summary)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to marshal metrics data", requestID)
		return
	}
	var dashboardSummary DashboardSummary
	if err := json.Unmarshal(jsonBytes, &dashboardSummary); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Invalid metrics data", requestID)
		return
	}

	// Build metrics response
	metricsResp := MetricsResponse{
		Gauge: MetricsGauge{
			CertificateTotal:        dashboardSummary.TotalCertificates,
			CertificateActive:       dashboardSummary.TotalCertificates - dashboardSummary.ExpiringCertificates - dashboardSummary.ExpiredCertificates - dashboardSummary.RevokedCertificates,
			CertificateExpiringSoon: dashboardSummary.ExpiringCertificates,
			CertificateExpired:      dashboardSummary.ExpiredCertificates,
			CertificateRevoked:      dashboardSummary.RevokedCertificates,
			AgentTotal:              dashboardSummary.TotalAgents,
			AgentOnline:             dashboardSummary.ActiveAgents,
			JobPending:              dashboardSummary.PendingJobs,
		},
		Counter: MetricsCounter{
			JobCompletedTotal:      dashboardSummary.CompleteJobs,
			JobFailedTotal:         dashboardSummary.FailedJobs,
			NotificationsDeadTotal: dashboardSummary.NotificationsDead,
		},
		Uptime: UptimeMetric{
			UptimeSeconds: int64(time.Since(h.serverStarted).Seconds()),
			ServerStarted: h.serverStarted,
			MeasuredAt:    time.Now(),
		},
	}

	JSON(w, http.StatusOK, metricsResp)
}

// GetPrometheusMetrics returns metrics in Prometheus exposition format (text/plain).
// GET /api/v1/metrics/prometheus
// Compatible with Prometheus, Grafana Agent, Datadog Agent, Victoria Metrics, and any
// OpenMetrics-compatible scraper. Metric names follow Prometheus naming conventions
// (lowercase, snake_case, prefixed with certctl_).
func (h MetricsHandler) GetPrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	summary, err := h.svc.GetDashboardSummary(r.Context())
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to collect metrics", requestID)
		return
	}

	// Extract fields from summary via JSON round-trip (avoids cross-package type assertion)
	jsonBytes, err := json.Marshal(summary)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to marshal metrics data", requestID)
		return
	}
	var dashboardSummary DashboardSummary
	if err := json.Unmarshal(jsonBytes, &dashboardSummary); err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Invalid metrics data", requestID)
		return
	}

	// Compute derived values
	active := dashboardSummary.TotalCertificates - dashboardSummary.ExpiringCertificates - dashboardSummary.ExpiredCertificates - dashboardSummary.RevokedCertificates
	uptimeSeconds := int64(time.Since(h.serverStarted).Seconds())

	// Build Prometheus exposition format
	// See: https://prometheus.io/docs/instrumenting/exposition_formats/
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Gauges — point-in-time values
	fmt.Fprintf(w, "# HELP certctl_certificate_total Total number of managed certificates.\n")
	fmt.Fprintf(w, "# TYPE certctl_certificate_total gauge\n")
	fmt.Fprintf(w, "certctl_certificate_total %d\n\n", dashboardSummary.TotalCertificates)

	fmt.Fprintf(w, "# HELP certctl_certificate_active Number of active (non-expiring, non-expired, non-revoked) certificates.\n")
	fmt.Fprintf(w, "# TYPE certctl_certificate_active gauge\n")
	fmt.Fprintf(w, "certctl_certificate_active %d\n\n", active)

	fmt.Fprintf(w, "# HELP certctl_certificate_expiring_soon Number of certificates expiring within 30 days.\n")
	fmt.Fprintf(w, "# TYPE certctl_certificate_expiring_soon gauge\n")
	fmt.Fprintf(w, "certctl_certificate_expiring_soon %d\n\n", dashboardSummary.ExpiringCertificates)

	fmt.Fprintf(w, "# HELP certctl_certificate_expired Number of expired certificates.\n")
	fmt.Fprintf(w, "# TYPE certctl_certificate_expired gauge\n")
	fmt.Fprintf(w, "certctl_certificate_expired %d\n\n", dashboardSummary.ExpiredCertificates)

	fmt.Fprintf(w, "# HELP certctl_certificate_revoked Number of revoked certificates.\n")
	fmt.Fprintf(w, "# TYPE certctl_certificate_revoked gauge\n")
	fmt.Fprintf(w, "certctl_certificate_revoked %d\n\n", dashboardSummary.RevokedCertificates)

	fmt.Fprintf(w, "# HELP certctl_agent_total Total number of registered agents.\n")
	fmt.Fprintf(w, "# TYPE certctl_agent_total gauge\n")
	fmt.Fprintf(w, "certctl_agent_total %d\n\n", dashboardSummary.TotalAgents)

	fmt.Fprintf(w, "# HELP certctl_agent_online Number of agents currently online.\n")
	fmt.Fprintf(w, "# TYPE certctl_agent_online gauge\n")
	fmt.Fprintf(w, "certctl_agent_online %d\n\n", dashboardSummary.ActiveAgents)

	fmt.Fprintf(w, "# HELP certctl_job_pending Number of jobs currently pending.\n")
	fmt.Fprintf(w, "# TYPE certctl_job_pending gauge\n")
	fmt.Fprintf(w, "certctl_job_pending %d\n\n", dashboardSummary.PendingJobs)

	// Counters — cumulative values
	fmt.Fprintf(w, "# HELP certctl_job_completed_total Total number of completed jobs.\n")
	fmt.Fprintf(w, "# TYPE certctl_job_completed_total counter\n")
	fmt.Fprintf(w, "certctl_job_completed_total %d\n\n", dashboardSummary.CompleteJobs)

	fmt.Fprintf(w, "# HELP certctl_job_failed_total Total number of failed jobs.\n")
	fmt.Fprintf(w, "# TYPE certctl_job_failed_total counter\n")
	fmt.Fprintf(w, "certctl_job_failed_total %d\n\n", dashboardSummary.FailedJobs)

	// I-005: notification dead-letter queue depth. Emitted with the _total
	// suffix to match the existing certctl_job_completed_total /
	// certctl_job_failed_total convention for DB-snapshot counters — the
	// value is a point-in-time COUNT(*) of notification_events rows where
	// status='dead', not a monotonically increasing process-lifetime counter.
	// Operators alert on this as "dead-letter depth" (thresholds in the
	// I-005 spec: > 0 → warning, > 10 → critical).
	fmt.Fprintf(w, "# HELP certctl_notification_dead_total Number of notifications in the dead-letter queue.\n")
	fmt.Fprintf(w, "# TYPE certctl_notification_dead_total counter\n")
	fmt.Fprintf(w, "certctl_notification_dead_total %d\n\n", dashboardSummary.NotificationsDead)

	// Info — server uptime
	fmt.Fprintf(w, "# HELP certctl_uptime_seconds Server uptime in seconds.\n")
	fmt.Fprintf(w, "# TYPE certctl_uptime_seconds gauge\n")
	fmt.Fprintf(w, "certctl_uptime_seconds %d\n", uptimeSeconds)

	// Production hardening II Phase 8 — per-area counters. Each block
	// is nil-guarded so a deploy without the wire still produces clean
	// output (just the legacy dashboard metrics above). Naming
	// convention: certctl_<area>_<label>_total per frozen decision
	// 0.10.
	if h.ocspCounters != nil {
		fmt.Fprintf(w, "\n# HELP certctl_ocsp_counter_total OCSP responder per-event counters (production hardening II Phase 8).\n")
		fmt.Fprintf(w, "# TYPE certctl_ocsp_counter_total counter\n")
		snap := h.ocspCounters.Snapshot()
		// Emit in a deterministic order so the output diff is stable
		// across requests (helps operators spot drift in dashboard
		// snapshots).
		labels := []string{
			"request_get", "request_post", "request_success", "request_invalid",
			"issuer_not_found", "cert_not_found", "signing_failed",
			"nonce_echoed", "nonce_malformed", "rate_limited",
		}
		for _, lbl := range labels {
			fmt.Fprintf(w, "certctl_ocsp_counter_total{label=%q} %d\n", lbl, snap[lbl])
		}
	}

	// Phase 10 (deploy-hardening I) — per-target-type deploy
	// counters. The exposer enumerates the (target_type, sub-label)
	// tuples to defend against drift; adding a new sub-counter to
	// DeployCounters without also adding it here would surface as
	// silent missing-metric in operator dashboards.
	if h.deployCounters != nil {
		fmt.Fprintf(w, "\n# HELP certctl_deploy_attempts_total Per-target-type deploy attempts (deploy-hardening I Phase 10).\n")
		fmt.Fprintf(w, "# TYPE certctl_deploy_attempts_total counter\n")
		snap := h.deployCounters.Snapshot()
		// Sort by target_type for stable output.
		sort.Slice(snap, func(i, j int) bool { return snap[i].TargetType < snap[j].TargetType })
		for _, s := range snap {
			fmt.Fprintf(w, "certctl_deploy_attempts_total{target_type=%q,result=%q} %d\n", s.TargetType, "success", s.AttemptsSuccess)
			fmt.Fprintf(w, "certctl_deploy_attempts_total{target_type=%q,result=%q} %d\n", s.TargetType, "failure", s.AttemptsFailure)
		}
		fmt.Fprintf(w, "\n# HELP certctl_deploy_validate_failures_total Per-target-type validate-step failures.\n")
		fmt.Fprintf(w, "# TYPE certctl_deploy_validate_failures_total counter\n")
		for _, s := range snap {
			fmt.Fprintf(w, "certctl_deploy_validate_failures_total{target_type=%q} %d\n", s.TargetType, s.ValidateFailures)
		}
		fmt.Fprintf(w, "\n# HELP certctl_deploy_reload_failures_total Per-target-type reload-step failures (rollback was attempted).\n")
		fmt.Fprintf(w, "# TYPE certctl_deploy_reload_failures_total counter\n")
		for _, s := range snap {
			fmt.Fprintf(w, "certctl_deploy_reload_failures_total{target_type=%q} %d\n", s.TargetType, s.ReloadFailures)
		}
		fmt.Fprintf(w, "\n# HELP certctl_deploy_post_verify_failures_total Per-target-type post-deploy TLS verify failures.\n")
		fmt.Fprintf(w, "# TYPE certctl_deploy_post_verify_failures_total counter\n")
		for _, s := range snap {
			fmt.Fprintf(w, "certctl_deploy_post_verify_failures_total{target_type=%q} %d\n", s.TargetType, s.PostVerifyFails)
		}
		fmt.Fprintf(w, "\n# HELP certctl_deploy_rollback_total Per-target-type rollbacks.\n")
		fmt.Fprintf(w, "# TYPE certctl_deploy_rollback_total counter\n")
		for _, s := range snap {
			fmt.Fprintf(w, "certctl_deploy_rollback_total{target_type=%q,outcome=%q} %d\n", s.TargetType, "restored", s.RollbackRestored)
			fmt.Fprintf(w, "certctl_deploy_rollback_total{target_type=%q,outcome=%q} %d\n", s.TargetType, "also_failed", s.RollbackAlsoFail)
		}
		fmt.Fprintf(w, "\n# HELP certctl_deploy_idempotent_skip_total Per-target-type SHA-256 idempotent skips (defends against retry storms).\n")
		fmt.Fprintf(w, "# TYPE certctl_deploy_idempotent_skip_total counter\n")
		for _, s := range snap {
			fmt.Fprintf(w, "certctl_deploy_idempotent_skip_total{target_type=%q} %d\n", s.TargetType, s.IdempotentSkips)
		}
	}
}

// DashboardSummary mirrors the service.DashboardSummary for JSON unmarshaling.
// JSON tags must match the service-layer struct exactly.
type DashboardSummary struct {
	TotalCertificates    int64 `json:"total_certificates"`
	ExpiringCertificates int64 `json:"expiring_certificates"`
	ExpiredCertificates  int64 `json:"expired_certificates"`
	RevokedCertificates  int64 `json:"revoked_certificates"`
	ActiveAgents         int64 `json:"active_agents"`
	OfflineAgents        int64 `json:"offline_agents"`
	TotalAgents          int64 `json:"total_agents"`
	PendingJobs          int64 `json:"pending_jobs"`
	FailedJobs           int64 `json:"failed_jobs"`
	CompleteJobs         int64 `json:"complete_jobs"`
	// NotificationsDead mirrors service.DashboardSummary.NotificationsDead.
	// JSON tag "notifications_dead" must match the service-layer struct
	// exactly — this cross-package mirror avoids a direct import cycle and
	// is driven by the I-005 Prometheus counter emission path. See
	// GetPrometheusMetrics and MetricsCounter.NotificationsDeadTotal.
	NotificationsDead int64     `json:"notifications_dead"`
	CompletedAt       time.Time `json:"completed_at"`
}
