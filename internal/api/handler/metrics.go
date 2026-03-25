package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
)

// MetricsService defines the service interface for metrics collection.
type MetricsService interface {
	GetDashboardSummary(ctx context.Context) (interface{}, error)
}

// MetricsHandler handles HTTP requests for metrics.
// Supports both JSON format (GET /api/v1/metrics) and Prometheus exposition format
// (GET /api/v1/metrics/prometheus) for integration with Prometheus, Grafana, Datadog, etc.
type MetricsHandler struct {
	svc           MetricsService
	serverStarted time.Time
}

// NewMetricsHandler creates a new MetricsHandler with a service dependency.
// serverStarted is used to calculate uptime_seconds.
func NewMetricsHandler(svc MetricsService, serverStarted time.Time) MetricsHandler {
	return MetricsHandler{
		svc:           svc,
		serverStarted: serverStarted,
	}
}

// MetricsResponse represents the JSON metrics response for V2.
type MetricsResponse struct {
	Gauge   MetricsGauge   `json:"gauge"`
	Counter MetricsCounter `json:"counter"`
	Uptime  UptimeMetric   `json:"uptime"`
}

// MetricsGauge represents gauge metrics (point-in-time values).
type MetricsGauge struct {
	CertificateTotal       int64   `json:"certificate_total"`
	CertificateActive      int64   `json:"certificate_active"`
	CertificateExpiringSoon int64  `json:"certificate_expiring_soon"` // Within 30d
	CertificateExpired     int64   `json:"certificate_expired"`
	CertificateRevoked     int64   `json:"certificate_revoked"`
	AgentTotal             int64   `json:"agent_total"`
	AgentOnline            int64   `json:"agent_online"`
	JobPending             int64   `json:"job_pending"`
}

// MetricsCounter represents counter metrics (cumulative values).
type MetricsCounter struct {
	JobCompletedTotal int64 `json:"job_completed_total"`
	JobFailedTotal    int64 `json:"job_failed_total"`
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
			CertificateTotal:      dashboardSummary.TotalCertificates,
			CertificateActive:     dashboardSummary.TotalCertificates - dashboardSummary.ExpiringCertificates - dashboardSummary.ExpiredCertificates - dashboardSummary.RevokedCertificates,
			CertificateExpiringSoon: dashboardSummary.ExpiringCertificates,
			CertificateExpired:    dashboardSummary.ExpiredCertificates,
			CertificateRevoked:    dashboardSummary.RevokedCertificates,
			AgentTotal:            dashboardSummary.TotalAgents,
			AgentOnline:           dashboardSummary.ActiveAgents,
			JobPending:            dashboardSummary.PendingJobs,
		},
		Counter: MetricsCounter{
			JobCompletedTotal: dashboardSummary.CompleteJobs,
			JobFailedTotal:    dashboardSummary.FailedJobs,
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

	// Info — server uptime
	fmt.Fprintf(w, "# HELP certctl_uptime_seconds Server uptime in seconds.\n")
	fmt.Fprintf(w, "# TYPE certctl_uptime_seconds gauge\n")
	fmt.Fprintf(w, "certctl_uptime_seconds %d\n", uptimeSeconds)
}

// DashboardSummary mirrors the service.DashboardSummary for JSON unmarshaling.
// JSON tags must match the service-layer struct exactly.
type DashboardSummary struct {
	TotalCertificates    int64     `json:"total_certificates"`
	ExpiringCertificates int64     `json:"expiring_certificates"`
	ExpiredCertificates  int64     `json:"expired_certificates"`
	RevokedCertificates  int64     `json:"revoked_certificates"`
	ActiveAgents         int64     `json:"active_agents"`
	OfflineAgents        int64     `json:"offline_agents"`
	TotalAgents          int64     `json:"total_agents"`
	PendingJobs          int64     `json:"pending_jobs"`
	FailedJobs           int64     `json:"failed_jobs"`
	CompleteJobs         int64     `json:"complete_jobs"`
	CompletedAt          time.Time `json:"completed_at"`
}
