package domain

import "time"

// HealthStatus represents the current health state of a monitored endpoint.
type HealthStatus string

const (
	HealthStatusHealthy      HealthStatus = "healthy"
	HealthStatusDegraded     HealthStatus = "degraded"
	HealthStatusDown         HealthStatus = "down"
	HealthStatusCertMismatch HealthStatus = "cert_mismatch"
	HealthStatusUnknown      HealthStatus = "unknown"
)

// IsValidHealthStatus checks if a health status string is valid.
func IsValidHealthStatus(s string) bool {
	switch HealthStatus(s) {
	case HealthStatusHealthy, HealthStatusDegraded, HealthStatusDown, HealthStatusCertMismatch, HealthStatusUnknown:
		return true
	}
	return false
}

// EndpointHealthCheck represents a monitored TLS endpoint.
type EndpointHealthCheck struct {
	ID                  string        `json:"id"`
	Endpoint            string        `json:"endpoint"`
	CertificateID       *string       `json:"certificate_id,omitempty"`
	NetworkScanTargetID *string       `json:"network_scan_target_id,omitempty"`
	ExpectedFingerprint string        `json:"expected_fingerprint"`
	ObservedFingerprint string        `json:"observed_fingerprint"`
	Status              HealthStatus  `json:"status"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	ResponseTimeMs      int           `json:"response_time_ms"`
	TLSVersion          string        `json:"tls_version"`
	CipherSuite         string        `json:"cipher_suite"`
	CertSubject         string        `json:"cert_subject"`
	CertIssuer          string        `json:"cert_issuer"`
	CertExpiry          *time.Time    `json:"cert_expiry,omitempty"`
	LastCheckedAt       *time.Time    `json:"last_checked_at,omitempty"`
	LastSuccessAt       *time.Time    `json:"last_success_at,omitempty"`
	LastFailureAt       *time.Time    `json:"last_failure_at,omitempty"`
	LastTransitionAt    *time.Time    `json:"last_transition_at,omitempty"`
	FailureReason       string        `json:"failure_reason"`
	DegradedThreshold   int           `json:"degraded_threshold"`
	DownThreshold       int           `json:"down_threshold"`
	CheckIntervalSecs   int           `json:"check_interval_seconds"`
	Enabled             bool          `json:"enabled"`
	Acknowledged        bool          `json:"acknowledged"`
	AcknowledgedBy      string        `json:"acknowledged_by,omitempty"`
	AcknowledgedAt      *time.Time    `json:"acknowledged_at,omitempty"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

// TransitionStatus computes the new health status based on the probe result.
// Returns the new status and whether a transition occurred.
func (h *EndpointHealthCheck) TransitionStatus(probeSuccess bool, observedFingerprint string) (HealthStatus, bool) {
	oldStatus := h.Status
	var newStatus HealthStatus

	if probeSuccess {
		if h.ExpectedFingerprint != "" && observedFingerprint != h.ExpectedFingerprint {
			newStatus = HealthStatusCertMismatch
		} else {
			newStatus = HealthStatusHealthy
		}
	} else {
		// Increment failures for next calculation (caller will update h.ConsecutiveFailures)
		failures := h.ConsecutiveFailures + 1
		if failures >= h.DownThreshold {
			newStatus = HealthStatusDown
		} else if failures >= h.DegradedThreshold {
			newStatus = HealthStatusDegraded
		} else {
			// Keep current status during initial failures before threshold
			// Unless we were in an error state, transition to degraded after first failure
			if h.Status == HealthStatusUnknown || h.Status == HealthStatusHealthy {
				newStatus = HealthStatusHealthy // still considered healthy during grace period
			} else {
				newStatus = h.Status
			}
		}
	}

	return newStatus, newStatus != oldStatus
}

// HealthHistoryEntry represents a single probe record.
type HealthHistoryEntry struct {
	ID            string    `json:"id"`
	HealthCheckID string    `json:"health_check_id"`
	Status        string    `json:"status"`
	ResponseTimeMs int      `json:"response_time_ms"`
	Fingerprint   string    `json:"fingerprint"`
	FailureReason string    `json:"failure_reason"`
	CheckedAt     time.Time `json:"checked_at"`
}

// HealthCheckSummary contains aggregate counts by status.
type HealthCheckSummary struct {
	Healthy      int `json:"healthy"`
	Degraded     int `json:"degraded"`
	Down         int `json:"down"`
	CertMismatch int `json:"cert_mismatch"`
	Unknown      int `json:"unknown"`
	Total        int `json:"total"`
}
