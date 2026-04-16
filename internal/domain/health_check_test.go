package domain

import (
	"testing"
	"time"
)

func TestIsValidHealthStatus(t *testing.T) {
	tests := []struct {
		status string
		valid  bool
	}{
		{"healthy", true},
		{"degraded", true},
		{"down", true},
		{"cert_mismatch", true},
		{"unknown", true},
		{"invalid", false},
		{"", false},
		{"HEALTHY", false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := IsValidHealthStatus(tt.status)
			if result != tt.valid {
				t.Errorf("IsValidHealthStatus(%q) = %v, want %v", tt.status, result, tt.valid)
			}
		})
	}
}

func TestTransitionStatus_HealthyProbe(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusUnknown,
		ConsecutiveFailures: 0,
		DegradedThreshold:   2,
		DownThreshold:       5,
		ExpectedFingerprint: "abc123",
	}

	newStatus, transitioned := h.TransitionStatus(true, "abc123")

	if newStatus != HealthStatusHealthy {
		t.Errorf("expected HealthStatusHealthy, got %s", newStatus)
	}
	if !transitioned {
		t.Errorf("expected transition=true, got false")
	}
}

func TestTransitionStatus_CertMismatch(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusHealthy,
		ConsecutiveFailures: 0,
		DegradedThreshold:   2,
		DownThreshold:       5,
		ExpectedFingerprint: "abc123",
	}

	newStatus, transitioned := h.TransitionStatus(true, "xyz789")

	if newStatus != HealthStatusCertMismatch {
		t.Errorf("expected HealthStatusCertMismatch, got %s", newStatus)
	}
	if !transitioned {
		t.Errorf("expected transition=true, got false")
	}
}

func TestTransitionStatus_FirstFailure_BelowThreshold(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusHealthy,
		ConsecutiveFailures: 0,
		DegradedThreshold:   2,
		DownThreshold:       5,
	}

	newStatus, transitioned := h.TransitionStatus(false, "")

	// At 1 failure with degraded threshold 2, still healthy
	if newStatus != HealthStatusHealthy {
		t.Errorf("expected HealthStatusHealthy (grace period), got %s", newStatus)
	}
	if transitioned {
		t.Errorf("expected transition=false (still healthy), got true")
	}
}

func TestTransitionStatus_DegradedThreshold(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusHealthy,
		ConsecutiveFailures: 1, // Now will be 2 after increment
		DegradedThreshold:   2,
		DownThreshold:       5,
	}

	newStatus, transitioned := h.TransitionStatus(false, "")

	if newStatus != HealthStatusDegraded {
		t.Errorf("expected HealthStatusDegraded, got %s", newStatus)
	}
	if !transitioned {
		t.Errorf("expected transition=true, got false")
	}
}

func TestTransitionStatus_DownThreshold(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusDegraded,
		ConsecutiveFailures: 4, // Now will be 5 after increment
		DegradedThreshold:   2,
		DownThreshold:       5,
	}

	newStatus, transitioned := h.TransitionStatus(false, "")

	if newStatus != HealthStatusDown {
		t.Errorf("expected HealthStatusDown, got %s", newStatus)
	}
	if !transitioned {
		t.Errorf("expected transition=true, got false")
	}
}

func TestTransitionStatus_Recovery(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusDown,
		ConsecutiveFailures: 10,
		DegradedThreshold:   2,
		DownThreshold:       5,
		ExpectedFingerprint: "abc123",
	}

	newStatus, transitioned := h.TransitionStatus(true, "abc123")

	if newStatus != HealthStatusHealthy {
		t.Errorf("expected HealthStatusHealthy (recovery), got %s", newStatus)
	}
	if !transitioned {
		t.Errorf("expected transition=true (from down to healthy), got false")
	}
}

func TestTransitionStatus_NoFingerprint(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusHealthy,
		ConsecutiveFailures: 0,
		DegradedThreshold:   2,
		DownThreshold:       5,
		ExpectedFingerprint: "", // No expected fingerprint
	}

	newStatus, transitioned := h.TransitionStatus(true, "anything")

	// Success with no expected fingerprint should always be healthy
	if newStatus != HealthStatusHealthy {
		t.Errorf("expected HealthStatusHealthy (no fingerprint check), got %s", newStatus)
	}
	if transitioned {
		t.Errorf("expected transition=false (already healthy), got true")
	}
}

func TestTransitionStatus_UnknownToHealthy(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusUnknown,
		ConsecutiveFailures: 0,
		DegradedThreshold:   2,
		DownThreshold:       5,
	}

	newStatus, transitioned := h.TransitionStatus(true, "")

	if newStatus != HealthStatusHealthy {
		t.Errorf("expected HealthStatusHealthy, got %s", newStatus)
	}
	if !transitioned {
		t.Errorf("expected transition=true (from unknown to healthy), got false")
	}
}

func TestTransitionStatus_NoTransitionWhenSame(t *testing.T) {
	h := &EndpointHealthCheck{
		Status:              HealthStatusHealthy,
		ConsecutiveFailures: 0,
		DegradedThreshold:   2,
		DownThreshold:       5,
	}

	newStatus, transitioned := h.TransitionStatus(true, "")

	if newStatus != HealthStatusHealthy {
		t.Errorf("expected HealthStatusHealthy, got %s", newStatus)
	}
	if transitioned {
		t.Errorf("expected transition=false (already healthy), got true")
	}
}

func TestHealthCheckSummary(t *testing.T) {
	summary := &HealthCheckSummary{
		Healthy:      5,
		Degraded:     2,
		Down:         1,
		CertMismatch: 1,
		Unknown:      0,
		Total:        9,
	}

	if summary.Total != 9 {
		t.Errorf("expected Total=9, got %d", summary.Total)
	}
	if summary.Healthy != 5 {
		t.Errorf("expected Healthy=5, got %d", summary.Healthy)
	}
}

func TestHealthHistoryEntry(t *testing.T) {
	now := time.Now()
	entry := &HealthHistoryEntry{
		ID:             "hh-test-123",
		HealthCheckID:  "hc-test-123",
		Status:         "healthy",
		ResponseTimeMs: 42,
		Fingerprint:    "abc123def456",
		FailureReason:  "",
		CheckedAt:      now,
	}

	if entry.ID != "hh-test-123" {
		t.Errorf("expected ID='hh-test-123', got %q", entry.ID)
	}
	if entry.ResponseTimeMs != 42 {
		t.Errorf("expected ResponseTimeMs=42, got %d", entry.ResponseTimeMs)
	}
}
