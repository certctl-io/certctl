package domain

import (
	"testing"
	"time"
)

func TestVerificationStatus_Constants(t *testing.T) {
	tests := []struct {
		name     string
		status   VerificationStatus
		expected string
	}{
		{"Pending", VerificationPending, "pending"},
		{"Success", VerificationSuccess, "success"},
		{"Failed", VerificationFailed, "failed"},
		{"Skipped", VerificationSkipped, "skipped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, string(tt.status))
			}
		})
	}
}

func TestVerificationResult_Marshaling(t *testing.T) {
	now := time.Now().UTC()
	result := &VerificationResult{
		JobID:               "j-test123",
		TargetID:            "t-nginx1",
		ExpectedFingerprint: "abc123def456",
		ActualFingerprint:   "abc123def456",
		Verified:            true,
		VerifiedAt:          now,
		Error:               "",
	}

	if result.JobID != "j-test123" {
		t.Errorf("JobID mismatch: got %s", result.JobID)
	}
	if !result.Verified {
		t.Error("expected Verified to be true")
	}
	if result.Error != "" {
		t.Errorf("expected no error, got %s", result.Error)
	}
}

func TestVerificationResult_WithError(t *testing.T) {
	now := time.Now().UTC()
	result := &VerificationResult{
		JobID:               "j-test456",
		TargetID:            "t-apache1",
		ExpectedFingerprint: "aaa111bbb222",
		ActualFingerprint:   "ccc333ddd444",
		Verified:            false,
		VerifiedAt:          now,
		Error:               "connection timeout",
	}

	if result.Verified {
		t.Error("expected Verified to be false")
	}
	if result.Error != "connection timeout" {
		t.Errorf("expected error message, got %s", result.Error)
	}
	if result.ExpectedFingerprint == result.ActualFingerprint {
		t.Error("expected fingerprints to differ")
	}
}
