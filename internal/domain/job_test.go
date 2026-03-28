package domain

import "testing"

func TestJobType_Constants(t *testing.T) {
	tests := map[string]JobType{
		"Issuance":   JobTypeIssuance,
		"Renewal":    JobTypeRenewal,
		"Deployment": JobTypeDeployment,
		"Validation": JobTypeValidation,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}

func TestJobStatus_Constants(t *testing.T) {
	tests := map[string]JobStatus{
		"Pending":          JobStatusPending,
		"AwaitingCSR":      JobStatusAwaitingCSR,
		"AwaitingApproval": JobStatusAwaitingApproval,
		"Running":          JobStatusRunning,
		"Completed":        JobStatusCompleted,
		"Failed":           JobStatusFailed,
		"Cancelled":        JobStatusCancelled,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}
