package domain

import (
	"testing"
	"time"
)

func TestIsValidDiscoveryStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{"Unmanaged", "Unmanaged", true},
		{"Managed", "Managed", true},
		{"Dismissed", "Dismissed", true},
		{"empty string", "", false},
		{"invalid status", "Unknown", false},
		{"partial match", "Manage", false},
		{"case sensitive", "unmanaged", false},
		{"lowercase managed", "managed", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidDiscoveryStatus(tt.status); got != tt.want {
				t.Errorf("IsValidDiscoveryStatus(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestDiscoveredCertificate_IsExpired(t *testing.T) {
	now := time.Now()
	pastTime := now.AddDate(-1, 0, 0)
	futureTime := now.AddDate(1, 0, 0)

	tests := []struct {
		name     string
		notAfter *time.Time
		want     bool
	}{
		{"expired certificate", &pastTime, true},
		{"valid certificate", &futureTime, false},
		{"nil NotAfter", nil, false},
		{"expires at current time (edge case)", &now, false}, // Before() = false when at same time
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := &DiscoveredCertificate{
				ID:       "dcert-1",
				NotAfter: tt.notAfter,
			}
			if got := dc.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscoveredCertificate_DaysUntilExpiry(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		notAfter *time.Time
		wantDays int
	}{
		{"nil NotAfter", nil, -1},
		{"expires in 30 days", &time.Time{}, 0}, // placeholder, will be calculated below
		{"expires in 1 day", &time.Time{}, 1},
		{"expires in 0 days (expired)", &time.Time{}, 0},
	}

	// Test with actual future times
	thirtyDaysFromNow := now.AddDate(0, 0, 30)
	oneDayFromNow := now.AddDate(0, 0, 1)
	pastTime := now.AddDate(0, 0, -1)

	testCases := []struct {
		name     string
		notAfter *time.Time
		wantMin  int
		wantMax  int
	}{
		{"nil NotAfter", nil, -1, -1},
		{"expires in 30 days", &thirtyDaysFromNow, 29, 31},
		{"expires in 1 day", &oneDayFromNow, 0, 2},
		{"already expired", &pastTime, -2, -1},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			dc := &DiscoveredCertificate{
				ID:       "dcert-2",
				NotAfter: tt.notAfter,
			}
			got := dc.DaysUntilExpiry()
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("DaysUntilExpiry() = %d, want between %d and %d", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}
