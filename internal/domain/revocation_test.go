package domain

import "testing"

func TestIsValidRevocationReason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   bool
	}{
		{"unspecified", "unspecified", true},
		{"keyCompromise", "keyCompromise", true},
		{"caCompromise", "caCompromise", true},
		{"affiliationChanged", "affiliationChanged", true},
		{"superseded", "superseded", true},
		{"cessationOfOperation", "cessationOfOperation", true},
		{"certificateHold", "certificateHold", true},
		{"privilegeWithdrawn", "privilegeWithdrawn", true},
		{"empty string", "", false},
		{"random string", "notAValidReason", false},
		{"partial match", "key", false},
		{"case sensitive", "KeyCompromise", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidRevocationReason(tt.reason); got != tt.want {
				t.Errorf("IsValidRevocationReason(%q) = %v, want %v", tt.reason, got, tt.want)
			}
		})
	}
}

func TestCRLReasonCode(t *testing.T) {
	tests := []struct {
		reason RevocationReason
		want   int
	}{
		{RevocationReasonUnspecified, 0},
		{RevocationReasonKeyCompromise, 1},
		{RevocationReasonCACompromise, 2},
		{RevocationReasonAffiliationChanged, 3},
		{RevocationReasonSuperseded, 4},
		{RevocationReasonCessationOfOperation, 5},
		{RevocationReasonCertificateHold, 6},
		{RevocationReasonPrivilegeWithdrawn, 9},
		{RevocationReason("unknown"), 0}, // falls back to unspecified
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			if got := CRLReasonCode(tt.reason); got != tt.want {
				t.Errorf("CRLReasonCode(%q) = %d, want %d", tt.reason, got, tt.want)
			}
		})
	}
}
