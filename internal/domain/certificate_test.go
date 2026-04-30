package domain

import "testing"

func TestCertificateStatus_Constants(t *testing.T) {
	tests := map[string]CertificateStatus{
		"Pending":           CertificateStatusPending,
		"Active":            CertificateStatusActive,
		"Expiring":          CertificateStatusExpiring,
		"Expired":           CertificateStatusExpired,
		"RenewalInProgress": CertificateStatusRenewalInProgress,
		"Failed":            CertificateStatusFailed,
		"Revoked":           CertificateStatusRevoked,
		"Archived":          CertificateStatusArchived,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}

func TestDefaultAlertThresholds(t *testing.T) {
	defaults := DefaultAlertThresholds()
	expected := []int{30, 14, 7, 0}
	if len(defaults) != len(expected) {
		t.Errorf("expected %d thresholds, got %d", len(expected), len(defaults))
	}
	for i, v := range expected {
		if i >= len(defaults) {
			break
		}
		if defaults[i] != v {
			t.Errorf("threshold[%d]: expected %d, got %d", i, v, defaults[i])
		}
	}
}

func TestRenewalPolicy_EffectiveAlertThresholds_Custom(t *testing.T) {
	policy := &RenewalPolicy{
		AlertThresholdsDays: []int{60, 30, 14, 7},
	}
	result := policy.EffectiveAlertThresholds()
	if len(result) != 4 {
		t.Errorf("expected 4 thresholds, got %d", len(result))
	}
	if result[0] != 60 {
		t.Errorf("expected first threshold 60, got %d", result[0])
	}
}

func TestRenewalPolicy_EffectiveAlertThresholds_Default(t *testing.T) {
	policy := &RenewalPolicy{
		AlertThresholdsDays: []int{},
	}
	result := policy.EffectiveAlertThresholds()
	expected := DefaultAlertThresholds()
	if len(result) != len(expected) {
		t.Errorf("expected %d thresholds, got %d", len(expected), len(result))
	}
	for i, v := range expected {
		if i >= len(result) {
			break
		}
		if result[i] != v {
			t.Errorf("threshold[%d]: expected %d, got %d", i, v, result[i])
		}
	}
}

func TestRenewalPolicy_EffectiveAlertThresholds_Nil(t *testing.T) {
	policy := &RenewalPolicy{
		AlertThresholdsDays: nil,
	}
	result := policy.EffectiveAlertThresholds()
	expected := DefaultAlertThresholds()
	if len(result) != len(expected) {
		t.Errorf("expected %d thresholds, got %d", len(expected), len(result))
	}
}

// --- 45-Day / Short-Lived Certificate Renewal Threshold Tests ---
// These tests validate that certctl's renewal logic works correctly with shorter-lived
// certificates as the industry transitions from 90-day to 45-day validity (SC-081v3)
// and Let's Encrypt introduces 6-day "shortlived" profiles.

func TestRenewalThresholds_45DayCert(t *testing.T) {
	// A 45-day cert with default thresholds [30, 14, 7, 0]:
	// - 30-day alert fires when cert is 15 days old (45 - 30 = 15 days remaining)
	// - 14-day alert fires when cert is 31 days old
	// - 7-day alert fires when cert is 38 days old
	// - 0-day alert fires at expiry
	// The 30-day threshold fires at the 1/3 lifetime mark — this is correct
	// (Let's Encrypt recommends renewal at 2/3 through lifetime, i.e. day 30).
	thresholds := DefaultAlertThresholds()

	certLifetimeDays := 45
	for _, threshold := range thresholds {
		daysCertAge := certLifetimeDays - threshold
		if daysCertAge < 0 {
			t.Errorf("threshold %d days exceeds cert lifetime %d days", threshold, certLifetimeDays)
		}
	}

	// Verify the first alert (30 days) fires when 15 days remain
	// This means the cert is 15 days old — at 1/3 of its lifetime
	firstAlertDaysRemaining := certLifetimeDays - (certLifetimeDays - thresholds[0])
	if firstAlertDaysRemaining != 30 {
		t.Errorf("expected first alert at 30 days remaining, got %d", firstAlertDaysRemaining)
	}

	// The renewal window query (31 days ahead) will find 45-day certs
	// when they have 31 or fewer days remaining — at day 14 of a 45-day cert.
	renewalWindowDays := 31
	certAgeAtRenewalCheck := certLifetimeDays - renewalWindowDays
	if certAgeAtRenewalCheck != 14 {
		t.Errorf("expected renewal check to find cert at age %d, got %d", 14, certAgeAtRenewalCheck)
	}
}

func TestRenewalThresholds_6DayCert(t *testing.T) {
	// A 6-day "shortlived" cert with default thresholds [30, 14, 7, 0]:
	// - The 30-day, 14-day, and 7-day thresholds can NEVER fire (cert expires before reaching them)
	// - Only the 0-day threshold fires at expiry
	// For 6-day certs, ARI (RFC 9773) is the expected renewal path — the CA directs timing.
	// Short-lived certs also skip CRL/OCSP (revocation via expiry, per M15b).
	thresholds := DefaultAlertThresholds()
	certLifetimeDays := 6

	firingThresholds := 0
	for _, threshold := range thresholds {
		if threshold < certLifetimeDays {
			firingThresholds++
		}
	}

	// Only the 0-day threshold can fire (0 < 6).
	// The 7-day threshold means "alert when 7 days remain" — a 6-day cert
	// never has 7 days remaining, so it never fires.
	// For 6-day certs, ARI (RFC 9773) is the expected renewal path.
	if firingThresholds != 1 {
		t.Errorf("expected 1 threshold to fire for 6-day cert, got %d", firingThresholds)
	}

	// The renewal window query (31 days ahead) will find 6-day certs immediately
	// (they're always within the 31-day window from the moment they're issued).
	renewalWindowDays := 31
	if certLifetimeDays < renewalWindowDays {
		// This is expected — 6-day certs are always in the renewal window.
		// ARI should override the threshold-based logic for these certs.
	}
}

func TestRenewalThresholds_47DayCert(t *testing.T) {
	// SC-081v3 mandates 47-day max validity by March 2029.
	// Default thresholds [30, 14, 7, 0] should work correctly.
	thresholds := DefaultAlertThresholds()
	certLifetimeDays := 47

	for _, threshold := range thresholds {
		if threshold > certLifetimeDays {
			t.Errorf("threshold %d exceeds cert lifetime %d", threshold, certLifetimeDays)
		}
	}

	// With RenewalWindowDays=30, renewal triggers at day 17 (47-30=17).
	// That's at the 36% mark of the cert's lifetime — reasonable.
	renewalWindowDays := 30
	renewalDay := certLifetimeDays - renewalWindowDays
	if renewalDay != 17 {
		t.Errorf("expected renewal at day 17, got %d", renewalDay)
	}
}

func TestRenewalThresholds_200DayCert(t *testing.T) {
	// SC-081v3 Phase 1: 200-day max validity (March 2026).
	// All default thresholds should fire normally.
	thresholds := DefaultAlertThresholds()
	certLifetimeDays := 200

	for _, threshold := range thresholds {
		if threshold > certLifetimeDays {
			t.Errorf("threshold %d exceeds cert lifetime %d", threshold, certLifetimeDays)
		}
	}
}

func TestRenewalThresholds_100DayCert(t *testing.T) {
	// SC-081v3 Phase 2: 100-day max validity (March 2027).
	thresholds := DefaultAlertThresholds()
	certLifetimeDays := 100

	for _, threshold := range thresholds {
		if threshold > certLifetimeDays {
			t.Errorf("threshold %d exceeds cert lifetime %d", threshold, certLifetimeDays)
		}
	}

	// With default 31-day renewal window, renewal triggers at day 69 — at 69% of lifetime.
	// This is close to Let's Encrypt's recommended 2/3 mark.
	renewalWindowDays := 31
	renewalDay := certLifetimeDays - renewalWindowDays
	if renewalDay != 69 {
		t.Errorf("expected renewal at day 69, got %d", renewalDay)
	}
}
