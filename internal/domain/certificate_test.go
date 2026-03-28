package domain

import "testing"

func TestCertificateStatus_Constants(t *testing.T) {
	tests := map[string]CertificateStatus{
		"Pending":             CertificateStatusPending,
		"Active":              CertificateStatusActive,
		"Expiring":            CertificateStatusExpiring,
		"Expired":             CertificateStatusExpired,
		"RenewalInProgress":   CertificateStatusRenewalInProgress,
		"Failed":              CertificateStatusFailed,
		"Revoked":             CertificateStatusRevoked,
		"Archived":            CertificateStatusArchived,
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
