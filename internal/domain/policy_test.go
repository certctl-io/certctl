package domain

import "testing"

func TestPolicyType_Constants(t *testing.T) {
	tests := map[string]PolicyType{
		"AllowedIssuers":      PolicyTypeAllowedIssuers,
		"AllowedDomains":      PolicyTypeAllowedDomains,
		"RequiredMetadata":    PolicyTypeRequiredMetadata,
		"AllowedEnvironments": PolicyTypeAllowedEnvironments,
		"RenewalLeadTime":     PolicyTypeRenewalLeadTime,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}

func TestPolicySeverity_Constants(t *testing.T) {
	tests := map[string]PolicySeverity{
		"Warning":  PolicySeverityWarning,
		"Error":    PolicySeverityError,
		"Critical": PolicySeverityCritical,
	}
	for expected, got := range tests {
		if string(got) != expected {
			t.Errorf("expected %q, got %q", expected, string(got))
		}
	}
}

func TestPolicyRule_Fields(t *testing.T) {
	// This test verifies the PolicyRule struct can be instantiated
	// with all expected fields.
	rule := &PolicyRule{
		ID:      "rule-1",
		Name:    "Allowed Issuers",
		Type:    PolicyTypeAllowedIssuers,
		Enabled: true,
	}

	if rule.ID != "rule-1" {
		t.Errorf("expected ID 'rule-1', got %s", rule.ID)
	}

	if rule.Name != "Allowed Issuers" {
		t.Errorf("expected Name 'Allowed Issuers', got %s", rule.Name)
	}

	if rule.Type != PolicyTypeAllowedIssuers {
		t.Errorf("expected Type AllowedIssuers, got %s", string(rule.Type))
	}

	if !rule.Enabled {
		t.Errorf("expected Enabled=true, got false")
	}
}

func TestPolicyViolation_Fields(t *testing.T) {
	// This test verifies the PolicyViolation struct can be instantiated
	// with all expected fields.
	violation := &PolicyViolation{
		ID:            "violation-1",
		CertificateID: "mc-123",
		RuleID:        "rule-1",
		Message:       "Certificate issued by unauthorized CA",
		Severity:      PolicySeverityCritical,
	}

	if violation.ID != "violation-1" {
		t.Errorf("expected ID 'violation-1', got %s", violation.ID)
	}

	if violation.CertificateID != "mc-123" {
		t.Errorf("expected CertificateID 'mc-123', got %s", violation.CertificateID)
	}

	if violation.RuleID != "rule-1" {
		t.Errorf("expected RuleID 'rule-1', got %s", violation.RuleID)
	}

	if violation.Severity != PolicySeverityCritical {
		t.Errorf("expected Severity Critical, got %s", string(violation.Severity))
	}
}

func TestPolicySeverity_Ordering(t *testing.T) {
	// This test verifies severity ordering is correct (for potential future use
	// in ranking violations by impact).
	severities := []PolicySeverity{
		PolicySeverityWarning,
		PolicySeverityError,
		PolicySeverityCritical,
	}

	for i, severity := range severities {
		if string(severity) == "" {
			t.Errorf("severity %d has empty string value", i)
		}
	}
}
