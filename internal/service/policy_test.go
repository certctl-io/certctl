package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

func TestCreateRule(t *testing.T) {
	ctx := context.Background()
	policyRepo := &mockPolicyRepo{
		Rules:      make(map[string]*domain.PolicyRule),
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	config := map[string]interface{}{"issuers": []string{"iss-acme"}}
	configJSON, _ := json.Marshal(config)

	rule := &domain.PolicyRule{
		ID:      "rule-001",
		Name:    "Allowed Issuers",
		Type:    domain.PolicyTypeAllowedIssuers,
		Config:  configJSON,
		Enabled: true,
	}

	err := policyService.CreateRule(ctx, rule, "user-1")
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	if len(policyRepo.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(policyRepo.Rules))
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestGetRule(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	rule := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": rule},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	retrieved, err := policyService.GetRule(ctx, "rule-001")
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}

	if retrieved.Name != "Allowed Issuers" {
		t.Errorf("expected name Allowed Issuers, got %s", retrieved.Name)
	}
}

func TestGetRule_NotFound(t *testing.T) {
	ctx := context.Background()
	policyRepo := &mockPolicyRepo{
		Rules:      make(map[string]*domain.PolicyRule),
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	_, err := policyService.GetRule(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent rule")
	}
}

func TestListRules(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	rule1 := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	rule2 := &domain.PolicyRule{
		ID:        "rule-002",
		Name:      "Required Metadata",
		Type:      domain.PolicyTypeRequiredMetadata,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": rule1, "rule-002": rule2},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	rules, err := policyService.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestUpdateRule(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	originalRule := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": originalRule},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	updatedRule := *originalRule
	updatedRule.Enabled = false

	err := policyService.UpdateRule(ctx, &updatedRule, "user-1")
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	stored := policyRepo.Rules["rule-001"]
	if stored.Enabled {
		t.Error("expected rule to be disabled")
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestDeleteRule(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	rule := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": rule},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{Events: []*domain.AuditEvent{}}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	err := policyService.DeleteRule(ctx, "rule-001", "user-1")
	if err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	if len(policyRepo.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(policyRepo.Rules))
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}
}

func TestValidateCertificate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	rule := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": rule},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "iss-acme",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	violations, err := policyService.ValidateCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("ValidateCertificate failed: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestValidateCertificate_WithViolation(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	rule := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": rule},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "", // Missing issuer
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	violations, err := policyService.ValidateCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("ValidateCertificate failed: %v", err)
	}

	if len(violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(violations))
	}

	if violations[0].CertificateID != "cert-001" {
		t.Errorf("expected violation for cert-001, got %s", violations[0].CertificateID)
	}
}

func TestValidateCertificate_MultipleViolations(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	rule1 := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Allowed Issuers",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	rule2 := &domain.PolicyRule{
		ID:        "rule-002",
		Name:      "Required Metadata",
		Type:      domain.PolicyTypeRequiredMetadata,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": rule1, "rule-002": rule2},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	cert := &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		IssuerID:   "",  // Missing issuer
		Tags:       nil, // Missing metadata
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  now.AddDate(1, 0, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	violations, err := policyService.ValidateCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("ValidateCertificate failed: %v", err)
	}

	if len(violations) != 2 {
		t.Errorf("expected 2 violations, got %d", len(violations))
	}
}

func TestListPolicies(t *testing.T) {
	now := time.Now()
	rule1 := &domain.PolicyRule{
		ID:        "rule-001",
		Name:      "Rule 1",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	rule2 := &domain.PolicyRule{
		ID:        "rule-002",
		Name:      "Rule 2",
		Type:      domain.PolicyTypeRequiredMetadata,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{"rule-001": rule1, "rule-002": rule2},
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	policies, total, err := policyService.ListPolicies(1, 50)
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
}

func TestCreatePolicy(t *testing.T) {
	now := time.Now()
	policyRepo := &mockPolicyRepo{
		Rules:      make(map[string]*domain.PolicyRule),
		Violations: []*domain.PolicyViolation{},
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)

	policyService := NewPolicyService(policyRepo, auditService)

	policy := domain.PolicyRule{
		Name:      "Test Policy",
		Type:      domain.PolicyTypeAllowedIssuers,
		Enabled:   true,
		CreatedAt: now,
	}

	created, err := policyService.CreatePolicy(policy)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	if created.ID == "" {
		t.Fatal("expected non-empty policy ID")
	}

	if len(policyRepo.Rules) != 1 {
		t.Errorf("expected 1 rule in repo, got %d", len(policyRepo.Rules))
	}
}
