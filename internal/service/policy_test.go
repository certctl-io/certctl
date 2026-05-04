package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
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

	policies, total, err := policyService.ListPolicies(context.Background(), 1, 50)
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

	created, err := policyService.CreatePolicy(context.Background(), policy)
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

// ============================================================================
// D-008 regression tests
//
// These pin the behavior that closes the D-006 loop:
//   1. evaluateRule copies rule.Severity onto every violation (pre-D-008 the
//      engine hardcoded Warning regardless of the rule's configured severity).
//   2. evaluateRule parses rule.Config per-arm so rules enforce real thresholds
//      and allowlists (pre-D-008 the configs were ignored; rules fired only on
//      the missing-field shape).
//   3. An empty/zero Config preserves the pre-D-008 missing-field violation
//      (backward-compat invariant).
//   4. Malformed Config returns an error; the caller logs and skips the rule
//      instead of producing a zero-value violation.
//   5. CertificateLifetime (new 6th arm) reads NotBefore/NotAfter from the
//      latest CertificateVersion via the cert repo wired with SetCertRepo.
// ============================================================================

// mkRule is a tiny constructor used by the D-008 tests to keep the table rows
// readable. Every rule is enabled; test-specific fields layer on top.
func mkRule(id string, t domain.PolicyType, sev domain.PolicySeverity, cfg string) *domain.PolicyRule {
	return &domain.PolicyRule{
		ID:       id,
		Name:     id,
		Type:     t,
		Config:   json.RawMessage(cfg),
		Enabled:  true,
		Severity: sev,
	}
}

// evalCert is a minimal cert used by the arms that don't look at much beyond
// the shape of the field they're testing. Tests shadow fields as needed.
func evalCert() *domain.ManagedCertificate {
	return &domain.ManagedCertificate{
		ID:         "cert-001",
		CommonName: "example.com",
		Status:     domain.CertificateStatusActive,
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	}
}

// TestEvaluateRule_SeverityPassThrough pins invariant #1 — every arm stamps
// rule.Severity onto the violation. The pre-D-008 bug was that arms
// independently hardcoded PolicySeverityWarning. We test each arm with a
// severity that isn't the legacy default so a regression would be visible.
func TestEvaluateRule_SeverityPassThrough(t *testing.T) {
	ctx := context.Background()

	// Cert shaped to fail every non-empty-config check via the backward-compat
	// missing-field path. Each row picks a severity intentionally ≠ Warning to
	// make a stray hardcoded default obvious.
	cases := []struct {
		name     string
		rule     *domain.PolicyRule
		cert     *domain.ManagedCertificate
		setupFn  func(svc *PolicyService)
		expected domain.PolicySeverity
	}{
		{
			name: "AllowedIssuers Critical via missing IssuerID",
			rule: mkRule("r-ai", domain.PolicyTypeAllowedIssuers, domain.PolicySeverityCritical, ""),
			cert: func() *domain.ManagedCertificate {
				c := evalCert()
				c.IssuerID = ""
				return c
			}(),
			expected: domain.PolicySeverityCritical,
		},
		{
			name: "AllowedDomains Error via empty SANs",
			rule: mkRule("r-ad", domain.PolicyTypeAllowedDomains, domain.PolicySeverityError, ""),
			cert: func() *domain.ManagedCertificate {
				c := evalCert()
				c.SANs = nil
				return c
			}(),
			expected: domain.PolicySeverityError,
		},
		{
			name: "RequiredMetadata Critical via empty Tags",
			rule: mkRule("r-rm", domain.PolicyTypeRequiredMetadata, domain.PolicySeverityCritical, ""),
			cert: func() *domain.ManagedCertificate {
				c := evalCert()
				c.Tags = nil
				return c
			}(),
			expected: domain.PolicySeverityCritical,
		},
		{
			name: "AllowedEnvironments Warning via empty Environment",
			rule: mkRule("r-ae", domain.PolicyTypeAllowedEnvironments, domain.PolicySeverityWarning, ""),
			cert: func() *domain.ManagedCertificate {
				c := evalCert()
				c.Environment = ""
				return c
			}(),
			expected: domain.PolicySeverityWarning,
		},
		{
			name: "RenewalLeadTime Critical via short remaining validity",
			rule: mkRule("r-rl", domain.PolicyTypeRenewalLeadTime, domain.PolicySeverityCritical, `{"lead_time_days": 60}`),
			cert: func() *domain.ManagedCertificate {
				c := evalCert()
				c.ExpiresAt = time.Now().AddDate(0, 0, 30) // 30d remaining < 60d lead
				return c
			}(),
			expected: domain.PolicySeverityCritical,
		},
		{
			name: "CertificateLifetime Error via 365d span vs 90d max",
			rule: mkRule("r-cl", domain.PolicyTypeCertificateLifetime, domain.PolicySeverityError, `{"max_days": 90}`),
			cert: evalCert(),
			setupFn: func(svc *PolicyService) {
				// Seed a version with 365d lifetime on the same cert ID used
				// by evalCert().
				cr := &mockCertRepo{
					Certs:    map[string]*domain.ManagedCertificate{},
					Versions: map[string][]*domain.CertificateVersion{},
				}
				now := time.Now()
				cr.Versions["cert-001"] = []*domain.CertificateVersion{{
					ID:            "ver-001",
					CertificateID: "cert-001",
					NotBefore:     now.AddDate(0, 0, -10),
					NotAfter:      now.AddDate(1, 0, -10), // ~365d lifetime
				}}
				svc.SetCertRepo(cr)
			},
			expected: domain.PolicySeverityError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policyRepo := &mockPolicyRepo{
				Rules:      map[string]*domain.PolicyRule{tc.rule.ID: tc.rule},
				Violations: []*domain.PolicyViolation{},
			}
			auditService := NewAuditService(&mockAuditRepo{})
			svc := NewPolicyService(policyRepo, auditService)
			if tc.setupFn != nil {
				tc.setupFn(svc)
			}

			violations, err := svc.ValidateCertificate(ctx, tc.cert)
			if err != nil {
				t.Fatalf("ValidateCertificate failed: %v", err)
			}
			if len(violations) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(violations))
			}
			if violations[0].Severity != tc.expected {
				t.Errorf("expected severity %q, got %q", tc.expected, violations[0].Severity)
			}
			if violations[0].RuleID != tc.rule.ID {
				t.Errorf("expected rule ID %q, got %q", tc.rule.ID, violations[0].RuleID)
			}
		})
	}
}

// TestEvaluateRule_ConfigConsumed pins invariant #2 — non-empty Config drives
// arm behavior (allowlists, thresholds, keys). Each subtest supplies a config
// that the cert would satisfy under the backward-compat missing-field path
// but violates under the config-aware path. A regression to the pre-D-008
// "config silently dropped" behavior would make these pass with 0 violations.
func TestEvaluateRule_ConfigConsumed(t *testing.T) {
	ctx := context.Background()

	t.Run("AllowedIssuers rejects issuer not in allowlist", func(t *testing.T) {
		rule := mkRule("r-ai", domain.PolicyTypeAllowedIssuers, domain.PolicySeverityWarning,
			`{"allowed_issuer_ids": ["iss-acme"]}`)
		cert := evalCert()
		cert.IssuerID = "iss-wrong"

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for disallowed issuer, got %d", len(violations))
		}
		if !strings.Contains(violations[0].Message, "iss-wrong") {
			t.Errorf("expected message to mention issuer ID, got %q", violations[0].Message)
		}
	})

	t.Run("AllowedIssuers accepts issuer in allowlist", func(t *testing.T) {
		rule := mkRule("r-ai", domain.PolicyTypeAllowedIssuers, domain.PolicySeverityWarning,
			`{"allowed_issuer_ids": ["iss-acme"]}`)
		cert := evalCert()
		cert.IssuerID = "iss-acme"

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations for allowed issuer, got %d", len(violations))
		}
	})

	t.Run("AllowedDomains rejects SAN outside allowlist", func(t *testing.T) {
		rule := mkRule("r-ad", domain.PolicyTypeAllowedDomains, domain.PolicySeverityWarning,
			`{"allowed_domains": ["*.foo.com"]}`)
		cert := evalCert()
		cert.SANs = []string{"bar.elsewhere.com"}

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for disallowed SAN, got %d", len(violations))
		}
	})

	t.Run("AllowedDomains wildcard matches single-label subdomain", func(t *testing.T) {
		rule := mkRule("r-ad", domain.PolicyTypeAllowedDomains, domain.PolicySeverityWarning,
			`{"allowed_domains": ["*.foo.com"]}`)
		cert := evalCert()
		cert.SANs = []string{"bar.foo.com"}

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations for single-label wildcard match, got %d", len(violations))
		}
	})

	t.Run("AllowedDomains wildcard rejects multi-label subdomain", func(t *testing.T) {
		// X.509 wildcard semantics: *.foo consumes exactly one label.
		rule := mkRule("r-ad", domain.PolicyTypeAllowedDomains, domain.PolicySeverityWarning,
			`{"allowed_domains": ["*.foo.com"]}`)
		cert := evalCert()
		cert.SANs = []string{"baz.bar.foo.com"}

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Errorf("expected 1 violation for multi-label wildcard (X.509 semantics), got %d", len(violations))
		}
	})

	t.Run("RequiredMetadata rejects missing key", func(t *testing.T) {
		rule := mkRule("r-rm", domain.PolicyTypeRequiredMetadata, domain.PolicySeverityWarning,
			`{"required_keys": ["owner"]}`)
		cert := evalCert()
		cert.Tags = map[string]string{"team": "platform"}

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for missing owner key, got %d", len(violations))
		}
		if !strings.Contains(violations[0].Message, "owner") {
			t.Errorf("expected message to mention the missing key, got %q", violations[0].Message)
		}
	})

	t.Run("RequiredMetadata accepts all required keys present", func(t *testing.T) {
		rule := mkRule("r-rm", domain.PolicyTypeRequiredMetadata, domain.PolicySeverityWarning,
			`{"required_keys": ["owner"]}`)
		cert := evalCert()
		cert.Tags = map[string]string{"owner": "alice"}

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations when all required keys present, got %d", len(violations))
		}
	})

	t.Run("AllowedEnvironments rejects env outside allowlist", func(t *testing.T) {
		rule := mkRule("r-ae", domain.PolicyTypeAllowedEnvironments, domain.PolicySeverityWarning,
			`{"allowed": ["production", "staging"]}`)
		cert := evalCert()
		cert.Environment = "wild-west"

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for disallowed env, got %d", len(violations))
		}
	})

	t.Run("RenewalLeadTime fires when remaining < configured lead", func(t *testing.T) {
		rule := mkRule("r-rl", domain.PolicyTypeRenewalLeadTime, domain.PolicySeverityWarning,
			`{"lead_time_days": 60}`)
		cert := evalCert()
		cert.ExpiresAt = time.Now().AddDate(0, 0, 30) // 30d < 60d lead

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for 30d remaining vs 60d lead, got %d", len(violations))
		}
	})

	t.Run("RenewalLeadTime quiet when remaining > configured lead", func(t *testing.T) {
		rule := mkRule("r-rl", domain.PolicyTypeRenewalLeadTime, domain.PolicySeverityWarning,
			`{"lead_time_days": 14}`)
		cert := evalCert()
		cert.ExpiresAt = time.Now().AddDate(0, 0, 60) // 60d > 14d lead

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations when plenty of runway remains, got %d", len(violations))
		}
	})

	t.Run("CertificateLifetime fires when lifetime exceeds max", func(t *testing.T) {
		rule := mkRule("r-cl", domain.PolicyTypeCertificateLifetime, domain.PolicySeverityWarning,
			`{"max_days": 90}`)
		cert := evalCert()
		now := time.Now()

		certRepo := &mockCertRepo{
			Certs:    map[string]*domain.ManagedCertificate{},
			Versions: map[string][]*domain.CertificateVersion{},
		}
		certRepo.Versions["cert-001"] = []*domain.CertificateVersion{{
			ID:            "ver-001",
			CertificateID: "cert-001",
			NotBefore:     now.AddDate(0, 0, -1),
			NotAfter:      now.AddDate(1, 0, -1), // ~365d > 90d
		}}

		violations := runEval(ctx, t, rule, cert, certRepo)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for 365d lifetime vs 90d max, got %d", len(violations))
		}
		if !strings.Contains(violations[0].Message, "90 days") {
			t.Errorf("expected message to mention max_days threshold, got %q", violations[0].Message)
		}
	})

	t.Run("CertificateLifetime quiet when lifetime within max", func(t *testing.T) {
		rule := mkRule("r-cl", domain.PolicyTypeCertificateLifetime, domain.PolicySeverityWarning,
			`{"max_days": 90}`)
		cert := evalCert()
		now := time.Now()

		certRepo := &mockCertRepo{
			Certs:    map[string]*domain.ManagedCertificate{},
			Versions: map[string][]*domain.CertificateVersion{},
		}
		certRepo.Versions["cert-001"] = []*domain.CertificateVersion{{
			ID:            "ver-001",
			CertificateID: "cert-001",
			NotBefore:     now.AddDate(0, 0, -10),
			NotAfter:      now.AddDate(0, 0, 60), // 70d lifetime < 90d
		}}

		violations := runEval(ctx, t, rule, cert, certRepo)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations for 70d lifetime under 90d max, got %d", len(violations))
		}
	})
}

// TestEvaluateRule_EmptyConfig_BackCompat pins invariant #3 — a rule with no
// Config (e.g., a legacy row from a pre-D-008 migration) still fires on the
// pre-D-008 missing-field shape using its configured severity. This is how
// we let existing deployments migrate without a schema rewrite.
func TestEvaluateRule_EmptyConfig_BackCompat(t *testing.T) {
	ctx := context.Background()

	t.Run("RequiredMetadata fires on zero tags", func(t *testing.T) {
		rule := mkRule("r-rm", domain.PolicyTypeRequiredMetadata, domain.PolicySeverityError, "")
		cert := evalCert()
		cert.Tags = nil

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 backcompat violation, got %d", len(violations))
		}
		if violations[0].Severity != domain.PolicySeverityError {
			t.Errorf("expected severity Error (passed through from rule), got %q", violations[0].Severity)
		}
	})

	t.Run("RequiredMetadata quiet when any tags present under empty config", func(t *testing.T) {
		// Empty config means "only fire on missing-field shape" — so a cert
		// with any tags (even not what a human would call meaningful) passes.
		rule := mkRule("r-rm", domain.PolicyTypeRequiredMetadata, domain.PolicySeverityError, "")
		cert := evalCert()
		cert.Tags = map[string]string{"arbitrary": "value"}

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations under backcompat shape w/ tags set, got %d", len(violations))
		}
	})

	t.Run("RenewalLeadTime uses 30d default under empty/zero config", func(t *testing.T) {
		rule := mkRule("r-rl", domain.PolicyTypeRenewalLeadTime, domain.PolicySeverityWarning, "")
		cert := evalCert()
		cert.ExpiresAt = time.Now().AddDate(0, 0, 15) // 15d < 30d default

		violations := runEval(ctx, t, rule, cert, nil)
		if len(violations) != 1 {
			t.Errorf("expected 1 violation under 30d backcompat default, got %d", len(violations))
		}
	})
}

// TestEvaluateRule_BadConfig_SkipsRule pins invariant #4 — malformed JSON in
// Config returns an error from evaluateRule, which ValidateCertificate logs
// and swallows. The pass continues; no zero-value violation is emitted.
// Co-located rules still fire normally.
func TestEvaluateRule_BadConfig_SkipsRule(t *testing.T) {
	ctx := context.Background()

	// Rule 1 has malformed JSON — should log+skip.
	// Rule 2 is a healthy AllowedIssuers rule that should still emit its
	// violation on the missing-IssuerID cert. If the bad rule poisoned the
	// loop, we'd see 0 or 2 violations instead of exactly 1.
	badRule := mkRule("r-bad", domain.PolicyTypeAllowedIssuers, domain.PolicySeverityError,
		`{"allowed_issuer_ids": [`) // unterminated JSON
	goodRule := mkRule("r-good", domain.PolicyTypeAllowedEnvironments, domain.PolicySeverityWarning, "")

	policyRepo := &mockPolicyRepo{
		Rules: map[string]*domain.PolicyRule{
			badRule.ID:  badRule,
			goodRule.ID: goodRule,
		},
		Violations: []*domain.PolicyViolation{},
	}
	auditService := NewAuditService(&mockAuditRepo{})
	svc := NewPolicyService(policyRepo, auditService)

	cert := evalCert()
	cert.IssuerID = ""    // would trigger the bad rule if it wasn't skipped
	cert.Environment = "" // triggers goodRule via missing-field backcompat

	violations, err := svc.ValidateCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("ValidateCertificate should swallow rule-eval errors, got %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected exactly 1 violation (bad rule skipped, good rule fires), got %d", len(violations))
	}
	if violations[0].RuleID != goodRule.ID {
		t.Errorf("expected violation from r-good, got %q", violations[0].RuleID)
	}
}

// TestEvaluateRule_CertificateLifetime_RepoScenarios pins the setter-injection
// pattern for the 6th arm. SetCertRepo wires the dependency; without it the
// arm errors (logged+skipped by the caller). With it but no version present,
// the arm silently returns nil (matching the missing-field backcompat shape).
func TestEvaluateRule_CertificateLifetime_RepoScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("repo not wired logs and skips", func(t *testing.T) {
		rule := mkRule("r-cl", domain.PolicyTypeCertificateLifetime, domain.PolicySeverityError,
			`{"max_days": 90}`)
		policyRepo := &mockPolicyRepo{
			Rules:      map[string]*domain.PolicyRule{rule.ID: rule},
			Violations: []*domain.PolicyViolation{},
		}
		svc := NewPolicyService(policyRepo, NewAuditService(&mockAuditRepo{}))
		// deliberately do NOT call SetCertRepo

		violations, err := svc.ValidateCertificate(ctx, evalCert())
		if err != nil {
			t.Fatalf("ValidateCertificate should swallow the nil-repo error, got %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations when repo unwired (rule skipped), got %d", len(violations))
		}
	})

	t.Run("version missing silently skips", func(t *testing.T) {
		rule := mkRule("r-cl", domain.PolicyTypeCertificateLifetime, domain.PolicySeverityError,
			`{"max_days": 90}`)
		policyRepo := &mockPolicyRepo{
			Rules:      map[string]*domain.PolicyRule{rule.ID: rule},
			Violations: []*domain.PolicyViolation{},
		}
		svc := NewPolicyService(policyRepo, NewAuditService(&mockAuditRepo{}))
		// Empty Versions map — GetLatestVersion returns errNotFound, arm skips.
		svc.SetCertRepo(&mockCertRepo{
			Certs:    map[string]*domain.ManagedCertificate{},
			Versions: map[string][]*domain.CertificateVersion{},
		})

		violations, err := svc.ValidateCertificate(ctx, evalCert())
		if err != nil {
			t.Fatalf("ValidateCertificate failed: %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations when no version exists (nothing to measure), got %d", len(violations))
		}
	})

	t.Run("max_days zero/absent means no enforcement", func(t *testing.T) {
		// Even with a version, max_days=0 is a no-op (matches the
		// no-threshold-configured guard in the arm).
		rule := mkRule("r-cl", domain.PolicyTypeCertificateLifetime, domain.PolicySeverityError, "")
		policyRepo := &mockPolicyRepo{
			Rules:      map[string]*domain.PolicyRule{rule.ID: rule},
			Violations: []*domain.PolicyViolation{},
		}
		svc := NewPolicyService(policyRepo, NewAuditService(&mockAuditRepo{}))
		now := time.Now()
		svc.SetCertRepo(&mockCertRepo{
			Certs: map[string]*domain.ManagedCertificate{},
			Versions: map[string][]*domain.CertificateVersion{
				"cert-001": {{
					CertificateID: "cert-001",
					NotBefore:     now.AddDate(0, 0, -1),
					NotAfter:      now.AddDate(10, 0, 0), // 10 years — huge but unchecked
				}},
			},
		})

		violations, err := svc.ValidateCertificate(ctx, evalCert())
		if err != nil {
			t.Fatalf("ValidateCertificate failed: %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations when max_days absent (no enforcement), got %d", len(violations))
		}
	})
}

// runEval is a test helper that exercises ValidateCertificate against a
// single-rule configuration and returns the violation slice. Optionally
// wires a cert repo for the CertificateLifetime arm.
func runEval(ctx context.Context, t *testing.T, rule *domain.PolicyRule, cert *domain.ManagedCertificate, certRepo *mockCertRepo) []*domain.PolicyViolation {
	t.Helper()
	policyRepo := &mockPolicyRepo{
		Rules:      map[string]*domain.PolicyRule{rule.ID: rule},
		Violations: []*domain.PolicyViolation{},
	}
	svc := NewPolicyService(policyRepo, NewAuditService(&mockAuditRepo{}))
	if certRepo != nil {
		svc.SetCertRepo(certRepo)
	}
	violations, err := svc.ValidateCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("ValidateCertificate failed: %v", err)
	}
	return violations
}
