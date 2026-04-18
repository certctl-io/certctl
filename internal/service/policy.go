package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// PolicyService provides business logic for compliance policy management.
type PolicyService struct {
	policyRepo   repository.PolicyRepository
	auditService *AuditService
}

// NewPolicyService creates a new policy service.
func NewPolicyService(
	policyRepo repository.PolicyRepository,
	auditService *AuditService,
) *PolicyService {
	return &PolicyService{
		policyRepo:   policyRepo,
		auditService: auditService,
	}
}

// ValidateCertificate runs all enabled policy rules against a certificate.
func (s *PolicyService) ValidateCertificate(ctx context.Context, cert *domain.ManagedCertificate) ([]*domain.PolicyViolation, error) {
	rules, err := s.policyRepo.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policy rules: %w", err)
	}

	var violations []*domain.PolicyViolation

	for _, rule := range rules {
		// Skip disabled rules
		if !rule.Enabled {
			continue
		}

		// Evaluate rule against certificate
		v, err := s.evaluateRule(rule, cert)
		if err != nil {
			slog.Error("failed to evaluate rule", "rule_id", rule.ID, "error", err)
			continue
		}

		if v != nil {
			violations = append(violations, v)
		}
	}

	return violations, nil
}

// evaluateRule checks if a certificate violates a single policy rule.
func (s *PolicyService) evaluateRule(rule *domain.PolicyRule, cert *domain.ManagedCertificate) (*domain.PolicyViolation, error) {
	switch rule.Type {
	case domain.PolicyTypeAllowedIssuers:
		// Restrict to specific issuers
		// Note: In a production implementation, we would parse rule.Config to extract parameters
		if cert.IssuerID == "" {
			return &domain.PolicyViolation{
				ID:            generateID("violation"),
				RuleID:        rule.ID,
				CertificateID: cert.ID,
				Severity:      domain.PolicySeverityWarning,
				Message:       "certificate has no issuer assigned",
				CreatedAt:     time.Now(),
			}, nil
		}

	case domain.PolicyTypeAllowedDomains:
		// Ensure certificate domains are in allowed list
		if len(cert.SANs) == 0 {
			return &domain.PolicyViolation{
				ID:            generateID("violation"),
				RuleID:        rule.ID,
				CertificateID: cert.ID,
				Severity:      domain.PolicySeverityWarning,
				Message:       "certificate has no subject alternative names",
				CreatedAt:     time.Now(),
			}, nil
		}

	case domain.PolicyTypeRequiredMetadata:
		// Ensure certificate has required metadata/tags
		if len(cert.Tags) == 0 {
			return &domain.PolicyViolation{
				ID:            generateID("violation"),
				RuleID:        rule.ID,
				CertificateID: cert.ID,
				Severity:      domain.PolicySeverityWarning,
				Message:       "certificate has no tags or metadata",
				CreatedAt:     time.Now(),
			}, nil
		}

	case domain.PolicyTypeAllowedEnvironments:
		// Restrict to specific environments
		if cert.Environment == "" {
			return &domain.PolicyViolation{
				ID:            generateID("violation"),
				RuleID:        rule.ID,
				CertificateID: cert.ID,
				Severity:      domain.PolicySeverityWarning,
				Message:       "certificate has no environment assigned",
				CreatedAt:     time.Now(),
			}, nil
		}

	case domain.PolicyTypeRenewalLeadTime:
		// Ensure renewal begins before certificate expires
		daysUntilExpiry := time.Until(cert.ExpiresAt).Hours() / 24
		if daysUntilExpiry < 30 && daysUntilExpiry > 0 {
			return &domain.PolicyViolation{
				ID:            generateID("violation"),
				RuleID:        rule.ID,
				CertificateID: cert.ID,
				Severity:      domain.PolicySeverityWarning,
				Message:       fmt.Sprintf("certificate expires in %.1f days, plan renewal soon", daysUntilExpiry),
				CreatedAt:     time.Now(),
			}, nil
		}

	default:
		return nil, fmt.Errorf("unknown policy rule type: %s", rule.Type)
	}

	return nil, nil
}

// CreateRule stores a new policy rule.
func (s *PolicyService) CreateRule(ctx context.Context, rule *domain.PolicyRule, actor string) error {
	if rule.ID == "" {
		rule.ID = generateID("rule")
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}

	if err := s.policyRepo.CreateRule(ctx, rule); err != nil {
		return fmt.Errorf("failed to create policy rule: %w", err)
	}

	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"policy_rule_created", "policy", rule.ID,
		map[string]interface{}{"rule_type": rule.Type}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// UpdateRule modifies an existing policy rule.
func (s *PolicyService) UpdateRule(ctx context.Context, rule *domain.PolicyRule, actor string) error {
	existing, err := s.policyRepo.GetRule(ctx, rule.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch existing rule: %w", err)
	}

	rule.UpdatedAt = time.Now()

	if err := s.policyRepo.UpdateRule(ctx, rule); err != nil {
		return fmt.Errorf("failed to update policy rule: %w", err)
	}

	changes := map[string]interface{}{}
	if existing.Enabled != rule.Enabled {
		changes["enabled"] = rule.Enabled
	}

	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"policy_rule_updated", "policy", rule.ID, changes); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// GetRule retrieves a policy rule by ID.
func (s *PolicyService) GetRule(ctx context.Context, id string) (*domain.PolicyRule, error) {
	rule, err := s.policyRepo.GetRule(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch policy rule: %w", err)
	}
	return rule, nil
}

// ListRules returns all policy rules.
func (s *PolicyService) ListRules(ctx context.Context) ([]*domain.PolicyRule, error) {
	rules, err := s.policyRepo.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policy rules: %w", err)
	}
	return rules, nil
}

// DeleteRule removes a policy rule.
func (s *PolicyService) DeleteRule(ctx context.Context, id string, actor string) error {
	rule, err := s.policyRepo.GetRule(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch rule: %w", err)
	}

	if err := s.policyRepo.DeleteRule(ctx, id); err != nil {
		return fmt.Errorf("failed to delete policy rule: %w", err)
	}

	if err := s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
		"policy_rule_deleted", "policy", id,
		map[string]interface{}{"rule_type": rule.Type}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// ListViolationsWithContext returns policy violations matching filter criteria.
func (s *PolicyService) ListViolationsWithContext(ctx context.Context, filter *repository.AuditFilter) ([]*domain.PolicyViolation, error) {
	violations, err := s.policyRepo.ListViolations(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list policy violations: %w", err)
	}
	return violations, nil
}

// ListPolicies returns paginated policies (handler interface method).
func (s *PolicyService) ListPolicies(ctx context.Context, page, perPage int) ([]domain.PolicyRule, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	rules, err := s.policyRepo.ListRules(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list policies: %w", err)
	}

	total := int64(len(rules))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}

	var result []domain.PolicyRule
	for _, r := range rules[start:end] {
		if r != nil {
			result = append(result, *r)
		}
	}

	return result, total, nil
}

// GetPolicy returns a single policy (handler interface method).
func (s *PolicyService) GetPolicy(ctx context.Context, id string) (*domain.PolicyRule, error) {
	return s.policyRepo.GetRule(ctx, id)
}

// CreatePolicy creates a new policy (handler interface method).
func (s *PolicyService) CreatePolicy(ctx context.Context, policy domain.PolicyRule) (*domain.PolicyRule, error) {
	if policy.ID == "" {
		policy.ID = generateID("rule")
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}

	if err := s.policyRepo.CreateRule(ctx, &policy); err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}
	return &policy, nil
}

// UpdatePolicy modifies a policy (handler interface method).
func (s *PolicyService) UpdatePolicy(ctx context.Context, id string, policy domain.PolicyRule) (*domain.PolicyRule, error) {
	policy.ID = id
	policy.UpdatedAt = time.Now()

	// Severity is NOT NULL with a CHECK constraint at the DB level
	// (migration 000013). If the client omits severity on a PUT (zero-value
	// empty string after json.Decode), preserve the existing severity rather
	// than letting the CHECK reject the write. Preserves partial-update
	// semantics for the new column without changing the pre-existing behavior
	// for Name/Type, which is out of scope for D-005/D-006.
	if policy.Severity == "" {
		existing, err := s.policyRepo.GetRule(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch existing rule for severity preservation: %w", err)
		}
		policy.Severity = existing.Severity
	}

	if err := s.policyRepo.UpdateRule(ctx, &policy); err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}
	return &policy, nil
}

// DeletePolicy removes a policy (handler interface method).
func (s *PolicyService) DeletePolicy(ctx context.Context, id string) error {
	return s.policyRepo.DeleteRule(ctx, id)
}

// ListViolations returns policy violations with pagination (handler interface method).
func (s *PolicyService) ListViolations(ctx context.Context, policyID string, page, perPage int) ([]domain.PolicyViolation, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	filter := &repository.AuditFilter{
		ResourceID: policyID,
		PerPage:    1000, // Get all violations for the policy
	}

	violations, err := s.policyRepo.ListViolations(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list violations: %w", err)
	}

	total := int64(len(violations))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}

	var result []domain.PolicyViolation
	for _, v := range violations[start:end] {
		if v != nil {
			result = append(result, *v)
		}
	}

	return result, total, nil
}
