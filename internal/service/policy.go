package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// PolicyService provides business logic for compliance policy management.
type PolicyService struct {
	policyRepo   repository.PolicyRepository
	auditService *AuditService
	// certRepo is optional and only required by the CertificateLifetime rule
	// arm, which must read NotBefore/NotAfter from the latest CertificateVersion.
	// Wire via SetCertRepo after construction; rules other than
	// CertificateLifetime operate without it.
	certRepo repository.CertificateRepository
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

// SetCertRepo wires the certificate repository needed for the CertificateLifetime
// rule arm. Kept as a setter (not a constructor parameter) so the ~36 existing
// NewPolicyService call sites don't churn for a single new arm's dependency.
// Safe to call before or after construction; evaluateRule checks for nil and
// returns an error if a CertificateLifetime rule fires without a wired repo
// (the caller at ValidateCertificate logs and continues).
func (s *PolicyService) SetCertRepo(r repository.CertificateRepository) {
	s.certRepo = r
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
		v, err := s.evaluateRule(ctx, rule, cert)
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
//
// D-008 closes the engine loop by:
//  1. Consuming rule.Severity on every violation (the pre-D-008 engine
//     hardcoded PolicySeverityWarning, which silently defeated the D-006
//     per-rule severity column).
//  2. Parsing rule.Config per-arm so rules carry real thresholds / allowlists
//     instead of the pre-D-008 "metadata absent" placeholders. Empty/null
//     Config preserves the pre-D-008 missing-field behavior as a
//     backward-compat invariant — a rule without config still fires on the
//     absent-field shape but using its configured severity.
//  3. Adding the CertificateLifetime arm, which reads NotBefore/NotAfter from
//     the latest CertificateVersion (injected via SetCertRepo). Required
//     because ManagedCertificate tracks ExpiresAt but not issuance date.
//
// Bad-config failure mode: json.Unmarshal error returns (nil, error) shaped
// as `invalid config for rule <id> (type=<type>): <err>`; the caller at
// ValidateCertificate logs and continues so one malformed rule doesn't fail
// the entire pass.
func (s *PolicyService) evaluateRule(ctx context.Context, rule *domain.PolicyRule, cert *domain.ManagedCertificate) (*domain.PolicyViolation, error) {
	switch rule.Type {
	case domain.PolicyTypeAllowedIssuers:
		// Config: {"allowed_issuer_ids": ["iss-a", "iss-b"]}
		// Empty config = fire only on absent IssuerID (backward-compat).
		var cfg struct {
			AllowedIssuerIDs []string `json:"allowed_issuer_ids"`
		}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfg); err != nil {
				return nil, fmt.Errorf("invalid config for rule %s (type=%s): %w", rule.ID, rule.Type, err)
			}
		}
		if cert.IssuerID == "" {
			return s.violation(rule, cert, "certificate has no issuer assigned"), nil
		}
		if len(cfg.AllowedIssuerIDs) > 0 && !containsString(cfg.AllowedIssuerIDs, cert.IssuerID) {
			return s.violation(rule, cert, fmt.Sprintf("issuer %q is not in the allowed list", cert.IssuerID)), nil
		}

	case domain.PolicyTypeAllowedDomains:
		// Config: {"allowed_domains": ["example.com", "*.internal.example.com"]}
		// Wildcards are literal prefix matches (*.foo matches anything ending
		// in .foo). Empty config = fire only on zero SANs (backward-compat).
		var cfg struct {
			AllowedDomains []string `json:"allowed_domains"`
		}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfg); err != nil {
				return nil, fmt.Errorf("invalid config for rule %s (type=%s): %w", rule.ID, rule.Type, err)
			}
		}
		if len(cert.SANs) == 0 {
			return s.violation(rule, cert, "certificate has no subject alternative names"), nil
		}
		if len(cfg.AllowedDomains) > 0 {
			for _, san := range cert.SANs {
				if !domainAllowed(san, cfg.AllowedDomains) {
					return s.violation(rule, cert, fmt.Sprintf("SAN %q is not in the allowed domain list", san)), nil
				}
			}
		}

	case domain.PolicyTypeRequiredMetadata:
		// Config: {"required_keys": ["owner", "cost-center"]}
		// Empty config = fire only on zero tags (backward-compat).
		var cfg struct {
			RequiredKeys []string `json:"required_keys"`
		}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfg); err != nil {
				return nil, fmt.Errorf("invalid config for rule %s (type=%s): %w", rule.ID, rule.Type, err)
			}
		}
		if len(cert.Tags) == 0 {
			return s.violation(rule, cert, "certificate has no tags or metadata"), nil
		}
		for _, key := range cfg.RequiredKeys {
			if _, ok := cert.Tags[key]; !ok {
				return s.violation(rule, cert, fmt.Sprintf("certificate is missing required metadata key %q", key)), nil
			}
		}

	case domain.PolicyTypeAllowedEnvironments:
		// Config: {"allowed": ["prod", "staging"]}
		// Empty config = fire only on empty Environment (backward-compat).
		var cfg struct {
			Allowed []string `json:"allowed"`
		}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfg); err != nil {
				return nil, fmt.Errorf("invalid config for rule %s (type=%s): %w", rule.ID, rule.Type, err)
			}
		}
		if cert.Environment == "" {
			return s.violation(rule, cert, "certificate has no environment assigned"), nil
		}
		if len(cfg.Allowed) > 0 && !containsString(cfg.Allowed, cert.Environment) {
			return s.violation(rule, cert, fmt.Sprintf("environment %q is not in the allowed list", cert.Environment)), nil
		}

	case domain.PolicyTypeRenewalLeadTime:
		// Config: {"lead_time_days": 30}
		// Fires when remaining validity drops below lead_time_days and the
		// cert is not already expired. Empty/zero config falls back to the
		// pre-D-008 hardcoded 30-day threshold for backward compatibility.
		var cfg struct {
			LeadTimeDays int `json:"lead_time_days"`
		}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfg); err != nil {
				return nil, fmt.Errorf("invalid config for rule %s (type=%s): %w", rule.ID, rule.Type, err)
			}
		}
		leadDays := cfg.LeadTimeDays
		if leadDays <= 0 {
			leadDays = 30
		}
		daysUntilExpiry := time.Until(cert.ExpiresAt).Hours() / 24
		if daysUntilExpiry < float64(leadDays) && daysUntilExpiry > 0 {
			return s.violation(rule, cert, fmt.Sprintf("certificate expires in %.1f days, plan renewal soon (policy lead time: %d days)", daysUntilExpiry, leadDays)), nil
		}

	case domain.PolicyTypeCertificateLifetime:
		// Config: {"max_days": 397}
		// Reads NotBefore/NotAfter from the latest CertificateVersion via the
		// injected certRepo. ManagedCertificate exposes ExpiresAt but not the
		// issuance date, so lifetime math requires the version record.
		//
		// If certRepo wasn't wired (test misconfiguration / early boot),
		// returns an error so the caller logs it — better a loud failure
		// than silently ignoring the rule. If GetLatestVersion errors (e.g.,
		// the cert hasn't been issued yet), we skip the check — a cert with
		// no version has no lifetime to measure, matching the missing-field
		// backward-compat pattern used by the other arms.
		if s.certRepo == nil {
			return nil, fmt.Errorf("CertificateLifetime rule %s requires cert repository (not wired via SetCertRepo)", rule.ID)
		}
		var cfg struct {
			MaxDays int `json:"max_days"`
		}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfg); err != nil {
				return nil, fmt.Errorf("invalid config for rule %s (type=%s): %w", rule.ID, rule.Type, err)
			}
		}
		if cfg.MaxDays <= 0 {
			// No threshold configured — nothing meaningful to enforce.
			return nil, nil
		}
		version, err := s.certRepo.GetLatestVersion(ctx, cert.ID)
		if err != nil {
			// No version yet — nothing to measure. Not an engine error;
			// the cert simply hasn't been issued.
			return nil, nil
		}
		lifetimeDays := version.NotAfter.Sub(version.NotBefore).Hours() / 24
		if lifetimeDays > float64(cfg.MaxDays) {
			return s.violation(rule, cert, fmt.Sprintf("certificate lifetime is %.1f days, exceeds policy max of %d days", lifetimeDays, cfg.MaxDays)), nil
		}

	default:
		return nil, fmt.Errorf("unknown policy rule type: %s", rule.Type)
	}

	return nil, nil
}

// violation constructs a PolicyViolation carrying the rule's configured
// severity. Centralizing the build eliminates the pre-D-008 bug where each
// arm independently stamped PolicySeverityWarning on its violation.
func (s *PolicyService) violation(rule *domain.PolicyRule, cert *domain.ManagedCertificate, message string) *domain.PolicyViolation {
	return &domain.PolicyViolation{
		ID:            generateID("violation"),
		RuleID:        rule.ID,
		CertificateID: cert.ID,
		Severity:      rule.Severity,
		Message:       message,
		CreatedAt:     time.Now(),
	}
}

// containsString reports whether needle is present in haystack.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// domainAllowed reports whether a SAN (hostname) matches any of the allowed
// domain patterns. Patterns may be exact matches or `*.example.com` wildcards
// (the wildcard consumes a single label: `*.foo.com` matches `bar.foo.com`
// but not `baz.bar.foo.com`, mirroring X.509 SAN wildcard semantics).
func domainAllowed(san string, allowed []string) bool {
	san = strings.ToLower(strings.TrimSpace(san))
	for _, pattern := range allowed {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == san {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".foo.com"
			if strings.HasSuffix(san, suffix) {
				// Ensure wildcard consumes exactly one label — reject
				// sub-subdomains.
				head := strings.TrimSuffix(san, suffix)
				if head != "" && !strings.Contains(head, ".") {
					return true
				}
			}
		}
	}
	return false
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
