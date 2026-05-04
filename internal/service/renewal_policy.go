package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// G-1: service-level sentinels alias the repository sentinels so errors.Is
// walks transparently across layers. Do NOT errors.New a fresh copy — the
// handler's `errors.Is(err, repository.ErrRenewalPolicyInUse)` branch and
// the service-layer tests' `errors.Is(err, service.ErrRenewalPolicyInUse)`
// branch need to match the same sentinel var identity.
var (
	ErrRenewalPolicyDuplicateName = repository.ErrRenewalPolicyDuplicateName
	ErrRenewalPolicyInUse         = repository.ErrRenewalPolicyInUse
)

// RenewalPolicyService implements the /api/v1/renewal-policies CRUD surface.
//
// G-1 scope note: the red-test contract pins NewRenewalPolicyService to a
// repo-only signature (no auditService). Renewal-policy CRUD does not emit
// audit events in this change — if audit coverage is needed later, add a
// SetAuditService setter rather than churning the constructor signature.
type RenewalPolicyService struct {
	repo repository.RenewalPolicyRepository
}

// NewRenewalPolicyService constructs the service bound to its repository.
func NewRenewalPolicyService(repo repository.RenewalPolicyRepository) *RenewalPolicyService {
	return &RenewalPolicyService{repo: repo}
}

// rpSlugRegex matches non-alphanumeric characters that slugifyRenewalPolicyName strips.
// Mirrors the identical regex in internal/repository/postgres/renewal_policy.go —
// the service owns the rp-<slug> convention so the repo's retry loop is a
// pure PK-collision safety net, not the primary ID generator.
var rpSlugRegex = regexp.MustCompile(`[^a-z0-9-]+`)

// slugifyRenewalPolicyName produces `rp-<slug>` for an auto-generated policy
// ID. Slug: lowercase, spaces→hyphens, non-alphanumeric stripped, trimmed to
// 64 chars. Matches the seed convention (rp-default, rp-standard, rp-urgent)
// and the repo's slugifyPolicyName byte-for-byte.
func slugifyRenewalPolicyName(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = rpSlugRegex.ReplaceAllString(slug, "")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "policy"
	}
	if len(slug) > 64 {
		slug = slug[:64]
	}
	return "rp-" + slug
}

// ListRenewalPolicies returns a single page of renewal policies sorted by
// name (the repo's ORDER BY name is index-served via idx_renewal_policies_name).
// Pagination is done in Go rather than SQL — the expected row count is in the
// single digits so LIMIT/OFFSET would be premature optimization and would
// churn the repo contract for no measurable benefit (design doc §Known
// Caller Audit).
//
// Bounds: page defaults to 1, per_page defaults to 50, caps at 500 to match
// the /api/v1/policies handler's behavior. Past-end slices return an empty
// slice with no error — callers use `total` to detect end of pagination.
func (s *RenewalPolicyService) ListRenewalPolicies(ctx context.Context, page, perPage int) ([]domain.RenewalPolicy, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}

	items, err := s.repo.List(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list renewal policies: %w", err)
	}

	total := int64(len(items))
	start := (page - 1) * perPage
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + perPage
	if end > int(total) {
		end = int(total)
	}

	out := make([]domain.RenewalPolicy, 0, end-start)
	for _, p := range items[start:end] {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out, total, nil
}

// GetRenewalPolicy retrieves one renewal policy by ID. Not-found errors
// surface from the repo verbatim; the handler translates them to 404.
func (s *RenewalPolicyService) GetRenewalPolicy(ctx context.Context, id string) (*domain.RenewalPolicy, error) {
	return s.repo.Get(ctx, id)
}

// validateBounds enforces the design doc §Validation Bounds invariants:
//   - name required, ≤ 255 chars
//   - renewal_window_days in [1, 365]
//   - max_retries in [0, 10]
//   - retry_interval_seconds in [60, 86400]
//   - alert_thresholds_days each in [0, 365]
//
// Called after applyCreateDefaults so zero-value fields that the caller
// expects to be defaulted don't trip the range checks.
func (s *RenewalPolicyService) validateBounds(rp *domain.RenewalPolicy) error {
	if strings.TrimSpace(rp.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(rp.Name) > 255 {
		return fmt.Errorf("name must be 255 characters or fewer, got %d", len(rp.Name))
	}
	if rp.RenewalWindowDays < 1 || rp.RenewalWindowDays > 365 {
		return fmt.Errorf("renewal_window_days must be between 1 and 365, got %d", rp.RenewalWindowDays)
	}
	if rp.MaxRetries < 0 || rp.MaxRetries > 10 {
		return fmt.Errorf("max_retries must be between 0 and 10, got %d", rp.MaxRetries)
	}
	if rp.RetryInterval < 60 || rp.RetryInterval > 86400 {
		return fmt.Errorf("retry_interval_seconds must be between 60 and 86400, got %d", rp.RetryInterval)
	}
	for i, t := range rp.AlertThresholdsDays {
		if t < 0 || t > 365 {
			return fmt.Errorf("alert_thresholds_days[%d]=%d must be between 0 and 365", i, t)
		}
	}
	return nil
}

// applyCreateDefaults fills in zero-valued optional fields with the design
// doc defaults. Name is never defaulted — missing name fails validation.
// MaxRetries=0 is a legal explicit value (no retries), so it is NOT
// defaulted; the DB default column handles that path if needed.
func (s *RenewalPolicyService) applyCreateDefaults(rp *domain.RenewalPolicy) {
	if rp.RenewalWindowDays == 0 {
		rp.RenewalWindowDays = 30
	}
	if rp.RetryInterval == 0 {
		rp.RetryInterval = 3600
	}
	if len(rp.AlertThresholdsDays) == 0 {
		rp.AlertThresholdsDays = domain.DefaultAlertThresholds()
	}
}

// CreateRenewalPolicy inserts a new renewal policy. Auto-generates
// `rp-<slug(name)>` for ID if empty. Defaults are applied before bounds
// validation so a caller can omit RenewalWindowDays / RetryInterval and
// still pass bounds. Returns ErrRenewalPolicyDuplicateName unwrapped from
// the repo when a name collision occurs (pg 23505 on the UNIQUE constraint);
// the handler surfaces that as 409 Conflict.
func (s *RenewalPolicyService) CreateRenewalPolicy(ctx context.Context, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
	s.applyCreateDefaults(&rp)
	if err := s.validateBounds(&rp); err != nil {
		return nil, err
	}
	if rp.ID == "" {
		rp.ID = slugifyRenewalPolicyName(rp.Name)
	}
	if rp.CreatedAt.IsZero() {
		rp.CreatedAt = time.Now()
	}
	if err := s.repo.Create(ctx, &rp); err != nil {
		// Propagate repository sentinels verbatim — service-level sentinels
		// alias repo sentinels (same var identity), so errors.Is walks
		// through without any translation.
		return nil, err
	}
	return &rp, nil
}

// UpdateRenewalPolicy replaces the fields of an existing renewal policy.
// Applies the same defaults+bounds as Create so partial updates do not slip
// an invalid row past validation via zero-value fields. id in the path wins
// over any id the caller supplied in the body.
func (s *RenewalPolicyService) UpdateRenewalPolicy(ctx context.Context, id string, rp domain.RenewalPolicy) (*domain.RenewalPolicy, error) {
	s.applyCreateDefaults(&rp)
	if err := s.validateBounds(&rp); err != nil {
		return nil, err
	}
	rp.ID = id
	if err := s.repo.Update(ctx, id, &rp); err != nil {
		return nil, err
	}
	return &rp, nil
}

// DeleteRenewalPolicy removes a renewal policy. Returns ErrRenewalPolicyInUse
// when the policy is still referenced by rows in managed_certificates (the
// repo translates pg 23503 FK_RESTRICT violations onto that sentinel). The
// handler surfaces that as 409 Conflict.
func (s *RenewalPolicyService) DeleteRenewalPolicy(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}
