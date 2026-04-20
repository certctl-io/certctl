package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lib/pq"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// RenewalPolicyRepository implements repository.RenewalPolicyRepository.
type RenewalPolicyRepository struct {
	db *sql.DB
}

// NewRenewalPolicyRepository creates a new RenewalPolicyRepository.
func NewRenewalPolicyRepository(db *sql.DB) *RenewalPolicyRepository {
	return &RenewalPolicyRepository{db: db}
}

// SELECT column order is the shared contract between scanRenewalPolicy and
// every SELECT/RETURNING in this file. Keep them in lockstep; if you add a
// new column, add it to all SELECTs, all scan calls, and scanRenewalPolicy.
//
// Note: certificate_profile_id and agent_group_id live on renewal_policies
// (migrations 000003 and 000004) but are deliberately NOT read here — that
// pre-existing drift is out of G-1's minimum-viable-delta and is tracked in
// the design doc §8. Introducing them would change struct shapes / JSON tags
// and require domain-layer churn we're not taking on in this change.
const renewalPolicyColumns = `
	id, name, renewal_window_days, auto_renew, max_retries,
	retry_interval_minutes, alert_thresholds_days, created_at, updated_at
`

// scanRenewalPolicy decodes one renewal_policies row from a Row or Rows
// scanner, unmarshaling alert_thresholds_days JSONB into the domain slice.
// Malformed JSONB silently falls back to DefaultAlertThresholds() — same
// behavior as the pre-G-1 code so we don't change observable semantics.
func scanRenewalPolicy(scanner interface {
	Scan(dest ...any) error
}) (*domain.RenewalPolicy, error) {
	var policy domain.RenewalPolicy
	var thresholdsJSON []byte

	if err := scanner.Scan(
		&policy.ID, &policy.Name, &policy.RenewalWindowDays, &policy.AutoRenew,
		&policy.MaxRetries, &policy.RetryInterval, &thresholdsJSON,
		&policy.CreatedAt, &policy.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(thresholdsJSON) > 0 {
		if err := json.Unmarshal(thresholdsJSON, &policy.AlertThresholdsDays); err != nil {
			policy.AlertThresholdsDays = domain.DefaultAlertThresholds()
		}
	}

	return &policy, nil
}

// Get retrieves a renewal policy by ID.
func (r *RenewalPolicyRepository) Get(ctx context.Context, id string) (*domain.RenewalPolicy, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+renewalPolicyColumns+` FROM renewal_policies WHERE id = $1`, id)
	policy, err := scanRenewalPolicy(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("renewal policy not found: %s", id)
		}
		return nil, fmt.Errorf("failed to query renewal policy: %w", err)
	}
	return policy, nil
}

// List returns all renewal policies, ordered by name (matches the index on
// renewal_policies.name from migration 000001 so ORDER BY is index-served).
func (r *RenewalPolicyRepository) List(ctx context.Context) ([]*domain.RenewalPolicy, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+renewalPolicyColumns+` FROM renewal_policies ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query renewal policies: %w", err)
	}
	defer rows.Close()

	var policies []*domain.RenewalPolicy
	for rows.Next() {
		policy, err := scanRenewalPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan renewal policy: %w", err)
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating renewal policy rows: %w", err)
	}

	return policies, nil
}

// slugRegex matches non-alphanumeric characters that slugifyPolicyName strips.
var slugRegex = regexp.MustCompile(`[^a-z0-9-]+`)

// slugifyPolicyName produces `rp-<slug>` for an auto-generated policy ID.
// Slug: lowercase, spaces→hyphens, non-alphanumeric stripped, trimmed to 64
// chars. Matches the existing seed convention (rp-default, rp-standard,
// rp-urgent). Collision resolution is handled by Create's retry loop.
func slugifyPolicyName(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = slugRegex.ReplaceAllString(slug, "")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "policy"
	}
	if len(slug) > 64 {
		slug = slug[:64]
	}
	return "rp-" + slug
}

// isUniqueViolation reports whether err is a PostgreSQL 23505 unique_violation.
// Used by Create/Update to translate name-collision errors onto the typed
// ErrRenewalPolicyDuplicateName sentinel.
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

// isForeignKeyViolation reports whether err is a PostgreSQL 23503
// foreign_key_violation. Used by Delete to translate ON DELETE RESTRICT
// failures onto the typed ErrRenewalPolicyInUse sentinel.
func isForeignKeyViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23503"
}

// Create inserts a new renewal policy. If policy.ID is empty, auto-generates
// `rp-<slug(name)>` with -2/-3/... suffixes on collision (up to 10 attempts).
// Returns ErrRenewalPolicyDuplicateName on pg 23505 (name collision).
//
// alert_thresholds_days is marshaled to JSONB here rather than relying on the
// DB default because the service layer already applies DefaultAlertThresholds
// for empty input — the DB default is a safety net, not the primary path.
func (r *RenewalPolicyRepository) Create(ctx context.Context, policy *domain.RenewalPolicy) error {
	if policy == nil {
		return errors.New("renewal policy is nil")
	}

	thresholdsJSON, err := json.Marshal(policy.AlertThresholdsDays)
	if err != nil {
		return fmt.Errorf("failed to marshal alert thresholds: %w", err)
	}

	// ID auto-generation with collision retry. We attempt up to 10 suffix
	// variants (rp-foo, rp-foo-2, ..., rp-foo-10) before giving up — the
	// 23505 error the caller gets back past that point is on Name (their
	// job to fix) rather than on a slug-collision we swallowed.
	baseID := policy.ID
	if baseID == "" {
		baseID = slugifyPolicyName(policy.Name)
	}

	insertSQL := `
		INSERT INTO renewal_policies (
			id, name, renewal_window_days, auto_renew, max_retries,
			retry_interval_minutes, alert_thresholds_days, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING ` + renewalPolicyColumns

	maxAttempts := 10
	if policy.ID != "" {
		// Caller supplied a specific ID — no collision-retry, just one shot.
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		candidateID := baseID
		if attempt > 1 {
			candidateID = fmt.Sprintf("%s-%d", baseID, attempt)
		}

		row := r.db.QueryRowContext(ctx, insertSQL,
			candidateID, policy.Name, policy.RenewalWindowDays, policy.AutoRenew,
			policy.MaxRetries, policy.RetryInterval, thresholdsJSON,
		)

		inserted, scanErr := scanRenewalPolicy(row)
		if scanErr == nil {
			*policy = *inserted
			return nil
		}

		if isUniqueViolation(scanErr) {
			// Determine which unique constraint — if it's the name UNIQUE
			// we can't recover (caller has to pick a new name); if it's the
			// primary-key slug collision we loop to the next suffix.
			var pqErr *pq.Error
			errors.As(scanErr, &pqErr)
			// Postgres reports the constraint name in pqErr.Constraint;
			// renewal_policies_name_key is the name UNIQUE, renewal_policies_pkey
			// is the PK. Name collision is terminal, PK collision is retryable.
			if pqErr.Constraint != "" && !strings.Contains(pqErr.Constraint, "pkey") {
				return repository.ErrRenewalPolicyDuplicateName
			}
			// PK collision — try next suffix.
			continue
		}

		return fmt.Errorf("failed to insert renewal policy: %w", scanErr)
	}

	// Exhausted retry budget on PK collisions — surface as duplicate so the
	// caller at least gets a 409 rather than a mysterious 500.
	return repository.ErrRenewalPolicyDuplicateName
}

// Update modifies an existing renewal policy by ID. Returns an error wrapping
// sql.ErrNoRows when id is unknown (detected by RETURNING returning zero rows),
// or ErrRenewalPolicyDuplicateName on pg 23505 (name collision with another row).
func (r *RenewalPolicyRepository) Update(ctx context.Context, id string, policy *domain.RenewalPolicy) error {
	if policy == nil {
		return errors.New("renewal policy is nil")
	}

	thresholdsJSON, err := json.Marshal(policy.AlertThresholdsDays)
	if err != nil {
		return fmt.Errorf("failed to marshal alert thresholds: %w", err)
	}

	row := r.db.QueryRowContext(ctx, `
		UPDATE renewal_policies SET
			name = $2,
			renewal_window_days = $3,
			auto_renew = $4,
			max_retries = $5,
			retry_interval_minutes = $6,
			alert_thresholds_days = $7,
			updated_at = NOW()
		WHERE id = $1
		RETURNING `+renewalPolicyColumns,
		id, policy.Name, policy.RenewalWindowDays, policy.AutoRenew,
		policy.MaxRetries, policy.RetryInterval, thresholdsJSON,
	)

	updated, err := scanRenewalPolicy(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("renewal policy not found: %s", id)
		}
		if isUniqueViolation(err) {
			return repository.ErrRenewalPolicyDuplicateName
		}
		return fmt.Errorf("failed to update renewal policy: %w", err)
	}

	*policy = *updated
	return nil
}

// Delete removes a renewal policy by ID. Returns ErrRenewalPolicyInUse when
// the policy is still referenced by rows in managed_certificates (pg 23503
// foreign_key_violation against the ON DELETE RESTRICT FK from
// managed_certificates.renewal_policy_id). Returns an error wrapping
// sql.ErrNoRows when id is unknown.
func (r *RenewalPolicyRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM renewal_policies WHERE id = $1`, id)
	if err != nil {
		if isForeignKeyViolation(err) {
			return repository.ErrRenewalPolicyInUse
		}
		return fmt.Errorf("failed to delete renewal policy: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read RowsAffected for delete: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("renewal policy not found: %s", id)
	}
	return nil
}
