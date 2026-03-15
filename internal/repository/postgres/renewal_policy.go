package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/shankar0123/certctl/internal/domain"
)

// RenewalPolicyRepository implements repository.RenewalPolicyRepository
type RenewalPolicyRepository struct {
	db *sql.DB
}

// NewRenewalPolicyRepository creates a new RenewalPolicyRepository
func NewRenewalPolicyRepository(db *sql.DB) *RenewalPolicyRepository {
	return &RenewalPolicyRepository{db: db}
}

// Get retrieves a renewal policy by ID
func (r *RenewalPolicyRepository) Get(ctx context.Context, id string) (*domain.RenewalPolicy, error) {
	var policy domain.RenewalPolicy
	var thresholdsJSON []byte

	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, renewal_window_days, auto_renew, max_retries,
		       retry_interval_minutes, alert_thresholds_days, created_at, updated_at
		FROM renewal_policies
		WHERE id = $1
	`, id).Scan(&policy.ID, &policy.Name, &policy.RenewalWindowDays, &policy.AutoRenew,
		&policy.MaxRetries, &policy.RetryInterval, &thresholdsJSON,
		&policy.CreatedAt, &policy.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("renewal policy not found: %s", id)
		}
		return nil, fmt.Errorf("failed to query renewal policy: %w", err)
	}

	// Parse alert thresholds from JSONB
	if len(thresholdsJSON) > 0 {
		if err := json.Unmarshal(thresholdsJSON, &policy.AlertThresholdsDays); err != nil {
			// Fall back to defaults if JSON is malformed
			policy.AlertThresholdsDays = domain.DefaultAlertThresholds()
		}
	}

	return &policy, nil
}

// List returns all renewal policies
func (r *RenewalPolicyRepository) List(ctx context.Context) ([]*domain.RenewalPolicy, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, renewal_window_days, auto_renew, max_retries,
		       retry_interval_minutes, alert_thresholds_days, created_at, updated_at
		FROM renewal_policies
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query renewal policies: %w", err)
	}
	defer rows.Close()

	var policies []*domain.RenewalPolicy
	for rows.Next() {
		var policy domain.RenewalPolicy
		var thresholdsJSON []byte

		if err := rows.Scan(&policy.ID, &policy.Name, &policy.RenewalWindowDays, &policy.AutoRenew,
			&policy.MaxRetries, &policy.RetryInterval, &thresholdsJSON,
			&policy.CreatedAt, &policy.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan renewal policy: %w", err)
		}

		if len(thresholdsJSON) > 0 {
			if err := json.Unmarshal(thresholdsJSON, &policy.AlertThresholdsDays); err != nil {
				policy.AlertThresholdsDays = domain.DefaultAlertThresholds()
			}
		}

		policies = append(policies, &policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating renewal policy rows: %w", err)
	}

	return policies, nil
}
