package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// PolicyRepository implements repository.PolicyRepository
type PolicyRepository struct {
	db *sql.DB
}

// NewPolicyRepository creates a new PolicyRepository
func NewPolicyRepository(db *sql.DB) *PolicyRepository {
	return &PolicyRepository{db: db}
}

// ListRules returns all policy rules
func (r *PolicyRepository) ListRules(ctx context.Context) ([]*domain.PolicyRule, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, type, config, enabled, severity, created_at, updated_at
		FROM policy_rules
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query policy rules: %w", err)
	}
	defer rows.Close()

	var rules []*domain.PolicyRule
	for rows.Next() {
		var rule domain.PolicyRule
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Type, &rule.Config,
			&rule.Enabled, &rule.Severity, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan policy rule: %w", err)
		}
		rules = append(rules, &rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating policy rule rows: %w", err)
	}

	return rules, nil
}

// GetRule retrieves a policy rule by ID
func (r *PolicyRepository) GetRule(ctx context.Context, id string) (*domain.PolicyRule, error) {
	var rule domain.PolicyRule
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, type, config, enabled, severity, created_at, updated_at
		FROM policy_rules
		WHERE id = $1
	`, id).Scan(&rule.ID, &rule.Name, &rule.Type, &rule.Config,
		&rule.Enabled, &rule.Severity, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("policy rule not found")
		}
		return nil, fmt.Errorf("failed to query policy rule: %w", err)
	}

	return &rule, nil
}

// CreateRule stores a new policy rule
func (r *PolicyRepository) CreateRule(ctx context.Context, rule *domain.PolicyRule) error {
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO policy_rules (id, name, type, config, enabled, severity, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, rule.ID, rule.Name, rule.Type, rule.Config, rule.Enabled,
		rule.Severity, rule.CreatedAt, rule.UpdatedAt).Scan(&rule.ID)

	if err != nil {
		return fmt.Errorf("failed to create policy rule: %w", err)
	}

	return nil
}

// UpdateRule modifies an existing policy rule
func (r *PolicyRepository) UpdateRule(ctx context.Context, rule *domain.PolicyRule) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE policy_rules SET
			name = $1,
			type = $2,
			config = $3,
			enabled = $4,
			severity = $5,
			updated_at = $6
		WHERE id = $7
	`, rule.Name, rule.Type, rule.Config, rule.Enabled, rule.Severity, rule.UpdatedAt, rule.ID)

	if err != nil {
		return fmt.Errorf("failed to update policy rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("policy rule not found")
	}

	return nil
}

// DeleteRule removes a policy rule
func (r *PolicyRepository) DeleteRule(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM policy_rules WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete policy rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("policy rule not found")
	}

	return nil
}

// CreateViolation records a policy violation
func (r *PolicyRepository) CreateViolation(ctx context.Context, violation *domain.PolicyViolation) error {
	if violation.ID == "" {
		violation.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO policy_violations (id, certificate_id, rule_id, message, severity, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, violation.ID, violation.CertificateID, violation.RuleID, violation.Message,
		violation.Severity, violation.CreatedAt).Scan(&violation.ID)

	if err != nil {
		return fmt.Errorf("failed to create policy violation: %w", err)
	}

	return nil
}

// ListViolations returns policy violations, optionally filtered
func (r *PolicyRepository) ListViolations(ctx context.Context, filter *repository.AuditFilter) ([]*domain.PolicyViolation, error) {
	if filter == nil {
		filter = &repository.AuditFilter{}
	}

	// Set defaults
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage == 0 || filter.PerPage > 500 {
		filter.PerPage = 50
	}

	// Build WHERE clause
	var whereConditions []string
	var args []interface{}
	argCount := 1

	if filter.ResourceID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("certificate_id = $%d", argCount))
		args = append(args, filter.ResourceID)
		argCount++
	}
	if !filter.From.IsZero() {
		whereConditions = append(whereConditions, fmt.Sprintf("created_at >= $%d", argCount))
		args = append(args, filter.From)
		argCount++
	}
	if !filter.To.IsZero() {
		whereConditions = append(whereConditions, fmt.Sprintf("created_at <= $%d", argCount))
		args = append(args, filter.To)
		argCount++
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM policy_violations %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count policy violations: %w", err)
	}

	// Get paginated results
	offset := (filter.Page - 1) * filter.PerPage
	query := fmt.Sprintf(`
		SELECT id, certificate_id, rule_id, message, severity, created_at
		FROM policy_violations
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount, argCount+1)

	args = append(args, filter.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query policy violations: %w", err)
	}
	defer rows.Close()

	var violations []*domain.PolicyViolation
	for rows.Next() {
		var v domain.PolicyViolation
		if err := rows.Scan(&v.ID, &v.CertificateID, &v.RuleID, &v.Message,
			&v.Severity, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan policy violation: %w", err)
		}
		violations = append(violations, &v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating policy violation rows: %w", err)
	}

	return violations, nil
}
