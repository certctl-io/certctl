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

// AuditRepository implements repository.AuditRepository
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates a new AuditRepository
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create stores a new audit event using the repository's package-level
// *sql.DB. Use CreateWithTx when the audit event must be atomic with
// another database operation in a service-layer transaction.
func (r *AuditRepository) Create(ctx context.Context, event *domain.AuditEvent) error {
	return r.CreateWithTx(ctx, r.db, event)
}

// CreateWithTx stores a new audit event using the supplied Querier.
// Pass *sql.Tx (typically from postgres.WithinTx) to participate in a
// caller's transaction; pass *sql.DB or call Create for stand-alone
// inserts. The SQL and side-effect contract is identical to Create —
// CreateWithTx is the load-bearing path that closes the audit's
// atomicity blocker (audit row must be transactional with the
// operation that triggered it).
func (r *AuditRepository) CreateWithTx(ctx context.Context, q repository.Querier, event *domain.AuditEvent) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}

	err := q.QueryRowContext(ctx, `
		INSERT INTO audit_events (
			id, actor, actor_type, action, resource_type, resource_id, details, timestamp
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, event.ID, event.Actor, event.ActorType, event.Action, event.ResourceType,
		event.ResourceID, event.Details, event.Timestamp).Scan(&event.ID)

	if err != nil {
		return fmt.Errorf("failed to create audit event: %w", err)
	}

	return nil
}

// List returns audit events matching the filter criteria
func (r *AuditRepository) List(ctx context.Context, filter *repository.AuditFilter) ([]*domain.AuditEvent, error) {
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

	if filter.Actor != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("actor = $%d", argCount))
		args = append(args, filter.Actor)
		argCount++
	}
	if filter.ActorType != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("actor_type = $%d", argCount))
		args = append(args, filter.ActorType)
		argCount++
	}
	if filter.ResourceType != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("resource_type = $%d", argCount))
		args = append(args, filter.ResourceType)
		argCount++
	}
	if filter.ResourceID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("resource_id = $%d", argCount))
		args = append(args, filter.ResourceID)
		argCount++
	}
	if !filter.From.IsZero() {
		whereConditions = append(whereConditions, fmt.Sprintf("timestamp >= $%d", argCount))
		args = append(args, filter.From)
		argCount++
	}
	if !filter.To.IsZero() {
		whereConditions = append(whereConditions, fmt.Sprintf("timestamp <= $%d", argCount))
		args = append(args, filter.To)
		argCount++
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_events %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count audit events: %w", err)
	}

	// Get paginated results
	offset := (filter.Page - 1) * filter.PerPage
	query := fmt.Sprintf(`
		SELECT id, actor, actor_type, action, resource_type, resource_id, details, timestamp
		FROM audit_events
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount, argCount+1)

	args = append(args, filter.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()

	var events []*domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		if err := rows.Scan(&event.ID, &event.Actor, &event.ActorType, &event.Action,
			&event.ResourceType, &event.ResourceID, &event.Details, &event.Timestamp); err != nil {
			return nil, fmt.Errorf("failed to scan audit event: %w", err)
		}
		events = append(events, &event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit event rows: %w", err)
	}

	return events, nil
}
