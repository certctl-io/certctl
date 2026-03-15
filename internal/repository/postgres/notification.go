package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// NotificationRepository implements repository.NotificationRepository
type NotificationRepository struct {
	db *sql.DB
}

// NewNotificationRepository creates a new NotificationRepository
func NewNotificationRepository(db *sql.DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

// Create stores a new notification
func (r *NotificationRepository) Create(ctx context.Context, notif *domain.NotificationEvent) error {
	if notif.ID == "" {
		notif.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO notification_events (
			id, type, certificate_id, channel, recipient, message, sent_at, status, error
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`, notif.ID, notif.Type, notif.CertificateID, notif.Channel, notif.Recipient,
		notif.Message, notif.SentAt, notif.Status, notif.Error).Scan(&notif.ID)

	if err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return nil
}

// List returns notifications matching the filter criteria
func (r *NotificationRepository) List(ctx context.Context, filter *repository.NotificationFilter) ([]*domain.NotificationEvent, error) {
	if filter == nil {
		filter = &repository.NotificationFilter{}
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

	if filter.CertificateID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("certificate_id = $%d", argCount))
		args = append(args, filter.CertificateID)
		argCount++
	}
	if filter.Type != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("type = $%d", argCount))
		args = append(args, filter.Type)
		argCount++
	}
	if filter.Status != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("status = $%d", argCount))
		args = append(args, filter.Status)
		argCount++
	}
	if filter.MessageLike != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("message LIKE $%d", argCount))
		args = append(args, filter.MessageLike)
		argCount++
	}
	if filter.Channel != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("channel = $%d", argCount))
		args = append(args, filter.Channel)
		argCount++
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM notification_events %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count notifications: %w", err)
	}

	// Get paginated results
	offset := (filter.Page - 1) * filter.PerPage
	query := fmt.Sprintf(`
		SELECT id, type, certificate_id, channel, recipient, message, sent_at, status, error
		FROM notification_events
		%s
		ORDER BY sent_at DESC NULLS LAST
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount, argCount+1)

	args = append(args, filter.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query notifications: %w", err)
	}
	defer rows.Close()

	var notifs []*domain.NotificationEvent
	for rows.Next() {
		notif, err := scanNotification(rows)
		if err != nil {
			return nil, err
		}
		notifs = append(notifs, notif)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating notification rows: %w", err)
	}

	return notifs, nil
}

// UpdateStatus updates a notification's delivery status
func (r *NotificationRepository) UpdateStatus(ctx context.Context, id string, status string, sentAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE notification_events SET status = $1, sent_at = $2 WHERE id = $3
	`, status, sentAt, id)

	if err != nil {
		return fmt.Errorf("failed to update notification status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("notification not found")
	}

	return nil
}

// scanNotification scans a notification from a row or rows
func scanNotification(scanner interface {
	Scan(...interface{}) error
}) (*domain.NotificationEvent, error) {
	var notif domain.NotificationEvent
	err := scanner.Scan(&notif.ID, &notif.Type, &notif.CertificateID, &notif.Channel,
		&notif.Recipient, &notif.Message, &notif.SentAt, &notif.Status, &notif.Error)

	if err != nil {
		return nil, fmt.Errorf("failed to scan notification: %w", err)
	}

	return &notif, nil
}
