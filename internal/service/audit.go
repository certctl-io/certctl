package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// AuditService provides business logic for recording and retrieving audit events.
type AuditService struct {
	auditRepo repository.AuditRepository
}

// NewAuditService creates a new audit service.
func NewAuditService(auditRepo repository.AuditRepository) *AuditService {
	return &AuditService{
		auditRepo: auditRepo,
	}
}

// RecordEvent records an audit event with actor, action, and resource information.
//
// Bundle-6 / Audit H-008 + M-022 / CWE-532: every details map flows through
// RedactDetailsForAudit BEFORE marshaling. The redactor scrubs credential
// keys (api_key, password, token, *_pem, eab_secret, ...) and PII keys
// (email, phone, ssn, name, address, ip_address, ...) and surfaces a
// `redacted_keys` array so operators can audit the redactor itself during
// a compliance review. See internal/service/audit_redact.go.
func (s *AuditService) RecordEvent(ctx context.Context, actor string, actorType domain.ActorType, action string, resourceType string, resourceID string, details map[string]interface{}) error {
	return s.RecordEventWithCategory(ctx, actor, actorType, action, "", resourceType, resourceID, details)
}

// RecordEventWithCategory is the Bundle 1 Phase 8 categorized variant
// of RecordEvent. eventCategory is one of
// domain.EventCategoryCertLifecycle, domain.EventCategoryAuth,
// domain.EventCategoryConfig — empty defaults to cert_lifecycle in
// the persistence layer + DB CHECK constraint.
//
// Existing 90+ call sites that don't yet pass a category route
// through the legacy RecordEvent and inherit the cert_lifecycle
// default; new callers (auth handlers, bootstrap, config-mutation
// handlers) call this method directly with their explicit category.
// Both paths share the same redaction + marshaling contract.
func (s *AuditService) RecordEventWithCategory(ctx context.Context, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, details map[string]interface{}) error {
	redacted := RedactDetailsForAudit(details)
	detailsJSON, err := json.Marshal(redacted)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	event := &domain.AuditEvent{
		ID:            generateID("audit"),
		Timestamp:     time.Now(),
		Actor:         actor,
		ActorType:     actorType,
		Action:        action,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		Details:       json.RawMessage(detailsJSON),
		EventCategory: eventCategory,
	}

	if err := s.auditRepo.Create(ctx, event); err != nil {
		return fmt.Errorf("failed to record audit event: %w", err)
	}

	return nil
}

// RecordEventWithTx records an audit event using the supplied repository.Querier.
//
// Pass *sql.Tx (typically obtained from postgres.WithinTx) to participate in
// a caller's transaction so the audit row is atomic with the operation that
// triggered it. Closes the #3 acquisition-readiness blocker from the
// 2026-05-01 issuer coverage audit (audit row not transactional with the
// operation it audits).
//
// Same redaction + marshalling contract as RecordEvent; only the database
// handle changes.
func (s *AuditService) RecordEventWithTx(ctx context.Context, q repository.Querier, actor string, actorType domain.ActorType, action string, resourceType string, resourceID string, details map[string]interface{}) error {
	redacted := RedactDetailsForAudit(details)
	detailsJSON, err := json.Marshal(redacted)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	event := &domain.AuditEvent{
		ID:           generateID("audit"),
		Timestamp:    time.Now(),
		Actor:        actor,
		ActorType:    actorType,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      json.RawMessage(detailsJSON),
	}

	if err := s.auditRepo.CreateWithTx(ctx, q, event); err != nil {
		return fmt.Errorf("failed to record audit event: %w", err)
	}

	return nil
}

// RecordEventWithCategoryWithTx records a categorized audit event using
// the supplied repository.Querier so the row is committed in the same
// transaction as the underlying action. Mirrors RecordEventWithCategory
// but takes the Querier (typically *sql.Tx from postgres.WithinTx).
//
// Audit 2026-05-10 HIGH-6 closure — closes the gap where Bundle-1+2
// auth-mutation paths emitted the audit row via a separate, non-
// transactional connection. A DB hiccup or connection reset between
// the action and the audit-row INSERT used to leave the action
// committed with no audit trail (CWE-778). With this method, the
// audit row participates in the action's transaction: rollback on
// any failure removes both the action row AND any audit row that the
// caller wrote inside the tx.
func (s *AuditService) RecordEventWithCategoryWithTx(ctx context.Context, q repository.Querier, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, details map[string]interface{}) error {
	redacted := RedactDetailsForAudit(details)
	detailsJSON, err := json.Marshal(redacted)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	event := &domain.AuditEvent{
		ID:            generateID("audit"),
		Timestamp:     time.Now(),
		Actor:         actor,
		ActorType:     actorType,
		Action:        action,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		Details:       json.RawMessage(detailsJSON),
		EventCategory: eventCategory,
	}

	if err := s.auditRepo.CreateWithTx(ctx, q, event); err != nil {
		return fmt.Errorf("failed to record audit event: %w", err)
	}

	return nil
}

// List returns audit events matching filter criteria.
func (s *AuditService) List(ctx context.Context, filter *repository.AuditFilter) ([]*domain.AuditEvent, error) {
	events, err := s.auditRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit events: %w", err)
	}
	return events, nil
}

// ListByResource returns all audit events for a specific resource.
func (s *AuditService) ListByResource(ctx context.Context, resourceType string, resourceID string) ([]*domain.AuditEvent, error) {
	filter := &repository.AuditFilter{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		PerPage:      1000, // reasonable default for single resource
	}

	events, err := s.auditRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit events: %w", err)
	}
	return events, nil
}

// ListByActor returns all audit events for a specific actor.
func (s *AuditService) ListByActor(ctx context.Context, actor string) ([]*domain.AuditEvent, error) {
	filter := &repository.AuditFilter{
		Actor:   actor,
		PerPage: 1000,
	}

	events, err := s.auditRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit events: %w", err)
	}
	return events, nil
}

// ListByAction returns all audit events for a specific action type.
func (s *AuditService) ListByAction(ctx context.Context, action string, from, to time.Time) ([]*domain.AuditEvent, error) {
	filter := &repository.AuditFilter{
		From:    from,
		To:      to,
		PerPage: 1000,
	}

	events, err := s.auditRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit events: %w", err)
	}

	// Filter by action on client side (repository may not filter by action directly)
	var filtered []*domain.AuditEvent
	for _, e := range events {
		if e.Action == action {
			filtered = append(filtered, e)
		}
	}

	return filtered, nil
}

// ListAuditEvents returns paginated audit events (handler interface method).
func (s *AuditService) ListAuditEvents(ctx context.Context, page, perPage int) ([]domain.AuditEvent, int64, error) {
	return s.ListAuditEventsByCategory(ctx, "", page, perPage)
}

// ListAuditEventsByCategory is the Bundle 1 Phase 8 categorized variant.
// Empty eventCategory disables the filter.
func (s *AuditService) ListAuditEventsByCategory(ctx context.Context, eventCategory string, page, perPage int) ([]domain.AuditEvent, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	filter := &repository.AuditFilter{
		EventCategory: eventCategory,
		Page:          page,
		PerPage:       perPage,
	}

	events, err := s.auditRepo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit events: %w", err)
	}

	// Convert pointers to values for the handler interface
	var result []domain.AuditEvent
	for _, e := range events {
		if e != nil {
			result = append(result, *e)
		}
	}

	// TODO: Get total count from repository
	total := int64(len(result))

	return result, total, nil
}

// GetAuditEvent returns a single audit event (handler interface method).
func (s *AuditService) GetAuditEvent(ctx context.Context, id string) (*domain.AuditEvent, error) {
	filter := &repository.AuditFilter{
		ResourceID: id,
		PerPage:    1,
	}

	events, err := s.auditRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit event: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("audit event not found")
	}

	return events[0], nil
}
