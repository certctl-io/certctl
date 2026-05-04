package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

func TestRecordEvent(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	service := NewAuditService(auditRepo)

	err := service.RecordEvent(ctx, "user123", domain.ActorTypeUser, "certificate_created", "certificate", "cert-001", map[string]interface{}{"common_name": "example.com"})
	if err != nil {
		t.Fatalf("RecordEvent failed: %v", err)
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(auditRepo.Events))
	}

	event := auditRepo.Events[0]
	if event.Actor != "user123" {
		t.Errorf("expected actor user123, got %s", event.Actor)
	}
	if event.ActorType != domain.ActorTypeUser {
		t.Errorf("expected actor type User, got %s", event.ActorType)
	}
	if event.Action != "certificate_created" {
		t.Errorf("expected action certificate_created, got %s", event.Action)
	}
	if event.ResourceType != "certificate" {
		t.Errorf("expected resource type certificate, got %s", event.ResourceType)
	}
	if event.ResourceID != "cert-001" {
		t.Errorf("expected resource ID cert-001, got %s", event.ResourceID)
	}
}

func TestRecordEvent_RepoError(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events:    []*domain.AuditEvent{},
		CreateErr: errNotFound,
	}
	service := NewAuditService(auditRepo)

	err := service.RecordEvent(ctx, "user123", domain.ActorTypeUser, "test_action", "resource", "res-001", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListByResource(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	service := NewAuditService(auditRepo)

	event1 := &domain.AuditEvent{
		ID:           "audit-1",
		Actor:        "user1",
		ActorType:    domain.ActorTypeUser,
		Action:       "created",
		ResourceType: "certificate",
		ResourceID:   "cert-001",
		Timestamp:    time.Now(),
	}
	event2 := &domain.AuditEvent{
		ID:           "audit-2",
		Actor:        "user2",
		ActorType:    domain.ActorTypeUser,
		Action:       "updated",
		ResourceType: "certificate",
		ResourceID:   "cert-001",
		Timestamp:    time.Now(),
	}
	event3 := &domain.AuditEvent{
		ID:           "audit-3",
		Actor:        "user1",
		ActorType:    domain.ActorTypeUser,
		Action:       "created",
		ResourceType: "certificate",
		ResourceID:   "cert-002",
		Timestamp:    time.Now(),
	}

	auditRepo.AddEvent(event1)
	auditRepo.AddEvent(event2)
	auditRepo.AddEvent(event3)

	events, err := service.ListByResource(ctx, "certificate", "cert-001")
	if err != nil {
		t.Fatalf("ListByResource failed: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestListByActor(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	service := NewAuditService(auditRepo)

	event1 := &domain.AuditEvent{
		ID:           "audit-1",
		Actor:        "user1",
		ActorType:    domain.ActorTypeUser,
		Action:       "created",
		ResourceType: "certificate",
		ResourceID:   "cert-001",
		Timestamp:    time.Now(),
	}
	event2 := &domain.AuditEvent{
		ID:           "audit-2",
		Actor:        "user1",
		ActorType:    domain.ActorTypeUser,
		Action:       "updated",
		ResourceType: "certificate",
		ResourceID:   "cert-002",
		Timestamp:    time.Now(),
	}
	event3 := &domain.AuditEvent{
		ID:           "audit-3",
		Actor:        "user2",
		ActorType:    domain.ActorTypeUser,
		Action:       "created",
		ResourceType: "certificate",
		ResourceID:   "cert-003",
		Timestamp:    time.Now(),
	}

	auditRepo.AddEvent(event1)
	auditRepo.AddEvent(event2)
	auditRepo.AddEvent(event3)

	events, err := service.ListByActor(ctx, "user1")
	if err != nil {
		t.Fatalf("ListByActor failed: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestListByAction(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	service := NewAuditService(auditRepo)

	now := time.Now()
	from := now.Add(-1 * time.Hour)
	to := now.Add(1 * time.Hour)

	event1 := &domain.AuditEvent{
		ID:           "audit-1",
		Actor:        "user1",
		ActorType:    domain.ActorTypeUser,
		Action:       "certificate_created",
		ResourceType: "certificate",
		ResourceID:   "cert-001",
		Timestamp:    now.Add(-30 * time.Minute),
	}
	event2 := &domain.AuditEvent{
		ID:           "audit-2",
		Actor:        "user2",
		ActorType:    domain.ActorTypeUser,
		Action:       "certificate_created",
		ResourceType: "certificate",
		ResourceID:   "cert-002",
		Timestamp:    now.Add(-20 * time.Minute),
	}
	event3 := &domain.AuditEvent{
		ID:           "audit-3",
		Actor:        "user1",
		ActorType:    domain.ActorTypeUser,
		Action:       "certificate_updated",
		ResourceType: "certificate",
		ResourceID:   "cert-001",
		Timestamp:    now.Add(-10 * time.Minute),
	}

	auditRepo.AddEvent(event1)
	auditRepo.AddEvent(event2)
	auditRepo.AddEvent(event3)

	events, err := service.ListByAction(ctx, "certificate_created", from, to)
	if err != nil {
		t.Fatalf("ListByAction failed: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}

	for _, e := range events {
		if e.Action != "certificate_created" {
			t.Errorf("expected action certificate_created, got %s", e.Action)
		}
	}
}

func TestListByAction_EmptyRange(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	service := NewAuditService(auditRepo)

	now := time.Now()
	from := now.Add(1 * time.Hour)
	to := now.Add(2 * time.Hour)

	event := &domain.AuditEvent{
		ID:           "audit-1",
		Actor:        "user1",
		ActorType:    domain.ActorTypeUser,
		Action:       "certificate_created",
		ResourceType: "certificate",
		ResourceID:   "cert-001",
		Timestamp:    now.Add(-30 * time.Minute),
	}
	auditRepo.AddEvent(event)

	events, err := service.ListByAction(ctx, "certificate_created", from, to)
	if err != nil {
		t.Fatalf("ListByAction failed: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestRecordEvent_ComplexDetails(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	service := NewAuditService(auditRepo)

	details := map[string]interface{}{
		"common_name": "example.com",
		"sans":        []string{"www.example.com", "api.example.com"},
		"issuer_id":   "iss-123",
		"count":       5,
	}

	err := service.RecordEvent(ctx, "user1", domain.ActorTypeUser, "certificate_created", "certificate", "cert-001", details)
	if err != nil {
		t.Fatalf("RecordEvent failed: %v", err)
	}

	event := auditRepo.Events[0]
	var decoded map[string]interface{}
	err = json.Unmarshal(event.Details, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal details: %v", err)
	}

	if decoded["common_name"] != "example.com" {
		t.Errorf("expected common_name example.com, got %v", decoded["common_name"])
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		Events: []*domain.AuditEvent{},
	}
	service := NewAuditService(auditRepo)

	for i := 0; i < 5; i++ {
		event := &domain.AuditEvent{
			ID:           "audit-" + string(rune(i)),
			Actor:        "user1",
			ActorType:    domain.ActorTypeUser,
			Action:       "test",
			ResourceType: "certificate",
			ResourceID:   "cert-001",
			Timestamp:    time.Now(),
		}
		auditRepo.AddEvent(event)
	}

	filter := &repository.AuditFilter{
		Page:    1,
		PerPage: 10,
	}

	events, err := service.List(ctx, filter)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestList_RepoError(t *testing.T) {
	ctx := context.Background()
	auditRepo := &mockAuditRepo{
		ListErr: errNotFound,
	}
	service := NewAuditService(auditRepo)

	filter := &repository.AuditFilter{}

	_, err := service.List(ctx, filter)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
