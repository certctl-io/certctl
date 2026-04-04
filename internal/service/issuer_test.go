package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// TestIssuerService_List tests listing issuers with pagination
func TestIssuerService_List(t *testing.T) {
	ctx := context.Background()

	issuer1 := &domain.Issuer{
		ID:        "iss-1",
		Name:      "ACME Provider",
		Type:      domain.IssuerTypeACME,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	issuer2 := &domain.Issuer{
		ID:        "iss-2",
		Name:      "Step CA",
		Type:      domain.IssuerTypeStepCA,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	issuer3 := &domain.Issuer{
		ID:        "iss-3",
		Name:      "Internal CA",
		Type:      domain.IssuerTypeGenericCA,
		Enabled:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	repo := newMockIssuerRepository()
	repo.AddIssuer(issuer1)
	repo.AddIssuer(issuer2)
	repo.AddIssuer(issuer3)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), nil, slog.Default())

	issuers, total, err := service.List(ctx, 1, 2)

	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}

	if len(issuers) != 2 {
		t.Errorf("expected 2 issuers on page 1, got %d", len(issuers))
	}

	// Test page 2
	issuers2, _, err := service.List(ctx, 2, 2)

	if err != nil {
		t.Fatalf("List page 2 failed: %v", err)
	}

	if len(issuers2) != 1 {
		t.Errorf("expected 1 issuer on page 2, got %d", len(issuers2))
	}
}

// TestIssuerService_List_DefaultPagination tests list with default pagination values
func TestIssuerService_List_DefaultPagination(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	// Call with invalid page and perPage
	issuers, total, err := service.List(ctx, 0, 0)

	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}

	if len(issuers) != 0 {
		t.Errorf("expected 0 issuers, got %d", len(issuers))
	}
}

// TestIssuerService_List_RepositoryError tests list when repository returns error
func TestIssuerService_List_RepositoryError(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	repo.ListErr = errors.New("database connection failed")

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), nil, slog.Default())

	_, _, err := service.List(ctx, 1, 50)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, repo.ListErr) {
		t.Errorf("expected error %v, got %v", repo.ListErr, err)
	}
}

// TestIssuerService_List_EmptyResult tests list returning empty list
func TestIssuerService_List_EmptyResult(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	issuers, total, err := service.List(ctx, 1, 50)

	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}

	if len(issuers) != 0 {
		t.Errorf("expected 0 issuers, got %d", len(issuers))
	}
}

// TestIssuerService_Get tests retrieving an issuer by ID
func TestIssuerService_Get(t *testing.T) {
	ctx := context.Background()

	issuer := &domain.Issuer{
		ID:        "iss-acme-prod",
		Name:      "ACME Production",
		Type:      domain.IssuerTypeACME,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	repo := newMockIssuerRepository()
	repo.AddIssuer(issuer)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), nil, slog.Default())

	retrieved, err := service.Get(ctx, "iss-acme-prod")

	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.Name != "ACME Production" {
		t.Errorf("expected name ACME Production, got %s", retrieved.Name)
	}

	if retrieved.Type != domain.IssuerTypeACME {
		t.Errorf("expected type ACME, got %s", retrieved.Type)
	}
}

// TestIssuerService_Get_NotFound tests Get when issuer doesn't exist
func TestIssuerService_Get_NotFound(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	_, err := service.Get(ctx, "nonexistent-issuer")

	if err == nil {
		t.Fatal("expected error for nonexistent issuer")
	}
}

// TestIssuerService_Create tests creating a new issuer
func TestIssuerService_Create(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	config := map[string]interface{}{"endpoint": "https://acme.example.com/v2/new-account"}
	configJSON, _ := json.Marshal(config)

	issuer := &domain.Issuer{
		Name:    "Test ACME",
		Type:    domain.IssuerTypeACME,
		Config:  configJSON,
		Enabled: true,
	}

	err := service.Create(ctx, issuer, "user-alice")

	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if issuer.ID == "" {
		t.Error("expected ID to be generated")
	}

	if issuer.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}

	if issuer.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}

	// Verify stored in repo
	retrieved, err := repo.Get(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("failed to retrieve created issuer: %v", err)
	}

	if retrieved.Name != "Test ACME" {
		t.Errorf("expected name Test ACME, got %s", retrieved.Name)
	}

	// Verify audit event recorded
	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	if auditRepo.Events[0].Action != "create_issuer" {
		t.Errorf("expected action create_issuer, got %s", auditRepo.Events[0].Action)
	}

	if auditRepo.Events[0].Actor != "user-alice" {
		t.Errorf("expected actor user-alice, got %s", auditRepo.Events[0].Actor)
	}
}

// TestIssuerService_Create_EmptyName tests Create with empty name validation
func TestIssuerService_Create_EmptyName(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	issuer := &domain.Issuer{
		Name:    "",
		Type:    domain.IssuerTypeACME,
		Enabled: true,
	}

	err := service.Create(ctx, issuer, "user-bob")

	if err == nil {
		t.Fatal("expected error for empty name")
	}

	if err.Error() != "issuer name is required" {
		t.Errorf("expected 'issuer name is required', got '%v'", err)
	}

	// Verify no audit event recorded on validation error
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected 0 audit events on validation error, got %d", len(auditRepo.Events))
	}
}

// TestIssuerService_Create_RepositoryError tests Create when repository fails
func TestIssuerService_Create_RepositoryError(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	repo.CreateErr = errors.New("database error")

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), nil, slog.Default())

	issuer := &domain.Issuer{
		Name:    "Test Issuer",
		Type:    domain.IssuerTypeACME,
		Enabled: true,
	}

	err := service.Create(ctx, issuer, "user-charlie")

	if err == nil {
		t.Fatal("expected error from repository")
	}

	if !errors.Is(err, repo.CreateErr) {
		t.Errorf("expected error %v, got %v", repo.CreateErr, err)
	}
}

// TestIssuerService_Update tests updating an existing issuer
func TestIssuerService_Update(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	config := map[string]interface{}{"endpoint": "https://acme.example.com"}
	configJSON, _ := json.Marshal(config)

	issuer := &domain.Issuer{
		Name:    "Updated ACME",
		Type:    domain.IssuerTypeACME,
		Config:  configJSON,
		Enabled: false,
	}

	err := service.Update(ctx, "iss-acme-001", issuer, "user-dave")

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if issuer.ID != "iss-acme-001" {
		t.Errorf("expected ID to be set to iss-acme-001, got %s", issuer.ID)
	}

	// Verify audit event recorded
	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	if auditRepo.Events[0].Action != "update_issuer" {
		t.Errorf("expected action update_issuer, got %s", auditRepo.Events[0].Action)
	}

	if auditRepo.Events[0].ResourceID != "iss-acme-001" {
		t.Errorf("expected ResourceID iss-acme-001, got %s", auditRepo.Events[0].ResourceID)
	}
}

// TestIssuerService_Update_EmptyName tests Update with empty name validation
func TestIssuerService_Update_EmptyName(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	issuer := &domain.Issuer{
		Name:    "",
		Type:    domain.IssuerTypeACME,
		Enabled: true,
	}

	err := service.Update(ctx, "iss-acme-001", issuer, "user-eve")

	if err == nil {
		t.Fatal("expected error for empty name")
	}

	if err.Error() != "issuer name is required" {
		t.Errorf("expected 'issuer name is required', got '%v'", err)
	}
}

// TestIssuerService_Delete tests deleting an issuer
func TestIssuerService_Delete(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	err := service.Delete(ctx, "iss-to-delete", "user-frank")

	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify audit event recorded
	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	if auditRepo.Events[0].Action != "delete_issuer" {
		t.Errorf("expected action delete_issuer, got %s", auditRepo.Events[0].Action)
	}

	if auditRepo.Events[0].ResourceID != "iss-to-delete" {
		t.Errorf("expected ResourceID iss-to-delete, got %s", auditRepo.Events[0].ResourceID)
	}
}

// TestIssuerService_Delete_RepositoryError tests Delete when repository fails
func TestIssuerService_Delete_RepositoryError(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	repo.DeleteErr = errors.New("delete failed")

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), nil, slog.Default())

	err := service.Delete(ctx, "iss-bad-id", "user-grace")

	if err == nil {
		t.Fatal("expected error from repository")
	}

	if !errors.Is(err, repo.DeleteErr) {
		t.Errorf("expected error %v, got %v", repo.DeleteErr, err)
	}
}

// TestIssuerService_TestConnection_Success tests successful connection test
func TestIssuerService_TestConnection_Success(t *testing.T) {
	ctx := context.Background()

	// Use GenericCA (Local CA) type because it has no required config fields,
	// so ValidateConfig succeeds with empty config.
	iss := &domain.Issuer{
		ID:        "iss-test-conn",
		Name:      "Test Connection",
		Type:      domain.IssuerTypeGenericCA,
		Config:    json.RawMessage(`{"validity_days":365}`),
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	repo := newMockIssuerRepository()
	repo.AddIssuer(iss)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	svc := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), nil, slog.Default())

	err := svc.TestConnectionWithContext(ctx, "iss-test-conn")

	if err != nil {
		t.Fatalf("TestConnectionWithContext failed: %v", err)
	}
}

// TestIssuerService_TestConnection_NotFound tests connection test when issuer not found
func TestIssuerService_TestConnection_NotFound(t *testing.T) {
	ctx := context.Background()

	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	err := service.TestConnectionWithContext(ctx, "nonexistent-issuer")

	if err == nil {
		t.Fatal("expected error for nonexistent issuer")
	}

	if !errors.Is(err, errNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

// TestIssuerService_ListIssuers_HandlerInterface tests handler interface method
func TestIssuerService_ListIssuers_HandlerInterface(t *testing.T) {
	issuer1 := &domain.Issuer{
		ID:        "iss-handler-1",
		Name:      "Handler Test 1",
		Type:      domain.IssuerTypeACME,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	issuer2 := &domain.Issuer{
		ID:        "iss-handler-2",
		Name:      "Handler Test 2",
		Type:      domain.IssuerTypeStepCA,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	repo := newMockIssuerRepository()
	repo.AddIssuer(issuer1)
	repo.AddIssuer(issuer2)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	service := NewIssuerService(repo, auditService, NewIssuerRegistry(slog.Default()), nil, slog.Default())

	issuers, total, err := service.ListIssuers(1, 50)

	if err != nil {
		t.Fatalf("ListIssuers failed: %v", err)
	}

	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}

	if len(issuers) != 2 {
		t.Errorf("expected 2 issuers, got %d", len(issuers))
	}

	if issuers[0].Name != "Handler Test 1" && issuers[1].Name != "Handler Test 1" {
		t.Error("expected to find Handler Test 1 in results")
	}
}

// TestIssuerService_CreateIssuer_HandlerInterface tests handler interface create method
func TestIssuerService_CreateIssuer_HandlerInterface(t *testing.T) {
	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	config := map[string]interface{}{"url": "https://example.com"}
	configJSON, _ := json.Marshal(config)

	issuer := domain.Issuer{
		Name:    "Handler Create Test",
		Type:    domain.IssuerTypeGenericCA,
		Config:  configJSON,
		Enabled: true,
	}

	result, err := service.CreateIssuer(issuer)

	if err != nil {
		t.Fatalf("CreateIssuer failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.ID == "" {
		t.Error("expected ID to be generated")
	}

	if result.Name != "Handler Create Test" {
		t.Errorf("expected name Handler Create Test, got %s", result.Name)
	}
}

// TestIssuerService_DeleteIssuer_HandlerInterface tests handler interface delete method
func TestIssuerService_DeleteIssuer_HandlerInterface(t *testing.T) {
	repo := newMockIssuerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	registry := NewIssuerRegistry(slog.Default())
	service := NewIssuerService(repo, auditService, registry, nil, slog.Default())

	err := service.DeleteIssuer("iss-handler-delete")

	if err != nil {
		t.Fatalf("DeleteIssuer failed: %v", err)
	}
}
