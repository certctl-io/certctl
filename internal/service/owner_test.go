package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// mockOwnerRepo is a test implementation of OwnerRepository
type mockOwnerRepo struct {
	owners    map[string]*domain.Owner
	CreateErr error
	UpdateErr error
	DeleteErr error
	GetErr    error
	ListErr   error
}

func (m *mockOwnerRepo) List(ctx context.Context) ([]*domain.Owner, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var owners []*domain.Owner
	for _, o := range m.owners {
		owners = append(owners, o)
	}
	return owners, nil
}

func (m *mockOwnerRepo) Get(ctx context.Context, id string) (*domain.Owner, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	owner, ok := m.owners[id]
	if !ok {
		return nil, errNotFound
	}
	return owner, nil
}

func (m *mockOwnerRepo) Create(ctx context.Context, owner *domain.Owner) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.owners[owner.ID] = owner
	return nil
}

func (m *mockOwnerRepo) Update(ctx context.Context, owner *domain.Owner) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.owners[owner.ID] = owner
	return nil
}

func (m *mockOwnerRepo) Delete(ctx context.Context, id string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.owners, id)
	return nil
}

func (m *mockOwnerRepo) AddOwner(owner *domain.Owner) {
	m.owners[owner.ID] = owner
}

func newMockOwnerRepository() *mockOwnerRepo {
	return &mockOwnerRepo{
		owners: make(map[string]*domain.Owner),
	}
}

// TestOwnerService_List tests paginated listing of owners.
func TestOwnerService_List(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	owner1 := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}
	owner2 := &domain.Owner{
		ID:        "owner-002",
		Name:      "Bob Jones",
		Email:     "bob@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner1)
	ownerRepo.AddOwner(owner2)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owners, total, err := ownerService.List(ctx, 1, 50)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(owners) != 2 {
		t.Errorf("expected 2 owners, got %d", len(owners))
	}

	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
}

// TestOwnerService_List_DefaultPagination tests that default pagination values are applied.
func TestOwnerService_List_DefaultPagination(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	owner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	// Test with page < 1 (should default to 1)
	owners, total, err := ownerService.List(ctx, 0, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(owners) != 1 {
		t.Errorf("expected 1 owner with default pagination, got %d", len(owners))
	}

	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
}

// TestOwnerService_List_RepositoryError tests handling of repository errors.
func TestOwnerService_List_RepositoryError(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	ownerRepo.ListErr = errors.New("database error")

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	_, _, err := ownerService.List(ctx, 1, 50)
	if err == nil {
		t.Fatal("expected error from List, got nil")
	}
}

// TestOwnerService_List_EmptyResult tests listing with no owners.
func TestOwnerService_List_EmptyResult(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owners, total, err := ownerService.List(ctx, 1, 50)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(owners) != 0 {
		t.Errorf("expected 0 owners, got %d", len(owners))
	}

	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
}

// TestOwnerService_List_PageBeyondRange tests pagination when page exceeds available data.
func TestOwnerService_List_PageBeyondRange(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	owner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	// Request page 3 with only 1 owner
	owners, total, err := ownerService.List(ctx, 3, 1)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(owners) != 0 {
		t.Errorf("expected 0 owners on page beyond range, got %d", len(owners))
	}

	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
}

// TestOwnerService_Get tests retrieving a single owner by ID.
func TestOwnerService_Get(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	owner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	retrieved, err := ownerService.Get(ctx, "owner-001")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.Name != "Alice Smith" {
		t.Errorf("expected name Alice Smith, got %s", retrieved.Name)
	}

	if retrieved.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", retrieved.Email)
	}
}

// TestOwnerService_Get_NotFound tests Get with a nonexistent owner.
func TestOwnerService_Get_NotFound(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	_, err := ownerService.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent owner, got nil")
	}
}

// TestOwnerService_Create tests creating a new owner with audit recording.
func TestOwnerService_Create(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owner := &domain.Owner{
		Name:   "Alice Smith",
		Email:  "alice@example.com",
		TeamID: "team-001",
	}

	err := ownerService.Create(ctx, owner, "user-1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if owner.ID == "" {
		t.Fatal("expected non-empty owner ID after creation")
	}

	if !owner.CreatedAt.IsZero() && owner.CreatedAt.After(time.Now().Add(-time.Second)) {
		// CreatedAt should have been set
	} else if owner.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	if len(ownerRepo.owners) != 1 {
		t.Errorf("expected 1 owner in repo, got %d", len(ownerRepo.owners))
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	auditEvent := auditRepo.Events[0]
	if auditEvent.Action != "create_owner" {
		t.Errorf("expected action create_owner, got %s", auditEvent.Action)
	}

	if auditEvent.ResourceType != "owner" {
		t.Errorf("expected resource type owner, got %s", auditEvent.ResourceType)
	}
}

// TestOwnerService_Create_EmptyName tests that Create rejects empty name.
func TestOwnerService_Create_EmptyName(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owner := &domain.Owner{
		Name:   "",
		Email:  "alice@example.com",
		TeamID: "team-001",
	}

	err := ownerService.Create(ctx, owner, "user-1")
	if err == nil {
		t.Fatal("expected error for empty owner name")
	}

	if len(ownerRepo.owners) != 0 {
		t.Errorf("expected 0 owners in repo after validation failure, got %d", len(ownerRepo.owners))
	}

	if len(auditRepo.Events) != 0 {
		t.Errorf("expected 0 audit events after validation failure, got %d", len(auditRepo.Events))
	}
}

// TestOwnerService_Create_WithExistingID tests that Create preserves existing ID.
func TestOwnerService_Create_WithExistingID(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owner := &domain.Owner{
		ID:     "custom-id-123",
		Name:   "Alice Smith",
		Email:  "alice@example.com",
		TeamID: "team-001",
	}

	err := ownerService.Create(ctx, owner, "user-1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if owner.ID != "custom-id-123" {
		t.Errorf("expected ID custom-id-123, got %s", owner.ID)
	}

	stored, ok := ownerRepo.owners["custom-id-123"]
	if !ok {
		t.Fatal("expected owner with custom ID in repo")
	}

	if stored.Name != "Alice Smith" {
		t.Errorf("expected name Alice Smith, got %s", stored.Name)
	}
}

// TestOwnerService_Create_RepositoryError tests Create with repository failure.
func TestOwnerService_Create_RepositoryError(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	ownerRepo.CreateErr = errors.New("database error")

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owner := &domain.Owner{
		Name:   "Alice Smith",
		Email:  "alice@example.com",
		TeamID: "team-001",
	}

	err := ownerService.Create(ctx, owner, "user-1")
	if err == nil {
		t.Fatal("expected error from Create")
	}
}

// TestOwnerService_Update tests updating an existing owner.
func TestOwnerService_Update(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	originalOwner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(originalOwner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	updatedOwner := &domain.Owner{
		Name:   "Alice Johnson",
		Email:  "alice.j@example.com",
		TeamID: "team-002",
	}

	err := ownerService.Update(ctx, "owner-001", updatedOwner, "user-1")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	stored := ownerRepo.owners["owner-001"]
	if stored.Name != "Alice Johnson" {
		t.Errorf("expected updated name Alice Johnson, got %s", stored.Name)
	}

	if stored.Email != "alice.j@example.com" {
		t.Errorf("expected updated email alice.j@example.com, got %s", stored.Email)
	}

	if stored.ID != "owner-001" {
		t.Errorf("expected ID to remain owner-001, got %s", stored.ID)
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	auditEvent := auditRepo.Events[0]
	if auditEvent.Action != "update_owner" {
		t.Errorf("expected action update_owner, got %s", auditEvent.Action)
	}
}

// TestOwnerService_Update_EmptyName tests that Update rejects empty name.
func TestOwnerService_Update_EmptyName(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	originalOwner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(originalOwner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	updatedOwner := &domain.Owner{
		Name:   "",
		Email:  "alice.j@example.com",
		TeamID: "team-002",
	}

	err := ownerService.Update(ctx, "owner-001", updatedOwner, "user-1")
	if err == nil {
		t.Fatal("expected error for empty owner name")
	}

	if len(auditRepo.Events) != 0 {
		t.Errorf("expected 0 audit events after validation failure, got %d", len(auditRepo.Events))
	}
}

// TestOwnerService_Update_RepositoryError tests Update with repository failure.
func TestOwnerService_Update_RepositoryError(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	ownerRepo.UpdateErr = errors.New("database error")

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	updatedOwner := &domain.Owner{
		Name:   "Alice Johnson",
		Email:  "alice.j@example.com",
		TeamID: "team-002",
	}

	err := ownerService.Update(ctx, "owner-001", updatedOwner, "user-1")
	if err == nil {
		t.Fatal("expected error from Update")
	}
}

// TestOwnerService_Delete tests deleting an owner with audit recording.
func TestOwnerService_Delete(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	owner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	err := ownerService.Delete(ctx, "owner-001", "user-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if len(ownerRepo.owners) != 0 {
		t.Errorf("expected 0 owners in repo after delete, got %d", len(ownerRepo.owners))
	}

	if len(auditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(auditRepo.Events))
	}

	auditEvent := auditRepo.Events[0]
	if auditEvent.Action != "delete_owner" {
		t.Errorf("expected action delete_owner, got %s", auditEvent.Action)
	}

	if auditEvent.ResourceID != "owner-001" {
		t.Errorf("expected resource ID owner-001, got %s", auditEvent.ResourceID)
	}
}

// TestOwnerService_Delete_RepositoryError tests Delete with repository failure.
func TestOwnerService_Delete_RepositoryError(t *testing.T) {
	ctx := context.Background()

	ownerRepo := newMockOwnerRepository()
	ownerRepo.DeleteErr = errors.New("database error")

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	err := ownerService.Delete(ctx, "owner-001", "user-1")
	if err == nil {
		t.Fatal("expected error from Delete")
	}
}

// TestOwnerService_ListOwners_HandlerInterface tests the handler interface method ListOwners.
func TestOwnerService_ListOwners_HandlerInterface(t *testing.T) {
	now := time.Now()

	owner1 := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}
	owner2 := &domain.Owner{
		ID:        "owner-002",
		Name:      "Bob Jones",
		Email:     "bob@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner1)
	ownerRepo.AddOwner(owner2)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owners, total, err := ownerService.ListOwners(1, 50)
	if err != nil {
		t.Fatalf("ListOwners failed: %v", err)
	}

	if len(owners) != 2 {
		t.Errorf("expected 2 owners, got %d", len(owners))
	}

	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}

	// Verify value type conversion worked
	if owners[0].ID == "" {
		t.Fatal("expected non-empty owner ID in result")
	}
}

// TestOwnerService_GetOwner_HandlerInterface tests the handler interface method GetOwner.
func TestOwnerService_GetOwner_HandlerInterface(t *testing.T) {
	now := time.Now()

	owner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	retrieved, err := ownerService.GetOwner("owner-001")
	if err != nil {
		t.Fatalf("GetOwner failed: %v", err)
	}

	if retrieved.Name != "Alice Smith" {
		t.Errorf("expected name Alice Smith, got %s", retrieved.Name)
	}
}

// TestOwnerService_CreateOwner_HandlerInterface tests the handler interface method CreateOwner.
func TestOwnerService_CreateOwner_HandlerInterface(t *testing.T) {
	ownerRepo := newMockOwnerRepository()
	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	owner := domain.Owner{
		Name:   "Alice Smith",
		Email:  "alice@example.com",
		TeamID: "team-001",
	}

	created, err := ownerService.CreateOwner(owner)
	if err != nil {
		t.Fatalf("CreateOwner failed: %v", err)
	}

	if created.ID == "" {
		t.Fatal("expected non-empty owner ID after creation")
	}

	if created.Name != "Alice Smith" {
		t.Errorf("expected name Alice Smith, got %s", created.Name)
	}

	if len(ownerRepo.owners) != 1 {
		t.Errorf("expected 1 owner in repo, got %d", len(ownerRepo.owners))
	}

	// Note: handler interface method does NOT record audit events (no actor parameter)
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected 0 audit events from handler interface method, got %d", len(auditRepo.Events))
	}
}

// TestOwnerService_UpdateOwner_HandlerInterface tests the handler interface method UpdateOwner.
func TestOwnerService_UpdateOwner_HandlerInterface(t *testing.T) {
	now := time.Now()

	originalOwner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(originalOwner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	updatedOwner := domain.Owner{
		Name:   "Alice Johnson",
		Email:  "alice.j@example.com",
		TeamID: "team-002",
	}

	updated, err := ownerService.UpdateOwner("owner-001", updatedOwner)
	if err != nil {
		t.Fatalf("UpdateOwner failed: %v", err)
	}

	if updated.ID != "owner-001" {
		t.Errorf("expected ID owner-001, got %s", updated.ID)
	}

	if updated.Name != "Alice Johnson" {
		t.Errorf("expected updated name Alice Johnson, got %s", updated.Name)
	}

	// Verify in repo
	stored := ownerRepo.owners["owner-001"]
	if stored.Email != "alice.j@example.com" {
		t.Errorf("expected updated email alice.j@example.com, got %s", stored.Email)
	}

	// Note: handler interface method does NOT record audit events
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected 0 audit events from handler interface method, got %d", len(auditRepo.Events))
	}
}

// TestOwnerService_DeleteOwner_HandlerInterface tests the handler interface method DeleteOwner.
func TestOwnerService_DeleteOwner_HandlerInterface(t *testing.T) {
	now := time.Now()

	owner := &domain.Owner{
		ID:        "owner-001",
		Name:      "Alice Smith",
		Email:     "alice@example.com",
		TeamID:    "team-001",
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerRepo := newMockOwnerRepository()
	ownerRepo.AddOwner(owner)

	auditRepo := newMockAuditRepository()
	auditService := NewAuditService(auditRepo)

	ownerService := NewOwnerService(ownerRepo, auditService)

	err := ownerService.DeleteOwner("owner-001")
	if err != nil {
		t.Fatalf("DeleteOwner failed: %v", err)
	}

	if len(ownerRepo.owners) != 0 {
		t.Errorf("expected 0 owners in repo after delete, got %d", len(ownerRepo.owners))
	}

	// Note: handler interface method does NOT record audit events
	if len(auditRepo.Events) != 0 {
		t.Errorf("expected 0 audit events from handler interface method, got %d", len(auditRepo.Events))
	}
}
