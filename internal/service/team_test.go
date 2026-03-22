package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// mockTeamRepo is a test implementation of TeamRepository
type mockTeamRepo struct {
	teams     map[string]*domain.Team
	CreateErr error
	UpdateErr error
	DeleteErr error
	GetErr    error
	ListErr   error
}

func (m *mockTeamRepo) List(ctx context.Context) ([]*domain.Team, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	var teams []*domain.Team
	for _, t := range m.teams {
		teams = append(teams, t)
	}
	return teams, nil
}

func (m *mockTeamRepo) Get(ctx context.Context, id string) (*domain.Team, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	team, ok := m.teams[id]
	if !ok {
		return nil, errNotFound
	}
	return team, nil
}

func (m *mockTeamRepo) Create(ctx context.Context, team *domain.Team) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.teams[team.ID] = team
	return nil
}

func (m *mockTeamRepo) Update(ctx context.Context, team *domain.Team) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.teams[team.ID] = team
	return nil
}

func (m *mockTeamRepo) Delete(ctx context.Context, id string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.teams, id)
	return nil
}

func (m *mockTeamRepo) AddTeam(team *domain.Team) {
	m.teams[team.ID] = team
}

func newMockTeamRepository() *mockTeamRepo {
	return &mockTeamRepo{
		teams: make(map[string]*domain.Team),
	}
}

// TestTeamService_List tests retrieving teams with pagination
func TestTeamService_List(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Add test teams
	for i := 0; i < 5; i++ {
		mockTeamRepo.AddTeam(&domain.Team{
			ID:   "team-" + string(rune(i)),
			Name: "Team " + string(rune(48+i)),
		})
	}

	teams, total, err := teamService.List(ctx, 1, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}

	if len(teams) != 2 {
		t.Errorf("expected 2 teams on page 1, got %d", len(teams))
	}
}

// TestTeamService_List_DefaultPagination tests default pagination values
func TestTeamService_List_DefaultPagination(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Add test teams
	for i := 0; i < 10; i++ {
		mockTeamRepo.AddTeam(&domain.Team{
			ID:   "team-" + string(rune(i)),
			Name: "Team " + string(rune(48+i)),
		})
	}

	// Test page < 1 defaults to 1
	teams, total, err := teamService.List(ctx, 0, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if total != 10 {
		t.Errorf("expected total 10, got %d", total)
	}

	if len(teams) != 5 {
		t.Errorf("expected 5 teams, got %d", len(teams))
	}

	// Test perPage < 1 defaults to 50
	teams, total, err = teamService.List(ctx, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(teams) != 10 {
		t.Errorf("expected 10 teams with perPage=50, got %d", len(teams))
	}
}

// TestTeamService_List_RepositoryError tests error handling from repo
func TestTeamService_List_RepositoryError(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	mockTeamRepo.ListErr = errors.New("database error")

	_, _, err := teamService.List(ctx, 1, 50)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !errors.Is(err, errors.New("database error")) {
		t.Errorf("expected database error, got %v", err)
	}
}

// TestTeamService_List_EmptyResult tests empty list response
func TestTeamService_List_EmptyResult(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	teams, total, err := teamService.List(ctx, 1, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}

	if len(teams) != 0 {
		t.Errorf("expected empty slice, got %d teams", len(teams))
	}
}

// TestTeamService_List_PageBeyondRange tests pagination beyond available data
func TestTeamService_List_PageBeyondRange(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Add only 3 teams
	for i := 0; i < 3; i++ {
		mockTeamRepo.AddTeam(&domain.Team{
			ID:   "team-" + string(rune(i)),
			Name: "Team " + string(rune(48+i)),
		})
	}

	// Request page beyond range
	teams, total, err := teamService.List(ctx, 10, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}

	if teams != nil && len(teams) != 0 {
		t.Errorf("expected empty slice for page beyond range, got %d teams", len(teams))
	}
}

// TestTeamService_Get tests retrieving a single team
func TestTeamService_Get(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	testTeam := &domain.Team{
		ID:   "team-1",
		Name: "Test Team",
	}
	mockTeamRepo.AddTeam(testTeam)

	team, err := teamService.Get(ctx, "team-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if team.ID != "team-1" || team.Name != "Test Team" {
		t.Errorf("expected team-1/Test Team, got %s/%s", team.ID, team.Name)
	}
}

// TestTeamService_Get_NotFound tests retrieval of nonexistent team
func TestTeamService_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	_, err := teamService.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatalf("expected error for nonexistent team, got nil")
	}
}

// TestTeamService_Create tests creating a new team
func TestTeamService_Create(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	team := &domain.Team{
		Name:        "New Team",
		Description: "A test team",
	}

	err := teamService.Create(ctx, team, "test-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ID was generated
	if team.ID == "" {
		t.Errorf("expected ID to be generated, got empty")
	}

	if !team.ID[:5] == "team-" {
		t.Logf("note: generated ID is %s", team.ID)
	}

	// Verify timestamps were set
	if team.CreatedAt.IsZero() {
		t.Errorf("expected CreatedAt to be set")
	}

	if team.UpdatedAt.IsZero() {
		t.Errorf("expected UpdatedAt to be set")
	}

	// Verify team was stored
	stored, err := teamService.Get(ctx, team.ID)
	if err != nil {
		t.Fatalf("failed to retrieve created team: %v", err)
	}

	if stored.Name != "New Team" {
		t.Errorf("expected name 'New Team', got %s", stored.Name)
	}
}

// TestTeamService_Create_EmptyName tests validation on empty name
func TestTeamService_Create_EmptyName(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	team := &domain.Team{
		Name: "",
	}

	err := teamService.Create(ctx, team, "test-user")
	if err == nil {
		t.Fatalf("expected validation error for empty name, got nil")
	}

	if !errors.Is(err, errors.New("team name is required")) {
		t.Logf("error: %v", err)
	}
}

// TestTeamService_Create_WithExistingID tests preserving provided ID
func TestTeamService_Create_WithExistingID(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	team := &domain.Team{
		ID:   "custom-team-id",
		Name: "Custom Team",
	}

	err := teamService.Create(ctx, team, "test-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if team.ID != "custom-team-id" {
		t.Errorf("expected ID to be preserved as custom-team-id, got %s", team.ID)
	}
}

// TestTeamService_Create_RepositoryError tests repo error handling
func TestTeamService_Create_RepositoryError(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	mockTeamRepo.CreateErr = errors.New("database insert failed")

	team := &domain.Team{
		Name: "Test Team",
	}

	err := teamService.Create(ctx, team, "test-user")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// TestTeamService_Create_AuditRecorded tests audit event recording
func TestTeamService_Create_AuditRecorded(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	team := &domain.Team{
		ID:   "audit-test-team",
		Name: "Audit Test Team",
	}

	err := teamService.Create(ctx, team, "audit-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify audit event was recorded
	if len(mockAuditRepo.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(mockAuditRepo.Events))
	}

	if mockAuditRepo.Events[0].Action != "create_team" {
		t.Errorf("expected action 'create_team', got %s", mockAuditRepo.Events[0].Action)
	}

	if mockAuditRepo.Events[0].ResourceID != "audit-test-team" {
		t.Errorf("expected resource ID 'audit-test-team', got %s", mockAuditRepo.Events[0].ResourceID)
	}
}

// TestTeamService_Update tests updating an existing team
func TestTeamService_Update(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Create initial team
	initialTeam := &domain.Team{
		ID:          "team-update",
		Name:        "Original Name",
		Description: "Original description",
	}
	mockTeamRepo.AddTeam(initialTeam)

	// Update team
	updateTeam := &domain.Team{
		Name:        "Updated Name",
		Description: "Updated description",
	}

	err := teamService.Update(ctx, "team-update", updateTeam, "update-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ID was set correctly
	if updateTeam.ID != "team-update" {
		t.Errorf("expected ID to be set to team-update, got %s", updateTeam.ID)
	}

	// Verify team was updated
	updated, err := teamService.Get(ctx, "team-update")
	if err != nil {
		t.Fatalf("failed to retrieve updated team: %v", err)
	}

	if updated.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %s", updated.Name)
	}
}

// TestTeamService_Update_EmptyName tests validation on update
func TestTeamService_Update_EmptyName(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	mockTeamRepo.AddTeam(&domain.Team{
		ID:   "team-1",
		Name: "Original",
	})

	updateTeam := &domain.Team{
		Name: "",
	}

	err := teamService.Update(ctx, "team-1", updateTeam, "user")
	if err == nil {
		t.Fatalf("expected validation error for empty name, got nil")
	}
}

// TestTeamService_Update_RepositoryError tests repo error handling
func TestTeamService_Update_RepositoryError(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	mockTeamRepo.UpdateErr = errors.New("database update failed")

	updateTeam := &domain.Team{
		Name: "Updated",
	}

	err := teamService.Update(ctx, "team-1", updateTeam, "user")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// TestTeamService_Delete tests deleting a team
func TestTeamService_Delete(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Create team to delete
	mockTeamRepo.AddTeam(&domain.Team{
		ID:   "team-delete",
		Name: "Team to Delete",
	})

	err := teamService.Delete(ctx, "team-delete", "delete-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify team was deleted
	_, err = teamService.Get(ctx, "team-delete")
	if err == nil {
		t.Errorf("expected error for deleted team, got nil")
	}
}

// TestTeamService_Delete_RepositoryError tests repo error handling
func TestTeamService_Delete_RepositoryError(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	mockTeamRepo.DeleteErr = errors.New("database delete failed")

	err := teamService.Delete(ctx, "team-1", "user")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// TestTeamService_ListTeams_HandlerInterface tests handler interface method
func TestTeamService_ListTeams_HandlerInterface(t *testing.T) {
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Add test teams
	for i := 0; i < 3; i++ {
		mockTeamRepo.AddTeam(&domain.Team{
			ID:   "team-" + string(rune(i)),
			Name: "Team " + string(rune(48+i)),
		})
	}

	teams, total, err := teamService.ListTeams(1, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}

	if len(teams) != 3 {
		t.Errorf("expected 3 teams (ListTeams doesn't paginate), got %d", len(teams))
	}
}

// TestTeamService_GetTeam_HandlerInterface tests handler interface method
func TestTeamService_GetTeam_HandlerInterface(t *testing.T) {
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	testTeam := &domain.Team{
		ID:   "handler-team",
		Name: "Handler Test Team",
	}
	mockTeamRepo.AddTeam(testTeam)

	team, err := teamService.GetTeam("handler-team")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if team.ID != "handler-team" || team.Name != "Handler Test Team" {
		t.Errorf("expected handler-team/Handler Test Team, got %s/%s", team.ID, team.Name)
	}
}

// TestTeamService_CreateTeam_HandlerInterface tests handler interface method
func TestTeamService_CreateTeam_HandlerInterface(t *testing.T) {
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	team := domain.Team{
		Name:        "Handler Create Team",
		Description: "Created via handler",
	}

	result, err := teamService.CreateTeam(team)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID == "" {
		t.Errorf("expected ID to be generated")
	}

	if result.Name != "Handler Create Team" {
		t.Errorf("expected name 'Handler Create Team', got %s", result.Name)
	}

	if result.CreatedAt.IsZero() {
		t.Errorf("expected CreatedAt to be set")
	}
}

// TestTeamService_UpdateTeam_HandlerInterface tests handler interface method
func TestTeamService_UpdateTeam_HandlerInterface(t *testing.T) {
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Create initial team
	mockTeamRepo.AddTeam(&domain.Team{
		ID:   "handler-update-team",
		Name: "Original",
	})

	updateTeam := domain.Team{
		Name:        "Updated via Handler",
		Description: "Handler update",
	}

	result, err := teamService.UpdateTeam("handler-update-team", updateTeam)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "handler-update-team" {
		t.Errorf("expected ID handler-update-team, got %s", result.ID)
	}

	if result.Name != "Updated via Handler" {
		t.Errorf("expected name 'Updated via Handler', got %s", result.Name)
	}
}

// TestTeamService_DeleteTeam_HandlerInterface tests handler interface method
func TestTeamService_DeleteTeam_HandlerInterface(t *testing.T) {
	mockTeamRepo := newMockTeamRepository()
	mockAuditRepo := newMockAuditRepository()
	auditService := NewAuditService(mockAuditRepo)
	teamService := NewTeamService(mockTeamRepo, auditService)

	// Create team to delete
	mockTeamRepo.AddTeam(&domain.Team{
		ID:   "handler-delete-team",
		Name: "To Delete",
	})

	err := teamService.DeleteTeam("handler-delete-team")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deletion
	_, err = mockTeamRepo.Get(context.Background(), "handler-delete-team")
	if err == nil {
		t.Errorf("expected error for deleted team")
	}
}

// TestTeamService_NilAuditService tests behavior when audit service is nil
func TestTeamService_NilAuditService(t *testing.T) {
	ctx := context.Background()
	mockTeamRepo := newMockTeamRepository()
	teamService := NewTeamService(mockTeamRepo, nil)

	team := &domain.Team{
		Name: "Test Team",
	}

	// Should not panic with nil audit service
	err := teamService.Create(ctx, team, "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if team.ID == "" {
		t.Errorf("expected ID to be generated")
	}
}
