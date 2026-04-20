package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// G-1 red tests: lock in the behavior of RenewalPolicyService before
// the production code exists. Every subtest here references a type or
// method that Phase 2b must introduce:
//
//   - NewRenewalPolicyService(repo)          (constructor)
//   - svc.ListRenewalPolicies(ctx, page, pp) ([]RenewalPolicy, int64, error)
//   - svc.GetRenewalPolicy(ctx, id)           (*RenewalPolicy, error)
//   - svc.CreateRenewalPolicy(ctx, rp)        (*RenewalPolicy, error)
//   - svc.UpdateRenewalPolicy(ctx, id, rp)    (*RenewalPolicy, error)
//   - svc.DeleteRenewalPolicy(ctx, id)         error
//   - ErrRenewalPolicyDuplicateName            sentinel (pg 23505 → 409)
//   - ErrRenewalPolicyInUse                    sentinel (pg 23503 → 409)
//
// Once Phase 2b lands, these should all turn green without modification.

func TestRenewalPolicyService_List_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	repo := &mockRenewalPolicyRepo{
		Policies: map[string]*domain.RenewalPolicy{
			"rp-default": {
				ID: "rp-default", Name: "Default", RenewalWindowDays: 30,
				MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
				CreatedAt: now, UpdatedAt: now,
			},
			"rp-urgent": {
				ID: "rp-urgent", Name: "Urgent", RenewalWindowDays: 7,
				MaxRetries: 5, RetryInterval: 600, AutoRenew: true,
				CreatedAt: now, UpdatedAt: now,
			},
		},
	}
	svc := NewRenewalPolicyService(repo)

	items, total, err := svc.ListRenewalPolicies(ctx, 1, 50)
	if err != nil {
		t.Fatalf("ListRenewalPolicies failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
}

func TestRenewalPolicyService_List_Empty(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	svc := NewRenewalPolicyService(repo)

	items, total, err := svc.ListRenewalPolicies(ctx, 1, 50)
	if err != nil {
		t.Fatalf("ListRenewalPolicies failed: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(items) != 0 {
		t.Errorf("expected 0 items, got %d", len(items))
	}
}

func TestRenewalPolicyService_List_Pagination(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	// Seed 5 policies, names A..E so the mock's sort.Slice yields a deterministic
	// ordering that pagination boundaries can assert against.
	for _, name := range []string{"A", "B", "C", "D", "E"} {
		p := &domain.RenewalPolicy{
			ID: "rp-" + strings.ToLower(name), Name: name,
			RenewalWindowDays: 30, MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
			CreatedAt: now, UpdatedAt: now,
		}
		repo.Policies[p.ID] = p
	}
	svc := NewRenewalPolicyService(repo)

	// Page 1, size 2 → [A, B]
	page1, total, err := svc.ListRenewalPolicies(ctx, 1, 2)
	if err != nil {
		t.Fatalf("page 1 failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(page1) != 2 || page1[0].Name != "A" || page1[1].Name != "B" {
		t.Errorf("unexpected page 1 slice: %+v", page1)
	}

	// Page 3, size 2 → [E]  (single-item last page)
	page3, _, err := svc.ListRenewalPolicies(ctx, 3, 2)
	if err != nil {
		t.Fatalf("page 3 failed: %v", err)
	}
	if len(page3) != 1 || page3[0].Name != "E" {
		t.Errorf("unexpected page 3 slice: %+v", page3)
	}

	// Page 4, size 2 → [] (past the end, no error)
	page4, _, err := svc.ListRenewalPolicies(ctx, 4, 2)
	if err != nil {
		t.Fatalf("page 4 failed: %v", err)
	}
	if len(page4) != 0 {
		t.Errorf("expected empty past-end slice, got %+v", page4)
	}
}

func TestRenewalPolicyService_List_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{
		Policies: map[string]*domain.RenewalPolicy{},
		ListErr:  errors.New("boom"),
	}
	svc := NewRenewalPolicyService(repo)

	_, _, err := svc.ListRenewalPolicies(ctx, 1, 50)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRenewalPolicyService_Get_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	rp := &domain.RenewalPolicy{
		ID: "rp-default", Name: "Default", RenewalWindowDays: 30,
		MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
		CreatedAt: now, UpdatedAt: now,
	}
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{"rp-default": rp}}
	svc := NewRenewalPolicyService(repo)

	got, err := svc.GetRenewalPolicy(ctx, "rp-default")
	if err != nil {
		t.Fatalf("GetRenewalPolicy failed: %v", err)
	}
	if got.Name != "Default" {
		t.Errorf("expected name Default, got %s", got.Name)
	}
}

func TestRenewalPolicyService_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	svc := NewRenewalPolicyService(repo)

	_, err := svc.GetRenewalPolicy(ctx, "rp-missing")
	if err == nil {
		t.Fatal("expected error for missing policy, got nil")
	}
}

func TestRenewalPolicyService_Create_Success(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	svc := NewRenewalPolicyService(repo)

	rp := domain.RenewalPolicy{
		Name:              "Weekly Renewal",
		RenewalWindowDays: 7,
		MaxRetries:        3,
		RetryInterval:     3600,
		AutoRenew:         true,
	}
	created, err := svc.CreateRenewalPolicy(ctx, rp)
	if err != nil {
		t.Fatalf("CreateRenewalPolicy failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected auto-generated ID, got empty")
	}
	// ID convention: rp-<slug(name)> matches seed rows rp-default/rp-standard/rp-urgent.
	if !strings.HasPrefix(created.ID, "rp-") {
		t.Errorf("expected ID prefix rp-, got %s", created.ID)
	}
	if created.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be populated")
	}
}

func TestRenewalPolicyService_Create_MissingName(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	svc := NewRenewalPolicyService(repo)

	_, err := svc.CreateRenewalPolicy(ctx, domain.RenewalPolicy{
		RenewalWindowDays: 30, MaxRetries: 3, RetryInterval: 3600,
	})
	if err == nil {
		t.Fatal("expected validation error for missing name, got nil")
	}
}

func TestRenewalPolicyService_Create_BoundsViolation(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	svc := NewRenewalPolicyService(repo)

	// RenewalWindowDays out of range [1, 365]
	_, err := svc.CreateRenewalPolicy(ctx, domain.RenewalPolicy{
		Name:              "Bad Window",
		RenewalWindowDays: 999,
		MaxRetries:        3,
		RetryInterval:     3600,
	})
	if err == nil {
		t.Fatal("expected bounds violation on RenewalWindowDays, got nil")
	}
}

func TestRenewalPolicyService_Create_DuplicateName(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{
		Policies:  map[string]*domain.RenewalPolicy{},
		CreateErr: ErrRenewalPolicyDuplicateName,
	}
	svc := NewRenewalPolicyService(repo)

	_, err := svc.CreateRenewalPolicy(ctx, domain.RenewalPolicy{
		Name:              "Duplicate",
		RenewalWindowDays: 30,
		MaxRetries:        3,
		RetryInterval:     3600,
	})
	if err == nil {
		t.Fatal("expected duplicate-name error, got nil")
	}
	if !errors.Is(err, ErrRenewalPolicyDuplicateName) {
		t.Errorf("expected ErrRenewalPolicyDuplicateName, got %v", err)
	}
}

func TestRenewalPolicyService_Update_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	rp := &domain.RenewalPolicy{
		ID: "rp-default", Name: "Default", RenewalWindowDays: 30,
		MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
		CreatedAt: now, UpdatedAt: now,
	}
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{"rp-default": rp}}
	svc := NewRenewalPolicyService(repo)

	updated, err := svc.UpdateRenewalPolicy(ctx, "rp-default", domain.RenewalPolicy{
		Name:              "Default Renamed",
		RenewalWindowDays: 45,
		MaxRetries:        5,
		RetryInterval:     1800,
		AutoRenew:         true,
	})
	if err != nil {
		t.Fatalf("UpdateRenewalPolicy failed: %v", err)
	}
	if updated.Name != "Default Renamed" {
		t.Errorf("expected updated name, got %s", updated.Name)
	}
	if updated.RenewalWindowDays != 45 {
		t.Errorf("expected window 45, got %d", updated.RenewalWindowDays)
	}
}

func TestRenewalPolicyService_Update_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	svc := NewRenewalPolicyService(repo)

	_, err := svc.UpdateRenewalPolicy(ctx, "rp-missing", domain.RenewalPolicy{
		Name: "X", RenewalWindowDays: 30, MaxRetries: 3, RetryInterval: 3600,
	})
	if err == nil {
		t.Fatal("expected error for missing policy, got nil")
	}
}

func TestRenewalPolicyService_Delete_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	rp := &domain.RenewalPolicy{
		ID: "rp-default", Name: "Default", RenewalWindowDays: 30,
		MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
		CreatedAt: now, UpdatedAt: now,
	}
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{"rp-default": rp}}
	svc := NewRenewalPolicyService(repo)

	if err := svc.DeleteRenewalPolicy(ctx, "rp-default"); err != nil {
		t.Fatalf("DeleteRenewalPolicy failed: %v", err)
	}
	if _, exists := repo.Policies["rp-default"]; exists {
		t.Error("expected policy to be removed from repo")
	}
}

func TestRenewalPolicyService_Delete_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := &mockRenewalPolicyRepo{Policies: map[string]*domain.RenewalPolicy{}}
	svc := NewRenewalPolicyService(repo)

	err := svc.DeleteRenewalPolicy(ctx, "rp-missing")
	if err == nil {
		t.Fatal("expected error for missing policy, got nil")
	}
}

func TestRenewalPolicyService_Delete_InUseConflict(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	rp := &domain.RenewalPolicy{
		ID: "rp-active", Name: "Active", RenewalWindowDays: 30,
		MaxRetries: 3, RetryInterval: 3600, AutoRenew: true,
		CreatedAt: now, UpdatedAt: now,
	}
	repo := &mockRenewalPolicyRepo{
		Policies:  map[string]*domain.RenewalPolicy{"rp-active": rp},
		DeleteErr: ErrRenewalPolicyInUse,
	}
	svc := NewRenewalPolicyService(repo)

	err := svc.DeleteRenewalPolicy(ctx, "rp-active")
	if err == nil {
		t.Fatal("expected in-use conflict error, got nil")
	}
	if !errors.Is(err, ErrRenewalPolicyInUse) {
		t.Errorf("expected ErrRenewalPolicyInUse, got %v", err)
	}
}
