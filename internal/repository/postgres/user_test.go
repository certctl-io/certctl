package postgres_test

import (
	"context"
	"errors"
	"testing"

	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// newValidUser is shared with oidc_test.go (same _test package).
func newValidUser(suffix, providerID string) *userdomain.User {
	return &userdomain.User{
		ID:                  "u-" + suffix,
		TenantID:            "t-default",
		Email:               suffix + "@example.com",
		DisplayName:         "User " + suffix,
		OIDCSubject:         "subject-" + suffix,
		OIDCProviderID:      providerID,
		WebAuthnCredentials: []byte("[]"),
	}
}

func TestUserRepository_CreateAndGet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("u")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := newValidUser("alice", p.ID)
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	got, err := userRepo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Email != u.Email {
		t.Errorf("Email roundtrip: got %q, want %q", got.Email, u.Email)
	}
	if string(got.WebAuthnCredentials) != "[]" {
		t.Errorf("WebAuthnCredentials default = %q; want []", string(got.WebAuthnCredentials))
	}
}

func TestUserRepository_GetNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewUserRepository(db)
	ctx := context.Background()

	_, err := repo.Get(ctx, "u-nonexistent")
	if !errors.Is(err, repository.ErrUserNotFound) {
		t.Errorf("err = %v; want ErrUserNotFound", err)
	}
}

func TestUserRepository_GetByOIDCSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("subj")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := newValidUser("bob", p.ID)
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	got, err := userRepo.GetByOIDCSubject(ctx, p.ID, u.OIDCSubject)
	if err != nil {
		t.Fatalf("GetByOIDCSubject: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("GetByOIDCSubject returned %q; want %q", got.ID, u.ID)
	}

	// Wrong subject: not found.
	_, err = userRepo.GetByOIDCSubject(ctx, p.ID, "wrong-subject")
	if !errors.Is(err, repository.ErrUserNotFound) {
		t.Errorf("err = %v; want ErrUserNotFound", err)
	}
}

func TestUserRepository_DuplicateOIDCSubjectRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("dupsubj")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u1 := newValidUser("first", p.ID)
	if err := userRepo.Create(ctx, u1); err != nil {
		t.Fatalf("Create u1: %v", err)
	}
	u2 := newValidUser("second", p.ID)
	u2.OIDCSubject = u1.OIDCSubject // collision on (provider, subject) UNIQUE
	err := userRepo.Create(ctx, u2)
	if !errors.Is(err, repository.ErrUserDuplicateOIDCSubject) {
		t.Errorf("Create duplicate (provider, subject) err = %v; want ErrUserDuplicateOIDCSubject", err)
	}
}

func TestUserRepository_UpdateMutableFields(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("upd")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := newValidUser("carol", p.ID)
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	u.Email = "carol-new@example.com"
	u.DisplayName = "Carol Renamed"
	if err := userRepo.Update(ctx, u); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := userRepo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get post-update: %v", err)
	}
	if got.Email != "carol-new@example.com" {
		t.Errorf("Update did not persist Email; got %q", got.Email)
	}
	if got.DisplayName != "Carol Renamed" {
		t.Errorf("Update did not persist DisplayName; got %q", got.DisplayName)
	}
	// Immutable: oidc_subject must NOT change.
	if got.OIDCSubject != u.OIDCSubject {
		t.Errorf("OIDCSubject mutated: got %q, want %q", got.OIDCSubject, u.OIDCSubject)
	}
}

func TestUserRepository_ListAll(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("la")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	for _, suf := range []string{"u1", "u2", "u3"} {
		u := newValidUser(suf, p.ID)
		if err := userRepo.Create(ctx, u); err != nil {
			t.Fatalf("Create %s: %v", suf, err)
		}
	}

	out, err := userRepo.ListAll(ctx, "t-default")
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("ListAll count = %d; want 3", len(out))
	}
}

// TestUserRepository_DeletingProviderRefusedWhenUsersReference complements
// the OIDCProviderRepository test of the same shape; pinning both ends
// of the FK ON DELETE RESTRICT contract.
func TestUserRepository_FKRestrictsProviderDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("fkrest")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := newValidUser("fkrest-user", p.ID)
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	if err := providerRepo.Delete(ctx, p.ID); !errors.Is(err, repository.ErrOIDCProviderInUse) {
		t.Errorf("Delete provider (with referencing user) err = %v; want ErrOIDCProviderInUse", err)
	}
}
