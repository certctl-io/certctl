package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

// TestUserRepository_DeactivatedAt_RoundTrip pins the A-2 closure at
// the SQL layer. Pre-fix scanUser did not include deactivated_at in
// userColumns, Update did not write it, and Create did not write it.
// Result: a non-nil DeactivatedAt set in the in-memory User by the
// handler was lost on persist + always nil on read. This test
// exercises both legs.
//
// Audit 2026-05-11 A-2 — round-trip a non-nil DeactivatedAt through
// Update and verify Get + GetByOIDCSubject + ListAll all return it
// non-nil. Then clear it (reactivate path) and verify the nil
// round-trips back.
func TestUserRepository_DeactivatedAt_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("deact-rt")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := newValidUser("deactivated-user", p.ID)
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	// Sanity: a freshly-created row reads back nil.
	got, err := userRepo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get (fresh): %v", err)
	}
	if got.DeactivatedAt != nil {
		t.Errorf("freshly-created user has non-nil DeactivatedAt: %v", got.DeactivatedAt)
	}

	// Soft-delete: set DeactivatedAt and Update.
	now := time.Now().UTC().Truncate(time.Microsecond) // pg precision
	got.DeactivatedAt = &now
	if err := userRepo.Update(ctx, got); err != nil {
		t.Fatalf("Update (deactivate): %v", err)
	}

	// Read via Get.
	rb, err := userRepo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get (post-deactivate): %v", err)
	}
	if rb.DeactivatedAt == nil {
		t.Fatal("Get returned nil DeactivatedAt after Update set it (A-2 regression)")
	}
	if !rb.DeactivatedAt.Equal(now) {
		t.Errorf("Get round-trip DeactivatedAt mismatch: got %v want %v", *rb.DeactivatedAt, now)
	}

	// Read via GetByOIDCSubject.
	rs, err := userRepo.GetByOIDCSubject(ctx, p.ID, u.OIDCSubject)
	if err != nil {
		t.Fatalf("GetByOIDCSubject (post-deactivate): %v", err)
	}
	if rs.DeactivatedAt == nil {
		t.Error("GetByOIDCSubject returned nil DeactivatedAt after Update set it (A-2 regression — OIDC login path leak)")
	}

	// Read via ListAll.
	rows, err := userRepo.ListAll(ctx, "t-default")
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(rows) != 1 || rows[0].DeactivatedAt == nil {
		t.Errorf("ListAll: expected 1 row with non-nil DeactivatedAt; got %d rows, first DeactivatedAt=%v",
			len(rows), func() interface{} {
				if len(rows) == 0 {
					return "no rows"
				}
				return rows[0].DeactivatedAt
			}())
	}

	// Reactivate: clear DeactivatedAt and verify the nil round-trips.
	rb.DeactivatedAt = nil
	if err := userRepo.Update(ctx, rb); err != nil {
		t.Fatalf("Update (reactivate): %v", err)
	}
	rfin, err := userRepo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get (post-reactivate): %v", err)
	}
	if rfin.DeactivatedAt != nil {
		t.Errorf("Get returned non-nil DeactivatedAt after reactivate Update cleared it: %v", *rfin.DeactivatedAt)
	}
}

// TestUserRepository_DeactivatedAt_CreateWritesNullForActive pins
// the Create path's behavior for the common case (active user).
// Pre-fix Create omitted deactivated_at entirely so the column took
// the schema default (NULL). Now Create writes it explicitly; the
// observable behavior is unchanged for nil, but a regression would
// flip new users to deactivated.
//
// Audit 2026-05-11 A-2.
func TestUserRepository_DeactivatedAt_CreateWritesNullForActive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("create-nil")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := newValidUser("active-user", p.ID)
	u.DeactivatedAt = nil // explicit: new user is active
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := userRepo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DeactivatedAt != nil {
		t.Errorf("active user has non-nil DeactivatedAt after Create: %v", *got.DeactivatedAt)
	}
}

// TestUserRepository_DeactivatedAt_CreatePersistsPreDeactivated
// covers the forward-compat path where a future seed-data flow
// (e.g. migration of an external user roster where some entries
// land deactivated) pre-populates the column on insert. Pre-fix
// Create omitted the column entirely, so this case wasn't
// representable; the A-2 closure makes the explicit write part of
// the Create contract.
//
// Audit 2026-05-11 A-2.
func TestUserRepository_DeactivatedAt_CreatePersistsPreDeactivated(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("create-deact")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := newValidUser("seed-deactivated", p.ID)
	pre := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Microsecond)
	u.DeactivatedAt = &pre
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := userRepo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DeactivatedAt == nil {
		t.Fatal("DeactivatedAt nil after Create persisted a pre-deactivated user")
	}
	if !got.DeactivatedAt.Equal(pre) {
		t.Errorf("Create round-trip DeactivatedAt: got %v want %v", *got.DeactivatedAt, pre)
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
