package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// =============================================================================
// OIDCProviderRepository tests (Auth Bundle 2 Phase 2)
//
// Schema-per-test isolation via getTestDB().freshSchema(t). Run with:
//
//   go test -count=1 ./internal/repository/postgres/...
//
// (omit -short; testing.Short() skips all integration tests.)
// =============================================================================

func newValidProvider(suffix string) *oidcdomain.OIDCProvider {
	return &oidcdomain.OIDCProvider{
		ID:                    "op-" + suffix,
		TenantID:              "t-default",
		Name:                  "Provider " + suffix,
		IssuerURL:             "https://idp." + suffix + ".example.com",
		ClientID:              "certctl",
		ClientSecretEncrypted: []byte{0x02, 0x00, 0x01, 0x02, 0x03},
		RedirectURI:           "https://certctl.example.com/auth/oidc/callback",
		GroupsClaimPath:       "groups",
		GroupsClaimFormat:     "string-array",
		Scopes:                []string{"openid", "profile", "email"},
		AllowedEmailDomains:   []string{},
		IATWindowSeconds:      300,
		JWKSCacheTTLSeconds:   3600,
	}
}

func TestOIDCProviderRepository_CreateAndGet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	p := newValidProvider("a")
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != p.Name {
		t.Errorf("Name roundtrip: got %q, want %q", got.Name, p.Name)
	}
	if got.IssuerURL != p.IssuerURL {
		t.Errorf("IssuerURL roundtrip mismatch")
	}
	// Defaults from the migration kicked in for any unset bool / array.
	if got.FetchUserinfo != false {
		t.Errorf("FetchUserinfo default = %v; want false", got.FetchUserinfo)
	}
	if len(got.Scopes) != 3 {
		t.Errorf("Scopes roundtrip count = %d; want 3", len(got.Scopes))
	}
	// Defense: client_secret_encrypted column must NOT contain plaintext.
	// Since we wrote a v2 magic-byte stub, the byte stream comes back as-is.
	if len(got.ClientSecretEncrypted) == 0 {
		t.Errorf("ClientSecretEncrypted lost on roundtrip")
	}
}

func TestOIDCProviderRepository_GetNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	_, err := repo.Get(ctx, "op-nonexistent")
	if !errors.Is(err, repository.ErrOIDCProviderNotFound) {
		t.Errorf("err = %v; want ErrOIDCProviderNotFound", err)
	}
}

func TestOIDCProviderRepository_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	p1 := newValidProvider("dup1")
	if err := repo.Create(ctx, p1); err != nil {
		t.Fatalf("Create p1: %v", err)
	}

	p2 := newValidProvider("dup2")
	p2.Name = p1.Name // collision on (tenant_id, name)
	err := repo.Create(ctx, p2)
	if !errors.Is(err, repository.ErrOIDCProviderDuplicateName) {
		t.Errorf("Create with duplicate name err = %v; want ErrOIDCProviderDuplicateName", err)
	}
}

func TestOIDCProviderRepository_List(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	for _, suf := range []string{"x", "y", "z"} {
		if err := repo.Create(ctx, newValidProvider(suf)); err != nil {
			t.Fatalf("Create %q: %v", suf, err)
		}
	}

	out, err := repo.List(ctx, "t-default")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("List count = %d; want 3", len(out))
	}
}

func TestOIDCProviderRepository_Update(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	p := newValidProvider("upd")
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	p.Name = "Renamed"
	p.FetchUserinfo = true
	if err := repo.Update(ctx, p); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("Get post-update: %v", err)
	}
	if got.Name != "Renamed" {
		t.Errorf("Update did not persist Name; got %q", got.Name)
	}
	if !got.FetchUserinfo {
		t.Errorf("Update did not persist FetchUserinfo")
	}
}

func TestOIDCProviderRepository_DeleteNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	err := repo.Delete(ctx, "op-nonexistent")
	if !errors.Is(err, repository.ErrOIDCProviderNotFound) {
		t.Errorf("err = %v; want ErrOIDCProviderNotFound", err)
	}
}

func TestOIDCProviderRepository_DeleteSucceedsWhenNoUsersReference(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	repo := postgres.NewOIDCProviderRepository(db)
	ctx := context.Background()

	p := newValidProvider("del")
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := repo.Get(ctx, p.ID)
	if !errors.Is(err, repository.ErrOIDCProviderNotFound) {
		t.Errorf("post-delete Get err = %v; want ErrOIDCProviderNotFound", err)
	}
}

// TestOIDCProviderRepository_DeleteRefusedWhenUsersReference pins the
// FK ON DELETE RESTRICT translation. With at least one users row
// referencing the provider, Delete must return ErrOIDCProviderInUse.
func TestOIDCProviderRepository_DeleteRefusedWhenUsersReference(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	userRepo := postgres.NewUserRepository(db)
	ctx := context.Background()

	p := newValidProvider("inuse")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	u := &struct{ ID string }{ID: "u-test"}
	_ = u
	user := newValidUser("inuse", p.ID)
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	err := providerRepo.Delete(ctx, p.ID)
	if !errors.Is(err, repository.ErrOIDCProviderInUse) {
		t.Errorf("Delete with referencing user err = %v; want ErrOIDCProviderInUse", err)
	}
}

// =============================================================================
// GroupRoleMappingRepository
// =============================================================================

func TestGroupRoleMappingRepository_AddListMap(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	mappingRepo := postgres.NewGroupRoleMappingRepository(db)
	ctx := context.Background()

	p := newValidProvider("grm")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}

	mappings := []*oidcdomain.GroupRoleMapping{
		{ID: "grm-1", TenantID: "t-default", ProviderID: p.ID, GroupName: "engineers", RoleID: "r-operator"},
		{ID: "grm-2", TenantID: "t-default", ProviderID: p.ID, GroupName: "platform-admins", RoleID: "r-admin"},
		{ID: "grm-3", TenantID: "t-default", ProviderID: p.ID, GroupName: "compliance", RoleID: "r-auditor"},
	}
	for _, m := range mappings {
		if err := mappingRepo.Add(ctx, m); err != nil {
			t.Fatalf("Add %s: %v", m.GroupName, err)
		}
	}

	listed, err := mappingRepo.ListByProvider(ctx, p.ID)
	if err != nil {
		t.Fatalf("ListByProvider: %v", err)
	}
	if len(listed) != 3 {
		t.Errorf("ListByProvider count = %d; want 3", len(listed))
	}

	// Map: user has groups [engineers, marketing]. Marketing has no
	// mapping; only engineers maps to r-operator.
	roleIDs, err := mappingRepo.Map(ctx, p.ID, []string{"engineers", "marketing"})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if len(roleIDs) != 1 || roleIDs[0] != "r-operator" {
		t.Errorf("Map(engineers, marketing) = %v; want [r-operator]", roleIDs)
	}

	// Map: user has groups [engineers, platform-admins]. Both map.
	roleIDs, err = mappingRepo.Map(ctx, p.ID, []string{"engineers", "platform-admins"})
	if err != nil {
		t.Fatalf("Map (multi): %v", err)
	}
	if len(roleIDs) != 2 {
		t.Errorf("Map(engineers, platform-admins) count = %d; want 2", len(roleIDs))
	}

	// Map empty groups: empty result, no error (Phase 3 fail-closes).
	roleIDs, err = mappingRepo.Map(ctx, p.ID, nil)
	if err != nil {
		t.Fatalf("Map(nil): %v", err)
	}
	if len(roleIDs) != 0 {
		t.Errorf("Map(nil) returned %d roles; want 0", len(roleIDs))
	}
}

func TestGroupRoleMappingRepository_DuplicateRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	mappingRepo := postgres.NewGroupRoleMappingRepository(db)
	ctx := context.Background()

	p := newValidProvider("dup")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	m := &oidcdomain.GroupRoleMapping{
		ID: "grm-dup-1", TenantID: "t-default", ProviderID: p.ID,
		GroupName: "engineers", RoleID: "r-operator",
	}
	if err := mappingRepo.Add(ctx, m); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	m2 := &oidcdomain.GroupRoleMapping{
		ID: "grm-dup-2", TenantID: "t-default", ProviderID: p.ID,
		GroupName: "engineers", RoleID: "r-operator",
	}
	err := mappingRepo.Add(ctx, m2)
	if !errors.Is(err, repository.ErrGroupRoleMappingDuplicate) {
		t.Errorf("Add duplicate err = %v; want ErrGroupRoleMappingDuplicate", err)
	}
}

func TestGroupRoleMappingRepository_ProviderDeleteCascades(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test in short mode")
	}
	db := getTestDB(t).freshSchema(t)
	providerRepo := postgres.NewOIDCProviderRepository(db)
	mappingRepo := postgres.NewGroupRoleMappingRepository(db)
	ctx := context.Background()

	p := newValidProvider("cascade")
	if err := providerRepo.Create(ctx, p); err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	for i, group := range []string{"a", "b", "c"} {
		m := &oidcdomain.GroupRoleMapping{
			ID: "grm-cas-" + string(rune('a'+i)), TenantID: "t-default",
			ProviderID: p.ID, GroupName: group, RoleID: "r-viewer",
		}
		if err := mappingRepo.Add(ctx, m); err != nil {
			t.Fatalf("Add %s: %v", group, err)
		}
	}

	// Delete provider: ON DELETE CASCADE on group_role_mappings.provider_id
	// should drop the 3 mappings too.
	if err := providerRepo.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete provider: %v", err)
	}
	listed, err := mappingRepo.ListByProvider(ctx, p.ID)
	if err != nil {
		t.Fatalf("ListByProvider post-cascade: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("CASCADE failed; %d mappings remain", len(listed))
	}
}

// quiet unused-import keepalives so single-test runs don't drop them.
var _ = time.Now
