// Package postgres_test provides repository integration tests covering 17 of 17
// PostgreSQL repository files. Each test function exercises CRUD operations,
// edge cases, and deduplication logic against a real database. HealthCheck
// and RenewalPolicy integration tests live in sibling *_test.go files in this
// package (see health_check_test.go and renewal_policy_test.go).
package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/repository/postgres"
)

// Shared test database — started once, reused across tests in this package.
// Each test creates its own schema for isolation.
var sharedDB *testDB

func TestMain(m *testing.M) {
	// Note: We can't use setupTestDB here because it needs a *testing.T.
	// Instead, each top-level test function calls setupTestDB if sharedDB is nil.
	// This is handled by the getTestDB helper.
	m.Run()
}

// getTestDB lazily initializes the shared container.
// In practice, the first test to call this starts the container.
func getTestDB(t *testing.T) *testDB {
	t.Helper()
	if sharedDB == nil {
		sharedDB = setupTestDB(t)
		// Register cleanup at the end of the entire test run
		t.Cleanup(func() {
			sharedDB.teardown(t)
			sharedDB = nil
		})
	}
	return sharedDB
}

// insertCertPrereqsRaw creates prerequisite FK records using raw SQL on the *sql.DB.
func insertCertPrereqsRaw(t *testing.T, db *sql.DB, ctx context.Context, suffix string) (ownerID, teamID, issuerID, policyID string) {
	t.Helper()
	teamID = "team-" + suffix
	ownerID = "o-" + suffix
	issuerID = "iss-" + suffix
	policyID = "pol-" + suffix

	now := time.Now().Truncate(time.Microsecond)

	// Create team
	_, err := db.ExecContext(ctx, `INSERT INTO teams (id, name, created_at, updated_at) VALUES ($1, $2, $3, $4)`,
		teamID, "Team "+suffix, now, now)
	if err != nil {
		t.Fatalf("insertCertPrereqs: create team failed: %v", err)
	}

	// Create owner (requires team)
	_, err = db.ExecContext(ctx, `INSERT INTO owners (id, name, email, team_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		ownerID, "Owner "+suffix, suffix+"@example.com", teamID, now, now)
	if err != nil {
		t.Fatalf("insertCertPrereqs: create owner failed: %v", err)
	}

	// Create issuer
	_, err = db.ExecContext(ctx, `INSERT INTO issuers (id, name, type, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		issuerID, "Issuer "+suffix, "generic-ca", true, now, now)
	if err != nil {
		t.Fatalf("insertCertPrereqs: create issuer failed: %v", err)
	}

	// Create renewal policy
	_, err = db.ExecContext(ctx, `INSERT INTO renewal_policies (id, name, renewal_window_days, auto_renew, max_retries, retry_interval_seconds, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		policyID, "Policy "+suffix, 30, true, 3, 60, now, now)
	if err != nil {
		t.Fatalf("insertCertPrereqs: create renewal_policy failed: %v", err)
	}

	return
}

// ============================================================
// Certificate Repository Tests
// ============================================================

func TestCertificateRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)
	expires := now.Add(90 * 24 * time.Hour)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "crud")

	cert := &domain.ManagedCertificate{
		ID:              "mc-test-crud",
		Name:            "test-cert",
		CommonName:      "test.example.com",
		SANs:            []string{"test.example.com", "www.test.example.com"},
		Environment:     "production",
		OwnerID:         ownerID,
		TeamID:          teamID,
		IssuerID:        issuerID,
		RenewalPolicyID: policyID,
		Status:          domain.CertificateStatusActive,
		ExpiresAt:       expires,
		Tags:            map[string]string{"team": "platform"},
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Create
	err := repo.Create(ctx, cert)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get
	got, err := repo.Get(ctx, "mc-test-crud")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", got.CommonName, "test.example.com")
	}
	if len(got.SANs) != 2 {
		t.Errorf("SANs length = %d, want 2", len(got.SANs))
	}
	if got.Tags["team"] != "platform" {
		t.Errorf("Tags[team] = %q, want %q", got.Tags["team"], "platform")
	}

	// Update
	cert.Status = domain.CertificateStatusExpiring
	cert.UpdatedAt = time.Now().Truncate(time.Microsecond)
	err = repo.Update(ctx, cert)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = repo.Get(ctx, "mc-test-crud")
	if got.Status != domain.CertificateStatusExpiring {
		t.Errorf("Status = %q, want %q", got.Status, domain.CertificateStatusExpiring)
	}

	// Archive
	err = repo.Archive(ctx, "mc-test-crud")
	if err != nil {
		t.Fatalf("Archive failed: %v", err)
	}
	got, _ = repo.Get(ctx, "mc-test-crud")
	if got.Status != domain.CertificateStatusArchived {
		t.Errorf("Status after archive = %q, want %q", got.Status, domain.CertificateStatusArchived)
	}
}

func TestCertificateRepository_List_Filtering(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "listfilt")

	// Create test certs in different states
	for _, tc := range []struct {
		id     string
		status domain.CertificateStatus
		env    string
	}{
		{"mc-list-1", domain.CertificateStatusActive, "production"},
		{"mc-list-2", domain.CertificateStatusActive, "staging"},
		{"mc-list-3", domain.CertificateStatusExpired, "production"},
	} {
		cert := &domain.ManagedCertificate{
			ID:              tc.id,
			Name:            tc.id,
			CommonName:      tc.id + ".example.com",
			SANs:            []string{},
			Environment:     tc.env,
			OwnerID:         ownerID,
			TeamID:          teamID,
			IssuerID:        issuerID,
			RenewalPolicyID: policyID,
			Status:          tc.status,
			ExpiresAt:       now.Add(30 * 24 * time.Hour),
			Tags:            map[string]string{},
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if err := repo.Create(ctx, cert); err != nil {
			t.Fatalf("Create %s failed: %v", tc.id, err)
		}
	}

	// Filter by status
	certs, total, err := repo.List(ctx, &repository.CertificateFilter{Status: "Active"})
	if err != nil {
		t.Fatalf("List with status filter failed: %v", err)
	}
	if total != 2 {
		t.Errorf("total Active = %d, want 2", total)
	}
	if len(certs) != 2 {
		t.Errorf("len(certs) = %d, want 2", len(certs))
	}

	// Filter by environment
	_, total, err = repo.List(ctx, &repository.CertificateFilter{Environment: "production"})
	if err != nil {
		t.Fatalf("List with env filter failed: %v", err)
	}
	if total != 2 {
		t.Errorf("total production = %d, want 2", total)
	}

	// Nil filter returns all
	_, total, err = repo.List(ctx, nil)
	if err != nil {
		t.Fatalf("List with nil filter failed: %v", err)
	}
	if total != 3 {
		t.Errorf("total all = %d, want 3", total)
	}
}

func TestCertificateRepository_Versions(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "ver")

	// Create parent cert
	cert := &domain.ManagedCertificate{
		ID: "mc-ver-test", Name: "ver-test", CommonName: "ver.example.com",
		SANs: []string{}, OwnerID: ownerID, TeamID: teamID, IssuerID: issuerID,
		RenewalPolicyID: policyID, Status: domain.CertificateStatusActive,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := repo.Create(ctx, cert); err != nil {
		t.Fatalf("Create cert failed: %v", err)
	}

	// Create two versions
	v1 := &domain.CertificateVersion{
		ID: "v-1", CertificateID: "mc-ver-test", SerialNumber: "AABB01",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
		FingerprintSHA256: "sha256-v1", PEMChain: "---BEGIN---", CSRPEM: "---CSR---",
		CreatedAt: now,
	}
	v2 := &domain.CertificateVersion{
		ID: "v-2", CertificateID: "mc-ver-test", SerialNumber: "AABB02",
		NotBefore: now, NotAfter: now.Add(180 * 24 * time.Hour),
		FingerprintSHA256: "sha256-v2", PEMChain: "---BEGIN2---", CSRPEM: "---CSR2---",
		CreatedAt: now.Add(1 * time.Second),
	}

	if err := repo.CreateVersion(ctx, v1); err != nil {
		t.Fatalf("CreateVersion v1 failed: %v", err)
	}
	if err := repo.CreateVersion(ctx, v2); err != nil {
		t.Fatalf("CreateVersion v2 failed: %v", err)
	}

	// ListVersions
	versions, err := repo.ListVersions(ctx, "mc-ver-test")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(versions))
	}

	// GetLatestVersion
	latest, err := repo.GetLatestVersion(ctx, "mc-ver-test")
	if err != nil {
		t.Fatalf("GetLatestVersion failed: %v", err)
	}
	if latest.SerialNumber != "AABB02" {
		t.Errorf("latest serial = %q, want %q", latest.SerialNumber, "AABB02")
	}
}

func TestCertificateRepository_GetExpiringCertificates(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "exp")

	// One expiring soon, one far out
	for _, tc := range []struct {
		id      string
		expires time.Time
	}{
		{"mc-exp-soon", now.Add(5 * 24 * time.Hour)},
		{"mc-exp-far", now.Add(365 * 24 * time.Hour)},
	} {
		cert := &domain.ManagedCertificate{
			ID: tc.id, Name: tc.id, CommonName: tc.id + ".example.com",
			SANs: []string{}, OwnerID: ownerID, TeamID: teamID,
			IssuerID: issuerID, RenewalPolicyID: policyID,
			Status: domain.CertificateStatusActive,
			ExpiresAt: tc.expires, Tags: map[string]string{},
			CreatedAt: now, UpdatedAt: now,
		}
		if err := repo.Create(ctx, cert); err != nil {
			t.Fatalf("Create %s failed: %v", tc.id, err)
		}
	}

	expiring, err := repo.GetExpiringCertificates(ctx, now.Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("GetExpiringCertificates failed: %v", err)
	}
	if len(expiring) != 1 {
		t.Errorf("len(expiring) = %d, want 1", len(expiring))
	}
	if len(expiring) > 0 && expiring[0].ID != "mc-exp-soon" {
		t.Errorf("expiring[0].ID = %q, want %q", expiring[0].ID, "mc-exp-soon")
	}
}

func TestCertificateRepository_Get_NotFound(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)

	_, err := repo.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent cert, got nil")
	}
}

func TestCertificateRepository_Update_NotFound(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)

	err := repo.Update(context.Background(), &domain.ManagedCertificate{
		ID: "nonexistent", Tags: map[string]string{},
	})
	if err == nil {
		t.Error("expected error for nonexistent update, got nil")
	}
}

// ============================================================
// Agent Repository Tests
// ============================================================

func TestAgentRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	agent := &domain.Agent{
		ID:              "agent-test-1",
		Name:            "test-agent",
		Hostname:        "host1.local",
		Status:          domain.AgentStatusOnline,
		RegisteredAt:    now,
		LastHeartbeatAt: &now,
		APIKeyHash:      "abc123hash",
		OS:              "linux",
		Architecture:    "amd64",
		IPAddress:       "10.0.0.1",
		Version:         "1.0.0",
	}

	// Create
	if err := repo.Create(ctx, agent); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get
	got, err := repo.Get(ctx, "agent-test-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Hostname != "host1.local" {
		t.Errorf("Hostname = %q, want %q", got.Hostname, "host1.local")
	}
	if got.OS != "linux" {
		t.Errorf("OS = %q, want %q", got.OS, "linux")
	}

	// List
	agents, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("len(agents) = %d, want 1", len(agents))
	}

	// UpdateHeartbeat with metadata
	metadata := &domain.AgentMetadata{
		OS: "linux", Architecture: "arm64", Hostname: "host1-updated.local",
		IPAddress: "10.0.0.2", Version: "1.1.0",
	}
	if err := repo.UpdateHeartbeat(ctx, "agent-test-1", metadata); err != nil {
		t.Fatalf("UpdateHeartbeat failed: %v", err)
	}
	got, _ = repo.Get(ctx, "agent-test-1")
	if got.Architecture != "arm64" {
		t.Errorf("Architecture after heartbeat = %q, want %q", got.Architecture, "arm64")
	}

	// GetByAPIKey
	got, err = repo.GetByAPIKey(ctx, "abc123hash")
	if err != nil {
		t.Fatalf("GetByAPIKey failed: %v", err)
	}
	if got.ID != "agent-test-1" {
		t.Errorf("GetByAPIKey ID = %q, want %q", got.ID, "agent-test-1")
	}

	// Delete
	if err := repo.Delete(ctx, "agent-test-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = repo.Get(ctx, "agent-test-1")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestAgentRepository_Delete_NotFound(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewAgentRepository(db)

	err := repo.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent delete, got nil")
	}
}

// TestAgentRepository_CreateIfNotExists_FirstInsert verifies that a brand-new
// sentinel agent row is inserted and the helper reports created=true (M-6).
func TestAgentRepository_CreateIfNotExists_FirstInsert(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)
	agent := &domain.Agent{
		ID:           "server-scanner",
		Name:         "Network Scanner (Server-Side)",
		Status:       domain.AgentStatusOnline,
		RegisteredAt: now,
	}

	created, err := repo.CreateIfNotExists(ctx, agent)
	if err != nil {
		t.Fatalf("CreateIfNotExists failed: %v", err)
	}
	if !created {
		t.Error("created = false on first insert, want true")
	}

	got, err := repo.Get(ctx, "server-scanner")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Network Scanner (Server-Side)" {
		t.Errorf("Name = %q, want %q", got.Name, "Network Scanner (Server-Side)")
	}
}

// TestAgentRepository_CreateIfNotExists_Idempotent verifies that a second
// call with the same ID returns created=false and err=nil without mutating
// the existing row — the core M-6 upgrade/restart scenario (CWE-662).
func TestAgentRepository_CreateIfNotExists_Idempotent(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)
	first := &domain.Agent{
		ID:           "cloud-aws-sm",
		Name:         "AWS Secrets Manager Discovery",
		Status:       domain.AgentStatusOnline,
		RegisteredAt: now,
	}
	created, err := repo.CreateIfNotExists(ctx, first)
	if err != nil {
		t.Fatalf("first CreateIfNotExists failed: %v", err)
	}
	if !created {
		t.Fatal("first created = false, want true")
	}

	// Second call with the same ID but a different name must be a no-op.
	second := &domain.Agent{
		ID:           "cloud-aws-sm",
		Name:         "Overwritten Name Should Not Persist",
		Status:       domain.AgentStatusOffline,
		RegisteredAt: now.Add(time.Hour),
	}
	created, err = repo.CreateIfNotExists(ctx, second)
	if err != nil {
		t.Fatalf("second CreateIfNotExists failed: %v", err)
	}
	if created {
		t.Error("second created = true, want false (row already existed)")
	}

	// Row must still reflect the original insert.
	got, err := repo.Get(ctx, "cloud-aws-sm")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "AWS Secrets Manager Discovery" {
		t.Errorf("Name = %q, want %q (ON CONFLICT DO NOTHING must preserve original row)", got.Name, "AWS Secrets Manager Discovery")
	}
	if got.Status != domain.AgentStatusOnline {
		t.Errorf("Status = %q, want %q", got.Status, domain.AgentStatusOnline)
	}
}

// TestAgentRepository_CreateIfNotExists_ConcurrentRace fires N concurrent
// inserts for the same sentinel ID. Exactly one goroutine must see
// created=true; every other must see created=false and err=nil. No panics,
// no duplicate rows, no swallowed errors. This is the scenario that the
// pre-M-6 plain-INSERT path masked with a blanket error log.
func TestAgentRepository_CreateIfNotExists_ConcurrentRace(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	const N = 16
	now := time.Now().Truncate(time.Microsecond)

	var (
		wg           sync.WaitGroup
		createdCount int64
		errorCount   int64
	)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			agent := &domain.Agent{
				ID:           "cloud-gcp-sm",
				Name:         "GCP Secret Manager Discovery",
				Status:       domain.AgentStatusOnline,
				RegisteredAt: now,
			}
			created, err := repo.CreateIfNotExists(ctx, agent)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				t.Errorf("CreateIfNotExists returned error: %v", err)
				return
			}
			if created {
				atomic.AddInt64(&createdCount, 1)
			}
		}()
	}
	wg.Wait()

	if errorCount != 0 {
		t.Fatalf("errorCount = %d, want 0", errorCount)
	}
	if createdCount != 1 {
		t.Errorf("createdCount = %d, want exactly 1 (only one goroutine may win the insert)", createdCount)
	}

	// Exactly one row must exist.
	agents, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	count := 0
	for _, a := range agents {
		if a.ID == "cloud-gcp-sm" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("row count for cloud-gcp-sm = %d, want 1", count)
	}
}

// TestAgentRepository_CreateIfNotExists_GenericErrorSurfaces verifies that
// failures other than the primary-key duplicate (the only collision
// ON CONFLICT (id) absorbs) propagate to the caller instead of being
// swallowed. This is the security property that M-6 restores: the
// pre-fix plain-INSERT path logged every error at Debug level, so a
// connectivity or permission failure would vanish into the log without
// the server surfacing a problem on startup (CWE-662 / CWE-209-adjacent).
//
// Uses a pre-cancelled context to force QueryRowContext to fail with
// context.Canceled — a non-duplicate error class that must surface.
// Does NOT close the shared sql.DB (that would break sibling tests).
func TestAgentRepository_CreateIfNotExists_GenericErrorSurfaces(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewAgentRepository(db)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the driver round-trip fails immediately.

	agent := &domain.Agent{
		ID:           "server-scanner",
		Name:         "Network Scanner (Server-Side)",
		Status:       domain.AgentStatusOnline,
		RegisteredAt: time.Now(),
	}
	created, err := repo.CreateIfNotExists(ctx, agent)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil (error would have been swallowed pre-M-6)")
	}
	if created {
		t.Error("created = true on failure, want false")
	}
	if err == sql.ErrNoRows {
		t.Error("got sql.ErrNoRows, want a real connection/context error (ErrNoRows is the duplicate-row sentinel)")
	}
}

// ============================================================
// Issuer Repository Tests
// ============================================================

func TestIssuerRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewIssuerRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)
	config, _ := json.Marshal(map[string]string{"type": "local"})

	issuer := &domain.Issuer{
		ID: "iss-test", Name: "Test Issuer", Type: domain.IssuerTypeGenericCA,
		Config: config, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}

	// Create
	if err := repo.Create(ctx, issuer); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get
	got, err := repo.Get(ctx, "iss-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Test Issuer" {
		t.Errorf("Name = %q, want %q", got.Name, "Test Issuer")
	}

	// Update
	issuer.Enabled = false
	issuer.UpdatedAt = time.Now().Truncate(time.Microsecond)
	if err := repo.Update(ctx, issuer); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = repo.Get(ctx, "iss-test")
	if got.Enabled {
		t.Error("expected Enabled=false after update")
	}

	// List
	issuers, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(issuers) != 1 {
		t.Errorf("len(issuers) = %d, want 1", len(issuers))
	}

	// Delete
	if err := repo.Delete(ctx, "iss-test"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = repo.Get(ctx, "iss-test")
	if err == nil {
		t.Error("expected error after delete")
	}
}

// ============================================================
// Target Repository Tests
// ============================================================

func TestTargetRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	targetRepo := postgres.NewTargetRepository(db)
	agentRepo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	// Create agent first (FK requirement)
	agent := &domain.Agent{
		ID: "agent-target-test", Name: "target-test-agent", Hostname: "host",
		Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "hash1",
	}
	agentRepo.Create(ctx, agent)

	config, _ := json.Marshal(map[string]string{"cert_path": "/etc/nginx/ssl/cert.pem"})
	target := &domain.DeploymentTarget{
		ID: "t-test", Name: "Test Target", Type: domain.TargetTypeNGINX,
		AgentID: "agent-target-test", Config: config, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}

	if err := targetRepo.Create(ctx, target); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := targetRepo.Get(ctx, "t-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Type != domain.TargetTypeNGINX {
		t.Errorf("Type = %q, want %q", got.Type, domain.TargetTypeNGINX)
	}

	targets, err := targetRepo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("len(targets) = %d, want 1", len(targets))
	}

	if err := targetRepo.Delete(ctx, "t-test"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

// ============================================================
// Job Repository Tests
// ============================================================

func TestJobRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	jobRepo := postgres.NewJobRepository(db)
	certRepo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "job")

	// Create prerequisite cert
	cert := &domain.ManagedCertificate{
		ID: "mc-job-test", Name: "job-test", CommonName: "job.example.com",
		SANs: []string{}, OwnerID: ownerID, TeamID: teamID,
		IssuerID: issuerID, RenewalPolicyID: policyID,
		Status: domain.CertificateStatusActive,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		t.Fatalf("Create cert failed: %v", err)
	}

	job := &domain.Job{
		ID: "job-test-1", Type: domain.JobTypeRenewal, CertificateID: "mc-job-test",
		Status: domain.JobStatusPending, Attempts: 0, MaxAttempts: 3,
		ScheduledAt: now, CreatedAt: now,
	}

	// Create
	if err := jobRepo.Create(ctx, job); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get
	got, err := jobRepo.Get(ctx, "job-test-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Type != domain.JobTypeRenewal {
		t.Errorf("Type = %q, want %q", got.Type, domain.JobTypeRenewal)
	}

	// ListByStatus
	pending, err := jobRepo.ListByStatus(ctx, domain.JobStatusPending)
	if err != nil {
		t.Fatalf("ListByStatus failed: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("len(pending) = %d, want 1", len(pending))
	}

	// UpdateStatus
	errMsg := "test error"
	if err := jobRepo.UpdateStatus(ctx, "job-test-1", domain.JobStatusFailed, errMsg); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
	got, _ = jobRepo.Get(ctx, "job-test-1")
	if got.Status != domain.JobStatusFailed {
		t.Errorf("Status after update = %q, want %q", got.Status, domain.JobStatusFailed)
	}

	// GetPendingJobs (should be empty now)
	pendingJobs, err := jobRepo.GetPendingJobs(ctx, domain.JobTypeRenewal)
	if err != nil {
		t.Fatalf("GetPendingJobs failed: %v", err)
	}
	if len(pendingJobs) != 0 {
		t.Errorf("len(pendingJobs) = %d, want 0 (job is now Failed)", len(pendingJobs))
	}

	// ListByCertificate
	certJobs, err := jobRepo.ListByCertificate(ctx, "mc-job-test")
	if err != nil {
		t.Fatalf("ListByCertificate failed: %v", err)
	}
	if len(certJobs) != 1 {
		t.Errorf("len(certJobs) = %d, want 1", len(certJobs))
	}

	// Delete
	if err := jobRepo.Delete(ctx, "job-test-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

// ============================================================
// Revocation Repository Tests
// ============================================================

func TestRevocationRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewRevocationRepository(db)
	certRepo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "rev")

	// Create prerequisite cert
	cert := &domain.ManagedCertificate{
		ID: "mc-rev-test", Name: "rev-test", CommonName: "rev.example.com",
		SANs: []string{}, OwnerID: ownerID, TeamID: teamID,
		IssuerID: issuerID, RenewalPolicyID: policyID,
		Status: domain.CertificateStatusRevoked,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		t.Fatalf("Create cert failed: %v", err)
	}

	revocation := &domain.CertificateRevocation{
		ID: "rev-test-1", CertificateID: "mc-rev-test", SerialNumber: "DEADBEEF01",
		Reason: "keyCompromise", RevokedBy: "admin", RevokedAt: now,
		IssuerID: issuerID, CreatedAt: now,
	}

	// Create
	if err := repo.Create(ctx, revocation); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Idempotent create (ON CONFLICT DO NOTHING)
	if err := repo.Create(ctx, revocation); err != nil {
		t.Fatalf("Idempotent create failed: %v", err)
	}

	// GetByIssuerAndSerial — lookups are scoped to (issuer_id, serial) per RFC 5280 §5.2.3.
	got, err := repo.GetByIssuerAndSerial(ctx, issuerID, "DEADBEEF01")
	if err != nil {
		t.Fatalf("GetByIssuerAndSerial failed: %v", err)
	}
	if got.Reason != "keyCompromise" {
		t.Errorf("Reason = %q, want %q", got.Reason, "keyCompromise")
	}

	// ListAll
	all, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("len(all) = %d, want 1", len(all))
	}

	// ListByCertificate
	certRevs, err := repo.ListByCertificate(ctx, "mc-rev-test")
	if err != nil {
		t.Fatalf("ListByCertificate failed: %v", err)
	}
	if len(certRevs) != 1 {
		t.Errorf("len(certRevs) = %d, want 1", len(certRevs))
	}

	// MarkIssuerNotified
	if err := repo.MarkIssuerNotified(ctx, "rev-test-1"); err != nil {
		t.Fatalf("MarkIssuerNotified failed: %v", err)
	}
	got, _ = repo.GetByIssuerAndSerial(ctx, issuerID, "DEADBEEF01")
	if !got.IssuerNotified {
		t.Error("expected IssuerNotified=true after marking")
	}
}

// TestRevocationRepository_CrossIssuerSerialCollision verifies that the same
// serial number can coexist under two different issuers — RFC 5280 §5.2.3
// defines serial uniqueness only within a single CA, and certctl supports
// multi-issuer deployments where serial collisions across issuers are
// legitimate (e.g., Local CA serial 0x01 and Vault PKI serial 0x01).
//
// This test locks in the behavior change from migration 000012: the unique
// index is on (issuer_id, serial_number), not on serial_number alone.
func TestRevocationRepository_CrossIssuerSerialCollision(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewRevocationRepository(db)
	certRepo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	// First issuer + cert + revocation with serial "CAFEBABE01".
	ownerID1, teamID1, issuerID1, policyID1 := insertCertPrereqsRaw(t, db, ctx, "dup-a")
	cert1 := &domain.ManagedCertificate{
		ID: "mc-dup-a", Name: "dup-a", CommonName: "a.example.com",
		SANs: []string{}, OwnerID: ownerID1, TeamID: teamID1,
		IssuerID: issuerID1, RenewalPolicyID: policyID1,
		Status:    domain.CertificateStatusRevoked,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := certRepo.Create(ctx, cert1); err != nil {
		t.Fatalf("Create cert1 failed: %v", err)
	}
	if err := repo.Create(ctx, &domain.CertificateRevocation{
		ID: "rev-dup-a", CertificateID: "mc-dup-a", SerialNumber: "CAFEBABE01",
		Reason: "keyCompromise", RevokedBy: "admin", RevokedAt: now,
		IssuerID: issuerID1, CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create revocation under issuer1 failed: %v", err)
	}

	// Second issuer + cert + revocation with the SAME serial "CAFEBABE01".
	// Under the pre-000012 global-unique index this would silently drop via
	// ON CONFLICT DO NOTHING. Under the new (issuer_id, serial_number) scope
	// it must succeed.
	ownerID2, teamID2, issuerID2, policyID2 := insertCertPrereqsRaw(t, db, ctx, "dup-b")
	cert2 := &domain.ManagedCertificate{
		ID: "mc-dup-b", Name: "dup-b", CommonName: "b.example.com",
		SANs: []string{}, OwnerID: ownerID2, TeamID: teamID2,
		IssuerID: issuerID2, RenewalPolicyID: policyID2,
		Status:    domain.CertificateStatusRevoked,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := certRepo.Create(ctx, cert2); err != nil {
		t.Fatalf("Create cert2 failed: %v", err)
	}
	if err := repo.Create(ctx, &domain.CertificateRevocation{
		ID: "rev-dup-b", CertificateID: "mc-dup-b", SerialNumber: "CAFEBABE01",
		Reason: "superseded", RevokedBy: "admin", RevokedAt: now,
		IssuerID: issuerID2, CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create revocation under issuer2 failed (cross-issuer duplicate serial must be allowed): %v", err)
	}

	// Both revocations must be retrievable under their respective issuers.
	revA, err := repo.GetByIssuerAndSerial(ctx, issuerID1, "CAFEBABE01")
	if err != nil {
		t.Fatalf("GetByIssuerAndSerial(issuer1) failed: %v", err)
	}
	if revA.ID != "rev-dup-a" || revA.Reason != "keyCompromise" {
		t.Errorf("issuer1 lookup returned wrong row: id=%q reason=%q", revA.ID, revA.Reason)
	}

	revB, err := repo.GetByIssuerAndSerial(ctx, issuerID2, "CAFEBABE01")
	if err != nil {
		t.Fatalf("GetByIssuerAndSerial(issuer2) failed: %v", err)
	}
	if revB.ID != "rev-dup-b" || revB.Reason != "superseded" {
		t.Errorf("issuer2 lookup returned wrong row: id=%q reason=%q", revB.ID, revB.Reason)
	}

	// ListAll should see both revocations.
	all, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("len(all) = %d, want 2 (cross-issuer duplicate serials)", len(all))
	}

	// Same-issuer idempotency guard still works (ON CONFLICT DO NOTHING on
	// (issuer_id, serial_number) — re-inserting the same (issuer, serial)
	// pair must not error and must not duplicate the row).
	if err := repo.Create(ctx, &domain.CertificateRevocation{
		ID: "rev-dup-a-repeat", CertificateID: "mc-dup-a", SerialNumber: "CAFEBABE01",
		Reason: "superseded", RevokedBy: "admin", RevokedAt: now,
		IssuerID: issuerID1, CreatedAt: now,
	}); err != nil {
		t.Fatalf("Idempotent create under same issuer failed: %v", err)
	}
	all, _ = repo.ListAll(ctx)
	if len(all) != 2 {
		t.Errorf("len(all) after idempotent re-insert = %d, want 2", len(all))
	}
}

// ============================================================
// Team Repository Tests
// ============================================================

func TestTeamRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewTeamRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	team := &domain.Team{
		ID: "team-test", Name: "Platform", Description: "Platform team",
		CreatedAt: now, UpdatedAt: now,
	}

	if err := repo.Create(ctx, team); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := repo.Get(ctx, "team-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Platform" {
		t.Errorf("Name = %q, want %q", got.Name, "Platform")
	}

	teams, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(teams) != 1 {
		t.Errorf("len(teams) = %d, want 1", len(teams))
	}

	team.Description = "Updated"
	team.UpdatedAt = time.Now().Truncate(time.Microsecond)
	if err := repo.Update(ctx, team); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if err := repo.Delete(ctx, "team-test"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

// ============================================================
// Owner Repository Tests
// ============================================================

func TestOwnerRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ownerRepo := postgres.NewOwnerRepository(db)
	teamRepo := postgres.NewTeamRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	// Create team first (FK)
	team := &domain.Team{
		ID: "team-owner-test", Name: "Owner Test Team",
		CreatedAt: now, UpdatedAt: now,
	}
	teamRepo.Create(ctx, team)

	owner := &domain.Owner{
		ID: "o-test", Name: "Alice", Email: "alice@example.com",
		TeamID: "team-owner-test", CreatedAt: now, UpdatedAt: now,
	}

	if err := ownerRepo.Create(ctx, owner); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := ownerRepo.Get(ctx, "o-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", got.Email, "alice@example.com")
	}

	owners, err := ownerRepo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(owners) != 1 {
		t.Errorf("len(owners) = %d, want 1", len(owners))
	}

	if err := ownerRepo.Delete(ctx, "o-test"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

// ============================================================
// Policy Repository Tests
// ============================================================

func TestPolicyRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewPolicyRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)
	config, _ := json.Marshal(map[string]interface{}{"domains": []string{"*.example.com"}})

	rule := &domain.PolicyRule{
		ID: "pol-test", Name: "Test Policy", Type: domain.PolicyTypeAllowedDomains,
		Config: config, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}

	// CreateRule
	if err := repo.CreateRule(ctx, rule); err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// GetRule
	got, err := repo.GetRule(ctx, "pol-test")
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}
	if got.Type != domain.PolicyTypeAllowedDomains {
		t.Errorf("Type = %q, want %q", got.Type, domain.PolicyTypeAllowedDomains)
	}

	// ListRules
	rules, err := repo.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("len(rules) = %d, want 1", len(rules))
	}

	// UpdateRule
	rule.Enabled = false
	rule.UpdatedAt = time.Now().Truncate(time.Microsecond)
	if err := repo.UpdateRule(ctx, rule); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	// DeleteRule
	if err := repo.DeleteRule(ctx, "pol-test"); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}
}

// ============================================================
// Audit Repository Tests
// ============================================================

func TestAuditRepository_CreateAndList(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewAuditRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	event := &domain.AuditEvent{
		ID: "audit-test-1", Actor: "admin", ActorType: "User",
		Action: "certificate_created", ResourceType: "certificate",
		ResourceID: "mc-test", Details: json.RawMessage(`{"cn":"test.example.com"}`),
		Timestamp: now,
	}

	if err := repo.Create(ctx, event); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// List with filter
	events, err := repo.List(ctx, &repository.AuditFilter{
		Actor: "admin", Page: 1, PerPage: 10,
	})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("len(events) = %d, want 1", len(events))
	}

	// List with empty filter
	events, err = repo.List(ctx, &repository.AuditFilter{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("List all failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("len(events) = %d, want 1", len(events))
	}
}

// ============================================================
// Profile Repository Tests
// ============================================================

func TestProfileRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewProfileRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	profile := &domain.CertificateProfile{
		ID: "prof-test", Name: "Test Profile", Description: "Test",
		AllowedKeyAlgorithms: []domain.KeyAlgorithmRule{
			{Algorithm: "RSA", MinSize: 2048},
			{Algorithm: "ECDSA", MinSize: 256},
		},
		MaxTTLSeconds:     86400,
		AllowedEKUs:       []string{"serverAuth"},
		AllowShortLived:   false,
		Enabled:           true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := repo.Create(ctx, profile); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := repo.Get(ctx, "prof-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.MaxTTLSeconds != 86400 {
		t.Errorf("MaxTTLSeconds = %d, want 86400", got.MaxTTLSeconds)
	}
	if len(got.AllowedKeyAlgorithms) != 2 {
		t.Errorf("len(AllowedKeyAlgorithms) = %d, want 2", len(got.AllowedKeyAlgorithms))
	}

	profiles, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(profiles) != 1 {
		t.Errorf("len(profiles) = %d, want 1", len(profiles))
	}

	if err := repo.Delete(ctx, "prof-test"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

// ============================================================
// Notification Repository Tests
// ============================================================

func TestNotificationRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNotificationRepository(db)
	certRepo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "notif")

	// Create prerequisite cert (notification references it via FK)
	cert := &domain.ManagedCertificate{
		ID: "mc-notif-test", Name: "notif-test", CommonName: "notif.example.com",
		SANs: []string{}, OwnerID: ownerID, TeamID: teamID,
		IssuerID: issuerID, RenewalPolicyID: policyID,
		Status: domain.CertificateStatusActive,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		t.Fatalf("Create cert failed: %v", err)
	}

	certID := "mc-notif-test"

	notif := &domain.NotificationEvent{
		ID: "notif-test-1", Type: domain.NotificationTypeExpirationWarning,
		CertificateID: &certID, Channel: domain.NotificationChannelEmail,
		Recipient: "admin@example.com", Message: "Cert expiring in 7 days",
		Status: "pending", CreatedAt: now,
	}

	if err := repo.Create(ctx, notif); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// List
	notifications, err := repo.List(ctx, &repository.NotificationFilter{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(notifications) != 1 {
		t.Errorf("len(notifications) = %d, want 1", len(notifications))
	}

	// UpdateStatus
	sentAt := time.Now().Truncate(time.Microsecond)
	if err := repo.UpdateStatus(ctx, "notif-test-1", "sent", sentAt); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
}

// ============================================================
// Discovery Repository Tests
// ============================================================

func TestDiscoveryRepository_ScanCRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewDiscoveryRepository(db)
	agentRepo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	// Create agent first (FK for discovered certs)
	agent := &domain.Agent{
		ID: "agent-disc-test", Name: "disc-agent", Hostname: "disc-host",
		Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "dischash",
	}
	agentRepo.Create(ctx, agent)

	completedAt := now.Add(5 * time.Second)
	scan := &domain.DiscoveryScan{
		ID: "scan-test-1", AgentID: "agent-disc-test",
		Directories:       []string{"/etc/ssl", "/opt/certs"},
		CertificatesFound: 10, CertificatesNew: 3, ErrorsCount: 1,
		ScanDurationMs: 1500, StartedAt: now, CompletedAt: &completedAt,
	}

	// CreateScan
	if err := repo.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan failed: %v", err)
	}

	// GetScan
	got, err := repo.GetScan(ctx, "scan-test-1")
	if err != nil {
		t.Fatalf("GetScan failed: %v", err)
	}
	if got.CertificatesFound != 10 {
		t.Errorf("CertificatesFound = %d, want 10", got.CertificatesFound)
	}
	if len(got.Directories) != 2 {
		t.Errorf("len(Directories) = %d, want 2", len(got.Directories))
	}

	// ListScans
	scans, total, err := repo.ListScans(ctx, "agent-disc-test", 1, 10)
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if total != 1 || len(scans) != 1 {
		t.Errorf("ListScans total=%d len=%d, want 1/1", total, len(scans))
	}

	// ListScans with empty agent (all)
	_, total, err = repo.ListScans(ctx, "", 1, 10)
	if err != nil {
		t.Fatalf("ListScans all failed: %v", err)
	}
	if total != 1 {
		t.Errorf("ListScans all total=%d, want 1", total)
	}
}

func TestDiscoveryRepository_DiscoveredCertCRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewDiscoveryRepository(db)
	agentRepo := postgres.NewAgentRepository(db)
	certRepo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)
	notBefore := now.Add(-30 * 24 * time.Hour)
	notAfter := now.Add(60 * 24 * time.Hour)

	// Create agent first
	agent := &domain.Agent{
		ID: "agent-dcert-test", Name: "dcert-agent", Hostname: "dcert-host",
		Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "dcerthash",
	}
	agentRepo.Create(ctx, agent)

	// Create a managed cert for the "claim" test (FK on managed_certificate_id)
	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "dcert")
	linkedCert := &domain.ManagedCertificate{
		ID: "mc-linked-cert", Name: "linked-cert", CommonName: "linked.example.com",
		SANs: []string{}, OwnerID: ownerID, TeamID: teamID,
		IssuerID: issuerID, RenewalPolicyID: policyID,
		Status: domain.CertificateStatusActive,
		ExpiresAt: now.Add(90 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := certRepo.Create(ctx, linkedCert); err != nil {
		t.Fatalf("Create linked cert failed: %v", err)
	}

	cert := &domain.DiscoveredCertificate{
		ID: "dc-test-1", FingerprintSHA256: "abcdef1234567890",
		CommonName: "disc.example.com", SANs: []string{"disc.example.com", "www.disc.example.com"},
		SerialNumber: "DISC01", IssuerDN: "CN=Test CA", SubjectDN: "CN=disc.example.com",
		NotBefore: &notBefore, NotAfter: &notAfter, KeyAlgorithm: "RSA", KeySize: 2048,
		IsCA: false, PEMData: "---PEM---", SourcePath: "/etc/ssl/certs/disc.pem",
		SourceFormat: "PEM", AgentID: "agent-dcert-test",
		Status: domain.DiscoveryStatusUnmanaged,
		FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now,
	}

	// CreateDiscovered — new insert
	isNew, err := repo.CreateDiscovered(ctx, cert)
	if err != nil {
		t.Fatalf("CreateDiscovered failed: %v", err)
	}
	if !isNew {
		t.Error("expected isNew=true for first insert")
	}

	// CreateDiscovered again — upsert (same fingerprint+agent+path)
	cert.ID = "dc-test-1-dup" // different ID, same fingerprint+agent+path
	cert.LastSeenAt = now.Add(1 * time.Hour)
	isNew, err = repo.CreateDiscovered(ctx, cert)
	if err != nil {
		t.Fatalf("CreateDiscovered upsert failed: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false for upsert")
	}

	// GetDiscovered
	got, err := repo.GetDiscovered(ctx, "dc-test-1")
	if err != nil {
		t.Fatalf("GetDiscovered failed: %v", err)
	}
	if got.CommonName != "disc.example.com" {
		t.Errorf("CommonName = %q, want %q", got.CommonName, "disc.example.com")
	}
	if len(got.SANs) != 2 {
		t.Errorf("len(SANs) = %d, want 2", len(got.SANs))
	}

	// ListDiscovered
	certs, total, err := repo.ListDiscovered(ctx, &repository.DiscoveryFilter{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("ListDiscovered failed: %v", err)
	}
	_ = certs // used in subsequent calls
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}

	// ListDiscovered by agent
	certs, total, err = repo.ListDiscovered(ctx, &repository.DiscoveryFilter{
		AgentID: "agent-dcert-test", Page: 1, PerPage: 10,
	})
	if err != nil {
		t.Fatalf("ListDiscovered by agent failed: %v", err)
	}
	if total != 1 || len(certs) != 1 {
		t.Errorf("agent filter: total=%d len=%d, want 1/1", total, len(certs))
	}

	// ListDiscovered by status
	certs, _, err = repo.ListDiscovered(ctx, &repository.DiscoveryFilter{
		Status: "Unmanaged", Page: 1, PerPage: 10,
	})
	if err != nil {
		t.Fatalf("ListDiscovered by status failed: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("status filter len = %d, want 1", len(certs))
	}

	// GetByFingerprint
	fpCerts, err := repo.GetByFingerprint(ctx, "abcdef1234567890")
	if err != nil {
		t.Fatalf("GetByFingerprint failed: %v", err)
	}
	if len(fpCerts) != 1 {
		t.Errorf("len(fpCerts) = %d, want 1", len(fpCerts))
	}

	// CountByStatus
	counts, err := repo.CountByStatus(ctx)
	if err != nil {
		t.Fatalf("CountByStatus failed: %v", err)
	}
	if counts["Unmanaged"] != 1 {
		t.Errorf("Unmanaged count = %d, want 1", counts["Unmanaged"])
	}

	// UpdateDiscoveredStatus to Dismissed
	if err := repo.UpdateDiscoveredStatus(ctx, "dc-test-1", domain.DiscoveryStatusDismissed, ""); err != nil {
		t.Fatalf("UpdateDiscoveredStatus to Dismissed failed: %v", err)
	}
	got, _ = repo.GetDiscovered(ctx, "dc-test-1")
	if got.Status != domain.DiscoveryStatusDismissed {
		t.Errorf("Status = %q, want %q", got.Status, domain.DiscoveryStatusDismissed)
	}
	if got.DismissedAt == nil {
		t.Error("expected DismissedAt to be set")
	}

	// UpdateDiscoveredStatus to Managed with link
	if err := repo.UpdateDiscoveredStatus(ctx, "dc-test-1", domain.DiscoveryStatusManaged, "mc-linked-cert"); err != nil {
		t.Fatalf("UpdateDiscoveredStatus to Managed failed: %v", err)
	}
	got, _ = repo.GetDiscovered(ctx, "dc-test-1")
	if got.Status != domain.DiscoveryStatusManaged {
		t.Errorf("Status = %q, want %q", got.Status, domain.DiscoveryStatusManaged)
	}
	if got.ManagedCertificateID != "mc-linked-cert" {
		t.Errorf("ManagedCertificateID = %q, want %q", got.ManagedCertificateID, "mc-linked-cert")
	}

	// UpdateDiscoveredStatus NotFound
	if err := repo.UpdateDiscoveredStatus(ctx, "nonexistent", domain.DiscoveryStatusDismissed, ""); err == nil {
		t.Error("expected error for nonexistent status update")
	}
}

// ============================================================
// Network Scan Repository Tests
// ============================================================

func TestNetworkScanRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewNetworkScanRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	target := &domain.NetworkScanTarget{
		ID: "ns-test-1", Name: "Internal Network",
		CIDRs: []string{"10.0.0.0/24", "192.168.1.0/24"},
		Ports: []int64{443, 8443},
		Enabled: true, ScanIntervalHours: 6, TimeoutMs: 5000,
		CreatedAt: now, UpdatedAt: now,
	}

	// Create
	if err := repo.Create(ctx, target); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get
	got, err := repo.Get(ctx, "ns-test-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Internal Network" {
		t.Errorf("Name = %q, want %q", got.Name, "Internal Network")
	}
	if len(got.CIDRs) != 2 {
		t.Errorf("len(CIDRs) = %d, want 2", len(got.CIDRs))
	}
	if len(got.Ports) != 2 {
		t.Errorf("len(Ports) = %d, want 2", len(got.Ports))
	}
	if got.LastScanAt != nil {
		t.Error("expected LastScanAt to be nil initially")
	}

	// List
	targets, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("len(targets) = %d, want 1", len(targets))
	}

	// ListEnabled
	enabled, err := repo.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled failed: %v", err)
	}
	if len(enabled) != 1 {
		t.Errorf("len(enabled) = %d, want 1", len(enabled))
	}

	// Update
	target.Name = "Updated Network"
	target.Enabled = false
	if err := repo.Update(ctx, target); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = repo.Get(ctx, "ns-test-1")
	if got.Name != "Updated Network" {
		t.Errorf("Name after update = %q, want %q", got.Name, "Updated Network")
	}

	// ListEnabled after disabling
	enabled, err = repo.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled after disable failed: %v", err)
	}
	if len(enabled) != 0 {
		t.Errorf("len(enabled) after disable = %d, want 0", len(enabled))
	}

	// UpdateScanResults
	scanTime := now.Add(1 * time.Hour)
	if err := repo.UpdateScanResults(ctx, "ns-test-1", scanTime, 1500, 5); err != nil {
		t.Fatalf("UpdateScanResults failed: %v", err)
	}
	got, _ = repo.Get(ctx, "ns-test-1")
	if got.LastScanAt == nil {
		t.Fatal("expected LastScanAt to be set after scan results update")
	}
	if got.LastScanCertsFound == nil || *got.LastScanCertsFound != 5 {
		t.Errorf("LastScanCertsFound = %v, want 5", got.LastScanCertsFound)
	}
	if got.LastScanDurationMs == nil || *got.LastScanDurationMs != 1500 {
		t.Errorf("LastScanDurationMs = %v, want 1500", got.LastScanDurationMs)
	}

	// Delete
	if err := repo.Delete(ctx, "ns-test-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = repo.Get(ctx, "ns-test-1")
	if err == nil {
		t.Error("expected error after delete")
	}

	// Delete NotFound
	if err := repo.Delete(ctx, "nonexistent"); err == nil {
		t.Error("expected error for nonexistent delete")
	}

	// Update NotFound
	target.ID = "nonexistent"
	if err := repo.Update(ctx, target); err == nil {
		t.Error("expected error for nonexistent update")
	}
}

// ============================================================
// Agent Group Repository Tests
// ============================================================

func TestAgentGroupRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	groupRepo := postgres.NewAgentGroupRepository(db)
	agentRepo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)

	group := &domain.AgentGroup{
		ID: "grp-test", Name: "Linux Servers", Description: "All Linux agents",
		MatchOS: "linux", MatchArchitecture: "amd64",
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}

	// Create
	if err := groupRepo.Create(ctx, group); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get
	got, err := groupRepo.Get(ctx, "grp-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Linux Servers" {
		t.Errorf("Name = %q, want %q", got.Name, "Linux Servers")
	}
	if got.MatchOS != "linux" {
		t.Errorf("MatchOS = %q, want %q", got.MatchOS, "linux")
	}

	// List
	groups, err := groupRepo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("len(groups) = %d, want 1", len(groups))
	}

	// Update
	group.Description = "Updated"
	if err := groupRepo.Update(ctx, group); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = groupRepo.Get(ctx, "grp-test")
	if got.Description != "Updated" {
		t.Errorf("Description after update = %q, want %q", got.Description, "Updated")
	}

	// Member management — create an agent first
	agent := &domain.Agent{
		ID: "agent-grp-test", Name: "grp-agent", Hostname: "grp-host",
		Status: domain.AgentStatusOnline, RegisteredAt: now, APIKeyHash: "grphash",
	}
	agentRepo.Create(ctx, agent)

	// AddMember
	if err := groupRepo.AddMember(ctx, "grp-test", "agent-grp-test", "include"); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	// AddMember again (ON CONFLICT upsert)
	if err := groupRepo.AddMember(ctx, "grp-test", "agent-grp-test", "exclude"); err != nil {
		t.Fatalf("AddMember upsert failed: %v", err)
	}

	// ListMembers (only includes — agent was changed to exclude, so should be empty)
	members, err := groupRepo.ListMembers(ctx, "grp-test")
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("len(members) = %d, want 0 (agent is excluded)", len(members))
	}

	// Change back to include
	if err := groupRepo.AddMember(ctx, "grp-test", "agent-grp-test", "include"); err != nil {
		t.Fatalf("AddMember back to include failed: %v", err)
	}
	members, err = groupRepo.ListMembers(ctx, "grp-test")
	if err != nil {
		t.Fatalf("ListMembers after re-include failed: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("len(members) = %d, want 1", len(members))
	}

	// RemoveMember
	if err := groupRepo.RemoveMember(ctx, "grp-test", "agent-grp-test"); err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}
	members, _ = groupRepo.ListMembers(ctx, "grp-test")
	if len(members) != 0 {
		t.Errorf("len(members) after remove = %d, want 0", len(members))
	}

	// Delete
	if err := groupRepo.Delete(ctx, "grp-test"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = groupRepo.Get(ctx, "grp-test")
	if err == nil {
		t.Error("expected error after delete")
	}

	// Delete NotFound
	if err := groupRepo.Delete(ctx, "nonexistent"); err == nil {
		t.Error("expected error for nonexistent delete")
	}
}

// ============================================================
// Empty Result Set Tests
// ============================================================

func TestEmptyResultSets(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	ctx := context.Background()

	// Certificates
	certRepo := postgres.NewCertificateRepository(db)
	certs, total, err := certRepo.List(ctx, nil)
	if err != nil {
		t.Fatalf("cert List failed: %v", err)
	}
	if total != 0 || len(certs) != 0 {
		t.Errorf("expected empty cert list, got total=%d len=%d", total, len(certs))
	}

	// Agents
	agentRepo := postgres.NewAgentRepository(db)
	agents, err := agentRepo.List(ctx)
	if err != nil {
		t.Fatalf("agent List failed: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected empty agent list, got %d", len(agents))
	}

	// Revocations
	revRepo := postgres.NewRevocationRepository(db)
	revs, err := revRepo.ListAll(ctx)
	if err != nil {
		t.Fatalf("revocation ListAll failed: %v", err)
	}
	if len(revs) != 0 {
		t.Errorf("expected empty revocations, got %d", len(revs))
	}

	// Discovery
	discRepo := postgres.NewDiscoveryRepository(db)
	dcerts, dtotal, err := discRepo.ListDiscovered(ctx, &repository.DiscoveryFilter{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("discovery ListDiscovered failed: %v", err)
	}
	if dtotal != 0 || len(dcerts) != 0 {
		t.Errorf("expected empty discovered certs, got total=%d len=%d", dtotal, len(dcerts))
	}
	counts, err := discRepo.CountByStatus(ctx)
	if err != nil {
		t.Fatalf("discovery CountByStatus failed: %v", err)
	}
	if len(counts) != 0 {
		t.Errorf("expected empty status counts, got %d", len(counts))
	}

	// Network Scans
	nsRepo := postgres.NewNetworkScanRepository(db)
	nsTargets, err := nsRepo.List(ctx)
	if err != nil {
		t.Fatalf("network scan List failed: %v", err)
	}
	if len(nsTargets) != 0 {
		t.Errorf("expected empty network scan targets, got %d", len(nsTargets))
	}

	// Agent Groups
	grpRepo := postgres.NewAgentGroupRepository(db)
	groups, err := grpRepo.List(ctx)
	if err != nil {
		t.Fatalf("agent group List failed: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected empty agent groups, got %d", len(groups))
	}
}

// ============================================================
// H-6 (CWE-362) Claim-Based Concurrency Tests
//
// These tests exercise the `SELECT ... FOR UPDATE SKIP LOCKED` worker-queue pattern
// introduced to remediate the H-6 race condition. They validate two invariants:
//
//  1. Disjoint claim: under concurrent callers, no Pending row is returned to more
//     than one worker (i.e. each claim is exclusive).
//  2. State transition: claimed rows are atomically flipped to Running inside the
//     same transaction that locked them, so a subsequent query must see the row in
//     the Running state and no other worker can observe it as Pending again.
//
// Skipped automatically in `-short` mode (CI) since they require a real PostgreSQL
// instance and take ~1s under contention.
// ============================================================

// seedPendingJobs creates n Pending renewal jobs against a single prerequisite
// certificate and returns the generated job IDs.
func seedPendingJobs(t *testing.T, ctx context.Context, db *sql.DB, certID string, n int) []string {
	t.Helper()
	certRepo := postgres.NewCertificateRepository(db)
	jobRepo := postgres.NewJobRepository(db)

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, certID)

	now := time.Now().Truncate(time.Microsecond)
	cert := &domain.ManagedCertificate{
		ID: "mc-" + certID, Name: certID, CommonName: certID + ".example.com",
		SANs: []string{}, OwnerID: ownerID, TeamID: teamID,
		IssuerID: issuerID, RenewalPolicyID: policyID,
		Status:    domain.CertificateStatusActive,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		t.Fatalf("seedPendingJobs: create cert failed: %v", err)
	}

	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		job := &domain.Job{
			ID:            fmt.Sprintf("job-%s-%03d", certID, i),
			Type:          domain.JobTypeRenewal,
			CertificateID: "mc-" + certID,
			Status:        domain.JobStatusPending,
			Attempts:      0,
			MaxAttempts:   3,
			ScheduledAt:   now,
			CreatedAt:     now,
		}
		if err := jobRepo.Create(ctx, job); err != nil {
			t.Fatalf("seedPendingJobs: create job %d failed: %v", i, err)
		}
		ids = append(ids, job.ID)
	}
	return ids
}

// TestJobRepository_ClaimPendingJobs_FlipsToRunning validates the basic claim
// semantics: a single call transitions Pending rows to Running atomically, and
// the rows returned to the caller reflect the post-update state.
func TestJobRepository_ClaimPendingJobs_FlipsToRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires PostgreSQL")
	}
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	jobRepo := postgres.NewJobRepository(db)
	ctx := context.Background()

	seeded := seedPendingJobs(t, ctx, db, "claimflip", 5)

	claimed, err := jobRepo.ClaimPendingJobs(ctx, domain.JobTypeRenewal, 0)
	if err != nil {
		t.Fatalf("ClaimPendingJobs failed: %v", err)
	}
	if len(claimed) != len(seeded) {
		t.Fatalf("len(claimed) = %d, want %d", len(claimed), len(seeded))
	}

	// In-memory return values must reflect the transitioned state.
	for _, j := range claimed {
		if j.Status != domain.JobStatusRunning {
			t.Errorf("claimed job %s Status = %q, want %q", j.ID, j.Status, domain.JobStatusRunning)
		}
	}

	// Persisted rows must also be Running — a fresh Get must not see Pending.
	for _, id := range seeded {
		got, err := jobRepo.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get(%s) failed: %v", id, err)
		}
		if got.Status != domain.JobStatusRunning {
			t.Errorf("persisted job %s Status = %q, want %q", id, got.Status, domain.JobStatusRunning)
		}
	}

	// A subsequent claim must return zero rows — nothing is Pending anymore.
	residual, err := jobRepo.ClaimPendingJobs(ctx, domain.JobTypeRenewal, 0)
	if err != nil {
		t.Fatalf("residual ClaimPendingJobs failed: %v", err)
	}
	if len(residual) != 0 {
		t.Errorf("residual claims = %d, want 0 (all should be Running now)", len(residual))
	}
}

// TestJobRepository_ClaimPendingJobs_ConcurrentDisjoint validates the core H-6
// invariant: under concurrent access, no row is handed to more than one worker.
//
// The test seeds M Pending jobs, fans out N goroutines each of which loops
// calling ClaimPendingJobs with limit=1, and finally asserts the union of all
// claimed IDs is exactly M with zero duplicates. Workers that transiently
// observe zero rows (because peers are holding the only remaining rows) re-check
// an atomic progress counter before exiting, so transient SKIP-LOCKED zeros do
// not cause premature termination.
func TestJobRepository_ClaimPendingJobs_ConcurrentDisjoint(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires PostgreSQL")
	}
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	jobRepo := postgres.NewJobRepository(db)
	ctx := context.Background()

	const M = 40 // seeded Pending jobs
	const N = 8  // concurrent workers
	seeded := seedPendingJobs(t, ctx, db, "concurrent", M)
	seededSet := make(map[string]bool, M)
	for _, id := range seeded {
		seededSet[id] = true
	}

	var (
		totalClaimed int64
		allClaims    []string
		mu           sync.Mutex
		wg           sync.WaitGroup
	)

	for w := 0; w < N; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			emptyStreak := 0
			for iter := 0; iter < M*4; iter++ { // generous ceiling to prevent hangs
				claimed, err := jobRepo.ClaimPendingJobs(ctx, domain.JobTypeRenewal, 1)
				if err != nil {
					t.Errorf("worker %d ClaimPendingJobs failed: %v", worker, err)
					return
				}
				if len(claimed) == 0 {
					// Transient zero (peer holds lock) vs. terminal zero (all claimed).
					// Bail only once the shared counter proves work is done, but guard
					// with a streak so we don't spin forever under starvation.
					if atomic.LoadInt64(&totalClaimed) >= int64(M) {
						return
					}
					emptyStreak++
					if emptyStreak >= 20 {
						return
					}
					time.Sleep(500 * time.Microsecond)
					continue
				}
				emptyStreak = 0
				mu.Lock()
				for _, j := range claimed {
					if j.Status != domain.JobStatusRunning {
						t.Errorf("worker %d got job %s in Status=%q (want Running) — claim did not flip state", worker, j.ID, j.Status)
					}
					allClaims = append(allClaims, j.ID)
				}
				mu.Unlock()
				atomic.AddInt64(&totalClaimed, int64(len(claimed)))
			}
		}(w)
	}
	wg.Wait()

	// Invariant 1: no duplicate claims across the worker pool.
	seen := make(map[string]int, len(allClaims))
	for _, id := range allClaims {
		seen[id]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("job %s claimed %d times — SKIP LOCKED invariant violated", id, count)
		}
	}

	// Invariant 2: every seeded job appears in the claim set exactly once.
	if len(seen) != M {
		t.Errorf("distinct claimed IDs = %d, want %d (all seeded jobs must be claimed)", len(seen), M)
	}
	for id := range seededSet {
		if seen[id] == 0 {
			t.Errorf("seeded job %s was never claimed by any worker", id)
		}
	}

	// Invariant 3: persisted state reflects the transition — every seeded row
	// is now Running; none is Pending.
	for id := range seededSet {
		got, err := jobRepo.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get(%s) failed: %v", id, err)
		}
		if got.Status != domain.JobStatusRunning {
			t.Errorf("job %s Status = %q, want %q", id, got.Status, domain.JobStatusRunning)
		}
	}

	// Final progress counter must match the total number of seeded jobs.
	if got := atomic.LoadInt64(&totalClaimed); got != int64(M) {
		t.Errorf("totalClaimed = %d, want %d", got, M)
	}
}

// TestJobRepository_ClaimPendingByAgentID_TransitionsDeployments validates the
// agent-scoped claim variant: Pending deployment rows for a given agent flip to
// Running; AwaitingCSR rows are returned but their state is preserved (the CSR
// submission path drives their next transition).
func TestJobRepository_ClaimPendingByAgentID_TransitionsDeployments(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires PostgreSQL")
	}
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	jobRepo := postgres.NewJobRepository(db)
	agentRepo := postgres.NewAgentRepository(db)
	ctx := context.Background()

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "agentclaim")

	now := time.Now().Truncate(time.Microsecond)
	cert := &domain.ManagedCertificate{
		ID: "mc-agentclaim", Name: "agentclaim", CommonName: "agentclaim.example.com",
		SANs: []string{}, OwnerID: ownerID, TeamID: teamID,
		IssuerID: issuerID, RenewalPolicyID: policyID,
		Status:    domain.CertificateStatusActive,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := postgres.NewCertificateRepository(db).Create(ctx, cert); err != nil {
		t.Fatalf("create cert failed: %v", err)
	}

	agent := &domain.Agent{
		ID:           "a-claim",
		Name:         "claim-agent",
		Hostname:     "claim-agent-host",
		Status:       domain.AgentStatusOnline,
		RegisteredAt: now,
		APIKeyHash:   "hash-claim",
	}
	if err := agentRepo.Create(ctx, agent); err != nil {
		t.Fatalf("create agent failed: %v", err)
	}

	agentID := agent.ID
	mkJob := func(id string, typ domain.JobType, status domain.JobStatus) *domain.Job {
		return &domain.Job{
			ID: id, Type: typ, CertificateID: cert.ID,
			AgentID:     &agentID,
			Status:      status,
			Attempts:    0,
			MaxAttempts: 3,
			ScheduledAt: now,
			CreatedAt:   now,
		}
	}
	jobs := []*domain.Job{
		mkJob("job-agentclaim-dep-1", domain.JobTypeDeployment, domain.JobStatusPending),
		mkJob("job-agentclaim-dep-2", domain.JobTypeDeployment, domain.JobStatusPending),
		mkJob("job-agentclaim-csr-1", domain.JobTypeRenewal, domain.JobStatusAwaitingCSR),
		// A Pending Renewal (not Deployment) must NOT be returned by the per-agent claim.
		mkJob("job-agentclaim-ren-pending", domain.JobTypeRenewal, domain.JobStatusPending),
	}
	for _, j := range jobs {
		if err := jobRepo.Create(ctx, j); err != nil {
			t.Fatalf("create job %s failed: %v", j.ID, err)
		}
	}

	claimed, err := jobRepo.ClaimPendingByAgentID(ctx, agentID)
	if err != nil {
		t.Fatalf("ClaimPendingByAgentID failed: %v", err)
	}
	// Expect exactly the 2 deployments + 1 AwaitingCSR.
	if len(claimed) != 3 {
		t.Fatalf("len(claimed) = %d, want 3 (2 deployments + 1 AwaitingCSR)", len(claimed))
	}

	statusByID := map[string]domain.JobStatus{}
	for _, j := range claimed {
		statusByID[j.ID] = j.Status
	}
	// Both deployments must be Running in the returned slice (in-memory reflection).
	for _, id := range []string{"job-agentclaim-dep-1", "job-agentclaim-dep-2"} {
		if statusByID[id] != domain.JobStatusRunning {
			t.Errorf("returned deployment %s Status = %q, want Running", id, statusByID[id])
		}
	}
	// AwaitingCSR must remain AwaitingCSR.
	if statusByID["job-agentclaim-csr-1"] != domain.JobStatusAwaitingCSR {
		t.Errorf("returned AwaitingCSR Status = %q, want AwaitingCSR", statusByID["job-agentclaim-csr-1"])
	}
	// The unrelated Pending Renewal must not be returned.
	if _, ok := statusByID["job-agentclaim-ren-pending"]; ok {
		t.Errorf("Pending Renewal job was returned by ClaimPendingByAgentID — scope violation")
	}

	// Persisted state: deployments Running, AwaitingCSR unchanged, Pending Renewal still Pending.
	for id, want := range map[string]domain.JobStatus{
		"job-agentclaim-dep-1":       domain.JobStatusRunning,
		"job-agentclaim-dep-2":       domain.JobStatusRunning,
		"job-agentclaim-csr-1":       domain.JobStatusAwaitingCSR,
		"job-agentclaim-ren-pending": domain.JobStatusPending,
	} {
		got, err := jobRepo.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get(%s) failed: %v", id, err)
		}
		if got.Status != want {
			t.Errorf("persisted %s Status = %q, want %q", id, got.Status, want)
		}
	}
}
