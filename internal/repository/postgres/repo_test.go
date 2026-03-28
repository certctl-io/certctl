// Package postgres_test provides repository integration tests covering 15 of 17
// PostgreSQL repository files. Each test function exercises CRUD operations,
// edge cases, and deduplication logic against a real database.
package postgres_test

import (
	"context"
	"encoding/json"
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

	cert := &domain.ManagedCertificate{
		ID:          "mc-test-crud",
		Name:        "test-cert",
		CommonName:  "test.example.com",
		SANs:        []string{"test.example.com", "www.test.example.com"},
		Environment: "production",
		IssuerID:    "iss-local",
		Status:      domain.CertificateStatusActive,
		ExpiresAt:   expires,
		Tags:        map[string]string{"team": "platform"},
		CreatedAt:   now,
		UpdatedAt:   now,
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
			ID:          tc.id,
			Name:        tc.id,
			CommonName:  tc.id + ".example.com",
			SANs:        []string{},
			Environment: tc.env,
			IssuerID:    "iss-local",
			Status:      tc.status,
			ExpiresAt:   now.Add(30 * 24 * time.Hour),
			Tags:        map[string]string{},
			CreatedAt:   now,
			UpdatedAt:   now,
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
	certs, total, err = repo.List(ctx, &repository.CertificateFilter{Environment: "production"})
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

	// Create parent cert
	cert := &domain.ManagedCertificate{
		ID: "mc-ver-test", Name: "ver-test", CommonName: "ver.example.com",
		SANs: []string{}, IssuerID: "iss-local", Status: domain.CertificateStatusActive,
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
			SANs: []string{}, IssuerID: "iss-local", Status: domain.CertificateStatusActive,
			ExpiresAt: tc.expires, Tags: map[string]string{},
			CreatedAt: now, UpdatedAt: now,
		}
		repo.Create(ctx, cert)
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

	// Create prerequisite cert
	cert := &domain.ManagedCertificate{
		ID: "mc-job-test", Name: "job-test", CommonName: "job.example.com",
		SANs: []string{}, IssuerID: "iss-local", Status: domain.CertificateStatusActive,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	certRepo.Create(ctx, cert)

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

	// Create prerequisite cert
	cert := &domain.ManagedCertificate{
		ID: "mc-rev-test", Name: "rev-test", CommonName: "rev.example.com",
		SANs: []string{}, IssuerID: "iss-local", Status: domain.CertificateStatusRevoked,
		ExpiresAt: now.Add(30 * 24 * time.Hour), Tags: map[string]string{},
		CreatedAt: now, UpdatedAt: now,
	}
	certRepo.Create(ctx, cert)

	revocation := &domain.CertificateRevocation{
		ID: "rev-test-1", CertificateID: "mc-rev-test", SerialNumber: "DEADBEEF01",
		Reason: "keyCompromise", RevokedBy: "admin", RevokedAt: now,
		IssuerID: "iss-local", CreatedAt: now,
	}

	// Create
	if err := repo.Create(ctx, revocation); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Idempotent create (ON CONFLICT DO NOTHING)
	if err := repo.Create(ctx, revocation); err != nil {
		t.Fatalf("Idempotent create failed: %v", err)
	}

	// GetBySerial
	got, err := repo.GetBySerial(ctx, "DEADBEEF01")
	if err != nil {
		t.Fatalf("GetBySerial failed: %v", err)
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
	got, _ = repo.GetBySerial(ctx, "DEADBEEF01")
	if !got.IssuerNotified {
		t.Error("expected IssuerNotified=true after marking")
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
		ResourceID: "mc-test", Details: `{"cn":"test.example.com"}`,
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
	ctx := context.Background()

	now := time.Now().Truncate(time.Microsecond)
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
	scans, total, err = repo.ListScans(ctx, "", 1, 10)
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
