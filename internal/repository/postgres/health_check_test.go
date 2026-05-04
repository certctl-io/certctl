package postgres_test

// Integration tests for HealthCheckRepository (M48). Closes the L-1
// coverage gap flagged in coverage-gap-audit.md: the 453-line repository
// shipped in M48 had zero live-DB tests, leaving 11 methods — including
// the time-sensitive ListDueForCheck, PurgeHistory, and GetSummary —
// without migration-pinned regression protection. These tests exercise
// every method against a real Postgres 16 container through the same
// schema-per-test harness used by repo_test.go.

import (
	"context"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// newHealthCheck builds a minimal EndpointHealthCheck the repository will
// accept. All time-pointer fields are left nil so callers can override
// exactly the bits each subtest cares about — Create stores nil pointers
// as NULL, which is what ListDueForCheck's `last_checked_at IS NULL`
// branch relies on.
func newHealthCheck(id, endpoint string, status domain.HealthStatus, enabled bool) *domain.EndpointHealthCheck {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.EndpointHealthCheck{
		ID:                id,
		Endpoint:          endpoint,
		Status:            status,
		DegradedThreshold: 2,
		DownThreshold:     5,
		CheckIntervalSecs: 300,
		Enabled:           enabled,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// TestHealthCheckRepository_CRUD covers Create → Get → Update → Delete on
// the nominal path. Also verifies the sql.NullTime round-trip: a check
// created without timestamps comes back with nil pointers (not
// zero-valued time.Time) so downstream Go code can distinguish "never
// probed" from "probed at epoch".
func TestHealthCheckRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewHealthCheckRepository(db)
	ctx := context.Background()

	check := newHealthCheck("hc-crud", "example.com:443", domain.HealthStatusHealthy, true)
	check.ExpectedFingerprint = "sha256:expected"
	check.ResponseTimeMs = 42

	if err := repo.Create(ctx, check); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := repo.Get(ctx, "hc-crud")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Endpoint != "example.com:443" {
		t.Errorf("Endpoint = %q, want example.com:443", got.Endpoint)
	}
	if got.Status != domain.HealthStatusHealthy {
		t.Errorf("Status = %q, want %q", got.Status, domain.HealthStatusHealthy)
	}
	if got.ExpectedFingerprint != "sha256:expected" {
		t.Errorf("ExpectedFingerprint = %q, want sha256:expected", got.ExpectedFingerprint)
	}
	if got.CheckIntervalSecs != 300 {
		t.Errorf("CheckIntervalSecs = %d, want 300", got.CheckIntervalSecs)
	}
	if got.LastCheckedAt != nil {
		t.Errorf("LastCheckedAt = %v, want nil (never probed)", got.LastCheckedAt)
	}

	// Update: status transition + observed fingerprint assignment.
	// Update() rewrites UpdatedAt to time.Now() regardless of what we
	// send, so record the pre-call timestamp to assert monotonic advance.
	preUpdate := got.UpdatedAt
	time.Sleep(2 * time.Millisecond) // ensure a measurable delta
	got.Status = domain.HealthStatusDegraded
	got.ObservedFingerprint = "sha256:observed"
	got.ConsecutiveFailures = 2
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	got2, err := repo.Get(ctx, "hc-crud")
	if err != nil {
		t.Fatalf("Get after Update failed: %v", err)
	}
	if got2.Status != domain.HealthStatusDegraded {
		t.Errorf("Status after Update = %q, want %q", got2.Status, domain.HealthStatusDegraded)
	}
	if got2.ObservedFingerprint != "sha256:observed" {
		t.Errorf("ObservedFingerprint after Update = %q, want sha256:observed", got2.ObservedFingerprint)
	}
	if got2.ConsecutiveFailures != 2 {
		t.Errorf("ConsecutiveFailures after Update = %d, want 2", got2.ConsecutiveFailures)
	}
	if !got2.UpdatedAt.After(preUpdate) {
		t.Errorf("UpdatedAt did not advance: pre=%v post=%v", preUpdate, got2.UpdatedAt)
	}

	if err := repo.Delete(ctx, "hc-crud"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := repo.Get(ctx, "hc-crud"); err == nil {
		t.Errorf("Get after Delete returned nil error, want not-found")
	}
}

// TestHealthCheckRepository_GetByEndpoint verifies the secondary lookup
// path used by AutoCreateFromDeployment to decide whether to INSERT or
// UPDATE. Missing endpoints return an error (not a nil cert) so the
// service layer can branch safely.
func TestHealthCheckRepository_GetByEndpoint(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewHealthCheckRepository(db)
	ctx := context.Background()

	check := newHealthCheck("hc-byep", "svc.internal:443", domain.HealthStatusHealthy, true)
	if err := repo.Create(ctx, check); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := repo.GetByEndpoint(ctx, "svc.internal:443")
	if err != nil {
		t.Fatalf("GetByEndpoint failed: %v", err)
	}
	if got.ID != "hc-byep" {
		t.Errorf("ID = %q, want hc-byep", got.ID)
	}

	if _, err := repo.GetByEndpoint(ctx, "never-seen.example.com:443"); err == nil {
		t.Errorf("GetByEndpoint on unknown endpoint returned nil error")
	}
}

// TestHealthCheckRepository_List_Filters seeds rows across the filter
// axes (status, certificate_id, enabled) and asserts each branch of the
// WHERE builder, plus the Page/PerPage pagination shim.
func TestHealthCheckRepository_List_Filters(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewHealthCheckRepository(db)
	ctx := context.Background()

	// Create prereq managed certificate so certificate_id FK can be
	// populated on one row — proves the filter path joins on a real ID.
	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "hclist")
	certID := "mc-hc-list"
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO managed_certificates (id, name, common_name, sans, environment, owner_id, team_id, issuer_id, renewal_policy_id, status, expires_at, tags, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		certID, "hc-list-cert", "hc.example.com", "{}", "production",
		ownerID, teamID, issuerID, policyID,
		string(domain.CertificateStatusActive), now.Add(90*24*time.Hour), "{}",
		now, now); err != nil {
		t.Fatalf("seed managed_certificate: %v", err)
	}

	// 4 rows: healthy+enabled+cert, degraded+enabled, down+disabled, unknown+enabled.
	rows := []*domain.EndpointHealthCheck{
		newHealthCheck("hc-list-1", "a.example.com:443", domain.HealthStatusHealthy, true),
		newHealthCheck("hc-list-2", "b.example.com:443", domain.HealthStatusDegraded, true),
		newHealthCheck("hc-list-3", "c.example.com:443", domain.HealthStatusDown, false),
		newHealthCheck("hc-list-4", "d.example.com:443", domain.HealthStatusUnknown, true),
	}
	rows[0].CertificateID = &certID
	for _, r := range rows {
		if err := repo.Create(ctx, r); err != nil {
			t.Fatalf("Create %s: %v", r.ID, err)
		}
	}

	// Filter: status=healthy → 1 result.
	got, total, err := repo.List(ctx, &repository.HealthCheckFilter{Status: string(domain.HealthStatusHealthy)})
	if err != nil {
		t.Fatalf("List status=healthy: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].ID != "hc-list-1" {
		t.Errorf("status=healthy: total=%d rows=%d want 1/1 with hc-list-1", total, len(got))
	}

	// Filter: certificate_id → 1 result.
	got, total, err = repo.List(ctx, &repository.HealthCheckFilter{CertificateID: certID})
	if err != nil {
		t.Fatalf("List certificate_id: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].ID != "hc-list-1" {
		t.Errorf("certificate_id filter: total=%d rows=%d want 1/1", total, len(got))
	}

	// Filter: enabled=false → 1 result.
	disabled := false
	got, total, err = repo.List(ctx, &repository.HealthCheckFilter{Enabled: &disabled})
	if err != nil {
		t.Fatalf("List enabled=false: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].ID != "hc-list-3" {
		t.Errorf("enabled=false: total=%d rows=%d want 1/1 with hc-list-3", total, len(got))
	}

	// Pagination: per_page=2 → first page has 2, total reflects all 4.
	got, total, err = repo.List(ctx, &repository.HealthCheckFilter{Page: 1, PerPage: 2})
	if err != nil {
		t.Fatalf("List paginated: %v", err)
	}
	if total != 4 {
		t.Errorf("paginated total = %d, want 4", total)
	}
	if len(got) != 2 {
		t.Errorf("paginated rows = %d, want 2", len(got))
	}
}

// TestHealthCheckRepository_ListDueForCheck seeds all four branches of
// the WHERE clause — (a) enabled+null → due, (b) enabled+past-due → due,
// (c) enabled+recent → not due, (d) disabled+null → excluded — and
// asserts the ORDER BY last_checked_at NULLS FIRST, ASC ordering.
//
// This is the hot path the scheduler's 8th loop hits every 60 seconds;
// a correctness regression here silently fails every probe.
func TestHealthCheckRepository_ListDueForCheck(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewHealthCheckRepository(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	pastDue := now.Add(-10 * time.Minute) // > 300s ago, enabled → due
	recent := now.Add(-30 * time.Second)  // < 300s ago, enabled → not due

	// (a) enabled + null last_checked_at — NULLS FIRST puts this first
	a := newHealthCheck("hc-due-a", "a.example.com:443", domain.HealthStatusUnknown, true)
	// (b) enabled + past-due last_checked_at
	b := newHealthCheck("hc-due-b", "b.example.com:443", domain.HealthStatusHealthy, true)
	b.LastCheckedAt = &pastDue
	// (c) enabled + recent last_checked_at — must NOT appear
	c := newHealthCheck("hc-due-c", "c.example.com:443", domain.HealthStatusHealthy, true)
	c.LastCheckedAt = &recent
	// (d) disabled + null last_checked_at — must NOT appear
	d := newHealthCheck("hc-due-d", "d.example.com:443", domain.HealthStatusUnknown, false)

	for _, r := range []*domain.EndpointHealthCheck{a, b, c, d} {
		if err := repo.Create(ctx, r); err != nil {
			t.Fatalf("Create %s: %v", r.ID, err)
		}
	}

	due, err := repo.ListDueForCheck(ctx)
	if err != nil {
		t.Fatalf("ListDueForCheck: %v", err)
	}
	if len(due) != 2 {
		ids := make([]string, 0, len(due))
		for _, r := range due {
			ids = append(ids, r.ID)
		}
		t.Fatalf("due rows = %d (%v), want exactly 2 (hc-due-a, hc-due-b)", len(due), ids)
	}
	// NULLS FIRST: variant (a) should precede variant (b).
	if due[0].ID != "hc-due-a" {
		t.Errorf("due[0].ID = %q, want hc-due-a (NULLS FIRST)", due[0].ID)
	}
	if due[1].ID != "hc-due-b" {
		t.Errorf("due[1].ID = %q, want hc-due-b", due[1].ID)
	}
	// Sanity: neither excluded row leaked through.
	for _, r := range due {
		if r.ID == "hc-due-c" {
			t.Errorf("recent-probed row hc-due-c leaked into due set")
		}
		if r.ID == "hc-due-d" {
			t.Errorf("disabled row hc-due-d leaked into due set")
		}
	}
}

// TestHealthCheckRepository_RecordHistory_GetHistory asserts FIFO
// insertion with DESC retrieval (most-recent-first) and the explicit
// limit clamp.
func TestHealthCheckRepository_RecordHistory_GetHistory(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewHealthCheckRepository(db)
	ctx := context.Background()

	parent := newHealthCheck("hc-hist", "hist.example.com:443", domain.HealthStatusHealthy, true)
	if err := repo.Create(ctx, parent); err != nil {
		t.Fatalf("Create parent: %v", err)
	}

	base := time.Now().UTC().Truncate(time.Microsecond)
	entries := []*domain.HealthHistoryEntry{
		{ID: "hh-1", HealthCheckID: "hc-hist", Status: string(domain.HealthStatusHealthy), ResponseTimeMs: 10, CheckedAt: base.Add(-3 * time.Minute)},
		{ID: "hh-2", HealthCheckID: "hc-hist", Status: string(domain.HealthStatusDegraded), ResponseTimeMs: 20, CheckedAt: base.Add(-2 * time.Minute)},
		{ID: "hh-3", HealthCheckID: "hc-hist", Status: string(domain.HealthStatusHealthy), ResponseTimeMs: 30, CheckedAt: base.Add(-1 * time.Minute)},
	}
	for _, e := range entries {
		if err := repo.RecordHistory(ctx, e); err != nil {
			t.Fatalf("RecordHistory %s: %v", e.ID, err)
		}
	}

	// limit=2 → newest 2 in DESC order: hh-3, hh-2.
	got, err := repo.GetHistory(ctx, "hc-hist", 2)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2", len(got))
	}
	if got[0].ID != "hh-3" || got[1].ID != "hh-2" {
		t.Errorf("order = [%s, %s], want [hh-3, hh-2]", got[0].ID, got[1].ID)
	}

	// limit=0 → default 100 → returns all 3.
	got, err = repo.GetHistory(ctx, "hc-hist", 0)
	if err != nil {
		t.Fatalf("GetHistory limit=0: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("limit=0 rows = %d, want 3", len(got))
	}
}

// TestHealthCheckRepository_PurgeHistory exercises the retention-sweep
// hot path (scheduler calls this once/day). 5 past + 5 future straddling
// the cutoff exposes both sides of the < comparator — an off-by-one
// regression here would either nuke live data or skip rows the retention
// policy was meant to remove.
func TestHealthCheckRepository_PurgeHistory(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewHealthCheckRepository(db)
	ctx := context.Background()

	parent := newHealthCheck("hc-purge", "purge.example.com:443", domain.HealthStatusHealthy, true)
	if err := repo.Create(ctx, parent); err != nil {
		t.Fatalf("Create parent: %v", err)
	}

	cutoff := time.Now().UTC().Truncate(time.Microsecond)

	// 5 rows BEFORE cutoff (should be purged).
	for i := 0; i < 5; i++ {
		e := &domain.HealthHistoryEntry{
			ID:            "hh-past-" + string(rune('0'+i)),
			HealthCheckID: "hc-purge",
			Status:        string(domain.HealthStatusHealthy),
			CheckedAt:     cutoff.Add(time.Duration(-10-i) * time.Minute),
		}
		if err := repo.RecordHistory(ctx, e); err != nil {
			t.Fatalf("RecordHistory past %d: %v", i, err)
		}
	}
	// 5 rows AFTER cutoff (should remain).
	for i := 0; i < 5; i++ {
		e := &domain.HealthHistoryEntry{
			ID:            "hh-future-" + string(rune('0'+i)),
			HealthCheckID: "hc-purge",
			Status:        string(domain.HealthStatusHealthy),
			CheckedAt:     cutoff.Add(time.Duration(1+i) * time.Minute),
		}
		if err := repo.RecordHistory(ctx, e); err != nil {
			t.Fatalf("RecordHistory future %d: %v", i, err)
		}
	}

	deleted, err := repo.PurgeHistory(ctx, cutoff)
	if err != nil {
		t.Fatalf("PurgeHistory: %v", err)
	}
	if deleted != 5 {
		t.Errorf("deleted = %d, want 5", deleted)
	}

	remaining, err := repo.GetHistory(ctx, "hc-purge", 100)
	if err != nil {
		t.Fatalf("GetHistory after purge: %v", err)
	}
	if len(remaining) != 5 {
		t.Errorf("remaining = %d, want 5", len(remaining))
	}
}

// TestHealthCheckRepository_GetSummary seeds all 5 HealthStatus values
// in a non-uniform distribution so the GROUP BY status branch-table gets
// exercised on each arm. The Total field is computed inside the
// aggregator — its drift would not surface unless we assert it too.
func TestHealthCheckRepository_GetSummary(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewHealthCheckRepository(db)
	ctx := context.Background()

	seed := map[domain.HealthStatus]int{
		domain.HealthStatusHealthy:      3,
		domain.HealthStatusDegraded:     2,
		domain.HealthStatusDown:         2,
		domain.HealthStatusCertMismatch: 1,
		domain.HealthStatusUnknown:      1,
	}
	idx := 0
	for status, count := range seed {
		for i := 0; i < count; i++ {
			check := newHealthCheck(
				"hc-sum-"+string(rune('a'+idx)),
				"sum.example.com:443",
				status,
				true,
			)
			// Endpoint uniqueness isn't enforced by the schema but making
			// it unique documents intent and rules out false-positives.
			check.Endpoint = check.ID + "-" + check.Endpoint
			if err := repo.Create(ctx, check); err != nil {
				t.Fatalf("Create %s: %v", check.ID, err)
			}
			idx++
		}
	}

	summary, err := repo.GetSummary(ctx)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary.Healthy != 3 {
		t.Errorf("Healthy = %d, want 3", summary.Healthy)
	}
	if summary.Degraded != 2 {
		t.Errorf("Degraded = %d, want 2", summary.Degraded)
	}
	if summary.Down != 2 {
		t.Errorf("Down = %d, want 2", summary.Down)
	}
	if summary.CertMismatch != 1 {
		t.Errorf("CertMismatch = %d, want 1", summary.CertMismatch)
	}
	if summary.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", summary.Unknown)
	}
	if summary.Total != 9 {
		t.Errorf("Total = %d, want 9 (3+2+2+1+1)", summary.Total)
	}
}
