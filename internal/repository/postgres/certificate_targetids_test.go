// Package postgres_test — integration tests for M-7: Certificate.TargetIDs
// must be populated from certificate_target_mappings on read.
//
// Before M-7 the repository scan helper never consulted the junction table, so
// Get / List / GetExpiringCertificates always returned empty TargetIDs even when
// rows existed in certificate_target_mappings. These tests exercise all three
// read paths end-to-end against a real PostgreSQL 16 container.
//
// Runs against the shared testcontainer from testutil_test.go. Skipped when
// `-short` is set (CI uses short mode; local runs pick it up by default).
package postgres_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// insertAgentAndTargetsRaw creates one agent and N deployment_targets, returns
// the agent ID and the list of target IDs (in insertion order).
func insertAgentAndTargetsRaw(t *testing.T, db *sql.DB, ctx context.Context, suffix string, n int) (agentID string, targetIDs []string) {
	t.Helper()
	now := time.Now().Truncate(time.Microsecond)
	agentID = "agent-" + suffix

	_, err := db.ExecContext(ctx, `
		INSERT INTO agents (id, name, hostname, status, registered_at, api_key_hash)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, agentID, "agent-"+suffix, "host-"+suffix, "online", now, "hash-"+suffix)
	if err != nil {
		t.Fatalf("insertAgent failed: %v", err)
	}

	for i := 0; i < n; i++ {
		tid := "t-" + suffix + "-" + intToStr(i)
		_, err := db.ExecContext(ctx, `
			INSERT INTO deployment_targets (id, name, type, agent_id, config, enabled, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, tid, tid, "NGINX", agentID, []byte(`{}`), true, now, now)
		if err != nil {
			t.Fatalf("insertTarget %d failed: %v", i, err)
		}
		targetIDs = append(targetIDs, tid)
	}
	return agentID, targetIDs
}

// intToStr converts a non-negative int to its decimal string.
// Local helper to avoid importing strconv for a single use.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// insertCertificateRow writes a minimal managed_certificates row via raw SQL.
// Bypasses the repository Create so we can isolate read-path tests from any
// write-path behavior. managed_certificates.sans is TEXT[], written here as an
// empty array literal.
func insertCertificateRow(t *testing.T, db *sql.DB, ctx context.Context, certID, ownerID, teamID, issuerID, policyID string, expiresAt time.Time) {
	t.Helper()
	now := time.Now().Truncate(time.Microsecond)
	_, err := db.ExecContext(ctx, `
		INSERT INTO managed_certificates (
			id, name, common_name, sans, environment,
			owner_id, team_id, issuer_id, renewal_policy_id,
			status, expires_at, tags,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, ARRAY[]::TEXT[], $4,
			$5, $6, $7, $8,
			$9, $10, $11,
			$12, $13
		)
	`,
		certID, certID, certID+".example.com", "production",
		ownerID, teamID, issuerID, policyID,
		string(domain.CertificateStatusActive), expiresAt, []byte(`{}`),
		now, now,
	)
	if err != nil {
		t.Fatalf("insertCertificateRow failed: %v", err)
	}
}

// insertMapping writes a single row into certificate_target_mappings via raw SQL.
func insertMapping(t *testing.T, db *sql.DB, ctx context.Context, certID, targetID string) {
	t.Helper()
	_, err := db.ExecContext(ctx,
		`INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ($1, $2)`,
		certID, targetID)
	if err != nil {
		t.Fatalf("insertMapping(%s, %s) failed: %v", certID, targetID, err)
	}
}

// --------------------------------------------------------------------
// Get() — single-cert read path
// --------------------------------------------------------------------

// TestGet_PopulatesTargetIDs_NoMappings: no mapping rows → TargetIDs must be
// an empty slice, not nil, so JSON serialisation emits "[]".
func TestGet_PopulatesTargetIDs_NoMappings(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "getnone")
	certID := "mc-getnone"
	insertCertificateRow(t, db, ctx, certID, ownerID, teamID, issuerID, policyID, time.Now().Add(30*24*time.Hour))

	got, err := repo.Get(ctx, certID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.TargetIDs == nil {
		t.Fatalf("TargetIDs = nil, want empty slice (JSON serialises nil as null and [] as [])")
	}
	if len(got.TargetIDs) != 0 {
		t.Errorf("len(TargetIDs) = %d, want 0; got %v", len(got.TargetIDs), got.TargetIDs)
	}
}

// TestGet_PopulatesTargetIDs_SingleTarget: one mapping → one entry.
func TestGet_PopulatesTargetIDs_SingleTarget(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "getone")
	_, targets := insertAgentAndTargetsRaw(t, db, ctx, "getone", 1)

	certID := "mc-getone"
	insertCertificateRow(t, db, ctx, certID, ownerID, teamID, issuerID, policyID, time.Now().Add(30*24*time.Hour))
	insertMapping(t, db, ctx, certID, targets[0])

	got, err := repo.Get(ctx, certID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(got.TargetIDs) != 1 {
		t.Fatalf("len(TargetIDs) = %d, want 1; got %v", len(got.TargetIDs), got.TargetIDs)
	}
	if got.TargetIDs[0] != targets[0] {
		t.Errorf("TargetIDs[0] = %q, want %q", got.TargetIDs[0], targets[0])
	}
}

// TestGet_PopulatesTargetIDs_MultipleTargets: many mappings → sorted by target_id ASC.
func TestGet_PopulatesTargetIDs_MultipleTargets(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "getmany")
	_, targets := insertAgentAndTargetsRaw(t, db, ctx, "getmany", 3)

	certID := "mc-getmany"
	insertCertificateRow(t, db, ctx, certID, ownerID, teamID, issuerID, policyID, time.Now().Add(30*24*time.Hour))
	// Insert mappings in reverse order to confirm ORDER BY target_id ASC in the query.
	insertMapping(t, db, ctx, certID, targets[2])
	insertMapping(t, db, ctx, certID, targets[0])
	insertMapping(t, db, ctx, certID, targets[1])

	got, err := repo.Get(ctx, certID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(got.TargetIDs) != 3 {
		t.Fatalf("len(TargetIDs) = %d, want 3; got %v", len(got.TargetIDs), got.TargetIDs)
	}
	// Ascending order: t-getmany-0, t-getmany-1, t-getmany-2
	want := []string{targets[0], targets[1], targets[2]}
	for i, tid := range want {
		if got.TargetIDs[i] != tid {
			t.Errorf("TargetIDs[%d] = %q, want %q (full: %v)", i, got.TargetIDs[i], tid, got.TargetIDs)
		}
	}
}

// --------------------------------------------------------------------
// List() — batch read path, must avoid N+1
// --------------------------------------------------------------------

// TestList_PopulatesTargetIDs_BatchFetch: three certs with different mapping counts;
// all must have their TargetIDs populated correctly, and the cert with no mapping
// must get an empty (non-nil) slice.
func TestList_PopulatesTargetIDs_BatchFetch(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "listbatch")
	_, targets := insertAgentAndTargetsRaw(t, db, ctx, "listbatch", 3)

	certA := "mc-list-a"
	certB := "mc-list-b"
	certC := "mc-list-c"
	insertCertificateRow(t, db, ctx, certA, ownerID, teamID, issuerID, policyID, time.Now().Add(30*24*time.Hour))
	insertCertificateRow(t, db, ctx, certB, ownerID, teamID, issuerID, policyID, time.Now().Add(30*24*time.Hour))
	insertCertificateRow(t, db, ctx, certC, ownerID, teamID, issuerID, policyID, time.Now().Add(30*24*time.Hour))

	// certA → 2 targets (t-0, t-1)
	insertMapping(t, db, ctx, certA, targets[0])
	insertMapping(t, db, ctx, certA, targets[1])
	// certB → 1 target (t-2)
	insertMapping(t, db, ctx, certB, targets[2])
	// certC → 0 targets

	got, total, err := repo.List(ctx, nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if total < 3 {
		t.Fatalf("total = %d, want >= 3", total)
	}

	want := map[string][]string{
		certA: {targets[0], targets[1]},
		certB: {targets[2]},
		certC: {},
	}
	seen := map[string]bool{}
	for _, c := range got {
		exp, ok := want[c.ID]
		if !ok {
			continue
		}
		seen[c.ID] = true
		if c.TargetIDs == nil {
			t.Errorf("cert %s: TargetIDs = nil, want %v", c.ID, exp)
			continue
		}
		if len(c.TargetIDs) != len(exp) {
			t.Errorf("cert %s: len(TargetIDs) = %d, want %d (got %v, want %v)", c.ID, len(c.TargetIDs), len(exp), c.TargetIDs, exp)
			continue
		}
		for i, tid := range exp {
			if c.TargetIDs[i] != tid {
				t.Errorf("cert %s: TargetIDs[%d] = %q, want %q", c.ID, i, c.TargetIDs[i], tid)
			}
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("cert %s missing from List() result", id)
		}
	}
}

// --------------------------------------------------------------------
// GetExpiringCertificates() — scheduler read path
// --------------------------------------------------------------------

// TestGetExpiringCertificates_PopulatesTargetIDs: expiring certs must also carry
// their mapping information so renewal-triggered deployments can route work.
func TestGetExpiringCertificates_PopulatesTargetIDs(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCertificateRepository(db)
	ctx := context.Background()

	ownerID, teamID, issuerID, policyID := insertCertPrereqsRaw(t, db, ctx, "expiring")
	_, targets := insertAgentAndTargetsRaw(t, db, ctx, "expiring", 2)

	// Two expiring certs (expires in 3 days). Threshold = 7 days → both selected.
	certA := "mc-exp-a"
	certB := "mc-exp-b"
	expiresSoon := time.Now().Add(3 * 24 * time.Hour)
	insertCertificateRow(t, db, ctx, certA, ownerID, teamID, issuerID, policyID, expiresSoon)
	insertCertificateRow(t, db, ctx, certB, ownerID, teamID, issuerID, policyID, expiresSoon)

	insertMapping(t, db, ctx, certA, targets[0])
	insertMapping(t, db, ctx, certA, targets[1])
	// certB has no mappings.

	threshold := time.Now().Add(7 * 24 * time.Hour)
	got, err := repo.GetExpiringCertificates(ctx, threshold)
	if err != nil {
		t.Fatalf("GetExpiringCertificates failed: %v", err)
	}

	found := map[string]*domain.ManagedCertificate{}
	for _, c := range got {
		found[c.ID] = c
	}

	a, ok := found[certA]
	if !ok {
		t.Fatalf("cert %s not in expiring list", certA)
	}
	if len(a.TargetIDs) != 2 || a.TargetIDs[0] != targets[0] || a.TargetIDs[1] != targets[1] {
		t.Errorf("cert %s: TargetIDs = %v, want %v", certA, a.TargetIDs, []string{targets[0], targets[1]})
	}

	b, ok := found[certB]
	if !ok {
		t.Fatalf("cert %s not in expiring list", certB)
	}
	if b.TargetIDs == nil {
		t.Errorf("cert %s: TargetIDs = nil, want empty slice", certB)
	}
	if len(b.TargetIDs) != 0 {
		t.Errorf("cert %s: len(TargetIDs) = %d, want 0", certB, len(b.TargetIDs))
	}
}
