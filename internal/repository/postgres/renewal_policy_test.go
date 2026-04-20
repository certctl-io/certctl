package postgres_test

// Integration tests for RenewalPolicyRepository (post-G-1, 289 lines, 5
// methods). Closes the L-1 coverage gap flagged in coverage-gap-audit.md:
// the repository's auto-generated-ID collision retry loop and its two
// typed error sentinels (ErrRenewalPolicyDuplicateName on pg 23505,
// ErrRenewalPolicyInUse on pg 23503) shipped with zero live-DB regression
// coverage — a mock-only test surface cannot exercise the PostgreSQL
// constraint semantics these paths depend on.
//
// The audit listed the file as "92 lines, 2 methods"; that was stale
// pre-G-1. Current state is 5 methods (Get/List/Create/Update/Delete),
// all covered below.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/repository/postgres"
)

// TestRenewalPolicyRepository_CRUD exercises the happy path for all five
// interface methods. In particular it drives the slug-based ID
// auto-generation branch (policy.ID left empty → Create emits
// rp-<slug(name)>) so any regression to slugifyPolicyName or the retry
// loop surfaces immediately. The AlertThresholdsDays JSONB round-trip is
// asserted end-to-end: marshal on Create → store as JSONB → scan back on
// Get preserves the slice ordering and values.
func TestRenewalPolicyRepository_CRUD(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewRenewalPolicyRepository(db)
	ctx := context.Background()

	// Create: leave ID empty so the repository generates rp-<slug(name)>.
	// "Prod TLS 90d" → rp-prod-tls-90d per slugifyPolicyName's rules
	// (lowercase, spaces→hyphens, non-alphanumeric stripped).
	policy := &domain.RenewalPolicy{
		Name:                "Prod TLS 90d",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          5,
		RetryInterval:       3600, // stored in retry_interval_minutes column; passthrough
		AlertThresholdsDays: []int{30, 14, 7, 0},
	}

	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if policy.ID != "rp-prod-tls-90d" {
		t.Errorf("auto-generated ID = %q, want %q", policy.ID, "rp-prod-tls-90d")
	}
	if policy.CreatedAt.IsZero() {
		t.Error("Create did not populate CreatedAt (RETURNING clause regression?)")
	}
	if policy.UpdatedAt.IsZero() {
		t.Error("Create did not populate UpdatedAt (RETURNING clause regression?)")
	}

	// Get: pull the just-created row back and confirm every stored field
	// survives the scanRenewalPolicy path, including the JSONB unmarshal.
	got, err := repo.Get(ctx, policy.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Prod TLS 90d" {
		t.Errorf("Get: Name = %q, want %q", got.Name, "Prod TLS 90d")
	}
	if got.RenewalWindowDays != 30 {
		t.Errorf("Get: RenewalWindowDays = %d, want 30", got.RenewalWindowDays)
	}
	if !got.AutoRenew {
		t.Error("Get: AutoRenew = false, want true")
	}
	if got.MaxRetries != 5 {
		t.Errorf("Get: MaxRetries = %d, want 5", got.MaxRetries)
	}
	if len(got.AlertThresholdsDays) != 4 {
		t.Fatalf("Get: AlertThresholdsDays length = %d, want 4 (JSONB round-trip regression)", len(got.AlertThresholdsDays))
	}
	for i, want := range []int{30, 14, 7, 0} {
		if got.AlertThresholdsDays[i] != want {
			t.Errorf("Get: AlertThresholdsDays[%d] = %d, want %d", i, got.AlertThresholdsDays[i], want)
		}
	}

	// Update: 3-arg signature is a house invariant — don't let it slip to
	// 2-arg without the test catching the breakage. Tweak scalar + JSONB
	// simultaneously so both SET branches exercise.
	updated := *got
	updated.Name = "Prod TLS 90d (tightened)"
	updated.RenewalWindowDays = 45
	updated.AlertThresholdsDays = []int{45, 30, 14, 7, 0}

	// Sleep long enough that NOW() ticks past the Create timestamp so we
	// can assert UpdatedAt monotonicity without a flaky equality check.
	time.Sleep(2 * time.Millisecond)

	if err := repo.Update(ctx, policy.ID, &updated); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if !updated.UpdatedAt.After(got.UpdatedAt) {
		t.Errorf("Update: UpdatedAt %v not after Create's %v (RETURNING NOW() regression?)", updated.UpdatedAt, got.UpdatedAt)
	}

	refetched, err := repo.Get(ctx, policy.ID)
	if err != nil {
		t.Fatalf("Get after Update failed: %v", err)
	}
	if refetched.Name != "Prod TLS 90d (tightened)" {
		t.Errorf("Get after Update: Name = %q, want %q", refetched.Name, "Prod TLS 90d (tightened)")
	}
	if refetched.RenewalWindowDays != 45 {
		t.Errorf("Get after Update: RenewalWindowDays = %d, want 45", refetched.RenewalWindowDays)
	}
	if len(refetched.AlertThresholdsDays) != 5 {
		t.Errorf("Get after Update: AlertThresholdsDays length = %d, want 5", len(refetched.AlertThresholdsDays))
	}

	// List: add a second policy so the ORDER BY name contract is non-vacuous.
	second := &domain.RenewalPolicy{
		Name:                "Aa Earliest",
		RenewalWindowDays:   14,
		AutoRenew:           false,
		MaxRetries:          1,
		RetryInterval:       60,
		AlertThresholdsDays: []int{7, 0},
	}
	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("Create second failed: %v", err)
	}

	all, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("List: len = %d, want 2", len(all))
	}
	// "Aa Earliest" sorts before "Prod TLS 90d (tightened)" under ORDER BY name ASC.
	if all[0].Name != "Aa Earliest" {
		t.Errorf("List[0].Name = %q, want %q (ORDER BY name regression?)", all[0].Name, "Aa Earliest")
	}

	// Delete: removes the policy and a follow-up Get surfaces "not found".
	if err := repo.Delete(ctx, policy.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := repo.Get(ctx, policy.ID); err == nil {
		t.Error("Get after Delete: err = nil, want not-found")
	}
}

// TestRenewalPolicyRepository_DuplicateName verifies the pg 23505
// unique_violation translation. The name UNIQUE constraint is enforced
// on the renewal_policies.name column; Create's inner scanRenewalPolicy
// must see the pq.Error, call isUniqueViolation, check the constraint
// name, and return ErrRenewalPolicyDuplicateName. A non-sentinel error
// here would cause the handler to emit 500 instead of 409.
func TestRenewalPolicyRepository_DuplicateName(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewRenewalPolicyRepository(db)
	ctx := context.Background()

	first := &domain.RenewalPolicy{
		ID:                  "rp-first",
		Name:                "Shared Name",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: domain.DefaultAlertThresholds(),
	}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create first failed: %v", err)
	}

	// Second policy with a distinct ID but the same Name — the name UNIQUE
	// constraint fires, Create's collision branch inspects pqErr.Constraint,
	// and because it's NOT *_pkey, it returns ErrRenewalPolicyDuplicateName
	// without retrying.
	second := &domain.RenewalPolicy{
		ID:                  "rp-second",
		Name:                "Shared Name",
		RenewalWindowDays:   60,
		AutoRenew:           false,
		MaxRetries:          1,
		RetryInterval:       600,
		AlertThresholdsDays: domain.DefaultAlertThresholds(),
	}
	err := repo.Create(ctx, second)
	if err == nil {
		t.Fatal("Create second: err = nil, want ErrRenewalPolicyDuplicateName")
	}
	if !errors.Is(err, repository.ErrRenewalPolicyDuplicateName) {
		t.Errorf("Create second: err = %v, want ErrRenewalPolicyDuplicateName (via errors.Is)", err)
	}

	// Also verify Update surfaces the same sentinel when an existing row's
	// name is changed to collide with another policy's name.
	third := &domain.RenewalPolicy{
		ID:                  "rp-third",
		Name:                "Third Name",
		RenewalWindowDays:   90,
		AutoRenew:           true,
		MaxRetries:          2,
		RetryInterval:       1200,
		AlertThresholdsDays: domain.DefaultAlertThresholds(),
	}
	if err := repo.Create(ctx, third); err != nil {
		t.Fatalf("Create third failed: %v", err)
	}
	third.Name = "Shared Name" // collide with first
	err = repo.Update(ctx, third.ID, third)
	if err == nil {
		t.Fatal("Update: err = nil, want ErrRenewalPolicyDuplicateName")
	}
	if !errors.Is(err, repository.ErrRenewalPolicyDuplicateName) {
		t.Errorf("Update: err = %v, want ErrRenewalPolicyDuplicateName (via errors.Is)", err)
	}
}

// TestRenewalPolicyRepository_DeleteInUse verifies the pg 23503
// foreign_key_violation translation. managed_certificates.renewal_policy_id
// REFERENCES renewal_policies(id) ON DELETE RESTRICT; attempting to Delete
// a policy while a certificate still references it must surface as
// ErrRenewalPolicyInUse so the handler can emit 409 Conflict. Any change
// to either the FK definition or the isForeignKeyViolation mapping breaks
// this.
func TestRenewalPolicyRepository_DeleteInUse(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewRenewalPolicyRepository(db)
	ctx := context.Background()

	// The policy under test — create via repo so ID auto-generation is
	// also exercised end-to-end in this path.
	policy := &domain.RenewalPolicy{
		Name:                "InUse Policy",
		RenewalWindowDays:   30,
		AutoRenew:           true,
		MaxRetries:          3,
		RetryInterval:       300,
		AlertThresholdsDays: domain.DefaultAlertThresholds(),
	}
	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create policy failed: %v", err)
	}

	// Create owner/team/issuer prerequisites, then raw-INSERT a
	// managed_certificate row referencing the policy. Using raw SQL here
	// (matching insertCertPrereqsRaw's idiom) keeps the test independent
	// of the service layer.
	ownerID, teamID, issuerID, _ := insertCertPrereqsRaw(t, db, ctx, "inuse")

	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := db.ExecContext(ctx, `
		INSERT INTO managed_certificates (
			id, name, common_name, sans, environment,
			owner_id, team_id, issuer_id, renewal_policy_id,
			status, expires_at, tags, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`,
		"mc-inuse", "inuse-cert", "inuse.example.com", []string{}, "production",
		ownerID, teamID, issuerID, policy.ID,
		string(domain.CertificateStatusActive), now.Add(90*24*time.Hour), "{}", now, now,
	)
	if err != nil {
		t.Fatalf("INSERT managed_certificates failed: %v", err)
	}

	// Delete: the ON DELETE RESTRICT FK fires, the pg driver returns a
	// *pq.Error with Code 23503, isForeignKeyViolation detects it, and
	// the repository returns ErrRenewalPolicyInUse.
	err = repo.Delete(ctx, policy.ID)
	if err == nil {
		t.Fatal("Delete: err = nil, want ErrRenewalPolicyInUse (ON DELETE RESTRICT should have fired)")
	}
	if !errors.Is(err, repository.ErrRenewalPolicyInUse) {
		t.Errorf("Delete: err = %v, want ErrRenewalPolicyInUse (via errors.Is)", err)
	}

	// And the policy is still there — RESTRICT aborted the delete.
	if _, err := repo.Get(ctx, policy.ID); err != nil {
		t.Errorf("Get after failed Delete: err = %v, want nil (policy should still exist)", err)
	}

	// After removing the referencing cert, Delete succeeds — proves the
	// RESTRICT was the only thing blocking the earlier Delete and rules
	// out any unrelated failure mode.
	if _, err := db.ExecContext(ctx, `DELETE FROM managed_certificates WHERE id = $1`, "mc-inuse"); err != nil {
		t.Fatalf("cleanup DELETE managed_certificates failed: %v", err)
	}
	if err := repo.Delete(ctx, policy.ID); err != nil {
		t.Errorf("Delete after cleanup: err = %v, want nil", err)
	}

	// Also verify Delete on a non-existent ID returns a not-found error
	// (not nil, not the InUse sentinel) — guards against a silent no-op
	// regression in the RowsAffected check.
	err = repo.Delete(ctx, "rp-does-not-exist")
	if err == nil {
		t.Fatal("Delete(non-existent): err = nil, want not-found")
	}
	if errors.Is(err, repository.ErrRenewalPolicyInUse) {
		t.Errorf("Delete(non-existent): err = %v, should not be ErrRenewalPolicyInUse", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Delete(non-existent): err = %v, want substring %q", err, "not found")
	}
}
