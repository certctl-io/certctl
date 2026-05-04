package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository/postgres"
)

// CRL cache repository tests run against the shared testcontainers
// Postgres started by repo_test.go::getTestDB. The cache table only
// has a FK to issuers(id), so the prereq insert is just an issuer row.

// insertIssuerForCRL deliberately does NOT take a ctx parameter — the
// inner getTestDB(t) helper has no ctx-aware variant in this package,
// so accepting one here would trip the contextcheck linter (the ctx
// would be "lost" at the getTestDB call boundary). The helper uses a
// fresh context.Background() for the single ExecContext call; that's
// fine because tests are short-lived and the per-test isolation comes
// from the schema-per-test pattern, not from ctx cancellation.
func insertIssuerForCRL(t *testing.T, suffix string) (issuerID string) {
	t.Helper()
	tdb := getTestDB(t)
	issuerID = "iss-crlcache-" + suffix
	now := time.Now().Truncate(time.Microsecond)
	_, err := tdb.db.ExecContext(context.Background(),
		`INSERT INTO issuers (id, name, type, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		issuerID, "Issuer "+suffix, "generic-ca", true, now, now)
	if err != nil {
		t.Fatalf("insert issuer: %v", err)
	}
	return
}

func TestCRLCacheRepository_GetMissReturnsNilNil(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	entry, err := repo.Get(ctx, "iss-does-not-exist")
	if err != nil {
		t.Fatalf("Get on missing row should return (nil, nil), got err %v", err)
	}
	if entry != nil {
		t.Fatalf("Get on missing row should return nil entry, got %+v", entry)
	}
}

func TestCRLCacheRepository_PutGet_RoundTrip(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	issuerID := insertIssuerForCRL(t, "roundtrip")
	now := time.Now().UTC().Truncate(time.Microsecond)

	want := &domain.CRLCacheEntry{
		IssuerID:           issuerID,
		CRLDER:             []byte{0x30, 0x82, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef},
		CRLNumber:          1,
		ThisUpdate:         now,
		NextUpdate:         now.Add(24 * time.Hour),
		GeneratedAt:        now,
		GenerationDuration: 87 * time.Millisecond,
		RevokedCount:       3,
	}
	if err := repo.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := repo.Get(ctx, issuerID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil entry after Put")
	}
	if got.IssuerID != want.IssuerID {
		t.Errorf("IssuerID = %q, want %q", got.IssuerID, want.IssuerID)
	}
	if string(got.CRLDER) != string(want.CRLDER) {
		t.Errorf("CRLDER bytes differ")
	}
	if got.CRLNumber != want.CRLNumber {
		t.Errorf("CRLNumber = %d, want %d", got.CRLNumber, want.CRLNumber)
	}
	if !got.ThisUpdate.Equal(want.ThisUpdate) {
		t.Errorf("ThisUpdate = %v, want %v", got.ThisUpdate, want.ThisUpdate)
	}
	if got.GenerationDuration != want.GenerationDuration {
		t.Errorf("GenerationDuration = %v, want %v", got.GenerationDuration, want.GenerationDuration)
	}
	if got.RevokedCount != want.RevokedCount {
		t.Errorf("RevokedCount = %d, want %d", got.RevokedCount, want.RevokedCount)
	}
}

func TestCRLCacheRepository_Put_Overwrites(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	issuerID := insertIssuerForCRL(t, "overwrite")
	now := time.Now().UTC().Truncate(time.Microsecond)

	first := &domain.CRLCacheEntry{
		IssuerID:           issuerID,
		CRLDER:             []byte("v1"),
		CRLNumber:          1,
		ThisUpdate:         now,
		NextUpdate:         now.Add(time.Hour),
		GeneratedAt:        now,
		GenerationDuration: 10 * time.Millisecond,
		RevokedCount:       1,
	}
	if err := repo.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}

	second := &domain.CRLCacheEntry{
		IssuerID:           issuerID,
		CRLDER:             []byte("v2"),
		CRLNumber:          2,
		ThisUpdate:         now.Add(time.Hour),
		NextUpdate:         now.Add(2 * time.Hour),
		GeneratedAt:        now.Add(time.Hour),
		GenerationDuration: 20 * time.Millisecond,
		RevokedCount:       2,
	}
	if err := repo.Put(ctx, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, _ := repo.Get(ctx, issuerID)
	if string(got.CRLDER) != "v2" {
		t.Errorf("Put did not overwrite: got CRLDER %q, want v2", got.CRLDER)
	}
	if got.CRLNumber != 2 {
		t.Errorf("CRLNumber = %d, want 2 (post-overwrite)", got.CRLNumber)
	}
}

func TestCRLCacheRepository_Put_RejectsNilOrEmpty(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	if err := repo.Put(ctx, nil); err == nil {
		t.Error("Put(nil) should error")
	}
	if err := repo.Put(ctx, &domain.CRLCacheEntry{}); err == nil {
		t.Error("Put(empty issuer_id) should error")
	}
}

func TestCRLCacheRepository_NextCRLNumber_FirstIsOne(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	issuerID := insertIssuerForCRL(t, "first")
	n, err := repo.NextCRLNumber(ctx, issuerID)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	if n != 1 {
		t.Fatalf("first NextCRLNumber = %d, want 1", n)
	}
}

func TestCRLCacheRepository_NextCRLNumber_Monotonic(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	issuerID := insertIssuerForCRL(t, "mono")
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Seed with a known crl_number.
	seed := &domain.CRLCacheEntry{
		IssuerID:    issuerID,
		CRLDER:      []byte("seed"),
		CRLNumber:   5,
		ThisUpdate:  now,
		NextUpdate:  now.Add(time.Hour),
		GeneratedAt: now,
	}
	if err := repo.Put(ctx, seed); err != nil {
		t.Fatalf("Put seed: %v", err)
	}

	n, err := repo.NextCRLNumber(ctx, issuerID)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	if n != 6 {
		t.Fatalf("NextCRLNumber after seed=5 = %d, want 6", n)
	}
}

func TestCRLCacheRepository_RecordAndListEvents(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	issuerID := insertIssuerForCRL(t, "events")
	base := time.Now().UTC().Truncate(time.Microsecond)

	for i := 0; i < 3; i++ {
		evt := &domain.CRLGenerationEvent{
			IssuerID:     issuerID,
			CRLNumber:    int64(i + 1),
			Duration:     time.Duration(50+i*10) * time.Millisecond,
			RevokedCount: i,
			StartedAt:    base.Add(time.Duration(i) * time.Minute),
			Succeeded:    true,
		}
		if err := repo.RecordGenerationEvent(ctx, evt); err != nil {
			t.Fatalf("RecordGenerationEvent[%d]: %v", i, err)
		}
		if evt.ID == 0 {
			t.Fatalf("event[%d] ID not populated by DB", i)
		}
	}

	events, err := repo.ListGenerationEvents(ctx, issuerID, 10)
	if err != nil {
		t.Fatalf("ListGenerationEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	// Order is newest-first, so events[0] should be CRLNumber=3.
	if events[0].CRLNumber != 3 {
		t.Errorf("first event CRLNumber = %d, want 3 (newest)", events[0].CRLNumber)
	}
	if events[2].CRLNumber != 1 {
		t.Errorf("last event CRLNumber = %d, want 1 (oldest)", events[2].CRLNumber)
	}
}

func TestCRLCacheRepository_RecordEvent_FailureWithError(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	issuerID := insertIssuerForCRL(t, "failevent")
	evt := &domain.CRLGenerationEvent{
		IssuerID:  issuerID,
		StartedAt: time.Now().UTC().Truncate(time.Microsecond),
		Succeeded: false,
		Error:     "issuer connector returned 500",
	}
	if err := repo.RecordGenerationEvent(ctx, evt); err != nil {
		t.Fatalf("RecordGenerationEvent: %v", err)
	}
	events, _ := repo.ListGenerationEvents(ctx, issuerID, 1)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Succeeded {
		t.Error("event should be Succeeded=false")
	}
	if events[0].Error != "issuer connector returned 500" {
		t.Errorf("Error = %q, want full message", events[0].Error)
	}
}

func TestCRLCacheRepository_ListEvents_LimitDefaults(t *testing.T) {
	tdb := getTestDB(t)
	db := tdb.freshSchema(t)
	repo := postgres.NewCRLCacheRepository(db)
	ctx := context.Background()

	issuerID := insertIssuerForCRL(t, "limit")
	for i := 0; i < 5; i++ {
		_ = repo.RecordGenerationEvent(ctx, &domain.CRLGenerationEvent{
			IssuerID:  issuerID,
			StartedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Succeeded: true,
		})
	}
	events, err := repo.ListGenerationEvents(ctx, issuerID, 0)
	if err != nil {
		t.Fatalf("ListGenerationEvents(limit=0): %v", err)
	}
	// limit=0 → default 50 per the impl; we have 5, expect all 5.
	if len(events) != 5 {
		t.Fatalf("expected 5 events with default limit, got %d", len(events))
	}
}
