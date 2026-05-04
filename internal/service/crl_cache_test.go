package service_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/issuer"
	localissuer "github.com/certctl-io/certctl/internal/connector/issuer/local"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/service"
)

// fakeCRLCacheRepo is an in-memory repository for CRLCacheService
// tests. The Postgres impl is covered by the testcontainers tests in
// internal/repository/postgres/crl_cache_test.go (CI only — needs Docker).
type fakeCRLCacheRepo struct {
	mu       sync.Mutex
	rows     map[string]*domain.CRLCacheEntry
	events   []*domain.CRLGenerationEvent
	getCount int
	putCount int
}

func newFakeCRLCacheRepo() *fakeCRLCacheRepo {
	return &fakeCRLCacheRepo{rows: map[string]*domain.CRLCacheEntry{}}
}

func (r *fakeCRLCacheRepo) Get(_ context.Context, issuerID string) (*domain.CRLCacheEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getCount++
	if entry, ok := r.rows[issuerID]; ok {
		copy := *entry
		return &copy, nil
	}
	return nil, nil
}

func (r *fakeCRLCacheRepo) Put(_ context.Context, entry *domain.CRLCacheEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.putCount++
	copy := *entry
	r.rows[entry.IssuerID] = &copy
	return nil
}

func (r *fakeCRLCacheRepo) NextCRLNumber(_ context.Context, issuerID string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.rows[issuerID]; ok {
		return entry.CRLNumber + 1, nil
	}
	return 1, nil
}

func (r *fakeCRLCacheRepo) RecordGenerationEvent(_ context.Context, evt *domain.CRLGenerationEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := *evt
	r.events = append(r.events, &copy)
	return nil
}

func (r *fakeCRLCacheRepo) ListGenerationEvents(_ context.Context, issuerID string, limit int) ([]*domain.CRLGenerationEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.CRLGenerationEvent
	for _, evt := range r.events {
		if evt.IssuerID == issuerID {
			copy := *evt
			out = append(out, &copy)
		}
	}
	return out, nil
}

// fakeRevocationRepo is the minimal shape CAOperationsSvc needs:
// returning revocations by issuer. The cache service walks
// CAOperationsSvc.GenerateDERCRL, which calls into this.
type fakeRevocationRepo struct{}

func (fakeRevocationRepo) Create(context.Context, *domain.CertificateRevocation) error {
	return nil
}
func (fakeRevocationRepo) CreateWithTx(context.Context, repository.Querier, *domain.CertificateRevocation) error {
	return nil
}
func (fakeRevocationRepo) GetByIssuerAndSerial(context.Context, string, string) (*domain.CertificateRevocation, error) {
	return nil, nil
}
func (fakeRevocationRepo) ListAll(context.Context) ([]*domain.CertificateRevocation, error) {
	return nil, nil
}
func (fakeRevocationRepo) ListByIssuer(_ context.Context, issuerID string) ([]*domain.CertificateRevocation, error) {
	// Empty list = no revoked certs; the issuer connector still
	// produces a valid empty CRL (RFC 5280 allows zero entries).
	return nil, nil
}
func (fakeRevocationRepo) ListByCertificate(context.Context, string) ([]*domain.CertificateRevocation, error) {
	return nil, nil
}
func (fakeRevocationRepo) MarkIssuerNotified(context.Context, string) error { return nil }

// helper: spin up a CAOperationsSvc + IssuerRegistry wired with a real
// local issuer connector. The local issuer's GenerateCRL produces a
// real DER-encoded CRL that the cache service can parse + persist.
func newCacheServiceFixture(t *testing.T) (svc *service.CRLCacheService, repo *fakeCRLCacheRepo, registry *service.IssuerRegistry) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo = newFakeCRLCacheRepo()

	// Real local issuer — produces a real CRL on GenerateCRL.
	localConn := localissuer.New(&localissuer.Config{
		CACommonName: "Test Cache CA",
		ValidityDays: 30,
	}, logger)

	registry = service.NewIssuerRegistry(logger)
	registry.Set("iss-cache-test", service.NewIssuerConnectorAdapter(localConn))

	caSvc := service.NewCAOperationsSvc(fakeRevocationRepo{}, nil, nil)
	caSvc.SetIssuerRegistry(registry)

	svc = service.NewCRLCacheService(repo, caSvc, registry, logger)
	return
}

// ---------------------------------------------------------------------------
// Get: cache hit, miss, staleness
// ---------------------------------------------------------------------------

func TestCRLCacheService_Get_MissTriggersGeneration(t *testing.T) {
	svc, repo, _ := newCacheServiceFixture(t)
	ctx := context.Background()

	der, thisUpdate, err := svc.Get(ctx, "iss-cache-test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("Get returned empty DER")
	}
	if thisUpdate.IsZero() {
		t.Fatal("ThisUpdate is zero")
	}
	if repo.putCount != 1 {
		t.Errorf("putCount = %d, want 1 (miss should trigger one generation)", repo.putCount)
	}
}

func TestCRLCacheService_Get_HitSkipsGeneration(t *testing.T) {
	svc, repo, _ := newCacheServiceFixture(t)
	ctx := context.Background()

	// Prime the cache.
	if _, _, err := svc.Get(ctx, "iss-cache-test"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if repo.putCount != 1 {
		t.Fatalf("prime: putCount = %d, want 1", repo.putCount)
	}

	// Second Get should be a cache hit.
	if _, _, err := svc.Get(ctx, "iss-cache-test"); err != nil {
		t.Fatalf("hit: %v", err)
	}
	if repo.putCount != 1 {
		t.Errorf("putCount = %d, want 1 (hit should not regenerate)", repo.putCount)
	}
}

func TestCRLCacheService_Get_StalenessTriggersRegeneration(t *testing.T) {
	svc, repo, _ := newCacheServiceFixture(t)
	ctx := context.Background()

	// Prime the cache with a row whose next_update is in the past.
	stale := &domain.CRLCacheEntry{
		IssuerID:    "iss-cache-test",
		CRLDER:      []byte("stale-der"),
		CRLNumber:   1,
		ThisUpdate:  time.Now().Add(-48 * time.Hour),
		NextUpdate:  time.Now().Add(-24 * time.Hour), // expired
		GeneratedAt: time.Now().Add(-48 * time.Hour),
	}
	if err := repo.Put(ctx, stale); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	repo.putCount = 0

	// Get should detect staleness and regenerate.
	der, _, err := svc.Get(ctx, "iss-cache-test")
	if err != nil {
		t.Fatalf("Get on stale: %v", err)
	}
	if string(der) == "stale-der" {
		t.Error("Get returned stale DER instead of regenerating")
	}
	if repo.putCount != 1 {
		t.Errorf("putCount = %d, want 1 (staleness should trigger one regen)", repo.putCount)
	}
}

// ---------------------------------------------------------------------------
// RegenerateAll
// ---------------------------------------------------------------------------

func TestCRLCacheService_RegenerateAll_PopulatesAllIssuers(t *testing.T) {
	svc, repo, _ := newCacheServiceFixture(t)
	ctx := context.Background()

	svc.RegenerateAll(ctx)

	row, _ := repo.Get(ctx, "iss-cache-test")
	if row == nil {
		t.Fatal("RegenerateAll did not populate iss-cache-test")
	}
	if row.RevokedCount != 0 {
		t.Errorf("RevokedCount = %d, want 0 (fakeRevocationRepo is empty)", row.RevokedCount)
	}
	events, _ := repo.ListGenerationEvents(ctx, "iss-cache-test", 10)
	if len(events) != 1 {
		t.Fatalf("expected 1 generation event, got %d", len(events))
	}
	if !events[0].Succeeded {
		t.Error("event.Succeeded should be true on happy path")
	}
}

func TestCRLCacheService_RegenerateAll_RespectsCancelledContext(t *testing.T) {
	svc, _, _ := newCacheServiceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should return without panicking. The single-issuer fixture means
	// there's nothing to iterate after the cancel check, so this is
	// mostly a smoke test for the ctx.Done() branch.
	svc.RegenerateAll(ctx)
}

// ---------------------------------------------------------------------------
// Singleflight: concurrent miss requests for the same issuer collapse
// ---------------------------------------------------------------------------

func TestCRLCacheService_Get_SingleflightCollapsesConcurrentMisses(t *testing.T) {
	svc, repo, _ := newCacheServiceFixture(t)
	ctx := context.Background()

	// Fire 20 concurrent Get calls for the same uncached issuer. The
	// in-tree singleflight gate should collapse them to a single
	// underlying generation (putCount == 1).
	var wg sync.WaitGroup
	var errCount atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := svc.Get(ctx, "iss-cache-test"); err != nil {
				errCount.Add(1)
				t.Errorf("concurrent Get: %v", err)
			}
		}()
	}
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("%d errors across concurrent Gets", errCount.Load())
	}
	if repo.putCount != 1 {
		t.Errorf("singleflight failed: putCount = %d, want 1 (20 concurrent misses must collapse)", repo.putCount)
	}
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestCRLCacheService_Get_NoIssuerInRegistry_RecordsFailureEvent(t *testing.T) {
	svc, repo, _ := newCacheServiceFixture(t)
	ctx := context.Background()

	// Issuer ID that doesn't exist in the registry → CAOperationsSvc
	// returns an error → cache service records a failure event +
	// surfaces the error to the caller.
	_, _, err := svc.Get(ctx, "iss-does-not-exist")
	if err == nil {
		t.Fatal("Get for unknown issuer should error")
	}
	events, _ := repo.ListGenerationEvents(ctx, "iss-does-not-exist", 10)
	if len(events) != 1 {
		t.Fatalf("expected 1 failure event, got %d", len(events))
	}
	if events[0].Succeeded {
		t.Error("failure event should have Succeeded=false")
	}
	if events[0].Error == "" {
		t.Error("failure event should carry an error message")
	}
}

func TestCRLCacheService_Get_NoCacheRepo_Errors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.NewCRLCacheService(nil, nil, nil, logger)
	_, _, err := svc.Get(context.Background(), "any")
	if err == nil {
		t.Fatal("Get with nil cacheRepo should error")
	}
}

// pin via interface satisfaction (compile-time check that fakeRevocationRepo
// matches what CAOperationsSvc actually calls — guards against shape drift
// in the repository.RevocationRepository interface).
var _ interface {
	ListByIssuer(ctx context.Context, issuerID string) ([]*domain.CertificateRevocation, error)
} = fakeRevocationRepo{}

// _ silence the unused import warning when issuer adapter machinery moves.
var _ = issuer.IssuanceRequest{}
