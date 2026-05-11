package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/domain"
)

// Coverage fill — v2.1.0 release gate Phase 3.
//
// A handful of constructor + setter + small-method functions added in
// recent fix bundles shipped without tests. The package-average
// floor (75%) trips because each 0%-function drags the script's
// per-function average down. The tests below cover the easy ones to
// lift the average back across.

// =============================================================================
// auth_session_oidc.go — WithPermissionChecker setter (added in MED-2).
// =============================================================================

type fakeOIDCPermChecker struct{}

func (f *fakeOIDCPermChecker) CheckPermission(_ context.Context, _, _, _, _, _ string, _ *string) (bool, error) {
	return true, nil
}

func TestAuthSessionOIDCHandler_WithPermissionChecker_ReturnsSelfAndSetsField(t *testing.T) {
	h := &AuthSessionOIDCHandler{}
	got := h.WithPermissionChecker(&fakeOIDCPermChecker{})
	if got != h {
		t.Errorf("WithPermissionChecker must return receiver for chaining; got %p, want %p", got, h)
	}
	if h.checker == nil {
		t.Errorf("WithPermissionChecker must install the checker; got nil")
	}
}

// =============================================================================
// admin_crl_cache.go — NewAdminCRLCacheServiceImpl + CacheRows (added by
// the CRL-cache admin panel; never had handler-layer tests).
// =============================================================================

type fakeCRLCacheRepo struct {
	getErr error
}

func (f *fakeCRLCacheRepo) Get(_ context.Context, _ string) (*domain.CRLCacheEntry, error) {
	return nil, f.getErr
}
func (f *fakeCRLCacheRepo) Put(_ context.Context, _ *domain.CRLCacheEntry) error {
	return nil
}
func (f *fakeCRLCacheRepo) NextCRLNumber(_ context.Context, _ string) (int64, error) {
	return 1, nil
}
func (f *fakeCRLCacheRepo) RecordGenerationEvent(_ context.Context, _ *domain.CRLGenerationEvent) error {
	return nil
}
func (f *fakeCRLCacheRepo) ListGenerationEvents(_ context.Context, _ string, _ int) ([]*domain.CRLGenerationEvent, error) {
	return nil, nil
}

func TestNewAdminCRLCacheServiceImpl_ConstructsWithDefaults(t *testing.T) {
	repo := &fakeCRLCacheRepo{}
	idsFn := func() []string { return []string{"iss-1", "iss-2"} }
	svc := NewAdminCRLCacheServiceImpl(repo, idsFn)
	if svc == nil {
		t.Fatalf("NewAdminCRLCacheServiceImpl returned nil")
	}
	if svc.cacheRepo == nil || svc.issuerIDs == nil || svc.now == nil {
		t.Errorf("constructor must wire all fields; got cacheRepo=%v issuerIDs!=nil=%v now!=nil=%v",
			svc.cacheRepo, svc.issuerIDs != nil, svc.now != nil)
	}
	if svc.eventLimit != 5 {
		t.Errorf("expected default eventLimit=5; got %d", svc.eventLimit)
	}
}

func TestAdminCRLCacheServiceImpl_CacheRows_EmptyIssuerListYieldsEmptyResult(t *testing.T) {
	svc := NewAdminCRLCacheServiceImpl(&fakeCRLCacheRepo{}, func() []string { return nil })
	rows, err := svc.CacheRows(context.Background())
	if err != nil {
		t.Fatalf("CacheRows on empty issuer list: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for empty issuer list; got %d", len(rows))
	}
}

// =============================================================================
// acme.go small helpers — itoaForRetryAfter + challengeURLBuilder.
// These are pure-helper functions added to the ACME surface; tested
// here to lift the package-average over the 75 floor.
// =============================================================================

func TestItoaForRetryAfter(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{-5, "-5"},
		{12345, "12345"},
	}
	for _, c := range cases {
		got := itoaForRetryAfter(c.in)
		if got != c.want {
			t.Errorf("itoaForRetryAfter(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestChallengeURLBuilder_ProfilePrefixAndHTTPS(t *testing.T) {
	req := httptest.NewRequest("GET", "https://certctl.local/acme/profile/p1/order", nil)
	req.TLS = nil  // simulate HTTP
	req.Host = "x" // override
	h := ACMEHandler{}
	build := h.challengeURLBuilder(req, "p1")
	got := build("chal-abc")
	if !strings.HasPrefix(got, "http://x/acme/profile/p1/challenge/") {
		t.Errorf("unexpected URL: %q", got)
	}
	if !strings.HasSuffix(got, "/chal-abc") {
		t.Errorf("unexpected URL suffix: %q", got)
	}
}

func TestChallengeURLBuilder_NoProfileFallsBackToShortPath(t *testing.T) {
	req := httptest.NewRequest("GET", "http://certctl.local/acme/order", nil)
	req.Host = "y"
	h := ACMEHandler{}
	build := h.challengeURLBuilder(req, "")
	got := build("chal-1")
	if !strings.Contains(got, "/acme/challenge/chal-1") {
		t.Errorf("expected /acme/challenge/chal-1 fallback; got %q", got)
	}
	if strings.Contains(got, "/profile/") {
		t.Errorf("must NOT contain /profile/ when profileID is empty; got %q", got)
	}
}

func TestAdminCRLCacheServiceImpl_CacheRows_PerIssuerErrorSurfacesAsEvent(t *testing.T) {
	svc := NewAdminCRLCacheServiceImpl(
		&fakeCRLCacheRepo{getErr: errors.New("lookup failed")},
		func() []string { return []string{"iss-broken"} },
	)
	rows, err := svc.CacheRows(context.Background())
	if err != nil {
		t.Fatalf("CacheRows must NOT short-circuit on per-issuer failure: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row; got %d", len(rows))
	}
	if rows[0].IssuerID != "iss-broken" {
		t.Errorf("expected issuer-id passthrough; got %q", rows[0].IssuerID)
	}
	if len(rows[0].RecentEvents) == 0 {
		t.Fatalf("expected at least 1 RecentEvent for the lookup failure")
	}
	ev := rows[0].RecentEvents[0]
	if ev.Succeeded {
		t.Errorf("expected Succeeded=false on lookup failure")
	}
}
