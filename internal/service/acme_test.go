// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// fakeACMERepo is an in-memory ACMERepo for tests. It tracks issued
// nonces in a map; Consume removes the entry to model one-shot use.
type fakeACMERepo struct {
	issued   map[string]time.Time // nonce → expires_at
	issueErr error
}

func newFakeACMERepo() *fakeACMERepo {
	return &fakeACMERepo{issued: make(map[string]time.Time)}
}

func (f *fakeACMERepo) IssueNonce(ctx context.Context, nonce string, ttl time.Duration) error {
	if f.issueErr != nil {
		return f.issueErr
	}
	f.issued[nonce] = time.Now().Add(ttl)
	return nil
}

func (f *fakeACMERepo) ConsumeNonce(ctx context.Context, nonce string) error {
	exp, ok := f.issued[nonce]
	if !ok {
		return errors.New("not found")
	}
	if time.Now().After(exp) {
		return errors.New("expired")
	}
	delete(f.issued, nonce)
	return nil
}

// fakeProfileLookup is an in-memory profileLookup that returns the
// profile by ID. Unknown IDs return repository.ErrNotFound (the
// canonical sentinel ACMEService maps to ErrACMEProfileNotFound).
type fakeProfileLookup struct {
	profiles map[string]*domain.CertificateProfile
}

func (f *fakeProfileLookup) Get(ctx context.Context, id string) (*domain.CertificateProfile, error) {
	p, ok := f.profiles[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return p, nil
}

func newSvc(t *testing.T, cfg config.ACMEServerConfig, profiles map[string]*domain.CertificateProfile) (*ACMEService, *fakeACMERepo) {
	t.Helper()
	repo := newFakeACMERepo()
	pl := &fakeProfileLookup{profiles: profiles}
	return NewACMEService(repo, pl, cfg), repo
}

func TestBuildDirectory_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{
		NonceTTL: 5 * time.Minute,
	}
	cfg.DirectoryMeta.TermsOfService = "https://example.com/tos"
	cfg.DirectoryMeta.Website = "https://example.com"
	svc, _ := newSvc(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	dir, err := svc.BuildDirectory(context.Background(), "prof-corp", "https://server/acme/profile/prof-corp")
	if err != nil {
		t.Fatalf("BuildDirectory: %v", err)
	}
	if dir == nil {
		t.Fatal("dir is nil")
	}
	if dir.NewNonce != "https://server/acme/profile/prof-corp/new-nonce" {
		t.Errorf("NewNonce = %q", dir.NewNonce)
	}
	if dir.Meta == nil || dir.Meta.TermsOfService != "https://example.com/tos" {
		t.Errorf("meta tos = %+v", dir.Meta)
	}
	if got := svc.Metrics().DirectoryTotal.Load(); got != 1 {
		t.Errorf("DirectoryTotal = %d, want 1", got)
	}
}

func TestBuildDirectory_UnknownProfile(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _ := newSvc(t, cfg, nil)
	_, err := svc.BuildDirectory(context.Background(), "prof-missing", "https://server/acme/profile/prof-missing")
	if !errors.Is(err, ErrACMEProfileNotFound) {
		t.Errorf("err = %v, want ErrACMEProfileNotFound", err)
	}
	if got := svc.Metrics().DirectoryFailureTotal.Load(); got != 1 {
		t.Errorf("DirectoryFailureTotal = %d, want 1", got)
	}
}

func TestBuildDirectory_EmptyProfileNoDefault(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _ := newSvc(t, cfg, nil)
	_, err := svc.BuildDirectory(context.Background(), "", "https://server/acme")
	if !errors.Is(err, ErrACMEUserActionRequired) {
		t.Errorf("err = %v, want ErrACMEUserActionRequired", err)
	}
}

func TestBuildDirectory_EmptyProfileWithDefault(t *testing.T) {
	cfg := config.ACMEServerConfig{
		NonceTTL:         5 * time.Minute,
		DefaultProfileID: "prof-default",
	}
	svc, _ := newSvc(t, cfg, map[string]*domain.CertificateProfile{
		"prof-default": {ID: "prof-default", Name: "default"},
	})
	dir, err := svc.BuildDirectory(context.Background(), "", "https://server/acme")
	if err != nil {
		t.Fatalf("BuildDirectory: %v", err)
	}
	if dir.NewNonce != "https://server/acme/new-nonce" {
		t.Errorf("NewNonce = %q (shorthand path)", dir.NewNonce)
	}
}

func TestIssueNonce_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, repo := newSvc(t, cfg, nil)
	n, err := svc.IssueNonce(context.Background())
	if err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}
	if len(n) != 43 {
		t.Errorf("nonce length = %d, want 43 (base64url-no-pad of 32 bytes)", len(n))
	}
	if _, ok := repo.issued[n]; !ok {
		t.Errorf("issued nonce was not persisted")
	}
	if got := svc.Metrics().NewNonceTotal.Load(); got != 1 {
		t.Errorf("NewNonceTotal = %d, want 1", got)
	}
}

func TestIssueNonce_RepoFailure(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, repo := newSvc(t, cfg, nil)
	repo.issueErr = errors.New("disk full")
	_, err := svc.IssueNonce(context.Background())
	if err == nil {
		t.Fatal("expected error from IssueNonce when repo fails")
	}
	if got := svc.Metrics().NewNonceFailureTotal.Load(); got != 1 {
		t.Errorf("NewNonceFailureTotal = %d, want 1", got)
	}
}

func TestACMEMetrics_Snapshot(t *testing.T) {
	m := NewACMEMetrics()
	m.DirectoryTotal.Store(7)
	m.NewNonceTotal.Store(11)
	m.NewNonceFailureTotal.Store(2)
	snap := m.Snapshot()
	if snap["certctl_acme_directory_total"] != 7 {
		t.Errorf("directory_total = %d", snap["certctl_acme_directory_total"])
	}
	if snap["certctl_acme_new_nonce_total"] != 11 {
		t.Errorf("new_nonce_total = %d", snap["certctl_acme_new_nonce_total"])
	}
	if snap["certctl_acme_new_nonce_failures_total"] != 2 {
		t.Errorf("new_nonce_failures_total = %d", snap["certctl_acme_new_nonce_failures_total"])
	}
}
