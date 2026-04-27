package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/domain"
)

// Bundle N.C-extended: service-layer round-out (70.5% → ≥80%).
// Targets the previously-uncovered handler-interface methods on
// CertificateService that delegate to the repo: GetCertificate,
// CreateCertificate, UpdateCertificate, ArchiveCertificate,
// GetCertificateVersions, SetJobRepo, SetKeygenMode,
// ListCertificatesWithFilter, TriggerDeployment.

func newTestCertSvc(t *testing.T) (*CertificateService, *mockCertRepo) {
	t.Helper()
	certRepo := &mockCertRepo{
		Certs:    make(map[string]*domain.ManagedCertificate),
		Versions: make(map[string][]*domain.CertificateVersion),
	}
	auditRepo := &mockAuditRepo{}
	auditService := NewAuditService(auditRepo)
	svc := NewCertificateService(certRepo, nil, auditService)
	return svc, certRepo
}

func TestCertificateService_GetCertificate_DelegatesToRepo(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.Certs["mc-1"] = &domain.ManagedCertificate{ID: "mc-1", Name: "x"}
	got, err := svc.GetCertificate(context.Background(), "mc-1")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil || got.ID != "mc-1" {
		t.Errorf("expected mc-1, got %+v", got)
	}
}

func TestCertificateService_GetCertificate_NotFound(t *testing.T) {
	svc, _ := newTestCertSvc(t)
	_, err := svc.GetCertificate(context.Background(), "missing")
	if err == nil {
		t.Errorf("expected NotFound error")
	}
}

func TestCertificateService_CreateCertificate_PopulatesDefaults(t *testing.T) {
	svc, _ := newTestCertSvc(t)
	cert := domain.ManagedCertificate{Name: "no-id-no-status"}
	got, err := svc.CreateCertificate(context.Background(), cert)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if got.ID == "" {
		t.Errorf("expected ID populated, got empty")
	}
	if got.Status == "" {
		t.Errorf("expected default status populated")
	}
	if got.Tags == nil {
		t.Errorf("expected Tags initialized to non-nil map")
	}
	if got.CreatedAt.IsZero() {
		t.Errorf("expected CreatedAt populated")
	}
}

func TestCertificateService_CreateCertificate_RepoError(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.CreateErr = errors.New("db down")
	_, err := svc.CreateCertificate(context.Background(), domain.ManagedCertificate{ID: "mc-x", Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "failed to create") {
		t.Errorf("expected create-error wrapper, got %v", err)
	}
}

func TestCertificateService_UpdateCertificate_MergesPatch(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.Certs["mc-u"] = &domain.ManagedCertificate{
		ID:          "mc-u",
		Name:        "old",
		CommonName:  "old.example.com",
		Environment: "staging",
	}
	patch := domain.ManagedCertificate{
		Name:        "new",
		CommonName:  "new.example.com",
		Environment: "prod",
		SANs:        []string{"new.example.com"},
		OwnerID:     "o-alice",
		TeamID:      "t-platform",
		IssuerID:    "iss-le",
	}
	got, err := svc.UpdateCertificate(context.Background(), "mc-u", patch)
	if err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}
	if got.Name != "new" || got.CommonName != "new.example.com" || got.Environment != "prod" {
		t.Errorf("expected merged fields, got %+v", got)
	}
	if got.OwnerID != "o-alice" || got.TeamID != "t-platform" {
		t.Errorf("expected owner/team merged, got %s/%s", got.OwnerID, got.TeamID)
	}
}

func TestCertificateService_UpdateCertificate_NotFound(t *testing.T) {
	svc, _ := newTestCertSvc(t)
	_, err := svc.UpdateCertificate(context.Background(), "missing", domain.ManagedCertificate{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected NotFound error, got %v", err)
	}
}

func TestCertificateService_UpdateCertificate_RepoUpdateError(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.Certs["mc-u"] = &domain.ManagedCertificate{ID: "mc-u", Name: "old"}
	repo.UpdateErr = errors.New("constraint violation")
	_, err := svc.UpdateCertificate(context.Background(), "mc-u", domain.ManagedCertificate{Name: "new"})
	if err == nil || !strings.Contains(err.Error(), "failed to update") {
		t.Errorf("expected update-error wrapper, got %v", err)
	}
}

func TestCertificateService_ArchiveCertificate_DelegatesToRepo(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.Certs["mc-a"] = &domain.ManagedCertificate{ID: "mc-a"}
	if err := svc.ArchiveCertificate(context.Background(), "mc-a"); err != nil {
		t.Errorf("ArchiveCertificate: %v", err)
	}
}

func TestCertificateService_ArchiveCertificate_RepoError(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.ArchiveErr = errors.New("archive fail")
	if err := svc.ArchiveCertificate(context.Background(), "mc-a"); err == nil {
		t.Errorf("expected archive error to propagate")
	}
}

func TestCertificateService_GetCertificateVersions_PaginationDefaults(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	versions := []*domain.CertificateVersion{
		{SerialNumber: "01"}, {SerialNumber: "02"}, {SerialNumber: "03"},
	}
	repo.ListVersionsResult = versions
	repo.Versions["mc-v"] = versions

	got, total, err := svc.GetCertificateVersions(context.Background(), "mc-v", 0, 0)
	if err != nil {
		t.Fatalf("GetCertificateVersions: %v", err)
	}
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 versions returned, got %d", len(got))
	}
}

func TestCertificateService_GetCertificateVersions_PageOutOfRange(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.ListVersionsResult = []*domain.CertificateVersion{{SerialNumber: "01"}}

	got, total, err := svc.GetCertificateVersions(context.Background(), "mc-v", 99, 50)
	if err != nil {
		t.Fatalf("GetCertificateVersions: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 results for out-of-range page, got %d", len(got))
	}
}

func TestCertificateService_GetCertificateVersions_RepoError(t *testing.T) {
	svc, repo := newTestCertSvc(t)
	repo.ListVersionsErr = errors.New("list down")
	_, _, err := svc.GetCertificateVersions(context.Background(), "mc-v", 1, 50)
	if err == nil {
		t.Errorf("expected versions-list error to propagate")
	}
}

func TestCertificateService_SetJobRepo_SetKeygenMode_NoCrash(t *testing.T) {
	svc, _ := newTestCertSvc(t)
	// SetJobRepo accepts a repo (or nil) — confirm no panic.
	svc.SetJobRepo(nil)
	svc.SetKeygenMode("agent")
	svc.SetKeygenMode("server")
}
