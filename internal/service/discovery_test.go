package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// mockDiscoveryRepo is a test implementation of DiscoveryRepository
type mockDiscoveryRepo struct {
	Scans              map[string]*domain.DiscoveryScan
	Discovered         map[string]*domain.DiscoveredCertificate
	CreateScanErr      error
	GetScanErr         error
	ListScansErr       error
	CreateDiscoveredErr error
	GetDiscoveredErr   error
	ListDiscoveredErr  error
	UpdateStatusErr    error
	GetByFingerprintErr error
	CountByStatusErr   error
}

func newMockDiscoveryRepository() *mockDiscoveryRepo {
	return &mockDiscoveryRepo{
		Scans:      make(map[string]*domain.DiscoveryScan),
		Discovered: make(map[string]*domain.DiscoveredCertificate),
	}
}

func (m *mockDiscoveryRepo) CreateScan(ctx context.Context, scan *domain.DiscoveryScan) error {
	if m.CreateScanErr != nil {
		return m.CreateScanErr
	}
	m.Scans[scan.ID] = scan
	return nil
}

func (m *mockDiscoveryRepo) GetScan(ctx context.Context, id string) (*domain.DiscoveryScan, error) {
	if m.GetScanErr != nil {
		return nil, m.GetScanErr
	}
	scan, ok := m.Scans[id]
	if !ok {
		return nil, errNotFound
	}
	return scan, nil
}

func (m *mockDiscoveryRepo) ListScans(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error) {
	if m.ListScansErr != nil {
		return nil, 0, m.ListScansErr
	}
	var scans []*domain.DiscoveryScan
	for _, s := range m.Scans {
		if agentID == "" || s.AgentID == agentID {
			scans = append(scans, s)
		}
	}
	return scans, len(scans), nil
}

func (m *mockDiscoveryRepo) CreateDiscovered(ctx context.Context, cert *domain.DiscoveredCertificate) (bool, error) {
	if m.CreateDiscoveredErr != nil {
		return false, m.CreateDiscoveredErr
	}
	_, exists := m.Discovered[cert.ID]
	m.Discovered[cert.ID] = cert
	return !exists, nil // true if new (not existed before)
}

func (m *mockDiscoveryRepo) GetDiscovered(ctx context.Context, id string) (*domain.DiscoveredCertificate, error) {
	if m.GetDiscoveredErr != nil {
		return nil, m.GetDiscoveredErr
	}
	cert, ok := m.Discovered[id]
	if !ok {
		return nil, errNotFound
	}
	return cert, nil
}

func (m *mockDiscoveryRepo) ListDiscovered(ctx context.Context, filter *repository.DiscoveryFilter) ([]*domain.DiscoveredCertificate, int, error) {
	if m.ListDiscoveredErr != nil {
		return nil, 0, m.ListDiscoveredErr
	}
	var certs []*domain.DiscoveredCertificate
	for _, c := range m.Discovered {
		if filter.AgentID != "" && c.AgentID != filter.AgentID {
			continue
		}
		if filter.Status != "" && string(c.Status) != filter.Status {
			continue
		}
		certs = append(certs, c)
	}
	return certs, len(certs), nil
}

func (m *mockDiscoveryRepo) UpdateDiscoveredStatus(ctx context.Context, id string, status domain.DiscoveryStatus, managedCertID string) error {
	if m.UpdateStatusErr != nil {
		return m.UpdateStatusErr
	}
	cert, ok := m.Discovered[id]
	if !ok {
		return errNotFound
	}
	cert.Status = status
	cert.ManagedCertificateID = managedCertID
	now := time.Now()
	if status == domain.DiscoveryStatusDismissed {
		cert.DismissedAt = &now
	}
	return nil
}

func (m *mockDiscoveryRepo) GetByFingerprint(ctx context.Context, fingerprint string) ([]*domain.DiscoveredCertificate, error) {
	if m.GetByFingerprintErr != nil {
		return nil, m.GetByFingerprintErr
	}
	var certs []*domain.DiscoveredCertificate
	for _, c := range m.Discovered {
		if c.FingerprintSHA256 == fingerprint {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func (m *mockDiscoveryRepo) CountByStatus(ctx context.Context) (map[string]int, error) {
	if m.CountByStatusErr != nil {
		return nil, m.CountByStatusErr
	}
	counts := make(map[string]int)
	for _, c := range m.Discovered {
		counts[string(c.Status)]++
	}
	return counts, nil
}

// helper to create a test DiscoveryService wired for discovery tests
func newDiscoveryTestService() (*DiscoveryService, *mockDiscoveryRepo, *mockCertRepo, *mockAuditRepo) {
	discoveryRepo := newMockDiscoveryRepository()
	certRepo := newMockCertificateRepository()
	auditRepo := newMockAuditRepository()

	auditService := NewAuditService(auditRepo)
	discoveryService := NewDiscoveryService(discoveryRepo, certRepo, auditService)

	return discoveryService, discoveryRepo, certRepo, auditRepo
}

func TestProcessDiscoveryReport_Success(t *testing.T) {
	svc, discoveryRepo, _, auditRepo := newDiscoveryTestService()

	report := &domain.DiscoveryReport{
		AgentID:        "agent-1",
		Directories:    []string{"/etc/certs", "/opt/certs"},
		ScanDurationMs: 150,
		Certificates: []domain.DiscoveredCertEntry{
			{
				FingerprintSHA256: "abc123",
				CommonName:        "example.com",
				SANs:              []string{"www.example.com"},
				SerialNumber:      "001",
				IssuerDN:          "CN=Let's Encrypt",
				SubjectDN:         "CN=example.com",
				NotBefore:         time.Now().AddDate(-1, 0, 0).Format(time.RFC3339),
				NotAfter:          time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
				KeyAlgorithm:      "RSA",
				KeySize:           2048,
				IsCA:              false,
				PEMData:           "-----BEGIN CERTIFICATE-----...",
				SourcePath:        "/etc/certs/example.com.crt",
				SourceFormat:      "PEM",
			},
		},
		Errors: []string{},
	}

	scan, err := svc.ProcessDiscoveryReport(context.Background(), report)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if scan == nil {
		t.Fatal("expected scan to be returned")
	}
	if scan.AgentID != "agent-1" {
		t.Errorf("expected agent ID agent-1, got %s", scan.AgentID)
	}
	if scan.CertificatesFound != 1 {
		t.Errorf("expected 1 certificate found, got %d", scan.CertificatesFound)
	}
	if scan.CertificatesNew != 1 {
		t.Errorf("expected 1 new certificate, got %d", scan.CertificatesNew)
	}

	// Verify scan was persisted
	if len(discoveryRepo.Scans) != 1 {
		t.Fatalf("expected 1 scan in repo, got %d", len(discoveryRepo.Scans))
	}

	// Verify discovered cert was persisted
	if len(discoveryRepo.Discovered) != 1 {
		t.Fatalf("expected 1 discovered cert in repo, got %d", len(discoveryRepo.Discovered))
	}

	// Verify audit event was recorded
	if len(auditRepo.Events) == 0 {
		t.Error("expected audit event to be recorded")
	}
	foundDiscoveryAudit := false
	for _, e := range auditRepo.Events {
		if e.Action == "discovery_scan_completed" {
			foundDiscoveryAudit = true
		}
	}
	if !foundDiscoveryAudit {
		t.Error("expected discovery_scan_completed audit event")
	}
}

func TestProcessDiscoveryReport_EmptyAgentID(t *testing.T) {
	svc, _, _, _ := newDiscoveryTestService()

	report := &domain.DiscoveryReport{
		AgentID: "", // empty agent ID
		Certificates: []domain.DiscoveredCertEntry{
			{
				FingerprintSHA256: "abc123",
				CommonName:        "example.com",
			},
		},
	}

	_, err := svc.ProcessDiscoveryReport(context.Background(), report)
	if err == nil {
		t.Fatal("expected error for empty agent_id")
	}
	if !errors.Is(err, err) { // just verify error occurred
		t.Errorf("expected validation error")
	}
}

func TestProcessDiscoveryReport_EmptyReport(t *testing.T) {
	svc, _, _, _ := newDiscoveryTestService()

	report := &domain.DiscoveryReport{
		AgentID:        "agent-1",
		Certificates:   []domain.DiscoveredCertEntry{},
		Errors:         []string{},
		ScanDurationMs: 100,
	}

	_, err := svc.ProcessDiscoveryReport(context.Background(), report)
	if err == nil {
		t.Fatal("expected error for empty report")
	}
}

func TestListDiscovered_Success(t *testing.T) {
	svc, discoveryRepo, _, _ := newDiscoveryTestService()

	now := time.Now()
	cert1 := &domain.DiscoveredCertificate{
		ID:           "dcert-1",
		AgentID:      "agent-1",
		CommonName:   "example.com",
		Status:       domain.DiscoveryStatusUnmanaged,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	cert2 := &domain.DiscoveredCertificate{
		ID:           "dcert-2",
		AgentID:      "agent-1",
		CommonName:   "api.example.com",
		Status:       domain.DiscoveryStatusManaged,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	discoveryRepo.Discovered[cert1.ID] = cert1
	discoveryRepo.Discovered[cert2.ID] = cert2

	certs, total, err := svc.ListDiscovered(context.Background(), "agent-1", "", 1, 50)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
}

func TestListDiscovered_WithStatusFilter(t *testing.T) {
	svc, discoveryRepo, _, _ := newDiscoveryTestService()

	now := time.Now()
	cert1 := &domain.DiscoveredCertificate{
		ID:        "dcert-1",
		AgentID:   "agent-1",
		CommonName: "example.com",
		Status:    domain.DiscoveryStatusUnmanaged,
		CreatedAt: now,
		UpdatedAt: now,
	}
	cert2 := &domain.DiscoveredCertificate{
		ID:        "dcert-2",
		AgentID:   "agent-1",
		CommonName: "api.example.com",
		Status:    domain.DiscoveryStatusManaged,
		CreatedAt: now,
		UpdatedAt: now,
	}
	discoveryRepo.Discovered[cert1.ID] = cert1
	discoveryRepo.Discovered[cert2.ID] = cert2

	certs, total, err := svc.ListDiscovered(context.Background(), "agent-1", "Unmanaged", 1, 50)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
}

func TestGetDiscovered_Success(t *testing.T) {
	svc, discoveryRepo, _, _ := newDiscoveryTestService()

	now := time.Now()
	cert := &domain.DiscoveredCertificate{
		ID:           "dcert-1",
		CommonName:   "example.com",
		Status:       domain.DiscoveryStatusUnmanaged,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	discoveryRepo.Discovered[cert.ID] = cert

	retrieved, err := svc.GetDiscovered(context.Background(), "dcert-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if retrieved.ID != "dcert-1" {
		t.Errorf("expected ID dcert-1, got %s", retrieved.ID)
	}
}

func TestClaimDiscovered_Success(t *testing.T) {
	svc, discoveryRepo, certRepo, auditRepo := newDiscoveryTestService()

	now := time.Now()
	discoveredCert := &domain.DiscoveredCertificate{
		ID:                   "dcert-1",
		CommonName:           "example.com",
		FingerprintSHA256:    "abc123",
		Status:               domain.DiscoveryStatusUnmanaged,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	discoveryRepo.Discovered[discoveredCert.ID] = discoveredCert

	managedCert := &domain.ManagedCertificate{
		ID:         "mc-prod-1",
		CommonName: "example.com",
		Status:     domain.CertificateStatusActive,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	certRepo.AddCert(managedCert)

	err := svc.ClaimDiscovered(context.Background(), "dcert-1", "mc-prod-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify status was updated
	updated := discoveryRepo.Discovered["dcert-1"]
	if updated.Status != domain.DiscoveryStatusManaged {
		t.Errorf("expected status Managed, got %s", updated.Status)
	}
	if updated.ManagedCertificateID != "mc-prod-1" {
		t.Errorf("expected managed cert ID mc-prod-1, got %s", updated.ManagedCertificateID)
	}

	// Verify audit event was recorded
	if len(auditRepo.Events) == 0 {
		t.Error("expected audit event to be recorded")
	}
	foundClaimAudit := false
	for _, e := range auditRepo.Events {
		if e.Action == "discovery_cert_claimed" {
			foundClaimAudit = true
		}
	}
	if !foundClaimAudit {
		t.Error("expected discovery_cert_claimed audit event")
	}
}

func TestClaimDiscovered_MissingManagedCertID(t *testing.T) {
	svc, discoveryRepo, _, _ := newDiscoveryTestService()

	now := time.Now()
	cert := &domain.DiscoveredCertificate{
		ID:        "dcert-1",
		CommonName: "example.com",
		Status:    domain.DiscoveryStatusUnmanaged,
		CreatedAt: now,
		UpdatedAt: now,
	}
	discoveryRepo.Discovered[cert.ID] = cert

	err := svc.ClaimDiscovered(context.Background(), "dcert-1", "")
	if err == nil {
		t.Fatal("expected error for empty managed_certificate_id")
	}
}

func TestClaimDiscovered_ManagedCertNotFound(t *testing.T) {
	svc, discoveryRepo, _, _ := newDiscoveryTestService()

	now := time.Now()
	cert := &domain.DiscoveredCertificate{
		ID:        "dcert-1",
		CommonName: "example.com",
		Status:    domain.DiscoveryStatusUnmanaged,
		CreatedAt: now,
		UpdatedAt: now,
	}
	discoveryRepo.Discovered[cert.ID] = cert

	err := svc.ClaimDiscovered(context.Background(), "dcert-1", "nonexistent-cert")
	if err == nil {
		t.Fatal("expected error for nonexistent managed certificate")
	}
	if !errors.Is(err, err) { // just verify error occurred
		t.Errorf("expected 'not found' error")
	}
}

func TestDismissDiscovered_Success(t *testing.T) {
	svc, discoveryRepo, _, auditRepo := newDiscoveryTestService()

	now := time.Now()
	cert := &domain.DiscoveredCertificate{
		ID:        "dcert-1",
		CommonName: "example.com",
		Status:    domain.DiscoveryStatusUnmanaged,
		CreatedAt: now,
		UpdatedAt: now,
	}
	discoveryRepo.Discovered[cert.ID] = cert

	err := svc.DismissDiscovered(context.Background(), "dcert-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify status was updated
	updated := discoveryRepo.Discovered["dcert-1"]
	if updated.Status != domain.DiscoveryStatusDismissed {
		t.Errorf("expected status Dismissed, got %s", updated.Status)
	}
	if updated.DismissedAt == nil {
		t.Error("expected DismissedAt to be set")
	}

	// Verify audit event was recorded
	if len(auditRepo.Events) == 0 {
		t.Error("expected audit event to be recorded")
	}
	foundDismissAudit := false
	for _, e := range auditRepo.Events {
		if e.Action == "discovery_cert_dismissed" {
			foundDismissAudit = true
		}
	}
	if !foundDismissAudit {
		t.Error("expected discovery_cert_dismissed audit event")
	}
}

func TestDismissDiscovered_NotFound(t *testing.T) {
	svc, discoveryRepo, _, _ := newDiscoveryTestService()

	discoveryRepo.UpdateStatusErr = errNotFound
	err := svc.DismissDiscovered(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent cert")
	}
}
