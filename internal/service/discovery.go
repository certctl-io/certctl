package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// DiscoveryService provides business logic for certificate discovery.
type DiscoveryService struct {
	discoveryRepo repository.DiscoveryRepository
	certRepo      repository.CertificateRepository
	auditService  *AuditService
}

// NewDiscoveryService creates a new discovery service.
func NewDiscoveryService(
	discoveryRepo repository.DiscoveryRepository,
	certRepo repository.CertificateRepository,
	auditService *AuditService,
) *DiscoveryService {
	return &DiscoveryService{
		discoveryRepo: discoveryRepo,
		certRepo:      certRepo,
		auditService:  auditService,
	}
}

// ProcessDiscoveryReport processes a discovery report from an agent.
// It creates a scan record, upserts each discovered certificate, and returns scan summary.
func (s *DiscoveryService) ProcessDiscoveryReport(ctx context.Context, report *domain.DiscoveryReport) (*domain.DiscoveryScan, error) {
	if report.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if len(report.Certificates) == 0 && len(report.Errors) == 0 {
		return nil, fmt.Errorf("report must contain at least one certificate or error")
	}

	now := time.Now()
	scan := &domain.DiscoveryScan{
		ID:                generateID("dscan"),
		AgentID:           report.AgentID,
		Directories:       report.Directories,
		CertificatesFound: len(report.Certificates),
		ErrorsCount:       len(report.Errors),
		ScanDurationMs:    report.ScanDurationMs,
		StartedAt:         now.Add(-time.Duration(report.ScanDurationMs) * time.Millisecond),
		CompletedAt:       &now,
	}

	// Upsert each discovered certificate
	newCount := 0
	for _, entry := range report.Certificates {
		cert := &domain.DiscoveredCertificate{
			ID:                generateID("dcert"),
			FingerprintSHA256: entry.FingerprintSHA256,
			CommonName:        entry.CommonName,
			SANs:              entry.SANs,
			SerialNumber:      entry.SerialNumber,
			IssuerDN:          entry.IssuerDN,
			SubjectDN:         entry.SubjectDN,
			KeyAlgorithm:      entry.KeyAlgorithm,
			KeySize:           entry.KeySize,
			IsCA:              entry.IsCA,
			PEMData:           entry.PEMData,
			SourcePath:        entry.SourcePath,
			SourceFormat:      entry.SourceFormat,
			AgentID:           report.AgentID,
			DiscoveryScanID:   scan.ID,
			Status:            domain.DiscoveryStatusUnmanaged,
			FirstSeenAt:       now,
			LastSeenAt:        now,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		// Parse time fields
		if entry.NotBefore != "" {
			if t, err := time.Parse(time.RFC3339, entry.NotBefore); err == nil {
				cert.NotBefore = &t
			}
		}
		if entry.NotAfter != "" {
			if t, err := time.Parse(time.RFC3339, entry.NotAfter); err == nil {
				cert.NotAfter = &t
			}
		}

		isNew, err := s.discoveryRepo.CreateDiscovered(ctx, cert)
		if err != nil {
			slog.Error("failed to upsert discovered certificate",
				"fingerprint", entry.FingerprintSHA256,
				"source_path", entry.SourcePath,
				"error", err)
			continue
		}
		if isNew {
			newCount++
		}
	}

	scan.CertificatesNew = newCount

	// Store the scan record
	if err := s.discoveryRepo.CreateScan(ctx, scan); err != nil {
		return nil, fmt.Errorf("failed to create scan record: %w", err)
	}

	// Audit trail
	if err := s.auditService.RecordEvent(ctx, report.AgentID, domain.ActorTypeSystem,
		"discovery_scan_completed", "discovery_scan", scan.ID,
		map[string]interface{}{
			"agent_id":           report.AgentID,
			"directories":        report.Directories,
			"certificates_found": scan.CertificatesFound,
			"certificates_new":   newCount,
			"errors_count":       scan.ErrorsCount,
		}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return scan, nil
}

// ListDiscovered returns discovered certificates matching the filter.
func (s *DiscoveryService) ListDiscovered(ctx context.Context, agentID, status string, page, perPage int) ([]*domain.DiscoveredCertificate, int, error) {
	filter := &repository.DiscoveryFilter{
		AgentID: agentID,
		Status:  status,
		Page:    page,
		PerPage: perPage,
	}
	return s.discoveryRepo.ListDiscovered(ctx, filter)
}

// GetDiscovered retrieves a discovered certificate by ID.
func (s *DiscoveryService) GetDiscovered(ctx context.Context, id string) (*domain.DiscoveredCertificate, error) {
	return s.discoveryRepo.GetDiscovered(ctx, id)
}

// ClaimDiscovered links a discovered certificate to a managed certificate.
func (s *DiscoveryService) ClaimDiscovered(ctx context.Context, id string, managedCertID string) error {
	if managedCertID == "" {
		return fmt.Errorf("managed_certificate_id is required")
	}

	// Verify the discovered cert exists
	disc, err := s.discoveryRepo.GetDiscovered(ctx, id)
	if err != nil {
		return err
	}

	// Verify the managed cert exists
	if _, err := s.certRepo.Get(ctx, managedCertID); err != nil {
		return fmt.Errorf("managed certificate not found: %s", managedCertID)
	}

	if err := s.discoveryRepo.UpdateDiscoveredStatus(ctx, id, domain.DiscoveryStatusManaged, managedCertID); err != nil {
		return err
	}

	// Audit trail
	if err := s.auditService.RecordEvent(ctx, "operator", domain.ActorTypeUser,
		"discovery_cert_claimed", "discovered_certificate", id,
		map[string]interface{}{
			"managed_certificate_id": managedCertID,
			"fingerprint":            disc.FingerprintSHA256,
			"common_name":            disc.CommonName,
		}); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// DismissDiscovered marks a discovered certificate as dismissed.
func (s *DiscoveryService) DismissDiscovered(ctx context.Context, id string) error {
	if err := s.discoveryRepo.UpdateDiscoveredStatus(ctx, id, domain.DiscoveryStatusDismissed, ""); err != nil {
		return err
	}

	// Audit trail
	if err := s.auditService.RecordEvent(ctx, "operator", domain.ActorTypeUser,
		"discovery_cert_dismissed", "discovered_certificate", id, nil); err != nil {
		slog.Error("failed to record audit event", "error", err)
	}

	return nil
}

// ListScans returns discovery scans, optionally filtered by agent ID.
func (s *DiscoveryService) ListScans(ctx context.Context, agentID string, page, perPage int) ([]*domain.DiscoveryScan, int, error) {
	return s.discoveryRepo.ListScans(ctx, agentID, page, perPage)
}

// GetScan retrieves a discovery scan by ID.
func (s *DiscoveryService) GetScan(ctx context.Context, id string) (*domain.DiscoveryScan, error) {
	return s.discoveryRepo.GetScan(ctx, id)
}

// GetDiscoverySummary returns a summary of discovery status counts.
func (s *DiscoveryService) GetDiscoverySummary(ctx context.Context) (map[string]int, error) {
	return s.discoveryRepo.CountByStatus(ctx)
}
