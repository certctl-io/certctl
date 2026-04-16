package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// Sentinel agent IDs for cloud discovery sources.
const (
	SentinelAWSSecretsMgr = "cloud-aws-sm"
	SentinelAzureKeyVault = "cloud-azure-kv"
	SentinelGCPSecretMgr  = "cloud-gcp-sm"
)

// CloudDiscoveryService orchestrates certificate discovery from multiple cloud sources.
// It iterates registered DiscoverySource implementations, feeds each report into
// ProcessDiscoveryReport for dedup, audit, and triage.
type CloudDiscoveryService struct {
	sources          []domain.DiscoverySource
	discoveryService *DiscoveryService
	logger           *slog.Logger
}

// NewCloudDiscoveryService creates a new CloudDiscoveryService.
func NewCloudDiscoveryService(
	discoveryService *DiscoveryService,
	logger *slog.Logger,
) *CloudDiscoveryService {
	return &CloudDiscoveryService{
		sources:          make([]domain.DiscoverySource, 0),
		discoveryService: discoveryService,
		logger:           logger,
	}
}

// RegisterSource adds a discovery source to the service.
func (s *CloudDiscoveryService) RegisterSource(source domain.DiscoverySource) {
	s.sources = append(s.sources, source)
	s.logger.Info("registered cloud discovery source",
		"name", source.Name(),
		"type", source.Type())
}

// SourceCount returns the number of registered discovery sources.
func (s *CloudDiscoveryService) SourceCount() int {
	return len(s.sources)
}

// DiscoverAll runs all registered discovery sources and feeds results into the
// existing discovery pipeline. Returns the total number of certificates found
// across all sources and any errors encountered.
func (s *CloudDiscoveryService) DiscoverAll(ctx context.Context) (int, []error) {
	if len(s.sources) == 0 {
		s.logger.Debug("no cloud discovery sources registered, skipping")
		return 0, nil
	}

	totalCerts := 0
	var allErrors []error

	for _, source := range s.sources {
		select {
		case <-ctx.Done():
			allErrors = append(allErrors, fmt.Errorf("cloud discovery cancelled: %w", ctx.Err()))
			return totalCerts, allErrors
		default:
		}

		s.logger.Info("running cloud discovery source",
			"name", source.Name(),
			"type", source.Type())

		start := time.Now()
		report, err := source.Discover(ctx)
		elapsed := time.Since(start)

		if err != nil {
			s.logger.Error("cloud discovery source failed",
				"name", source.Name(),
				"type", source.Type(),
				"error", err,
				"elapsed", elapsed.String())
			allErrors = append(allErrors, fmt.Errorf("source %s failed: %w", source.Name(), err))
			continue
		}

		if report == nil {
			s.logger.Warn("cloud discovery source returned nil report",
				"name", source.Name(),
				"type", source.Type())
			continue
		}

		certCount := len(report.Certificates)
		s.logger.Info("cloud discovery source completed",
			"name", source.Name(),
			"type", source.Type(),
			"certificates_found", certCount,
			"errors", len(report.Errors),
			"elapsed", elapsed.String())

		// Feed the report into the existing discovery pipeline for dedup, audit, and triage.
		if certCount > 0 || len(report.Errors) > 0 {
			if _, err := s.discoveryService.ProcessDiscoveryReport(ctx, report); err != nil {
				s.logger.Error("failed to process cloud discovery report",
					"name", source.Name(),
					"type", source.Type(),
					"error", err)
				allErrors = append(allErrors, fmt.Errorf("process report for %s: %w", source.Name(), err))
			}
		}

		totalCerts += certCount
	}

	return totalCerts, allErrors
}
