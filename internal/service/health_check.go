package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/tlsprobe"
)

// HealthCheckService manages endpoint TLS health monitoring.
type HealthCheckService struct {
	repo             repository.HealthCheckRepository
	auditService     *AuditService
	notifService     *NotificationService
	logger           *slog.Logger
	maxConcurrent    int
	defaultTimeout   time.Duration
	historyRetention time.Duration
	autoCreate       bool
}

// NewHealthCheckService creates a new HealthCheckService.
func NewHealthCheckService(
	repo repository.HealthCheckRepository,
	auditService *AuditService,
	logger *slog.Logger,
	maxConcurrent int,
	defaultTimeout time.Duration,
	historyRetention time.Duration,
	autoCreate bool,
) *HealthCheckService {
	return &HealthCheckService{
		repo:             repo,
		auditService:     auditService,
		logger:           logger,
		maxConcurrent:    maxConcurrent,
		defaultTimeout:   defaultTimeout,
		historyRetention: historyRetention,
		autoCreate:       autoCreate,
	}
}

// SetNotificationService sets the notification service for sending status transition alerts.
func (s *HealthCheckService) SetNotificationService(ns *NotificationService) {
	s.notifService = ns
}

// RunHealthChecks is the scheduler entry point for continuous TLS health monitoring.
// Fetches endpoints due for check, probes concurrently with semaphore control,
// updates health status with state transitions, records history, and sends notifications.
func (s *HealthCheckService) RunHealthChecks(ctx context.Context) error {
	// Fetch all endpoints due for check
	checks, err := s.repo.ListDueForCheck(ctx)
	if err != nil {
		return fmt.Errorf("failed to list endpoints due for check: %w", err)
	}

	if len(checks) == 0 {
		s.logger.Debug("no endpoints due for health check")
		return nil
	}

	s.logger.Debug("running health checks", "endpoint_count", len(checks))

	// Concurrent probing with semaphore
	sem := make(chan struct{}, s.maxConcurrent)
	var wg sync.WaitGroup
	probeResults := make(map[string]tlsprobe.ProbeResult)
	var mu sync.Mutex

	for _, check := range checks {
		wg.Add(1)
		go func(c *domain.EndpointHealthCheck) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			result := tlsprobe.ProbeTLS(ctx, c.Endpoint, s.defaultTimeout)
			mu.Lock()
			probeResults[c.ID] = result
			mu.Unlock()
		}(check)
	}

	wg.Wait()

	// Process results and update health status
	successCount := 0
	failureCount := 0
	transitionCount := 0

	for _, check := range checks {
		result := probeResults[check.ID]

		// Determine old status for transition detection
		oldStatus := check.Status

		// Update probe result fields
		check.LastCheckedAt = timePtr(time.Now())
		check.ResponseTimeMs = result.ResponseTimeMs

		if result.Success {
			successCount++
			check.ObservedFingerprint = result.Fingerprint
			check.TLSVersion = result.TLSVersion
			check.CipherSuite = result.CipherSuite
			check.CertSubject = result.Subject
			check.CertIssuer = result.Issuer
			check.CertExpiry = timePtr(result.NotAfter)
			check.FailureReason = ""
			check.LastSuccessAt = timePtr(time.Now())
			check.ConsecutiveFailures = 0
		} else {
			failureCount++
			check.LastFailureAt = timePtr(time.Now())
			check.ConsecutiveFailures++
			check.FailureReason = result.Error
		}

		// Transition state based on consecutive failures and fingerprint match
		newStatus, transitioned := check.TransitionStatus(result.Success, result.Fingerprint)

		if transitioned {
			transitionCount++
			check.Status = newStatus
			check.LastTransitionAt = timePtr(time.Now())
			// Reset acknowledged on transition
			check.Acknowledged = false

			// Log transition
			s.logger.Info("health check status transition",
				"endpoint", check.Endpoint,
				"old_status", string(oldStatus),
				"new_status", string(newStatus))

			// Record audit event
			if s.auditService != nil {
				_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
					"health_check_status_transition", "health_check", check.ID,
					map[string]interface{}{
						"endpoint":   check.Endpoint,
						"old_status": string(oldStatus),
						"new_status": string(newStatus),
					})
			}
		}

		// Update health check record
		if err := s.repo.Update(ctx, check); err != nil {
			s.logger.Error("failed to update health check",
				"endpoint", check.Endpoint,
				"error", err)
			continue
		}

		// Record probe result in history
		if err := s.repo.RecordHistory(ctx, &domain.HealthHistoryEntry{
			HealthCheckID:  check.ID,
			Status:         string(check.Status),
			ResponseTimeMs: check.ResponseTimeMs,
			Fingerprint:    check.ObservedFingerprint,
			FailureReason:  check.FailureReason,
			CheckedAt:      time.Now(),
		}); err != nil {
			s.logger.Warn("failed to record health check history",
				"endpoint", check.Endpoint,
				"error", err)
		}
	}

	// Purge old history entries once per run
	if err := s.PurgeOldHistory(ctx); err != nil {
		s.logger.Warn("failed to purge old health check history", "error", err)
	}

	s.logger.Debug("health check run completed",
		"total", len(checks),
		"success", successCount,
		"failure", failureCount,
		"transitions", transitionCount)

	return nil
}

// Create creates a new health check endpoint.
func (s *HealthCheckService) Create(ctx context.Context, check *domain.EndpointHealthCheck) error {
	if check.ID == "" {
		check.ID = generateID("hc")
	}
	check.CreatedAt = time.Now()
	check.UpdatedAt = time.Now()

	if err := s.repo.Create(ctx, check); err != nil {
		return fmt.Errorf("failed to create health check: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"health_check_created", "health_check", check.ID,
			map[string]interface{}{
				"endpoint": check.Endpoint,
			})
	}

	return nil
}

// Get retrieves a health check by ID.
func (s *HealthCheckService) Get(ctx context.Context, id string) (*domain.EndpointHealthCheck, error) {
	return s.repo.Get(ctx, id)
}

// Update updates an existing health check.
func (s *HealthCheckService) Update(ctx context.Context, check *domain.EndpointHealthCheck) error {
	check.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, check); err != nil {
		return fmt.Errorf("failed to update health check: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"health_check_updated", "health_check", check.ID,
			map[string]interface{}{
				"endpoint": check.Endpoint,
			})
	}

	return nil
}

// Delete deletes a health check.
func (s *HealthCheckService) Delete(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete health check: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, "system", domain.ActorTypeSystem,
			"health_check_deleted", "health_check", id,
			map[string]interface{}{})
	}

	return nil
}

// List lists health checks with optional filtering.
func (s *HealthCheckService) List(ctx context.Context, filter *repository.HealthCheckFilter) ([]*domain.EndpointHealthCheck, int, error) {
	if filter == nil {
		filter = &repository.HealthCheckFilter{}
	}
	return s.repo.List(ctx, filter)
}

// GetHistory retrieves health check history for an endpoint.
func (s *HealthCheckService) GetHistory(ctx context.Context, healthCheckID string, limit int) ([]*domain.HealthHistoryEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return s.repo.GetHistory(ctx, healthCheckID, limit)
}

// AcknowledgeIncident marks a health check incident as acknowledged.
func (s *HealthCheckService) AcknowledgeIncident(ctx context.Context, id string, actor string) error {
	check, err := s.repo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get health check: %w", err)
	}

	check.Acknowledged = true
	check.AcknowledgedBy = actor
	check.AcknowledgedAt = timePtr(time.Now())

	if err := s.repo.Update(ctx, check); err != nil {
		return fmt.Errorf("failed to update health check: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser,
			"health_check_acknowledged", "health_check", id,
			map[string]interface{}{
				"endpoint": check.Endpoint,
			})
	}

	return nil
}

// GetSummary returns aggregated health check status counts.
func (s *HealthCheckService) GetSummary(ctx context.Context) (*domain.HealthCheckSummary, error) {
	return s.repo.GetSummary(ctx)
}

// PurgeOldHistory removes health check history entries older than the retention period.
func (s *HealthCheckService) PurgeOldHistory(ctx context.Context) error {
	cutoff := time.Now().Add(-s.historyRetention)
	_, err := s.repo.PurgeHistory(ctx, cutoff)
	return err
}

// Helper functions

func timePtr(t time.Time) *time.Time {
	return &t
}
