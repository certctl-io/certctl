package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/shankar0123/certctl/internal/service"
)

// Scheduler manages background jobs and periodic tasks for the certificate control plane.
// It runs multiple concurrent loops for renewal checks, job processing, agent health checks,
// and notification processing.
type Scheduler struct {
	renewalService      *service.RenewalService
	jobService          *service.JobService
	agentService        *service.AgentService
	notificationService *service.NotificationService
	logger              *slog.Logger

	// Configurable tick intervals
	renewalCheckInterval            time.Duration
	jobProcessorInterval            time.Duration
	agentHealthCheckInterval        time.Duration
	notificationProcessInterval     time.Duration
	shortLivedExpiryCheckInterval   time.Duration
}

// NewScheduler creates a new scheduler with configurable intervals.
func NewScheduler(
	renewalService *service.RenewalService,
	jobService *service.JobService,
	agentService *service.AgentService,
	notificationService *service.NotificationService,
	logger *slog.Logger,
) *Scheduler {
	return &Scheduler{
		renewalService:      renewalService,
		jobService:          jobService,
		agentService:        agentService,
		notificationService: notificationService,
		logger:              logger,

		// Default intervals
		renewalCheckInterval:          1 * time.Hour,
		jobProcessorInterval:          30 * time.Second,
		agentHealthCheckInterval:      2 * time.Minute,
		notificationProcessInterval:   1 * time.Minute,
		shortLivedExpiryCheckInterval: 30 * time.Second,
	}
}

// SetRenewalCheckInterval configures the interval for renewal checks.
func (s *Scheduler) SetRenewalCheckInterval(d time.Duration) {
	s.renewalCheckInterval = d
}

// SetJobProcessorInterval configures the interval for job processing.
func (s *Scheduler) SetJobProcessorInterval(d time.Duration) {
	s.jobProcessorInterval = d
}

// SetAgentHealthCheckInterval configures the interval for agent health checks.
func (s *Scheduler) SetAgentHealthCheckInterval(d time.Duration) {
	s.agentHealthCheckInterval = d
}

// SetNotificationProcessInterval configures the interval for notification processing.
func (s *Scheduler) SetNotificationProcessInterval(d time.Duration) {
	s.notificationProcessInterval = d
}

// Start initiates all background scheduler loops. It returns a channel that signals
// when the scheduler has started all loops. The scheduler runs until the context is cancelled.
func (s *Scheduler) Start(ctx context.Context) <-chan struct{} {
	startedChan := make(chan struct{})

	go func() {
		s.logger.Info("scheduler starting")

		// Signal that the scheduler has started all loops
		go func() {
			<-time.After(100 * time.Millisecond)
			close(startedChan)
		}()

		// Start all scheduler loops concurrently
		go s.renewalCheckLoop(ctx)
		go s.jobProcessorLoop(ctx)
		go s.agentHealthCheckLoop(ctx)
		go s.notificationProcessLoop(ctx)
		go s.shortLivedExpiryCheckLoop(ctx)

		// Wait for context cancellation
		<-ctx.Done()
		s.logger.Info("scheduler shutting down", "reason", ctx.Err())
	}()

	return startedChan
}

// renewalCheckLoop runs every renewalCheckInterval and checks for expiring certificates.
// If an error occurs, it logs the error but continues running.
func (s *Scheduler) renewalCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.renewalCheckInterval)
	defer ticker.Stop()

	// Run immediately on start
	s.runRenewalCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runRenewalCheck(ctx)
		}
	}
}

// runRenewalCheck executes a single renewal check with error recovery.
func (s *Scheduler) runRenewalCheck(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := s.renewalService.CheckExpiringCertificates(opCtx); err != nil {
		s.logger.Error("renewal check failed",
			"error", err,
			"interval", s.renewalCheckInterval.String())
	} else {
		s.logger.Debug("renewal check completed")
	}
}

// jobProcessorLoop runs every jobProcessorInterval and processes pending jobs.
// It picks up pending jobs, executes them, and handles the results.
// If an error occurs, it logs the error but continues running.
func (s *Scheduler) jobProcessorLoop(ctx context.Context) {
	ticker := time.NewTicker(s.jobProcessorInterval)
	defer ticker.Stop()

	// Run immediately on start
	s.runJobProcessor(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runJobProcessor(ctx)
		}
	}
}

// runJobProcessor executes a single job processing cycle with error recovery.
func (s *Scheduler) runJobProcessor(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := s.jobService.ProcessPendingJobs(opCtx); err != nil {
		s.logger.Error("job processor failed",
			"error", err,
			"interval", s.jobProcessorInterval.String())
	} else {
		s.logger.Debug("job processor completed")
	}
}

// agentHealthCheckLoop runs every agentHealthCheckInterval and marks stale agents as offline.
// An agent is considered stale if it hasn't sent a heartbeat within the health check interval.
// If an error occurs, it logs the error but continues running.
func (s *Scheduler) agentHealthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.agentHealthCheckInterval)
	defer ticker.Stop()

	// Run immediately on start
	s.runAgentHealthCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runAgentHealthCheck(ctx)
		}
	}
}

// runAgentHealthCheck executes a single agent health check with error recovery.
func (s *Scheduler) runAgentHealthCheck(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	if err := s.agentService.MarkStaleAgentsOffline(opCtx, s.agentHealthCheckInterval); err != nil {
		s.logger.Error("agent health check failed",
			"error", err,
			"interval", s.agentHealthCheckInterval.String())
	} else {
		s.logger.Debug("agent health check completed")
	}
}

// notificationProcessLoop runs every notificationProcessInterval and processes pending notifications.
// If an error occurs, it logs the error but continues running.
func (s *Scheduler) notificationProcessLoop(ctx context.Context) {
	ticker := time.NewTicker(s.notificationProcessInterval)
	defer ticker.Stop()

	// Run immediately on start
	s.runNotificationProcess(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runNotificationProcess(ctx)
		}
	}
}

// runNotificationProcess executes a single notification processing cycle with error recovery.
func (s *Scheduler) runNotificationProcess(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	if err := s.notificationService.ProcessPendingNotifications(opCtx); err != nil {
		s.logger.Error("notification processor failed",
			"error", err,
			"interval", s.notificationProcessInterval.String())
	} else {
		s.logger.Debug("notification processor completed")
	}
}

// shortLivedExpiryCheckLoop runs every shortLivedExpiryCheckInterval and marks expired
// short-lived certificates. For certs with TTL < 1 hour, expiry IS revocation —
// no CRL/OCSP needed.
func (s *Scheduler) shortLivedExpiryCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.shortLivedExpiryCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runShortLivedExpiryCheck(ctx)
		}
	}
}

// runShortLivedExpiryCheck executes a single short-lived expiry check with error recovery.
func (s *Scheduler) runShortLivedExpiryCheck(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.renewalService.ExpireShortLivedCertificates(opCtx); err != nil {
		s.logger.Error("short-lived expiry check failed",
			"error", err,
			"interval", s.shortLivedExpiryCheckInterval.String())
	} else {
		s.logger.Debug("short-lived expiry check completed")
	}
}
