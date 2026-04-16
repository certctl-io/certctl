package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// RenewalServicer defines the interface for renewal operations used by the scheduler.
type RenewalServicer interface {
	CheckExpiringCertificates(ctx context.Context) error
	ExpireShortLivedCertificates(ctx context.Context) error
}

// JobServicer defines the interface for job processing used by the scheduler.
type JobServicer interface {
	ProcessPendingJobs(ctx context.Context) error
}

// AgentServicer defines the interface for agent health checks used by the scheduler.
type AgentServicer interface {
	MarkStaleAgentsOffline(ctx context.Context, interval time.Duration) error
}

// NotificationServicer defines the interface for notification processing used by the scheduler.
type NotificationServicer interface {
	ProcessPendingNotifications(ctx context.Context) error
}

// NetworkScanServicer defines the interface for network scanning used by the scheduler.
type NetworkScanServicer interface {
	ScanAllTargets(ctx context.Context) error
}

// DigestServicer defines the interface for digest email processing used by the scheduler.
type DigestServicer interface {
	ProcessDigest(ctx context.Context) error
}

// HealthCheckServicer defines the interface for endpoint TLS health monitoring used by the scheduler.
type HealthCheckServicer interface {
	RunHealthChecks(ctx context.Context) error
}

// Scheduler manages background jobs and periodic tasks for the certificate control plane.
// It runs multiple concurrent loops for renewal checks, job processing, agent health checks,
// and notification processing.
type Scheduler struct {
	renewalService      RenewalServicer
	jobService          JobServicer
	agentService        AgentServicer
	notificationService NotificationServicer
	networkScanService  NetworkScanServicer
	digestService       DigestServicer
	healthCheckService  HealthCheckServicer
	logger              *slog.Logger

	// Configurable tick intervals
	renewalCheckInterval            time.Duration
	jobProcessorInterval            time.Duration
	agentHealthCheckInterval        time.Duration
	notificationProcessInterval     time.Duration
	shortLivedExpiryCheckInterval   time.Duration
	networkScanInterval             time.Duration
	digestInterval                  time.Duration
	healthCheckInterval             time.Duration

	// Idempotency guards: prevent duplicate execution of slow jobs
	renewalCheckRunning           atomic.Bool
	jobProcessorRunning           atomic.Bool
	agentHealthCheckRunning       atomic.Bool
	notificationProcessRunning    atomic.Bool
	shortLivedExpiryCheckRunning  atomic.Bool
	networkScanRunning            atomic.Bool
	digestRunning                 atomic.Bool
	healthCheckRunning            atomic.Bool

	// Graceful shutdown: wait for in-flight work to complete
	wg sync.WaitGroup
}

// NewScheduler creates a new scheduler with configurable intervals.
func NewScheduler(
	renewalService RenewalServicer,
	jobService JobServicer,
	agentService AgentServicer,
	notificationService NotificationServicer,
	networkScanService NetworkScanServicer,
	logger *slog.Logger,
) *Scheduler {
	return &Scheduler{
		renewalService:      renewalService,
		jobService:          jobService,
		agentService:        agentService,
		notificationService: notificationService,
		networkScanService:  networkScanService,
		logger:              logger,

		// Default intervals
		renewalCheckInterval:          1 * time.Hour,
		jobProcessorInterval:          30 * time.Second,
		agentHealthCheckInterval:      2 * time.Minute,
		notificationProcessInterval:   1 * time.Minute,
		shortLivedExpiryCheckInterval: 30 * time.Second,
		networkScanInterval:           6 * time.Hour,
		digestInterval:                24 * time.Hour,
		healthCheckInterval:           60 * time.Second,
	}
}

// SetDigestService sets the digest service for the 7th scheduler loop.
// Called after construction since digest is optional.
func (s *Scheduler) SetDigestService(ds DigestServicer) {
	s.digestService = ds
}

// SetDigestInterval configures the interval for digest email processing.
func (s *Scheduler) SetDigestInterval(d time.Duration) {
	s.digestInterval = d
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

// SetNetworkScanInterval configures the interval for network scanning.
func (s *Scheduler) SetNetworkScanInterval(d time.Duration) {
	s.networkScanInterval = d
}

// SetShortLivedExpiryCheckInterval configures the interval for short-lived certificate expiry checks.
func (s *Scheduler) SetShortLivedExpiryCheckInterval(d time.Duration) {
	s.shortLivedExpiryCheckInterval = d
}

// SetHealthCheckService sets the health check service for the 8th scheduler loop.
// Called after construction since health monitoring is optional.
func (s *Scheduler) SetHealthCheckService(hcs HealthCheckServicer) {
	s.healthCheckService = hcs
}

// SetHealthCheckInterval configures the interval for endpoint TLS health checks.
func (s *Scheduler) SetHealthCheckInterval(d time.Duration) {
	s.healthCheckInterval = d
}

// Start initiates all background scheduler loops. It returns a channel that signals
// when the scheduler has started all loops. The scheduler runs until the context is cancelled.
func (s *Scheduler) Start(ctx context.Context) <-chan struct{} {
	startedChan := make(chan struct{})

	go func() {
		s.logger.Info("scheduler starting")

		// Track all loop goroutines in the WaitGroup so WaitForCompletion
		// blocks until they've fully exited (prevents test races).
		loopCount := 5
		if s.networkScanService != nil {
			loopCount++
		}
		if s.digestService != nil {
			loopCount++
		}
		if s.healthCheckService != nil {
			loopCount++
		}
		s.wg.Add(loopCount)

		go func() { defer s.wg.Done(); s.renewalCheckLoop(ctx) }()
		go func() { defer s.wg.Done(); s.jobProcessorLoop(ctx) }()
		go func() { defer s.wg.Done(); s.agentHealthCheckLoop(ctx) }()
		go func() { defer s.wg.Done(); s.notificationProcessLoop(ctx) }()
		go func() { defer s.wg.Done(); s.shortLivedExpiryCheckLoop(ctx) }()
		if s.networkScanService != nil {
			go func() { defer s.wg.Done(); s.networkScanLoop(ctx) }()
		}
		if s.digestService != nil {
			go func() { defer s.wg.Done(); s.digestLoop(ctx) }()
		}
		if s.healthCheckService != nil {
			go func() { defer s.wg.Done(); s.healthCheckLoop(ctx) }()
		}

		// Signal that all loops are launched
		close(startedChan)

		// Wait for context cancellation
		<-ctx.Done()
		s.logger.Info("scheduler shutting down", "reason", ctx.Err())
	}()

	return startedChan
}

// renewalCheckLoop runs every renewalCheckInterval and checks for expiring certificates.
// If an error occurs, it logs the error but continues running.
// Uses atomic.Bool to prevent duplicate execution if the previous check is still running.
func (s *Scheduler) renewalCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.renewalCheckInterval)
	defer ticker.Stop()

	// Run immediately on start (with idempotency guard)
	s.renewalCheckRunning.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.renewalCheckRunning.Store(false)
		s.runRenewalCheck(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.renewalCheckRunning.CompareAndSwap(false, true) {
				s.logger.Warn("renewal check still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.renewalCheckRunning.Store(false)
				s.runRenewalCheck(ctx)
			}()
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
// Uses atomic.Bool to prevent duplicate execution if the previous job is still running.
func (s *Scheduler) jobProcessorLoop(ctx context.Context) {
	ticker := time.NewTicker(s.jobProcessorInterval)
	defer ticker.Stop()

	// Run immediately on start (with idempotency guard)
	s.jobProcessorRunning.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.jobProcessorRunning.Store(false)
		s.runJobProcessor(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.jobProcessorRunning.CompareAndSwap(false, true) {
				s.logger.Warn("job processor still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.jobProcessorRunning.Store(false)
				s.runJobProcessor(ctx)
			}()
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
// Uses atomic.Bool to prevent duplicate execution if the previous check is still running.
func (s *Scheduler) agentHealthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.agentHealthCheckInterval)
	defer ticker.Stop()

	// Run immediately on start (with idempotency guard)
	s.agentHealthCheckRunning.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.agentHealthCheckRunning.Store(false)
		s.runAgentHealthCheck(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.agentHealthCheckRunning.CompareAndSwap(false, true) {
				s.logger.Warn("agent health check still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.agentHealthCheckRunning.Store(false)
				s.runAgentHealthCheck(ctx)
			}()
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
// Uses atomic.Bool to prevent duplicate execution if the previous process is still running.
func (s *Scheduler) notificationProcessLoop(ctx context.Context) {
	ticker := time.NewTicker(s.notificationProcessInterval)
	defer ticker.Stop()

	// Run immediately on start (with idempotency guard)
	s.notificationProcessRunning.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.notificationProcessRunning.Store(false)
		s.runNotificationProcess(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.notificationProcessRunning.CompareAndSwap(false, true) {
				s.logger.Warn("notification processor still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.notificationProcessRunning.Store(false)
				s.runNotificationProcess(ctx)
			}()
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
// Uses atomic.Bool to prevent duplicate execution if the previous check is still running.
func (s *Scheduler) shortLivedExpiryCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.shortLivedExpiryCheckInterval)
	defer ticker.Stop()

	// Run immediately on start (with idempotency guard)
	s.shortLivedExpiryCheckRunning.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.shortLivedExpiryCheckRunning.Store(false)
		s.runShortLivedExpiryCheck(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.shortLivedExpiryCheckRunning.CompareAndSwap(false, true) {
				s.logger.Warn("short-lived expiry check still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.shortLivedExpiryCheckRunning.Store(false)
				s.runShortLivedExpiryCheck(ctx)
			}()
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

// networkScanLoop runs every networkScanInterval and performs active TLS scanning
// of configured network targets.
// Uses atomic.Bool to prevent duplicate execution if the previous scan is still running.
func (s *Scheduler) networkScanLoop(ctx context.Context) {
	ticker := time.NewTicker(s.networkScanInterval)
	defer ticker.Stop()

	// Run immediately on start (with idempotency guard)
	s.networkScanRunning.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.networkScanRunning.Store(false)
		s.runNetworkScan(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.networkScanRunning.CompareAndSwap(false, true) {
				s.logger.Warn("network scan still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.networkScanRunning.Store(false)
				s.runNetworkScan(ctx)
			}()
		}
	}
}

// runNetworkScan executes a single network scan cycle with error recovery.
func (s *Scheduler) runNetworkScan(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if err := s.networkScanService.ScanAllTargets(opCtx); err != nil {
		s.logger.Error("network scan failed",
			"error", err,
			"interval", s.networkScanInterval.String())
	} else {
		s.logger.Debug("network scan completed")
	}
}

// digestLoop runs every digestInterval and generates/sends certificate digest emails.
// Uses atomic.Bool to prevent duplicate execution if the previous digest is still running.
func (s *Scheduler) digestLoop(ctx context.Context) {
	ticker := time.NewTicker(s.digestInterval)
	defer ticker.Stop()

	// Do NOT run immediately on start for digest — wait for the first tick.
	// Digests are infrequent (24h default) and shouldn't fire on every restart.

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.digestRunning.CompareAndSwap(false, true) {
				s.logger.Warn("digest processor still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.digestRunning.Store(false)
				s.runDigest(ctx)
			}()
		}
	}
}

// runDigest executes a single digest processing cycle with error recovery.
func (s *Scheduler) runDigest(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := s.digestService.ProcessDigest(opCtx); err != nil {
		s.logger.Error("digest processor failed",
			"error", err,
			"interval", s.digestInterval.String())
	} else {
		s.logger.Debug("digest processor completed")
	}
}

// healthCheckLoop runs every healthCheckInterval and performs endpoint TLS health checks.
// Do NOT run immediately on start — health checks are frequent (60s default) and may be
// resource-intensive. Wait for the first tick.
// Uses atomic.Bool to prevent duplicate execution if the previous check is still running.
func (s *Scheduler) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.healthCheckInterval)
	defer ticker.Stop()

	// Do NOT run immediately on start for health checks — wait for the first tick.
	// Health checks are frequent and shouldn't fire on every restart.

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.healthCheckRunning.CompareAndSwap(false, true) {
				s.logger.Debug("health check still running, skipping tick")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.healthCheckRunning.Store(false)
				s.runHealthCheck(ctx)
			}()
		}
	}
}

// runHealthCheck executes a single health check cycle with error recovery.
func (s *Scheduler) runHealthCheck(ctx context.Context) {
	opCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := s.healthCheckService.RunHealthChecks(opCtx); err != nil {
		s.logger.Error("health check run failed",
			"error", err,
			"interval", s.healthCheckInterval.String())
	} else {
		s.logger.Debug("health check completed")
	}
}

// WaitForCompletion waits for all in-flight scheduler work to complete.
// It respects the provided timeout and returns an error if work is still in progress after timeout.
// Call this after the scheduler context has been cancelled to ensure graceful shutdown.
func (s *Scheduler) WaitForCompletion(timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("all scheduler work completed")
		return nil
	case <-time.After(timeout):
		s.logger.Warn("scheduler work did not complete within timeout", "timeout", timeout.String())
		return ErrSchedulerShutdownTimeout
	}
}

// ErrSchedulerShutdownTimeout is returned when scheduler graceful shutdown times out.
var ErrSchedulerShutdownTimeout = errors.New("scheduler graceful shutdown timeout")
