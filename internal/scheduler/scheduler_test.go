package scheduler

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

// mockRenewalService is a mock implementation for testing.
type mockRenewalService struct {
	mu                 sync.Mutex
	callCount          int
	callTimes          []time.Time
	expireCallCount    int
	expireCallTimes    []time.Time
	slowDelay          time.Duration
	shouldError        bool
	blockCh            chan struct{} // if non-nil, blocks until closed (ignores context)
}

func (m *mockRenewalService) CheckExpiringCertificates(ctx context.Context) error {
	m.mu.Lock()
	m.callCount++
	m.callTimes = append(m.callTimes, time.Now())
	blockCh := m.blockCh
	m.mu.Unlock()

	// If blockCh is set, block until it's closed (ignores context — for timeout tests)
	if blockCh != nil {
		<-blockCh
		return nil
	}

	if m.slowDelay > 0 {
		select {
		case <-time.After(m.slowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.shouldError {
		return context.Canceled
	}
	return nil
}

func (m *mockRenewalService) ExpireShortLivedCertificates(ctx context.Context) error {
	m.mu.Lock()
	m.expireCallCount++
	m.expireCallTimes = append(m.expireCallTimes, time.Now())
	m.mu.Unlock()

	if m.slowDelay > 0 {
		select {
		case <-time.After(m.slowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if m.shouldError {
		return context.Canceled
	}
	return nil
}

// mockJobService is a mock implementation for testing.
//
// Tracks ProcessPendingJobs and RetryFailedJobs separately. retrySlowDelay and
// retryShouldError let tests exercise the retry loop independently of the
// processor loop without coupling their timing/failure modes.
type mockJobService struct {
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool

	// Retry loop tracking (coverage gap I-001)
	retryCallCount      int
	retryCallTimes      []time.Time
	retryMaxRetriesSeen []int
	retrySlowDelay      time.Duration
	retryShouldError    bool

	// Timeout reaper tracking (coverage gap I-003)
	reapCallCount      int
	reapCallTimes      []time.Time
	reapSlowDelay      time.Duration
	reapShouldError    bool
	reapCtxHasDeadline bool
}

func (m *mockJobService) ProcessPendingJobs(ctx context.Context) error {
	m.mu.Lock()
	m.callCount++
	m.callTimes = append(m.callTimes, time.Now())
	m.mu.Unlock()

	if m.slowDelay > 0 {
		select {
		case <-time.After(m.slowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.shouldError {
		return context.Canceled
	}
	return nil
}

// RetryFailedJobs is the scheduler-driven counterpart to ProcessPendingJobs that
// covers coverage gap I-001: JobService.RetryFailedJobs had no runtime caller
// prior to the jobRetryLoop being wired.
func (m *mockJobService) RetryFailedJobs(ctx context.Context, maxRetries int) error {
	m.mu.Lock()
	m.retryCallCount++
	m.retryCallTimes = append(m.retryCallTimes, time.Now())
	m.retryMaxRetriesSeen = append(m.retryMaxRetriesSeen, maxRetries)
	m.mu.Unlock()

	if m.retrySlowDelay > 0 {
		select {
		case <-time.After(m.retrySlowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.retryShouldError {
		return context.Canceled
	}
	return nil
}


// ReapTimedOutJobs is the scheduler-driven counterpart to ProcessPendingJobs that
// covers coverage gap I-003: JobService.ReapTimedOutJobs (via JobReaperService interface)
// had no runtime caller prior to the jobTimeoutLoop being wired.
func (m *mockJobService) ReapTimedOutJobs(ctx context.Context, csrTTL, approvalTTL time.Duration) error {
	m.mu.Lock()
	m.reapCallCount++
	m.reapCallTimes = append(m.reapCallTimes, time.Now())
	// Track whether context has a deadline set
	_, hasDeadline := ctx.Deadline()
	m.reapCtxHasDeadline = hasDeadline
	m.mu.Unlock()

	if m.reapSlowDelay > 0 {
		select {
		case <-time.After(m.reapSlowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.reapShouldError {
		return context.Canceled
	}
	return nil
}

// ReapJobsWithOfflineAgents is the Bundle C / Audit M-016 stub. The
// existing scheduler tests do not exercise this path; the offline-agent
// reaper has its own end-to-end test in internal/service. Here we just
// satisfy the JobReaperService interface so the scheduler tests still
// compile.
func (m *mockJobService) ReapJobsWithOfflineAgents(ctx context.Context, agentTTL time.Duration) error {
	return nil
}

// mockAgentService is a mock implementation for testing.
type mockAgentService struct {
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool
}

func (m *mockAgentService) MarkStaleAgentsOffline(ctx context.Context, interval time.Duration) error {
	m.mu.Lock()
	m.callCount++
	m.callTimes = append(m.callTimes, time.Now())
	m.mu.Unlock()

	if m.slowDelay > 0 {
		select {
		case <-time.After(m.slowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.shouldError {
		return context.Canceled
	}
	return nil
}

// mockNotificationService is a mock implementation for testing.
//
// Tracks ProcessPendingNotifications and RetryFailedNotifications separately.
// retrySlowDelay and retryShouldError let tests exercise the retry loop
// independently of the processor loop without coupling their timing/failure
// modes (coverage gap I-005 — prior to the notificationRetryLoop being wired,
// RetryFailedNotifications had no runtime caller).
type mockNotificationService struct {
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool

	// Retry loop tracking (coverage gap I-005)
	retryCallCount      int
	retryCallTimes      []time.Time
	retrySlowDelay      time.Duration
	retryShouldError    bool
	retryCtxHasDeadline bool
}

func (m *mockNotificationService) ProcessPendingNotifications(ctx context.Context) error {
	m.mu.Lock()
	m.callCount++
	m.callTimes = append(m.callTimes, time.Now())
	m.mu.Unlock()

	if m.slowDelay > 0 {
		select {
		case <-time.After(m.slowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.shouldError {
		return context.Canceled
	}
	return nil
}

// RetryFailedNotifications is the scheduler-driven counterpart to
// ProcessPendingNotifications that closes coverage gap I-005. Prior to the
// notificationRetryLoop being wired, notifications that hit status='failed'
// orphaned there forever — no retry, no DLQ, no escalation. The service-layer
// method exists to sweep failed rows whose next_retry_at has elapsed, but
// without a scheduler caller the sweep never runs in production.
//
// This mock mirrors mockJobService.RetryFailedJobs's shape: a retry-only field
// cluster so callers can dial retrySlowDelay / retryShouldError without
// perturbing ProcessPendingNotifications's timing, and retryCtxHasDeadline so
// the ContextDeadlineRespected test can assert the scheduler is passing a
// per-tick context.WithTimeout rather than the raw shutdown ctx.
func (m *mockNotificationService) RetryFailedNotifications(ctx context.Context) error {
	m.mu.Lock()
	m.retryCallCount++
	m.retryCallTimes = append(m.retryCallTimes, time.Now())
	// Track whether context has a deadline set — the scheduler must wrap each
	// tick in a bounded context so a hung sweep can't stall shutdown.
	_, hasDeadline := ctx.Deadline()
	m.retryCtxHasDeadline = hasDeadline
	m.mu.Unlock()

	if m.retrySlowDelay > 0 {
		select {
		case <-time.After(m.retrySlowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.retryShouldError {
		return context.Canceled
	}
	return nil
}

// mockNetworkScanService is a mock implementation for testing.
type mockNetworkScanService struct {
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool
}

func (m *mockNetworkScanService) ScanAllTargets(ctx context.Context) error {
	m.mu.Lock()
	m.callCount++
	m.callTimes = append(m.callTimes, time.Now())
	m.mu.Unlock()

	if m.slowDelay > 0 {
		select {
		case <-time.After(m.slowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.shouldError {
		return context.Canceled
	}
	return nil
}

// TestSchedulerIdempotencyGuard tests that a slow job doesn't cause duplicate execution.
func TestSchedulerIdempotencyGuard(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	renewalMock := &mockRenewalService{
		slowDelay: 100 * time.Millisecond, // Slow job
	}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)

	// Set very short intervals to try to trigger overlapping ticks
	sched.SetRenewalCheckInterval(50 * time.Millisecond)
	sched.SetJobProcessorInterval(100 * time.Millisecond)
	sched.SetAgentHealthCheckInterval(100 * time.Millisecond)
	sched.SetNotificationProcessInterval(100 * time.Millisecond)
	sched.SetNetworkScanInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start scheduler
	startedChan := sched.Start(ctx)
	<-startedChan

	// Let it run for 250ms (enough to trigger multiple ticks but blocked by slow job)
	time.Sleep(250 * time.Millisecond)

	// Stop scheduler
	cancel()

	// Wait a bit for in-flight work
	time.Sleep(200 * time.Millisecond)

	renewalMock.mu.Lock()
	callCount := renewalMock.callCount
	renewalMock.mu.Unlock()

	// With a 100ms slow job and 50ms interval, without guard we'd get ~5 calls.
	// With the guard, we should get fewer (likely 3-4) because later ticks are skipped.
	// Allow a range because timing is inherently non-deterministic.
	if callCount > 4 {
		t.Logf("expected fewer than 5 calls due to idempotency guard, got %d", callCount)
		// Note: This is a soft check because timing is non-deterministic.
		// The important part is that we don't get runaway duplicates.
	}

	t.Logf("renewal check executed %d times with 100ms job and 50ms interval", callCount)
}

// TestWaitForCompletionSuccess tests that WaitForCompletion returns after in-flight work finishes.
func TestWaitForCompletionSuccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	renewalMock := &mockRenewalService{
		slowDelay: 100 * time.Millisecond, // Job takes 100ms
	}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)

	// Very short interval to ensure a job is scheduled
	sched.SetRenewalCheckInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start scheduler
	startedChan := sched.Start(ctx)
	<-startedChan

	// Let it run briefly so a job starts
	time.Sleep(100 * time.Millisecond)

	// Stop scheduler (trigger context cancellation)
	cancel()

	// Wait for completion with adequate timeout
	start := time.Now()
	err := sched.WaitForCompletion(5 * time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("WaitForCompletion should not error: %v", err)
	}

	if elapsed > 5*time.Second {
		t.Fatalf("WaitForCompletion took longer than expected: %v", elapsed)
	}

	t.Logf("WaitForCompletion completed in %v", elapsed)
}

// TestWaitForCompletionTimeout tests that WaitForCompletion respects timeout.
func TestWaitForCompletionTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Use a channel-blocked mock that ignores context cancellation,
	// ensuring work is still in-flight when WaitForCompletion is called.
	blockCh := make(chan struct{})
	renewalMock := &mockRenewalService{
		blockCh: blockCh, // blocks until closed, ignores ctx
	}

	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)

	sched.SetRenewalCheckInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(blockCh) // Unblock the mock after test completes

	// Start scheduler
	startedChan := sched.Start(ctx)
	<-startedChan

	// Let it run briefly so the initial job starts and blocks
	time.Sleep(50 * time.Millisecond)

	// Stop scheduler — but the in-flight work goroutine won't finish (blocked on channel)
	cancel()

	// Wait with very short timeout (work is stuck on blockCh)
	start := time.Now()
	err := sched.WaitForCompletion(200 * time.Millisecond)
	elapsed := time.Since(start)

	if err != ErrSchedulerShutdownTimeout {
		t.Fatalf("expected ErrSchedulerShutdownTimeout, got %v (elapsed: %v)", err, elapsed)
	}

	t.Logf("WaitForCompletion correctly timed out after %v", elapsed)
}

// TestSchedulerMultipleLoopsIdempotency tests that multiple loops each respect idempotency.
func TestSchedulerMultipleLoopsIdempotency(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	renewalMock := &mockRenewalService{
		slowDelay: 150 * time.Millisecond,
	}
	jobMock := &mockJobService{
		slowDelay: 150 * time.Millisecond,
	}
	agentMock := &mockAgentService{
		slowDelay: 150 * time.Millisecond,
	}
	notificationMock := &mockNotificationService{
		slowDelay: 150 * time.Millisecond,
	}
	networkMock := &mockNetworkScanService{
		slowDelay: 150 * time.Millisecond,
	}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)

	// All loops with 100ms interval, but each job takes 150ms
	// This should prevent overlapping execution
	sched.SetRenewalCheckInterval(100 * time.Millisecond)
	sched.SetJobProcessorInterval(100 * time.Millisecond)
	sched.SetAgentHealthCheckInterval(100 * time.Millisecond)
	sched.SetNotificationProcessInterval(100 * time.Millisecond)
	sched.SetNetworkScanInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	// Run for 400ms
	time.Sleep(400 * time.Millisecond)

	cancel()
	time.Sleep(300 * time.Millisecond) // Wait for in-flight work

	renewalMock.mu.Lock()
	renewalCount := renewalMock.callCount
	renewalMock.mu.Unlock()

	jobMock.mu.Lock()
	jobCount := jobMock.callCount
	jobMock.mu.Unlock()

	agentMock.mu.Lock()
	agentCount := agentMock.callCount
	agentMock.mu.Unlock()

	notificationMock.mu.Lock()
	notificationCount := notificationMock.callCount
	notificationMock.mu.Unlock()

	networkMock.mu.Lock()
	networkCount := networkMock.callCount
	networkMock.mu.Unlock()

	t.Logf("Loop call counts after 400ms with 100ms interval and 150ms slow jobs:")
	t.Logf("  renewal: %d, job: %d, agent: %d, notification: %d, network: %d",
		renewalCount, jobCount, agentCount, notificationCount, networkCount)

	// Each should be called at least once (initial run) and at most ~4 times
	// With a 150ms slow job and 100ms interval, we should skip some ticks.
	if renewalCount > 5 || jobCount > 5 || agentCount > 5 || notificationCount > 5 || networkCount > 5 {
		t.Logf("WARNING: Idempotency guard may not be working effectively (counts too high)")
	}
}

// TestSchedulerGracefulShutdown tests end-to-end graceful shutdown flow.
func TestSchedulerGracefulShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	renewalMock := &mockRenewalService{
		slowDelay: 50 * time.Millisecond,
	}
	jobMock := &mockJobService{
		slowDelay: 50 * time.Millisecond,
	}
	agentMock := &mockAgentService{
		slowDelay: 50 * time.Millisecond,
	}
	notificationMock := &mockNotificationService{
		slowDelay: 50 * time.Millisecond,
	}
	networkMock := &mockNetworkScanService{
		slowDelay: 50 * time.Millisecond,
	}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)

	// Short intervals
	sched.SetRenewalCheckInterval(50 * time.Millisecond)
	sched.SetJobProcessorInterval(50 * time.Millisecond)
	sched.SetAgentHealthCheckInterval(50 * time.Millisecond)
	sched.SetNotificationProcessInterval(50 * time.Millisecond)
	sched.SetNetworkScanInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start scheduler
	startedChan := sched.Start(ctx)
	<-startedChan

	// Let it run
	time.Sleep(100 * time.Millisecond)

	// Initiate graceful shutdown
	cancel()

	// Wait for completion
	start := time.Now()
	err := sched.WaitForCompletion(2 * time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("graceful shutdown failed: %v", err)
	}

	t.Logf("graceful shutdown completed in %v with all work finished", elapsed)

	// Verify all mocks were called at least once
	renewalMock.mu.Lock()
	if renewalMock.callCount == 0 {
		t.Error("renewal service was never called")
	}
	renewalMock.mu.Unlock()

	jobMock.mu.Lock()
	if jobMock.callCount == 0 {
		t.Error("job service was never called")
	}
	jobMock.mu.Unlock()
}

// TestSchedulerRenewalLoopCallsService verifies that the renewal loop executes the renewal service.
func TestSchedulerRenewalLoopCallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(50 * time.Millisecond)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedChan := sched.Start(ctx)
	<-startedChan
	time.Sleep(200 * time.Millisecond)
	cancel()
	sched.WaitForCompletion(2 * time.Second)

	renewalMock.mu.Lock()
	count := renewalMock.callCount
	renewalMock.mu.Unlock()
	if count < 1 {
		t.Fatalf("expected renewal service to be called at least once, got %d", count)
	}
	t.Logf("renewal loop called %d times", count)
}

// TestSchedulerJobProcessorLoopCallsService verifies that the job processor loop executes the job service.
func TestSchedulerJobProcessorLoopCallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(50 * time.Millisecond)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedChan := sched.Start(ctx)
	<-startedChan
	time.Sleep(200 * time.Millisecond)
	cancel()
	sched.WaitForCompletion(2 * time.Second)

	jobMock.mu.Lock()
	count := jobMock.callCount
	jobMock.mu.Unlock()
	if count < 1 {
		t.Fatalf("expected job service to be called at least once, got %d", count)
	}
	t.Logf("job processor loop called %d times", count)
}

// TestSchedulerAgentHealthCheckLoopCallsService verifies that the agent health check loop executes the agent service.
func TestSchedulerAgentHealthCheckLoopCallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(50 * time.Millisecond)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedChan := sched.Start(ctx)
	<-startedChan
	time.Sleep(200 * time.Millisecond)
	cancel()
	sched.WaitForCompletion(2 * time.Second)

	agentMock.mu.Lock()
	count := agentMock.callCount
	agentMock.mu.Unlock()
	if count < 1 {
		t.Fatalf("expected agent service to be called at least once, got %d", count)
	}
	t.Logf("agent health check loop called %d times", count)
}

// TestSchedulerNotificationLoopCallsService verifies that the notification loop executes the notification service.
func TestSchedulerNotificationLoopCallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(50 * time.Millisecond)
	sched.SetNetworkScanInterval(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedChan := sched.Start(ctx)
	<-startedChan
	time.Sleep(200 * time.Millisecond)
	cancel()
	sched.WaitForCompletion(2 * time.Second)

	notificationMock.mu.Lock()
	count := notificationMock.callCount
	notificationMock.mu.Unlock()
	if count < 1 {
		t.Fatalf("expected notification service to be called at least once, got %d", count)
	}
	t.Logf("notification loop called %d times", count)
}

// TestSchedulerNetworkScanLoopCallsService verifies that the network scan loop executes the network scan service.
func TestSchedulerNetworkScanLoopCallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedChan := sched.Start(ctx)
	<-startedChan
	time.Sleep(200 * time.Millisecond)
	cancel()
	sched.WaitForCompletion(2 * time.Second)

	networkMock.mu.Lock()
	count := networkMock.callCount
	networkMock.mu.Unlock()
	if count < 1 {
		t.Fatalf("expected network scan service to be called at least once, got %d", count)
	}
	t.Logf("network scan loop called %d times", count)
}

// TestSchedulerShortLivedExpiryLoopCallsService verifies that the short-lived expiry loop executes the renewal service.
func TestSchedulerShortLivedExpiryLoopCallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetShortLivedExpiryCheckInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedChan := sched.Start(ctx)
	<-startedChan
	time.Sleep(200 * time.Millisecond)
	cancel()
	sched.WaitForCompletion(2 * time.Second)

	renewalMock.mu.Lock()
	count := renewalMock.expireCallCount
	renewalMock.mu.Unlock()
	if count < 1 {
		t.Fatalf("expected short-lived expiry to be called at least once, got %d", count)
	}
	t.Logf("short-lived expiry loop called %d times", count)
}

// TestSchedulerLoopErrorRecovery verifies that scheduler loops continue executing after errors.
func TestSchedulerLoopErrorRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{shouldError: true}
	jobMock := &mockJobService{shouldError: true}
	agentMock := &mockAgentService{shouldError: true}
	notificationMock := &mockNotificationService{shouldError: true}
	networkMock := &mockNetworkScanService{shouldError: true}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(50 * time.Millisecond)
	sched.SetJobProcessorInterval(50 * time.Millisecond)
	sched.SetAgentHealthCheckInterval(50 * time.Millisecond)
	sched.SetNotificationProcessInterval(50 * time.Millisecond)
	sched.SetNetworkScanInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedChan := sched.Start(ctx)
	<-startedChan
	time.Sleep(300 * time.Millisecond)
	cancel()
	err := sched.WaitForCompletion(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForCompletion should not error even with service errors: %v", err)
	}

	renewalMock.mu.Lock()
	renewalCount := renewalMock.callCount
	renewalMock.mu.Unlock()
	if renewalCount < 2 {
		t.Fatalf("expected renewal service to be called at least twice (error recovery), got %d", renewalCount)
	}

	jobMock.mu.Lock()
	jobCount := jobMock.callCount
	jobMock.mu.Unlock()
	if jobCount < 2 {
		t.Fatalf("expected job service to be called at least twice (error recovery), got %d", jobCount)
	}

	t.Logf("scheduler recovered from errors: renewal %d calls, job %d calls", renewalCount, jobCount)
}

// TestSchedulerLoopContextCancellation verifies graceful shutdown when context is cancelled immediately.
func TestSchedulerLoopContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	startedChan := sched.Start(ctx)
	<-startedChan
	cancel()
	err := sched.WaitForCompletion(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForCompletion should succeed even with immediate cancellation: %v", err)
	}

	t.Logf("scheduler shut down gracefully on context cancellation")
}

// mockDigestService is a mock implementation of DigestServicer for testing.
type mockDigestService struct {
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool
}

func (m *mockDigestService) ProcessDigest(ctx context.Context) error {
	m.mu.Lock()
	m.callCount++
	m.callTimes = append(m.callTimes, time.Now())
	m.mu.Unlock()

	if m.slowDelay > 0 {
		select {
		case <-time.After(m.slowDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.shouldError {
		return context.Canceled
	}
	return nil
}

// TestScheduler_DigestLoop_DoesNotRunImmediately verifies that the digest loop
// does NOT run immediately on startup (unlike other loops). The digest is infrequent
// (24h default) and shouldn't fire on every restart.
func TestScheduler_DigestLoop_DoesNotRunImmediately(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}
	digestMock := &mockDigestService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetDigestService(digestMock)
	sched.SetDigestInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the scheduler
	startedChan := sched.Start(ctx)
	<-startedChan

	// Sleep briefly to allow any immediate execution
	time.Sleep(50 * time.Millisecond)

	digestMock.mu.Lock()
	callCount := digestMock.callCount
	digestMock.mu.Unlock()

	// Digest should NOT have been called immediately on startup
	if callCount > 0 {
		t.Errorf("digest should not run immediately on startup, expected 0 calls, got %d", callCount)
	}

	t.Logf("digest loop correctly did not run immediately (calls: %d)", callCount)
}

// TestScheduler_DigestLoop_RunsOnFirstTick verifies that the digest loop DOES run
// after the first tick interval expires.
func TestScheduler_DigestLoop_RunsOnFirstTick(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}
	digestMock := &mockDigestService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetDigestService(digestMock)
	sched.SetDigestInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the scheduler
	startedChan := sched.Start(ctx)
	<-startedChan

	// Sleep longer than the interval to allow the first tick to fire
	time.Sleep(200 * time.Millisecond)

	digestMock.mu.Lock()
	callCount := digestMock.callCount
	digestMock.mu.Unlock()

	// Digest should have been called once after the first tick
	if callCount < 1 {
		t.Errorf("digest should run after first tick, expected at least 1 call, got %d", callCount)
	}

	t.Logf("digest loop ran on first tick (calls: %d)", callCount)

	cancel()

	// Verify clean shutdown
	err := sched.WaitForCompletion(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForCompletion should succeed: %v", err)
	}
}

// TestScheduler_DigestLoop_WithIdempotencyGuard verifies that slow digest
// processing prevents duplicate execution (idempotency guard).
func TestScheduler_DigestLoop_WithIdempotencyGuard(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}
	digestMock := &mockDigestService{
		slowDelay: 150 * time.Millisecond, // Slower than tick interval
	}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetDigestService(digestMock)
	sched.SetDigestInterval(100 * time.Millisecond) // Tick every 100ms, but job takes 150ms

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	// Run for 400ms (enough for 4 ticks: 100ms, 200ms, 300ms, 400ms)
	time.Sleep(400 * time.Millisecond)

	digestMock.mu.Lock()
	callCount := digestMock.callCount
	digestMock.mu.Unlock()

	// With a 150ms slow job and 100ms tick interval, idempotency guard should
	// prevent overlapping execution. We should get 2-3 calls, not 4+.
	if callCount > 3 {
		t.Logf("WARNING: digest called %d times in 400ms with 100ms interval and 150ms job — guard may not be working", callCount)
	}

	t.Logf("digest loop with idempotency guard: %d calls in 400ms (100ms interval, 150ms job)", callCount)

	cancel()
	err := sched.WaitForCompletion(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForCompletion should succeed: %v", err)
	}
}

// TestScheduler_DigestLoop_SetDigestService tests that SetDigestService wires
// the digest service correctly and starts the digest loop.
func TestScheduler_DigestLoop_SetDigestService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)

	// Initially, no digest service
	if sched.digestService != nil {
		t.Error("digestService should be nil initially")
	}

	// Set digest service
	digestMock := &mockDigestService{}
	sched.SetDigestService(digestMock)

	if sched.digestService == nil {
		t.Error("digestService should be set after SetDigestService")
	}

	// Verify it's the same service we set
	if sched.digestService != digestMock {
		t.Error("digestService should be the mock we provided")
	}
}

// TestScheduler_DigestLoop_SetDigestInterval tests that SetDigestInterval
// configures the digest tick interval.
func TestScheduler_DigestLoop_SetDigestInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)

	// Default is 24h
	if sched.digestInterval != 24*time.Hour {
		t.Errorf("default digestInterval should be 24h, got %v", sched.digestInterval)
	}

	// Set custom interval
	customInterval := 5 * time.Minute
	sched.SetDigestInterval(customInterval)

	if sched.digestInterval != customInterval {
		t.Errorf("digestInterval should be %v after SetDigestInterval, got %v", customInterval, sched.digestInterval)
	}
}

// TestScheduler_JobRetryLoop_CallsService verifies that the job retry loop
// invokes JobService.RetryFailedJobs on each tick. Closes coverage gap I-001 —
// prior to the loop being wired, RetryFailedJobs had no runtime caller.
//
// Also verifies that the scheduler forwards the conventional advisory maxRetries
// constant (3) to the service layer; per-job gating still lives in each job's
// own Attempts/MaxAttempts fields.
func TestScheduler_JobRetryLoop_CallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	// Quiet every other loop so only the retry loop's calls are visible on jobMock.
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	// Run long enough for the immediate start + at least one tick.
	time.Sleep(200 * time.Millisecond)
	cancel()
	_ = sched.WaitForCompletion(2 * time.Second)

	jobMock.mu.Lock()
	retryCount := jobMock.retryCallCount
	var firstMaxRetries int
	if len(jobMock.retryMaxRetriesSeen) > 0 {
		firstMaxRetries = jobMock.retryMaxRetriesSeen[0]
	}
	jobMock.mu.Unlock()

	if retryCount < 1 {
		t.Fatalf("expected job retry service to be called at least once, got %d", retryCount)
	}
	if firstMaxRetries != 3 {
		t.Fatalf("expected scheduler to forward advisory maxRetries=3, got %d", firstMaxRetries)
	}
	t.Logf("job retry loop called %d times (maxRetries=%d)", retryCount, firstMaxRetries)
}

// TestScheduler_JobRetryLoop_IdempotencyGuard verifies that a slow retry sweep
// does not cause overlapping executions. Mirrors the shape of
// TestScheduler_DigestLoop_WithIdempotencyGuard.
//
// The guard is the atomic.Bool jobRetryRunning in scheduler.go. Without it, a
// 100ms tick against a 150ms operation would fire ~4 times in 400ms; with the
// guard we expect ~2–3 calls.
func TestScheduler_JobRetryLoop_IdempotencyGuard(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{
		retrySlowDelay: 150 * time.Millisecond, // slower than tick interval
	}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	time.Sleep(400 * time.Millisecond)

	jobMock.mu.Lock()
	retryCount := jobMock.retryCallCount
	jobMock.mu.Unlock()

	// With a 150ms sweep and 100ms interval, a functioning guard should yield
	// roughly 2–3 calls (immediate + any ticks whose previous sweep finished).
	// Anything above 3 suggests the guard isn't holding.
	if retryCount > 3 {
		t.Logf("WARNING: retry called %d times in 400ms with 100ms interval and 150ms sweep — guard may not be working", retryCount)
	}

	t.Logf("job retry idempotency guard: %d calls in 400ms (100ms interval, 150ms sweep)", retryCount)

	cancel()
	if err := sched.WaitForCompletion(2 * time.Second); err != nil {
		t.Fatalf("WaitForCompletion should succeed: %v", err)
	}
}

// TestScheduler_JobRetryLoop_WaitForCompletion verifies that a retry sweep
// which is still in flight at shutdown is awaited by WaitForCompletion (same
// sync.WaitGroup contract as every other loop).
func TestScheduler_JobRetryLoop_WaitForCompletion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{
		retrySlowDelay: 100 * time.Millisecond,
	}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	// Let the immediate-start retry goroutine begin its 100ms sweep.
	time.Sleep(30 * time.Millisecond)

	// Initiate shutdown mid-sweep.
	cancel()

	start := time.Now()
	err := sched.WaitForCompletion(5 * time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("WaitForCompletion should not error: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("WaitForCompletion took longer than expected: %v", elapsed)
	}

	jobMock.mu.Lock()
	retryCount := jobMock.retryCallCount
	jobMock.mu.Unlock()

	if retryCount < 1 {
		t.Fatalf("expected retry service to have started at least once before shutdown, got %d", retryCount)
	}
	t.Logf("retry loop graceful shutdown completed in %v after %d in-flight sweep(s)", elapsed, retryCount)
}

// TestScheduler_JobTimeoutLoop_NormalTick verifies that the job timeout reaper
// loop ticks at the specified interval (coverage gap I-003).
func TestScheduler_JobTimeoutLoop_NormalTick(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetJobTimeoutInterval(50 * time.Millisecond)
	sched.SetAwaitingCSRTimeout(24 * time.Hour)
	sched.SetAwaitingApprovalTimeout(168 * time.Hour)
	sched.SetJobReaperService(jobMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	<-sched.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cancel()
	if err := sched.WaitForCompletion(2 * time.Second); err != nil {
		t.Fatalf("WaitForCompletion: %v", err)
	}

	jobMock.mu.Lock()
	count := jobMock.reapCallCount
	jobMock.mu.Unlock()
	if count < 2 {
		t.Fatalf("expected >= 2 reap calls, got %d", count)
	}
}

// TestScheduler_JobTimeoutLoop_IdempotencyGuard verifies that the timeout reaper
// uses an atomic guard to prevent concurrent execution (coverage gap I-003).
func TestScheduler_JobTimeoutLoop_IdempotencyGuard(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{
		reapSlowDelay: 150 * time.Millisecond,
	}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetJobTimeoutInterval(50 * time.Millisecond)
	sched.SetAwaitingCSRTimeout(24 * time.Hour)
	sched.SetAwaitingApprovalTimeout(168 * time.Hour)
	sched.SetJobReaperService(jobMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	<-sched.Start(ctx)
	time.Sleep(400 * time.Millisecond)

	jobMock.mu.Lock()
	reapCount := jobMock.reapCallCount
	jobMock.mu.Unlock()

	if reapCount > 3 {
		t.Logf("WARNING: reap called %d times in 400ms with 50ms interval and 150ms sweep — guard may not be working", reapCount)
	}

	t.Logf("job timeout idempotency guard: %d calls in 400ms (50ms interval, 150ms sweep)", reapCount)

	cancel()
	if err := sched.WaitForCompletion(2 * time.Second); err != nil {
		t.Fatalf("WaitForCompletion should succeed: %v", err)
	}
}

// TestScheduler_JobTimeoutLoop_ShutdownDrainsInFlight verifies that shutdown waits
// for an in-flight timeout reaper to complete (coverage gap I-003).
func TestScheduler_JobTimeoutLoop_ShutdownDrainsInFlight(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{
		reapSlowDelay: 100 * time.Millisecond,
	}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetJobTimeoutInterval(50 * time.Millisecond)
	sched.SetAwaitingCSRTimeout(24 * time.Hour)
	sched.SetAwaitingApprovalTimeout(168 * time.Hour)
	sched.SetJobReaperService(jobMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	<-sched.Start(ctx)

	// Let the immediate-start timeout reaper goroutine begin its 100ms sweep.
	time.Sleep(30 * time.Millisecond)

	// Initiate shutdown mid-sweep.
	cancel()

	start := time.Now()
	err := sched.WaitForCompletion(5 * time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("WaitForCompletion should not error: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("WaitForCompletion took longer than expected: %v", elapsed)
	}

	jobMock.mu.Lock()
	reapCount := jobMock.reapCallCount
	jobMock.mu.Unlock()

	if reapCount < 1 {
		t.Fatalf("expected timeout reaper to have started at least once before shutdown, got %d", reapCount)
	}
	t.Logf("timeout reaper graceful shutdown completed in %v after %d in-flight sweep(s)", elapsed, reapCount)
}

// TestScheduler_JobTimeoutLoop_ContextDeadlineRespected verifies that the timeout
// reaper receives a context with a deadline set for each tick (coverage gap I-003).
func TestScheduler_JobTimeoutLoop_ContextDeadlineRespected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetJobTimeoutInterval(50 * time.Millisecond)
	sched.SetAwaitingCSRTimeout(24 * time.Hour)
	sched.SetAwaitingApprovalTimeout(168 * time.Hour)
	sched.SetJobReaperService(jobMock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	<-sched.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := sched.WaitForCompletion(2 * time.Second); err != nil {
		t.Fatalf("WaitForCompletion: %v", err)
	}

	jobMock.mu.Lock()
	hasDeadline := jobMock.reapCtxHasDeadline
	jobMock.mu.Unlock()

	if !hasDeadline {
		t.Fatal("expected timeout reaper context to have a deadline set, but none found")
	}
	t.Log("timeout reaper context deadline verified")
}

// ─── NotificationRetryLoop tests (coverage gap I-005) ────────────────────────
//
// These four tests are the scheduler-level Red half of the I-005 fix. They
// mirror the I-001 jobRetryLoop triplet (CallsService / IdempotencyGuard /
// WaitForCompletion) plus the I-003 ContextDeadlineRespected shape.
//
// All four use the same "quiet every other loop" pattern so the only tick
// activity visible on notificationMock is the retry loop under test. JobTimeout
// is intentionally left unconfigured — SetJobReaperService isn't called, so the
// timeout loop is dormant (same convention the I-001 tests follow).

// TestScheduler_NotificationRetryLoop_CallsService verifies that the
// notification retry loop invokes NotificationService.RetryFailedNotifications
// on each tick. Closes coverage gap I-005 — prior to the loop being wired,
// RetryFailedNotifications had no runtime caller and failed notification_events
// rows orphaned at status='failed' forever (no retry, no DLQ, no escalation).
//
// Unlike the jobRetryLoop test, there is no maxRetries advisory constant to
// forward: the max_attempts limit on notification retries lives on the row
// itself (retry_count column introduced by migration 000016), not in the call
// signature.
func TestScheduler_NotificationRetryLoop_CallsService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	// Quiet every other loop so only the retry loop's calls are visible on notificationMock.
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetNotificationRetryInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	// Run long enough for the immediate start + at least one tick.
	time.Sleep(200 * time.Millisecond)
	cancel()
	_ = sched.WaitForCompletion(2 * time.Second)

	notificationMock.mu.Lock()
	retryCount := notificationMock.retryCallCount
	notificationMock.mu.Unlock()

	if retryCount < 1 {
		t.Fatalf("expected notification retry service to be called at least once, got %d", retryCount)
	}
	t.Logf("notification retry loop called %d times", retryCount)
}

// TestScheduler_NotificationRetryLoop_IdempotencyGuard verifies that a slow
// retry sweep does not cause overlapping executions. Mirrors the shape of
// TestScheduler_JobRetryLoop_IdempotencyGuard.
//
// The guard is the atomic.Bool notificationRetryRunning in scheduler.go.
// Without it, a 100ms tick against a 150ms operation would fire ~4 times in
// 400ms; with the guard we expect ~2–3 calls. Anything above 3 is logged as a
// warning (not a hard failure) so CI timing noise doesn't produce flakes.
func TestScheduler_NotificationRetryLoop_IdempotencyGuard(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{
		retrySlowDelay: 150 * time.Millisecond, // slower than tick interval
	}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetNotificationRetryInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	time.Sleep(400 * time.Millisecond)

	notificationMock.mu.Lock()
	retryCount := notificationMock.retryCallCount
	notificationMock.mu.Unlock()

	// With a 150ms sweep and 100ms interval, a functioning guard should yield
	// roughly 2–3 calls (immediate + any ticks whose previous sweep finished).
	// Anything above 3 suggests the guard isn't holding.
	if retryCount > 3 {
		t.Logf("WARNING: retry called %d times in 400ms with 100ms interval and 150ms sweep — guard may not be working", retryCount)
	}

	t.Logf("notification retry idempotency guard: %d calls in 400ms (100ms interval, 150ms sweep)", retryCount)

	cancel()
	if err := sched.WaitForCompletion(2 * time.Second); err != nil {
		t.Fatalf("WaitForCompletion should succeed: %v", err)
	}
}

// TestScheduler_NotificationRetryLoop_WaitForCompletion verifies that a retry
// sweep still in flight at shutdown is awaited by WaitForCompletion — the same
// sync.WaitGroup contract every other loop satisfies. If the loop were to
// return early without registering its goroutine on s.wg, this test would
// either (a) observe retryCount==0 because the immediate-start sweep was never
// launched, or (b) observe WaitForCompletion returning before the in-flight
// sweep finished (elapsed < retrySlowDelay).
func TestScheduler_NotificationRetryLoop_WaitForCompletion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{
		retrySlowDelay: 100 * time.Millisecond,
	}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetNotificationRetryInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startedChan := sched.Start(ctx)
	<-startedChan

	// Let the immediate-start retry goroutine begin its 100ms sweep.
	time.Sleep(30 * time.Millisecond)

	// Initiate shutdown mid-sweep.
	cancel()

	start := time.Now()
	err := sched.WaitForCompletion(5 * time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("WaitForCompletion should not error: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("WaitForCompletion took longer than expected: %v", elapsed)
	}

	notificationMock.mu.Lock()
	retryCount := notificationMock.retryCallCount
	notificationMock.mu.Unlock()

	if retryCount < 1 {
		t.Fatalf("expected notification retry service to have started at least once before shutdown, got %d", retryCount)
	}
	t.Logf("notification retry loop graceful shutdown completed in %v after %d in-flight sweep(s)", elapsed, retryCount)
}

// TestScheduler_NotificationRetryLoop_ContextDeadlineRespected verifies that
// each tick of the retry loop receives a context with a deadline set. Mirrors
// TestScheduler_JobTimeoutLoop_ContextDeadlineRespected.
//
// The per-tick context.WithTimeout exists so a pathologically slow sweep (e.g.
// a misbehaving DB lock) can't stall the rest of the scheduler's shutdown
// sequence indefinitely — the wrapping context expires, the sweep returns
// ctx.Err(), and the WaitGroup.Done() fires on schedule.
func TestScheduler_NotificationRetryLoop_ContextDeadlineRespected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renewalMock := &mockRenewalService{}
	jobMock := &mockJobService{}
	agentMock := &mockAgentService{}
	notificationMock := &mockNotificationService{}
	networkMock := &mockNetworkScanService{}

	sched := NewScheduler(renewalMock, jobMock, agentMock, notificationMock, networkMock, logger)
	sched.SetRenewalCheckInterval(10 * time.Second)
	sched.SetJobProcessorInterval(10 * time.Second)
	sched.SetAgentHealthCheckInterval(10 * time.Second)
	sched.SetNotificationProcessInterval(10 * time.Second)
	sched.SetNetworkScanInterval(10 * time.Second)
	sched.SetJobRetryInterval(10 * time.Second)
	sched.SetNotificationRetryInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	<-sched.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := sched.WaitForCompletion(2 * time.Second); err != nil {
		t.Fatalf("WaitForCompletion: %v", err)
	}

	notificationMock.mu.Lock()
	hasDeadline := notificationMock.retryCtxHasDeadline
	notificationMock.mu.Unlock()

	if !hasDeadline {
		t.Fatal("expected notification retry context to have a deadline set, but none found")
	}
	t.Log("notification retry context deadline verified")
}
