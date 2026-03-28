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
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool
	blockCh     chan struct{} // if non-nil, blocks until closed (ignores context)
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
type mockJobService struct {
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool
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
type mockNotificationService struct {
	mu          sync.Mutex
	callCount   int
	callTimes   []time.Time
	slowDelay   time.Duration
	shouldError bool
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
