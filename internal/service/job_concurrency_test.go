package service

// Audit fix #9 — bounded scheduler concurrency tests.
//
// boundedFanOut is the load-bearing primitive that caps the number of
// concurrent renewal/issuance/deployment goroutines per scheduler tick.
// Production wiring in cmd/server/main.go calls
// SetRenewalConcurrency(cfg.Scheduler.RenewalConcurrency) (default 25);
// these tests pin the cap behaviour directly against boundedFanOut so
// they don't have to stand up the full renewal/deployment service
// graph just to assert "the cap holds."

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// quietLogger discards the boundedFanOut log output so the test runner
// doesn't drown in info-level lines for every dispatched job.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// makeJobs builds n pending renewal jobs with deterministic IDs.
func makeJobs(n int) []*domain.Job {
	jobs := make([]*domain.Job, n)
	for i := 0; i < n; i++ {
		jobs[i] = &domain.Job{
			ID:     "job-" + strconv.Itoa(i),
			Type:   domain.JobTypeRenewal,
			Status: domain.JobStatusPending,
		}
	}
	return jobs
}

// TestBoundedFanOut_CapHolds is the primary regression guard for the
// audit's #9 blocker. It runs 50 jobs through a fan-out with cap=5,
// where each "job" sleeps 50ms to ensure several dispatchers are
// in-flight simultaneously, and asserts that the peak in-flight count
// never exceeded the cap. Pre-fix the renewal fan-out had no cap, so
// this test would have observed peak in-flight = 50.
func TestBoundedFanOut_CapHolds(t *testing.T) {
	const (
		capN       = 5
		totalJobs  = 50
		workSleep  = 50 * time.Millisecond
		hardBudget = 30 * time.Second // generous; cap=5 + 50 jobs * 50ms ≈ 500ms
	)

	jobs := makeJobs(totalJobs)

	var inFlight atomic.Int64
	var peak atomic.Int64

	work := func(ctx context.Context, job *domain.Job) error {
		now := inFlight.Add(1)
		// Lock-free max via CompareAndSwap loop. Avoids a mutex on the
		// hot path which would itself constrain concurrency and
		// invalidate the measurement.
		for {
			cur := peak.Load()
			if now <= cur {
				break
			}
			if peak.CompareAndSwap(cur, now) {
				break
			}
		}
		time.Sleep(workSleep)
		inFlight.Add(-1)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), hardBudget)
	defer cancel()
	if err := boundedFanOut(ctx, jobs, capN, work, quietLogger()); err != nil {
		t.Fatalf("boundedFanOut returned error: %v", err)
	}

	if got := peak.Load(); got > int64(capN) {
		t.Errorf("peak in-flight count exceeded the cap: got %d, cap %d", got, capN)
	}
	// Sanity: the cap should actually be reached at least once with
	// 50 jobs × 50ms sleep — if it isn't, either the workload is too
	// short or the gate is broken in a way that caps below the
	// intended value.
	if got := peak.Load(); got < int64(capN) {
		t.Errorf("peak in-flight count never reached the cap: got %d, cap %d (workload too short or gate broken low?)", got, capN)
	}
}

// TestBoundedFanOut_AllJobsRun pins that every (non-skipped) job is
// actually dispatched — the cap should add backpressure, not drop
// jobs. Counterpart to TestBoundedFanOut_CapHolds: that test asserts
// the upper bound; this one asserts the lower bound.
func TestBoundedFanOut_AllJobsRun(t *testing.T) {
	const capN = 3
	jobs := makeJobs(20)

	var dispatched atomic.Int64
	work := func(ctx context.Context, job *domain.Job) error {
		dispatched.Add(1)
		return nil
	}

	if err := boundedFanOut(context.Background(), jobs, capN, work, quietLogger()); err != nil {
		t.Fatalf("boundedFanOut returned error: %v", err)
	}

	if got := dispatched.Load(); got != int64(len(jobs)) {
		t.Errorf("expected all %d jobs to be dispatched, got %d", len(jobs), got)
	}
}

// TestBoundedFanOut_SkipsAgentRoutedDeployments pins the
// shouldSkipJob contract: deployment jobs with a non-empty AgentID
// belong to the agent's GetPendingWork path, so the server-side
// fan-out must skip them. boundedFanOut's behaviour here matches the
// pre-audit-#9 sequential loop's behaviour exactly.
func TestBoundedFanOut_SkipsAgentRoutedDeployments(t *testing.T) {
	agentID := "agent-1"
	jobs := []*domain.Job{
		{ID: "j1", Type: domain.JobTypeRenewal, Status: domain.JobStatusPending},
		{ID: "j2", Type: domain.JobTypeDeployment, Status: domain.JobStatusPending, AgentID: &agentID},
		{ID: "j3", Type: domain.JobTypeIssuance, Status: domain.JobStatusPending},
	}

	var seen atomic.Int64
	var seenIDs []string
	work := func(ctx context.Context, job *domain.Job) error {
		seen.Add(1)
		seenIDs = append(seenIDs, job.ID)
		return nil
	}

	if err := boundedFanOut(context.Background(), jobs, 5, work, quietLogger()); err != nil {
		t.Fatalf("boundedFanOut returned error: %v", err)
	}

	if got := seen.Load(); got != 2 {
		t.Errorf("expected 2 jobs to run (renewal + issuance, deployment-with-agent skipped), got %d (ids=%v)", got, seenIDs)
	}
}

// TestBoundedFanOut_CtxCancelInterrupts pins that ctx cancellation
// during a long-running fan-out interrupts the dispatch loop. Without
// the ctx-aware Acquire (audit prompt's "anti-pattern: channel-based
// semaphore without ctx-aware acquire"), this test would hang the
// scheduler indefinitely on a stuck CA call.
func TestBoundedFanOut_CtxCancelInterrupts(t *testing.T) {
	jobs := makeJobs(100)

	work := func(ctx context.Context, job *domain.Job) error {
		// Work that respects ctx — sleeps until ctx done or 5s elapsed.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after 100ms so the fan-out aborts mid-stream.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := boundedFanOut(ctx, jobs, 3, work, quietLogger())
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("boundedFanOut should not propagate the ctx error from work; got %v", err)
	}
	// Even with ctx cancel, the function returns nil because the
	// loop exits via the Acquire-cancel branch (logged warn) and
	// the Wait drains in-flight goroutines. Total elapsed should be
	// well under the 5s "stuck CA" cap if the cancel actually
	// interrupted the dispatch.
	if elapsed > 6*time.Second {
		t.Errorf("ctx cancel did not interrupt fan-out: elapsed=%v, expected <6s", elapsed)
	}
}

// TestBoundedFanOut_FailedJobsCounted pins that errors from `work`
// don't cause the fan-out to abort — the failed counter increments
// and the loop continues. Jobs are independent; one cert failing
// shouldn't block the rest.
func TestBoundedFanOut_FailedJobsCounted(t *testing.T) {
	const totalJobs = 10
	jobs := makeJobs(totalJobs)

	var dispatched atomic.Int64
	failEvery := 3 // jobs 0, 3, 6, 9 fail
	work := func(ctx context.Context, job *domain.Job) error {
		idx, _ := strconv.Atoi(job.ID[len("job-"):])
		dispatched.Add(1)
		if idx%failEvery == 0 {
			return fmt.Errorf("simulated failure for %s", job.ID)
		}
		return nil
	}

	if err := boundedFanOut(context.Background(), jobs, 4, work, quietLogger()); err != nil {
		t.Fatalf("boundedFanOut should swallow per-job errors; got %v", err)
	}

	if got := dispatched.Load(); got != int64(totalJobs) {
		t.Errorf("expected all %d jobs dispatched even with failures, got %d", totalJobs, got)
	}
}

// TestSetRenewalConcurrency_NormalizesNonPositive pins the ≤0 → 1
// fail-safe in SetRenewalConcurrency. semaphore.NewWeighted(0)
// constructs a semaphore that blocks every Acquire forever; the
// normalization prevents a misconfigured env var from wedging the
// scheduler.
func TestSetRenewalConcurrency_NormalizesNonPositive(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{-100, 1},
		{-1, 1},
		{0, 1},
		{1, 1},
		{25, 25},
		{1000, 1000},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.in), func(t *testing.T) {
			s := &JobService{}
			s.SetRenewalConcurrency(tc.in)
			if s.renewalConcurrency != tc.want {
				t.Errorf("SetRenewalConcurrency(%d) -> renewalConcurrency=%d, want %d", tc.in, s.renewalConcurrency, tc.want)
			}
		})
	}
}
