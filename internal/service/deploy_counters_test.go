package service

import (
	"sync"
	"testing"
)

// Phase 10 of the deploy-hardening I master bundle — DeployCounters
// unit tests. Mirrors ocsp_counters_test.go.

func TestDeployCounters_NewIsZero(t *testing.T) {
	c := NewDeployCounters()
	if got := c.Snapshot(); len(got) != 0 {
		t.Errorf("snapshot at zero state = %d entries, want 0", len(got))
	}
}

func TestDeployCounters_IncTicksTargetTypeBucket(t *testing.T) {
	c := NewDeployCounters()
	c.IncAttemptSuccess("nginx")
	c.IncAttemptSuccess("nginx")
	c.IncAttemptSuccess("apache")
	c.IncAttemptFailure("nginx")
	c.IncValidateFailure("nginx")
	c.IncReloadFailure("nginx")
	c.IncPostVerifyFailure("nginx")
	c.IncRollbackRestored("nginx")
	c.IncRollbackAlsoFailed("nginx")
	c.IncIdempotentSkip("nginx")

	snap := c.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2 (nginx + apache)", len(snap))
	}
	got := map[string]DeploySnapshot{}
	for _, s := range snap {
		got[s.TargetType] = s
	}
	n := got["nginx"]
	if n.AttemptsSuccess != 2 {
		t.Errorf("nginx success = %d, want 2", n.AttemptsSuccess)
	}
	if n.AttemptsFailure != 1 {
		t.Errorf("nginx failure = %d, want 1", n.AttemptsFailure)
	}
	if n.ValidateFailures != 1 || n.ReloadFailures != 1 || n.PostVerifyFails != 1 ||
		n.RollbackRestored != 1 || n.RollbackAlsoFail != 1 || n.IdempotentSkips != 1 {
		t.Errorf("nginx sub-counter mismatch: %+v", n)
	}
	a := got["apache"]
	if a.AttemptsSuccess != 1 {
		t.Errorf("apache success = %d, want 1", a.AttemptsSuccess)
	}
}

func TestDeployCounters_ConcurrentTicks(t *testing.T) {
	c := NewDeployCounters()
	const goroutines = 10
	const ticks = 100
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < ticks; j++ {
				c.IncAttemptSuccess("nginx")
			}
		}()
	}
	wg.Wait()
	for _, s := range c.Snapshot() {
		if s.TargetType == "nginx" && s.AttemptsSuccess != goroutines*ticks {
			t.Errorf("nginx success = %d, want %d", s.AttemptsSuccess, goroutines*ticks)
		}
	}
}

func TestDeployCounters_BucketsIsolatedAcrossTargetTypes(t *testing.T) {
	c := NewDeployCounters()
	c.IncAttemptSuccess("nginx")
	c.IncReloadFailure("apache")
	snap := c.Snapshot()
	got := map[string]DeploySnapshot{}
	for _, s := range snap {
		got[s.TargetType] = s
	}
	if got["nginx"].ReloadFailures != 0 {
		t.Errorf("nginx ReloadFailures bled across: got %d", got["nginx"].ReloadFailures)
	}
	if got["apache"].AttemptsSuccess != 0 {
		t.Errorf("apache AttemptsSuccess bled across: got %d", got["apache"].AttemptsSuccess)
	}
}

func TestDeployCounters_StableSnapshot(t *testing.T) {
	// Snapshot read returns a copy — mutating the returned slice
	// must NOT affect the underlying counters.
	c := NewDeployCounters()
	c.IncAttemptSuccess("nginx")
	snap := c.Snapshot()
	snap[0].AttemptsSuccess = 999
	again := c.Snapshot()
	if again[0].AttemptsSuccess != 1 {
		t.Errorf("counter mutated through snapshot: got %d", again[0].AttemptsSuccess)
	}
}
