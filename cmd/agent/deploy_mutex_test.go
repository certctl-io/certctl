package main

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Phase 2 of the deploy-hardening I master bundle: per-target
// deploy mutex serializes concurrent deploys to the same target
// at the agent dispatch layer.

// TestAgent_ConcurrentDeploysToSameTarget_Serialize spawns N
// goroutines acquiring the same target's mutex and asserts that
// only one is in the critical section at a time. The "critical
// section" is simulated as an atomic-counter increment + sleep +
// decrement; if the lock works, max-in-flight is 1.
func TestAgent_ConcurrentDeploysToSameTarget_Serialize(t *testing.T) {
	a := &Agent{}

	const N = 10
	var inFlight, maxInFlight int32
	var done int32
	var wg sync.WaitGroup

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu := a.targetDeployMutex("target-A")
			if mu == nil {
				t.Errorf("expected non-nil mutex for non-empty target id")
				return
			}
			mu.Lock()
			defer mu.Unlock()
			n := atomic.AddInt32(&inFlight, 1)
			for {
				m := atomic.LoadInt32(&maxInFlight)
				if n <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, n) {
					break
				}
			}
			// Brief work simulating the connector's Deploy.
			for j := 0; j < 1000; j++ {
				_ = j * j
			}
			atomic.AddInt32(&inFlight, -1)
			atomic.AddInt32(&done, 1)
		}()
	}
	wg.Wait()

	if done != N {
		t.Errorf("done = %d, want %d (some goroutines didn't run)", done, N)
	}
	if maxInFlight > 1 {
		t.Errorf("max concurrent critical sections = %d, want 1 (mutex broken)", maxInFlight)
	}
}

// TestAgent_DifferentTargetIDs_ParallelizeIndependently verifies
// the per-target granularity: deploys to target-A and target-B
// proceed in parallel (no global serialization point).
func TestAgent_DifferentTargetIDs_ParallelizeIndependently(t *testing.T) {
	a := &Agent{}

	muA := a.targetDeployMutex("target-A")
	muB := a.targetDeployMutex("target-B")

	if muA == nil || muB == nil {
		t.Fatal("nil mutexes")
	}
	if muA == muB {
		t.Error("target-A and target-B share the same mutex (broken granularity)")
	}

	// Acquire A; B should still be acquirable concurrently.
	muA.Lock()
	defer muA.Unlock()

	acquired := make(chan struct{})
	go func() {
		muB.Lock()
		close(acquired)
		muB.Unlock()
	}()
	<-acquired // would deadlock if B were blocked by A
}

// TestAgent_EmptyTargetID_ReturnsNilMutex pins the
// "no-targetID = no-lock" contract. Defends against the
// pathological case where every targetless deploy serializes on a
// shared empty-string mutex.
func TestAgent_EmptyTargetID_ReturnsNilMutex(t *testing.T) {
	a := &Agent{}
	if mu := a.targetDeployMutex(""); mu != nil {
		t.Errorf("empty targetID returned non-nil mutex: %p", mu)
	}
}

// TestAgent_TargetMutex_IsStable verifies sync.Map LoadOrStore
// semantics: same target ID returns the same *sync.Mutex pointer
// across calls (so the lock actually works across goroutines that
// look up the mutex independently).
func TestAgent_TargetMutex_IsStable(t *testing.T) {
	a := &Agent{}
	mu1 := a.targetDeployMutex("target-X")
	mu2 := a.targetDeployMutex("target-X")
	if mu1 != mu2 {
		t.Errorf("targetMutex returned %p then %p for same id (stability broken)", mu1, mu2)
	}
}

// TestAgent_TargetMutex_RaceLookup pins the race-detector
// invariant: many goroutines calling targetDeployMutex
// concurrently for the same key all get the same pointer (no
// torn read).
func TestAgent_TargetMutex_RaceLookup(t *testing.T) {
	a := &Agent{}
	const N = 50
	results := make(chan *sync.Mutex, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- a.targetDeployMutex("target-shared")
		}()
	}
	wg.Wait()
	close(results)
	var first *sync.Mutex
	for got := range results {
		if first == nil {
			first = got
			continue
		}
		if got != first {
			t.Errorf("goroutine got different mutex (%p vs %p)", got, first)
		}
	}
}
