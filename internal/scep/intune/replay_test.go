package intune

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestReplayCache_FirstInsertFresh(t *testing.T) {
	c := NewReplayCache(60*time.Minute, 100)
	defer c.Close()
	if !c.CheckAndInsert("nonce-1", time.Now()) {
		t.Fatalf("first insert must report fresh")
	}
}

func TestReplayCache_DuplicateRejected(t *testing.T) {
	c := NewReplayCache(60*time.Minute, 100)
	defer c.Close()
	now := time.Now()
	if !c.CheckAndInsert("nonce-1", now) {
		t.Fatalf("first insert must report fresh")
	}
	if c.CheckAndInsert("nonce-1", now) {
		t.Fatalf("second insert must report replay")
	}
}

func TestReplayCache_PastTTLTreatedAsFresh(t *testing.T) {
	// TTL=0 disables the janitor; we drive expiry by passing future timestamps.
	c := NewReplayCache(10*time.Minute, 100)
	defer c.Close()

	t0 := time.Now()
	if !c.CheckAndInsert("nonce-1", t0) {
		t.Fatalf("first insert must report fresh")
	}
	// Same nonce, but observation time is past expiry → fresh again.
	if !c.CheckAndInsert("nonce-1", t0.Add(11*time.Minute)) {
		t.Fatalf("post-TTL re-insert must report fresh")
	}
}

func TestReplayCache_SweepEvictsExpired(t *testing.T) {
	c := NewReplayCache(10*time.Minute, 100)
	defer c.Close()

	t0 := time.Now()
	c.CheckAndInsert("nonce-1", t0)
	c.CheckAndInsert("nonce-2", t0)
	if got := c.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}

	evicted := c.Sweep(t0.Add(11 * time.Minute))
	if evicted != 2 {
		t.Errorf("Sweep evicted %d, want 2", evicted)
	}
	if got := c.Len(); got != 0 {
		t.Errorf("Len after sweep = %d, want 0", got)
	}
}

func TestReplayCache_EmptyNonceTreatedAsFresh(t *testing.T) {
	c := NewReplayCache(10*time.Minute, 100)
	defer c.Close()
	if !c.CheckAndInsert("", time.Now()) {
		t.Fatalf("empty nonce must short-circuit to fresh (caller validates separately)")
	}
	// And a second empty also returns fresh (we don't track them).
	if !c.CheckAndInsert("", time.Now()) {
		t.Fatalf("second empty nonce should also report fresh; we don't cache empties")
	}
}

func TestReplayCache_AtCapEvictsOldest(t *testing.T) {
	// Cap of 3 makes the boundary easy to hit deterministically.
	c := NewReplayCache(60*time.Minute, 3)
	defer c.Close()

	t0 := time.Now()
	// Insert 3 entries with strictly increasing expiries.
	c.CheckAndInsert("oldest", t0)
	c.CheckAndInsert("middle", t0.Add(1*time.Minute))
	c.CheckAndInsert("newest", t0.Add(2*time.Minute))
	if got := c.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3", got)
	}

	// 4th insert must evict "oldest".
	c.CheckAndInsert("brand-new", t0.Add(3*time.Minute))
	if got := c.Len(); got != 3 {
		t.Errorf("Len after at-cap insert = %d, want 3 (cap honored)", got)
	}
	// "oldest" should now be re-insertable as fresh.
	if !c.CheckAndInsert("oldest", t0.Add(4*time.Minute)) {
		t.Errorf("oldest must have been evicted under LRU at-cap policy")
	}
}

func TestReplayCache_DefaultCap(t *testing.T) {
	// capHint = 0 should default to 100,000 per the documented sizing.
	c := NewReplayCache(60*time.Minute, 0)
	defer c.Close()
	if c.cap != 100_000 {
		t.Errorf("default cap = %d, want 100000", c.cap)
	}
}

func TestReplayCache_CloseIsIdempotent(t *testing.T) {
	c := NewReplayCache(60*time.Minute, 10)
	c.Close()
	c.Close() // must not panic
}

func TestReplayCache_TTLZeroDisablesJanitor(t *testing.T) {
	// TTL=0 + capHint=0 should produce a usable cache that doesn't
	// background-evict; the test mostly pins that NewReplayCache returns
	// without panicking and that Close still works.
	c := NewReplayCache(0, 10)
	defer c.Close()
	// Empty nonce path is the only safe one without TTL semantics; exercise it.
	if !c.CheckAndInsert("", time.Now()) {
		t.Fatalf("zero-TTL cache must still serve empty-nonce fast path")
	}
}

func TestReplayCache_ConcurrentInsertsRaceFree(t *testing.T) {
	if testing.Short() {
		t.Skip("race-style test under -short; run full suite for coverage")
	}
	c := NewReplayCache(60*time.Minute, 10000)
	defer c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			now := time.Now()
			for j := 0; j < 200; j++ {
				c.CheckAndInsert(fmt.Sprintf("g%d-n%d", id, j), now)
			}
		}(i)
	}
	wg.Wait()
	if got := c.Len(); got != 50*200 {
		t.Errorf("Len = %d, want %d (no Insert dropped under contention)", got, 50*200)
	}
}
