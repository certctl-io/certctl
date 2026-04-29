package intune

import (
	"sync"
	"time"
)

// ReplayCache is a bounded in-memory cache of seen Intune challenge
// nonces with TTL. Gates against the same Connector-signed challenge
// being replayed against the SCEP server within its validity window.
//
// SCEP RFC 8894 + Intune master bundle Phase 7.4b.
//
// Sizing rationale (cap = 100,000 entries):
//
//   - Microsoft's published Connector defaults give each challenge
//     a 60-minute validity window. A high-volume Intune fleet
//     enrolling at ~25 RPS hits ~90,000 challenges/hour.
//   - Capping at 100,000 covers the steady-state load with headroom.
//     When the cap is hit, the janitor goroutine evicts entries past
//     TTL first; if all entries are still in-window, oldest-first
//     eviction kicks in (LRU semantics) — accepting the small
//     replay-window risk over an OOM crash.
//   - Operators who push beyond this rate should flip to a Redis-
//     backed implementation (deferred to V3-Pro per the master
//     prompt's deferral list); the in-memory variant is V2 default.
//
// Concurrency: sync.Map handles concurrent read/write without an
// explicit lock; the janitor goroutine periodically walks for expired
// entries. Cap enforcement on Insert is done under a small mutex so
// the cap check + size update are atomic.
type ReplayCache struct {
	entries  sync.Map   // nonce → expiry (time.Time)
	mu       sync.Mutex // guards size + janitor lifecycle
	size     int        // approximate count (sync.Map has no Len)
	cap      int        // max entries before LRU eviction kicks in
	ttl      time.Duration
	stop     chan struct{}
	stopOnce sync.Once
}

// NewReplayCache returns a ReplayCache with the given TTL + cap. Starts
// a janitor goroutine that wakes every TTL/4 to evict expired entries.
// Caller MUST call Close when done to stop the goroutine.
//
// TTL = 0 disables the janitor (useful for tests that drive expiry
// manually).
// cap = 0 defaults to 100,000 (the rationale-documented production
// default).
func NewReplayCache(ttl time.Duration, capHint int) *ReplayCache {
	if capHint <= 0 {
		capHint = 100_000
	}
	c := &ReplayCache{
		cap:  capHint,
		ttl:  ttl,
		stop: make(chan struct{}),
	}
	if ttl > 0 {
		go c.janitor()
	}
	return c
}

// CheckAndInsert returns true when the nonce has NOT been seen before
// (i.e. the challenge is not a replay) AND records the nonce as seen
// with expiry = now + c.ttl. Returns false when the nonce was already
// seen and is still within its TTL window — the caller should treat
// this as a replay attack and reject the challenge.
//
// At-cap behavior: when the cache is full, CheckAndInsert evicts the
// oldest entry (a single Range pass to find min-expiry) before
// inserting. This is O(N) at the boundary; in practice the janitor
// keeps the cache below cap so the eviction path rarely fires.
func (c *ReplayCache) CheckAndInsert(nonce string, now time.Time) bool {
	if nonce == "" {
		// Empty nonce can't be tracked meaningfully; treat as 'fresh'
		// — the caller's claim-validation should reject empty-nonce
		// challenges separately (it's a Connector-emitted-format bug).
		return true
	}

	if existing, ok := c.entries.Load(nonce); ok {
		if existingExpiry, _ := existing.(time.Time); now.Before(existingExpiry) {
			return false // replay
		}
		// Past TTL; drop + treat as fresh (race-safe: even if two
		// goroutines see the expired entry, both proceed and the second
		// Insert wins).
		c.delete(nonce)
	}

	// At-cap LRU eviction.
	c.mu.Lock()
	if c.size >= c.cap {
		c.evictOldestLocked()
	}
	c.size++
	c.mu.Unlock()

	c.entries.Store(nonce, now.Add(c.ttl))
	return true
}

// Close stops the janitor goroutine. Safe to call multiple times.
func (c *ReplayCache) Close() {
	c.stopOnce.Do(func() {
		close(c.stop)
	})
}

// Sweep walks the entries and evicts any past TTL. Public so tests
// can drive expiry without waiting for the janitor's tick. Returns
// the number of entries evicted.
func (c *ReplayCache) Sweep(now time.Time) int {
	evicted := 0
	c.entries.Range(func(k, v any) bool {
		expiry, _ := v.(time.Time)
		if !now.Before(expiry) {
			c.delete(k.(string))
			evicted++
		}
		return true
	})
	return evicted
}

// delete is the size-tracked counterpart to entries.Delete. The size
// counter is approximate (sync.Map.Range races with Insert), but the
// approximation only affects cap enforcement timing — never causes a
// false replay rejection.
func (c *ReplayCache) delete(nonce string) {
	if _, loaded := c.entries.LoadAndDelete(nonce); loaded {
		c.mu.Lock()
		if c.size > 0 {
			c.size--
		}
		c.mu.Unlock()
	}
}

// evictOldestLocked is called under c.mu held. Walks entries to find
// the entry with the minimum expiry (i.e. the oldest entry — closest
// to its TTL deadline) and removes it. O(N) but rarely hit; the
// janitor keeps the cache below cap.
func (c *ReplayCache) evictOldestLocked() {
	var oldestKey string
	var oldestExpiry time.Time
	first := true
	c.entries.Range(func(k, v any) bool {
		expiry, _ := v.(time.Time)
		if first || expiry.Before(oldestExpiry) {
			oldestKey = k.(string)
			oldestExpiry = expiry
			first = false
		}
		return true
	})
	if oldestKey != "" {
		if _, loaded := c.entries.LoadAndDelete(oldestKey); loaded && c.size > 0 {
			c.size--
		}
	}
}

// janitor wakes every ttl/4 and sweeps expired entries. Background-only;
// the test harness can drive expiry deterministically via Sweep.
func (c *ReplayCache) janitor() {
	interval := c.ttl / 4
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.Sweep(time.Now())
		}
	}
}

// Len returns the approximate cache size for observability. Not
// load-stable; use only for metrics + debug logs.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.size
}
