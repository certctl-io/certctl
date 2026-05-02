// Package mtlscache caches a parsed mTLS keypair plus a precomputed
// *http.Transport across API calls in connectors that authenticate via
// client certificates. RefreshIfStale stats the cert file on the
// caller's hot path; when the mtime has advanced beyond the last load,
// the keypair is re-parsed and the transport is rebuilt.
//
// Closes the #10 acquisition-readiness blocker from the 2026-05-01
// issuer coverage audit. Pre-fix, GlobalSign and Entrust reloaded
// the keypair from disk on every API call. Per-call disk reads are a
// latency floor that doesn't go away no matter how much the upstream
// CA improves; under a 100-cert renewal sweep that's 200 file opens
// + parses + tls.X509KeyPair calls in flight.
//
// Concurrency model:
//
//   - Reads (Transport / Client / Certificate) take the RWMutex's
//     read lock briefly to copy the pointer out, then release. The
//     HTTP request itself happens with no lock held — holding the
//     mutex across the request would serialise every concurrent
//     call and defeat the cache.
//   - RefreshIfStale takes the read lock for the cheap path (mtime
//     unchanged) and only escalates to the write lock for the
//     reload. The double-checked-lock pattern (re-check mtime
//     after acquiring the write lock) prevents two callers who
//     observed the same stale mtime from both reloading — one
//     wins, the other returns immediately.
//
// Out of scope (per audit prompt):
//
//   - Inotify / fsnotify file watching. Cross-platform pain (Linux
//     vs macOS divergence) without meaningful benefit over
//     stat-on-read; mtime granularity is fine for operator-driven
//     rotation cadence.
//   - HSM / KMS-backed mTLS. The crypto/signer abstraction has
//     stubs for those drivers; if/when they land, this cache
//     adapts to call the signer instead of tls.LoadX509KeyPair.
package mtlscache

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Cache holds a parsed mTLS keypair plus a precomputed *http.Transport
// so repeated API calls amortize the per-call cost of parsing the
// keypair from disk. RefreshIfStale on the hot path picks up rotated
// certs without a process restart.
type Cache struct {
	certPath string
	keyPath  string

	// tlsConfigBuilder lets the caller (e.g. GlobalSign with its
	// ServerCAPath pinning) inject extra TLS-config customization.
	// The freshly-parsed leaf cert is passed in; the builder returns
	// the full *tls.Config used for the transport. nil means "use
	// the default builder" (no server-CA pinning, MinVersion=TLS1.2).
	tlsConfigBuilder func(tls.Certificate) (*tls.Config, error)

	// httpTimeout is the per-request timeout on the cached http.Client.
	httpTimeout time.Duration

	mu        sync.RWMutex
	cert      tls.Certificate
	mtime     time.Time
	transport *http.Transport
	client    *http.Client
}

// Options configures cache behaviour at construction. Zero-value
// fields fall back to sensible defaults documented per field.
type Options struct {
	// TLSConfigBuilder customises the *tls.Config built around the
	// parsed leaf certificate. Use this to inject a pinned RootCAs
	// pool (GlobalSign's ServerCAPath case) or a custom MinVersion.
	// nil → default (Certificates only, MinVersion=TLS1.2, system
	// trust store).
	TLSConfigBuilder func(tls.Certificate) (*tls.Config, error)

	// HTTPTimeout is the *http.Client timeout. Zero → 30s, matching
	// the historical default in both connector packages.
	HTTPTimeout time.Duration
}

// New constructs a cache for the supplied cert+key paths and performs
// the initial load, so the returned cache is ready to serve calls
// immediately. Returns the file-load / parse error from the first load
// — callers should fail-fast at construction rather than discover a
// broken cert path on the first API call.
func New(certPath, keyPath string, opts Options) (*Cache, error) {
	if certPath == "" {
		return nil, fmt.Errorf("mtlscache: cert path required")
	}
	if keyPath == "" {
		return nil, fmt.Errorf("mtlscache: key path required")
	}
	timeout := opts.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	c := &Cache{
		certPath:         certPath,
		keyPath:          keyPath,
		tlsConfigBuilder: opts.TLSConfigBuilder,
		httpTimeout:      timeout,
	}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// reload performs the actual cert+key load + transport rebuild. The
// caller must hold the write lock. The mtime stamp captures the cert
// file's mtime BEFORE the parse so a concurrent in-place rewrite that
// races with our stat is observed as "still stale" on the next
// RefreshIfStale call (errs on the side of one extra reload, which is
// the safe direction).
func (c *Cache) reload() error {
	info, err := os.Stat(c.certPath)
	if err != nil {
		return fmt.Errorf("mtlscache: stat cert %q: %w", c.certPath, err)
	}
	mtime := info.ModTime()

	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("mtlscache: load keypair (%q,%q): %w", c.certPath, c.keyPath, err)
	}

	var tlsConfig *tls.Config
	if c.tlsConfigBuilder != nil {
		tlsConfig, err = c.tlsConfigBuilder(cert)
		if err != nil {
			return fmt.Errorf("mtlscache: build tls config: %w", err)
		}
	} else {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{
		Transport: transport,
		Timeout:   c.httpTimeout,
	}

	c.mu.Lock()
	c.cert = cert
	c.mtime = mtime
	c.transport = transport
	c.client = client
	c.mu.Unlock()

	return nil
}

// RefreshIfStale stats the cert file; if its mtime is later than the
// last-loaded mtime, the keypair is re-parsed and the transport is
// rebuilt. The fast path (mtime unchanged) is read-locked and does no
// allocations beyond the os.Stat syscall.
//
// The double-checked-lock pattern (read lock → stat → release →
// acquire write lock → re-stat) prevents two callers who observed
// the same stale mtime from both reloading; one wins, the other
// returns immediately.
//
// stat errors are returned to the caller — a missing or unreadable
// cert file is a real outage signal that should bubble up rather
// than silently serving stale credentials.
func (c *Cache) RefreshIfStale() error {
	info, err := os.Stat(c.certPath)
	if err != nil {
		return fmt.Errorf("mtlscache: stat cert %q: %w", c.certPath, err)
	}
	mtime := info.ModTime()

	c.mu.RLock()
	stale := mtime.After(c.mtime)
	c.mu.RUnlock()

	if !stale {
		return nil
	}

	// Escalate to the write lock and re-check; another goroutine
	// may have reloaded between our RUnlock and Lock.
	c.mu.Lock()
	if !mtime.After(c.mtime) {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	return c.reload()
}

// Client returns the cached *http.Client. Callers should call this
// AFTER RefreshIfStale to ensure they receive the post-reload client
// when a rotation just happened. Holding the read lock is briefly
// acquired to copy out the pointer and then released — the HTTP
// request itself happens lock-free.
func (c *Cache) Client() *http.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

// Transport returns the cached *http.Transport. Same locking
// discipline as Client.
func (c *Cache) Transport() *http.Transport {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.transport
}

// Certificate returns the cached parsed leaf certificate. Useful for
// connectors that need to inspect the cert (subject, expiry) for
// logging or pre-flight validation.
func (c *Cache) Certificate() tls.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert
}

// LoadedAt returns the mtime stamp captured at the most recent load.
// Useful for tests and for surfacing in operator-facing diagnostics
// (e.g., "this cert was loaded N hours ago").
func (c *Cache) LoadedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mtime
}
