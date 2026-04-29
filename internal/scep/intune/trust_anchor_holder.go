package intune

import (
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// TrustAnchorHolder is the SIGHUP-reloadable wrapper around a per-profile
// Intune Connector trust anchor pool.
//
// SCEP RFC 8894 + Intune master bundle Phase 8.5.
//
// Mirrors the shape established by `cmd/server/tls.go::certHolder` for the
// server TLS cert: an RWMutex-guarded pool, a Get accessor that's safe for
// concurrent callers from the request path, a Reload that re-reads the file
// and atomically swaps the slice on success (failure leaves the OLD pool in
// place so a bad reload doesn't take Intune enrollment down), and a
// watchSIGHUP goroutine that responds to the same SIGHUP the operator uses
// to rotate the server TLS cert.
//
// Why SIGHUP specifically (vs fsnotify or a polling loop): SIGHUP is the
// repo-established convention (see cmd/server/tls.go). fsnotify would add a
// new direct dep + complicate the cleanup story. The operator's Connector-
// rotation script writes the new PEM bundle then sends SIGHUP — the same
// signal that already rotates the server TLS cert — and both swap atomically.
//
// Concurrency contract:
//   - Get returns the pool slice header by value; the slice itself is
//     immutable per-snapshot (Reload swaps a fresh slice rather than
//     mutating the existing one). Callers may iterate the returned slice
//     without holding any lock.
//   - Reload acquires a write lock briefly for the swap. Concurrent Get
//     calls block only for that swap window (microseconds).
//   - watchSIGHUP runs at most one Reload at a time per holder.
type TrustAnchorHolder struct {
	mu     sync.RWMutex
	certs  []*x509.Certificate
	path   string
	logger *slog.Logger
}

// NewTrustAnchorHolder loads the trust bundle and returns a holder. Returns
// the same fail-loud error LoadTrustAnchor does on initial load — the
// startup gate at cmd/server/main.go is supposed to refuse boot when this
// fails. Subsequent Reload errors are non-fatal (logged + old pool retained).
//
// The logger is required (never nil); the caller passes a per-profile
// scoped logger so SIGHUP-reload events show the PathID for triage.
func NewTrustAnchorHolder(path string, logger *slog.Logger) (*TrustAnchorHolder, error) {
	if logger == nil {
		return nil, errors.New("intune: TrustAnchorHolder requires a non-nil logger")
	}
	certs, err := LoadTrustAnchor(path)
	if err != nil {
		return nil, err
	}
	return &TrustAnchorHolder{
		certs:  certs,
		path:   path,
		logger: logger,
	}, nil
}

// Get returns the current trust anchor pool. Safe for concurrent callers;
// the slice header is returned by value and the underlying slice is
// immutable per-snapshot (Reload swaps a fresh slice, doesn't mutate in
// place — see Reload).
func (h *TrustAnchorHolder) Get() []*x509.Certificate {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.certs
}

// Path returns the on-disk path the holder reloads from. Useful for
// observability (admin endpoints, log lines) without exposing the cert
// pool itself.
func (h *TrustAnchorHolder) Path() string {
	return h.path
}

// Reload re-reads the trust anchor file at h.path and atomically swaps the
// pool. Returns the parse error if the new file is invalid; the OLD pool
// stays in place so a bad reload doesn't take Intune enrollment down.
//
// Same fail-safe pattern as cmd/server/tls.go::(*certHolder).Reload — a
// rotation that writes a half-file (operator overwrites the bundle while
// only some of the new certs are in it) would otherwise crash the
// service mid-rotation. Logging + retaining the old pool gives the
// operator a bounded window to fix and re-SIGHUP.
func (h *TrustAnchorHolder) Reload() error {
	certs, err := LoadTrustAnchor(h.path)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.certs = certs
	h.mu.Unlock()
	return nil
}

// WatchSIGHUP installs a signal handler that calls Reload on each SIGHUP.
// The returned stop function closes the internal done channel and stops
// signal delivery so the goroutine can exit cleanly during shutdown.
//
// Errors from Reload are logged but do not terminate the watcher — the
// operator can fix the files and send another SIGHUP. Mirrors the
// (*certHolder).watchSIGHUP contract exactly.
//
// Multiple holders can coexist: each registers its own goroutine on the
// same SIGHUP signal. signal.Notify multicasts to every registered
// channel, so a single SIGHUP reloads every per-profile Intune trust
// anchor PLUS the server TLS cert in one operator action — exactly the
// design requirement (one SIGHUP rotates everything).
func (h *TrustAnchorHolder) WatchSIGHUP() (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				if err := h.Reload(); err != nil {
					h.logger.Error("Intune trust anchor reload failed; continuing with previous pool",
						"error", err,
						"path", h.path)
					continue
				}
				h.logger.Info("Intune trust anchor reloaded via SIGHUP",
					"path", h.path,
					"certs_loaded", len(h.Get()))
			case <-done:
				signal.Stop(ch)
				return
			}
		}
	}()
	return func() { close(done) }
}
