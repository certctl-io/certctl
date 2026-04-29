// Package trustanchor provides a SIGHUP-reloadable PEM-bundle trust pool
// shared by the SCEP/Intune dispatcher (per-profile Microsoft Intune
// Connector signing-cert anchor), the EST mTLS sibling route (per-profile
// client-CA trust bundle for /.well-known/est-mtls/<pathID>/), and any
// future caller that needs the same pattern (operator rotates an on-disk
// PEM bundle, sends SIGHUP, certctl swaps the in-memory pool atomically
// without a restart).
//
// EST RFC 7030 hardening master bundle Phase 2.1: extracted from
// internal/scep/intune/trust_anchor_holder.go where it originally lived.
// The intune package preserves a thin alias-style wrapper for back-compat
// (existing intune.TrustAnchorHolder + NewTrustAnchorHolder + LoadTrustAnchor
// callers compile unchanged); new callers SHOULD import this package
// directly.
//
// Concurrency contract:
//
//   - Get returns the pool slice header by value; the slice itself is
//     immutable per-snapshot (Reload swaps a fresh slice rather than
//     mutating the existing one). Callers may iterate the returned slice
//     without holding any lock.
//   - Reload acquires a write lock briefly for the swap. Concurrent Get
//     calls block only for that swap window (microseconds).
//   - WatchSIGHUP runs at most one Reload at a time per holder.
//
// Threat model: the rationale for SIGHUP-as-reload-trigger (vs fsnotify
// or polling) is that the existing certctl rotation playbook (server TLS
// cert at cmd/server/tls.go::certHolder) already uses SIGHUP. Operators
// running the standard "rotate file, kill -HUP" workflow get every
// holder reloaded with one signal: server TLS + Intune trust anchors +
// EST mTLS trust bundles all swap atomically.
package trustanchor

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Holder is the SIGHUP-reloadable wrapper around a PEM-bundle trust
// pool. Construct via New. The zero value is NOT usable.
type Holder struct {
	mu     sync.RWMutex
	certs  []*x509.Certificate
	path   string
	logger *slog.Logger
	// labelForLog is used only in error / info log lines so an operator
	// running multiple holders (per-profile EST mTLS, per-profile Intune,
	// server TLS) can distinguish which one fired. Defaults to "trust
	// anchor" when not set; callers SHOULD set this to a descriptive
	// string like "intune trust anchor (PathID=corp)" or "EST mTLS
	// client CA bundle (PathID=corp)".
	labelForLog string
}

// New loads the trust bundle and returns a holder. Returns the same
// fail-loud error LoadBundle does on initial load — the startup gate at
// cmd/server/main.go is supposed to refuse boot when this fails.
// Subsequent Reload errors are non-fatal (logged + old pool retained).
//
// The logger is required (never nil); the caller passes a per-profile
// scoped logger so SIGHUP-reload events show the PathID for triage.
func New(path string, logger *slog.Logger) (*Holder, error) {
	if logger == nil {
		return nil, errors.New("trustanchor: New requires a non-nil logger")
	}
	certs, err := LoadBundle(path)
	if err != nil {
		return nil, err
	}
	return &Holder{certs: certs, path: path, logger: logger, labelForLog: "trust anchor"}, nil
}

// SetLabelForLog records a descriptive label that future reload log
// lines use to distinguish this holder from others (e.g. "intune trust
// anchor (PathID=corp)"). Idempotent + safe for concurrent callers
// (the field is read only by the SIGHUP watcher goroutine after
// WatchSIGHUP starts).
func (h *Holder) SetLabelForLog(label string) {
	if label == "" {
		return
	}
	h.mu.Lock()
	h.labelForLog = label
	h.mu.Unlock()
}

// Get returns the current trust anchor pool. Safe for concurrent
// callers; the slice header is returned by value and the underlying
// slice is immutable per-snapshot.
func (h *Holder) Get() []*x509.Certificate {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.certs
}

// Path returns the on-disk path the holder reloads from.
func (h *Holder) Path() string {
	return h.path
}

// Pool returns a fresh *x509.CertPool populated with the holder's
// current certs. Helper for callers that need a pool instead of a
// slice (the EST mTLS handler verifies client cert chains via
// cert.Verify(VerifyOptions{Roots: pool}); the Intune dispatcher uses
// the slice directly for signature-walk).
func (h *Holder) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range h.Get() {
		pool.AddCert(c)
	}
	return pool
}

// Reload re-reads the trust anchor file at h.path and atomically swaps
// the pool. Returns the parse error if the new file is invalid; the
// OLD pool stays in place so a bad reload doesn't take dependent
// dispatch paths down. Same fail-safe pattern as cmd/server/tls.go::
// (*certHolder).Reload — a rotation that writes a half-file would
// otherwise crash the service mid-rotation.
func (h *Holder) Reload() error {
	certs, err := LoadBundle(h.path)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.certs = certs
	h.mu.Unlock()
	return nil
}

// WatchSIGHUP installs a signal handler that calls Reload on each
// SIGHUP. The returned stop function closes the internal done channel
// and stops signal delivery so the goroutine can exit cleanly during
// shutdown.
//
// Errors from Reload are logged but do not terminate the watcher — the
// operator can fix the files and send another SIGHUP. Mirrors the
// (*certHolder).watchSIGHUP contract from cmd/server/tls.go exactly.
//
// Multiple holders coexist: each registers its own goroutine on the
// same SIGHUP signal. signal.Notify multicasts to every registered
// channel, so a single SIGHUP reloads every per-profile trust anchor
// + the server TLS cert in one operator action.
func (h *Holder) WatchSIGHUP() (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				if err := h.Reload(); err != nil {
					h.logger.Error(h.labelForLog+" reload failed; continuing with previous pool",
						"error", err,
						"path", h.path)
					continue
				}
				h.logger.Info(h.labelForLog+" reloaded via SIGHUP",
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

// LoadBundle reads a PEM bundle from disk + returns the parsed cert
// slice. Refuses empty bundles (zero CERTIFICATE blocks); refuses any
// bundle containing a cert past NotAfter (fail loud at boot rather than
// silently rejecting every request at runtime).
//
// Non-CERTIFICATE PEM blocks are skipped (so an operator can paste a
// chain that includes a private key by mistake without breaking the
// load — the priv key is just ignored). Operators rotating signing
// certs typically want this tolerance.
func LoadBundle(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, errors.New("trustanchor: bundle path is empty")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trustanchor: read bundle %q: %w", path, err)
	}
	return parseBundlePEM(body, path, time.Now())
}

// parseBundlePEM is the file-IO-free core of LoadBundle. Split out so
// unit tests can hand it byte slices without writing temp files. `now`
// is taken as a parameter so expiry tests can pin a deterministic clock.
func parseBundlePEM(body []byte, sourceLabel string, now time.Time) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trustanchor: parse cert in %q: %w", sourceLabel, err)
		}
		if now.After(cert.NotAfter) {
			return nil, fmt.Errorf("trustanchor: cert in %q expired at %s (subject=%q) — operator must rotate the trust bundle before restart",
				sourceLabel, cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("trustanchor: %q contains no CERTIFICATE PEM blocks", sourceLabel)
	}
	return out, nil
}
