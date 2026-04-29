package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// certHolder stores the server's TLS certificate under a mutex so it can be
// swapped atomically by a SIGHUP handler without restarting the server. A
// *tls.Config that wires GetCertificate → (*certHolder).GetCertificate reads
// through the holder on every ClientHello, so a successful reload takes
// effect on the next new connection immediately and without dropping
// in-flight requests.
//
// Concurrency: GetCertificate is invoked from crypto/tls handshake goroutines
// on every new inbound connection; Reload is invoked from the SIGHUP watcher
// goroutine. sync.Mutex is sufficient — TLS handshakes are not an inner-loop
// hot path and the critical section is a single pointer read.
type certHolder struct {
	mu       sync.Mutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

// newCertHolder loads the initial cert+key pair from disk and returns a
// holder ready to serve handshakes. Returns a non-nil error if either file
// is missing, unreadable, or the pair does not round-trip through
// tls.LoadX509KeyPair (for example the key does not sign the cert). The
// caller is expected to treat a non-nil error as a fail-loud startup gate
// and os.Exit(1) — the HTTPS-everywhere milestone (§3 locked decisions)
// prohibits plaintext HTTP fallback.
func newCertHolder(certPath, keyPath string) (*certHolder, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert/key (cert=%q key=%q): %w", certPath, keyPath, err)
	}
	return &certHolder{
		cert:     &cert,
		certPath: certPath,
		keyPath:  keyPath,
	}, nil
}

// GetCertificate is the tls.Config.GetCertificate hook. Returns the current
// cert under the holder's mutex. ClientHelloInfo is ignored — the control
// plane does not multiplex by SNI.
func (h *certHolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cert, nil
}

// Reload re-reads the cert+key pair from disk and swaps the holder
// atomically on success. On failure the holder retains its previous cert
// and the error is propagated to the caller — the SIGHUP watcher logs and
// keeps serving the previous cert rather than crashing on a bad reload.
// This is deliberately "fail-safe on reload, fail-loud on startup": an
// operator rotating certs wants a recoverable error, not a restart loop.
func (h *certHolder) Reload() error {
	cert, err := tls.LoadX509KeyPair(h.certPath, h.keyPath)
	if err != nil {
		return fmt.Errorf("reload TLS cert/key (cert=%q key=%q): %w", h.certPath, h.keyPath, err)
	}
	h.mu.Lock()
	h.cert = &cert
	h.mu.Unlock()
	return nil
}

// watchSIGHUP installs a signal handler that calls Reload() on each SIGHUP.
// The returned stop function closes the internal done channel and stops
// signal delivery so the goroutine can exit cleanly during shutdown. Errors
// from Reload are logged but do not terminate the watcher — the operator
// can fix the files and send another SIGHUP.
//
// Defensive design note: this deliberately does NOT panic on Reload error
// even though HTTPS is mission-critical. A rotation that writes half-files
// (operator overwrites cert.pem then key.pem as two separate copies) would
// otherwise crash the server mid-rotation. Logging + retaining the old
// cert gives the operator a bounded window to fix and re-SIGHUP.
func (h *certHolder) watchSIGHUP(logger *slog.Logger) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				if err := h.Reload(); err != nil {
					logger.Error("TLS cert reload failed; continuing with previous cert",
						"error", err,
						"cert_path", h.certPath,
						"key_path", h.keyPath)
					continue
				}
				logger.Info("TLS cert reloaded via SIGHUP",
					"cert_path", h.certPath,
					"key_path", h.keyPath)
			case <-done:
				signal.Stop(ch)
				return
			}
		}
	}()
	return func() { close(done) }
}

// buildServerTLSConfig returns the TLS 1.3-only *tls.Config for the HTTPS
// server. Pinned per HTTPS-everywhere milestone §2.1 + §3 locked decisions:
//
//   - MinVersion: TLS 1.3 (no TLS 1.2 escape hatch). Go 1.25's crypto/tls
//     automatically rejects older versions.
//   - CurvePreferences: explicit [X25519, P-256]. Explicit ordering keeps
//     the handshake deterministic and documents the accepted curves.
//   - No CipherSuites field: TLS 1.3 cipher suites are not negotiable in
//     the handshake (all three mandatory suites — AES-128-GCM-SHA256,
//     AES-256-GCM-SHA384, CHACHA20-POLY1305-SHA256 — are always offered).
//     Go's crypto/tls ignores CipherSuites for TLS 1.3.
//   - GetCertificate: reads through the holder so SIGHUP rotations take
//     effect on the next new connection without a restart. Setting
//     tls.Config.Certificates directly would pin the first-loaded cert
//     and defeat SIGHUP reload.
func buildServerTLSConfig(holder *certHolder) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		GetCertificate:   holder.GetCertificate,
	}
}

// buildServerTLSConfigWithMTLS extends buildServerTLSConfig with a client-cert
// trust pool for the SCEP/EST mTLS sibling routes.
//
// SCEP RFC 8894 + Intune master bundle Phase 6.5 introduced this for the
// /scep-mtls/<pathID> route; EST RFC 7030 hardening master bundle Phase 2
// extended it so the same TLS listener also serves /.well-known/est-mtls/
// <pathID>. Both protocols' mTLS profiles contribute their trust bundles
// to a UNION pool that the caller (cmd/server/main.go) builds by walking
// every enabled mTLS profile's bundle bytes once. The per-protocol
// handlers re-verify against just THIS profile's bundle (so an EST-mTLS
// bootstrap cert can't enroll against a SCEP-mTLS profile and vice versa).
//
// ClientAuth: VerifyClientCertIfGiven — request a cert during handshake; if
// the client presents one, verify it against the union pool; if absent, the
// request still reaches the handler and the per-route handler decides
// whether to accept. Critical that we do NOT use RequireAndVerifyClientCert
// here — that would break the standard /scep + /.well-known/est routes
// (challenge-password-only / unauth-or-Basic, no client cert expected).
//
// Pass clientCAs == nil to disable mTLS (no profile opted in across either
// protocol). The function then returns the same shape as
// buildServerTLSConfig.
func buildServerTLSConfigWithMTLS(holder *certHolder, clientCAs *x509.CertPool) *tls.Config {
	cfg := buildServerTLSConfig(holder)
	if clientCAs != nil {
		cfg.ClientCAs = clientCAs
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg
}

// preflightServerTLS is the fail-loud startup gate for HTTPS. Returns a
// non-nil error when the TLS configuration is missing or the cert+key pair
// cannot be parsed, so the caller refuses to start the control plane
// (HTTPS-everywhere §3 locked decisions: no plaintext HTTP fallback).
//
// Duplicates the emptiness + stat + parse checks in config.Validate() for
// defense in depth, mirroring the pattern established by
// preflightSCEPChallengePassword (which itself duplicates
// config.Validate()'s SCEP check for CWE-306). Extracted into a separate
// function so the gate is unit-testable without booting the full server.
func preflightServerTLS(certPath, keyPath string) error {
	if certPath == "" {
		return fmt.Errorf("CERTCTL_SERVER_TLS_CERT_PATH is empty: HTTPS-only control plane refuses to start (see docs/tls.md)")
	}
	if keyPath == "" {
		return fmt.Errorf("CERTCTL_SERVER_TLS_KEY_PATH is empty: HTTPS-only control plane refuses to start (see docs/tls.md)")
	}
	if _, err := os.Stat(certPath); err != nil {
		return fmt.Errorf("TLS cert file %q unreadable: %w (see docs/tls.md)", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("TLS key file %q unreadable: %w (see docs/tls.md)", keyPath, err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Errorf("TLS cert/key pair invalid (cert=%q key=%q): %w (see docs/tls.md)", certPath, keyPath, err)
	}
	return nil
}
