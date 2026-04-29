package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// SCEP RFC 8894 + Intune master prompt §13 line 1853 acceptance —
// boot regression tests for preflightSCEPIntuneTrustAnchor. Closed in
// the 2026-04-29 audit-closure bundle (Phase F).
//
// Spec text:
//   "clean boot with Intune disabled (backward compat)" and
//   "refuses-to-start with broken per-profile config (PathID logged)."
//
// These three tests exercise the function the cmd/server/main.go boot
// loop calls per profile. We can't (and don't want to) run main()
// itself in a unit test — that would require docker compose + a real
// listener. Instead we drive the function directly and assert its
// contract holds: nil error on disabled, structured error containing
// the PathID on enabled-but-broken.

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

// TestPreflightSCEPIntuneTrustAnchor_DisabledIsBackwardCompat — when
// the profile has Intune disabled, preflight returns (nil, nil) and
// MUST NOT touch the filesystem. This is the dominant path in
// production: most operators run SCEP without Intune. A regression
// here would make every non-Intune deploy fail boot with a confusing
// "trust anchor missing" error.
func TestPreflightSCEPIntuneTrustAnchor_DisabledIsBackwardCompat(t *testing.T) {
	holder, err := preflightSCEPIntuneTrustAnchor(false, "corp", "", discardLogger())
	if err != nil {
		t.Fatalf("disabled preflight should be a no-op, got error: %v", err)
	}
	if holder != nil {
		t.Errorf("disabled preflight should return nil holder, got %#v", holder)
	}

	// Confirm the no-touch contract: even if PathID + path are both
	// non-empty, disabled=false short-circuits before any I/O. Pass a
	// path that doesn't exist — the call MUST still succeed.
	holder, err = preflightSCEPIntuneTrustAnchor(false, "iot", "/tmp/this-file-does-not-exist-12345.pem", discardLogger())
	if err != nil {
		t.Fatalf("disabled preflight with non-existent path should still succeed: %v", err)
	}
	if holder != nil {
		t.Error("disabled preflight should return nil holder even with non-existent path")
	}
}

// TestPreflightSCEPIntuneTrustAnchor_BrokenConfigRefusesWithPathID —
// when the profile has Intune enabled but the trust-anchor file
// doesn't exist, preflight returns an error whose text contains the
// literal PathID. Operators grep their boot log for the PathID to
// triage which profile is broken in a multi-profile deploy.
func TestPreflightSCEPIntuneTrustAnchor_BrokenConfigRefusesWithPathID(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "this-trust-anchor-was-never-written.pem")
	holder, err := preflightSCEPIntuneTrustAnchor(true, "corp", missingPath, discardLogger())
	if err == nil {
		t.Fatal("expected error when trust anchor file is missing, got nil")
	}
	if holder != nil {
		t.Errorf("expected nil holder on broken config, got %#v", holder)
	}
	if !strings.Contains(err.Error(), `PathID="corp"`) {
		t.Errorf("error should contain PathID for operator log-grep: %v", err)
	}
	if !strings.Contains(err.Error(), missingPath) {
		t.Errorf("error should contain the path for operator log-grep: %v", err)
	}

	// Empty PathID (legacy /scep root) — the error MUST surface a
	// readable label, not an empty quoted string that looks like a
	// missing variable.
	_, err = preflightSCEPIntuneTrustAnchor(true, "", missingPath, discardLogger())
	if err == nil {
		t.Fatal("expected error on broken legacy-root config")
	}
	if !strings.Contains(err.Error(), `PathID="<root>"`) {
		t.Errorf("error should label empty PathID as <root>: %v", err)
	}

	// Empty path with enabled=true — distinct error path (path-empty
	// vs file-missing). Spec requires this branch ALSO surfaces the
	// PathID so the operator's grep narrows to the profile.
	_, err = preflightSCEPIntuneTrustAnchor(true, "iot", "", discardLogger())
	if err == nil {
		t.Fatal("expected error when trust anchor path is empty")
	}
	if !strings.Contains(err.Error(), `PathID="iot"`) {
		t.Errorf("empty-path error should contain PathID for operator log-grep: %v", err)
	}
}

// TestPreflightSCEPIntuneTrustAnchor_ExpiredTrustAnchorRefuses — an
// expired Connector signing cert in the trust anchor file is the
// silent-failure mode this preflight is built to catch. Without the
// gate, the SCEP server boots cleanly and then rejects every Intune
// enrollment at runtime with "no trust anchor recognizes this
// signature" — confusing for the operator whose Connector is healthy
// (the cert just expired without rotation). Pin the contract: the
// boot MUST refuse with an error that names the expired cert's
// subject CN so the operator knows what to rotate.
func TestPreflightSCEPIntuneTrustAnchor_ExpiredTrustAnchorRefuses(t *testing.T) {
	// Build a deterministic ECDSA cert with NotAfter 1 hour in the past.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "intune-connector-rotated-must-replace"},
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(-1 * time.Hour), // expired
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	bundlePath := filepath.Join(t.TempDir(), "intune-expired.pem")
	if err := os.WriteFile(bundlePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write expired cert: %v", err)
	}

	holder, err := preflightSCEPIntuneTrustAnchor(true, "corp-expired", bundlePath, discardLogger())
	if err == nil {
		t.Fatal("expected refuse-to-start on expired trust anchor cert, got nil error")
	}
	if holder != nil {
		t.Errorf("expected nil holder on expired-cert refusal, got %#v", holder)
	}
	if !strings.Contains(err.Error(), `PathID="corp-expired"`) {
		t.Errorf("error should contain PathID for operator log-grep: %v", err)
	}
	if !strings.Contains(err.Error(), "intune-connector-rotated-must-replace") {
		t.Errorf("error should contain the expired cert's subject CN so the operator knows what to rotate: %v", err)
	}
}
