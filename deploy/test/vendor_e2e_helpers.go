//go:build integration

// Package integration's vendor-e2e helpers — shared utilities used
// by the deploy-hardening II Phase 2-13 per-vendor edge tests.
//
// Every TestVendorEdge_<vendor>_<edge>_E2E test follows the same
// shape:
//
//   - Skip if the sidecar isn't reachable (CI / dev environments
//     without `docker compose --profile deploy-e2e up -d`).
//   - Build a minimal connector config pointing at the sidecar.
//   - Exercise the connector's atomic + verify + rollback contract
//     against the real binary.
//   - Assert the post-deploy TLS handshake serves the new cert.
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// vendorSidecar describes one Bundle II Phase 1 sidecar. Used by
// the per-vendor e2e helpers to reach the sidecar over its
// host-port mapping AND to skip the test cleanly when the sidecar
// isn't running.
type vendorSidecar struct {
	name       string // matches the docker-compose service name
	hostPort   string // the localhost:<port> mapping the test dials
	healthPath string // optional HTTP path for readiness probe; empty = TCP-only
}

var sidecarMap = map[string]vendorSidecar{
	"apache":      {name: "apache-test", hostPort: "127.0.0.1:20443"},
	"haproxy":     {name: "haproxy-test", hostPort: "127.0.0.1:20444"},
	"traefik":     {name: "traefik-test", hostPort: "127.0.0.1:20445"},
	"caddy":       {name: "caddy-test", hostPort: "127.0.0.1:20446", healthPath: "http://127.0.0.1:22019/config/"},
	"envoy":       {name: "envoy-test", hostPort: "127.0.0.1:20447"},
	"postfix":     {name: "postfix-test", hostPort: "127.0.0.1:20465"},
	"dovecot":     {name: "dovecot-test", hostPort: "127.0.0.1:20993"},
	"openssh":     {name: "openssh-test", hostPort: "127.0.0.1:20022"},
	"f5-mock":     {name: "f5-mock-icontrol", hostPort: "127.0.0.1:20443"},
	"k8s-kind":    {name: "k8s-kind-test", hostPort: ""},
	"windows-iis": {name: "windows-iis-test", hostPort: "127.0.0.1:20448"},
}

// requireSidecar skips the test cleanly when the sidecar isn't
// reachable. CI's per-vendor matrix job (Phase 15) runs each
// vendor with its sidecar up; dev/local runs without
// `docker compose up` skip rather than fail.
func requireSidecar(t *testing.T, vendor string) vendorSidecar {
	t.Helper()
	s, ok := sidecarMap[vendor]
	if !ok {
		t.Fatalf("unknown vendor %q in sidecar map", vendor)
	}
	if s.hostPort == "" {
		// Connector-internal sidecar (k8s-kind); the test handles
		// reachability through its own client setup.
		return s
	}
	conn, err := net.DialTimeout("tcp", s.hostPort, 2*time.Second)
	if err != nil {
		t.Skipf("vendor sidecar %q not reachable at %s (run docker compose --profile deploy-e2e up -d %s); err: %v",
			vendor, s.hostPort, s.name, err)
	}
	_ = conn.Close()
	return s
}

// generateSelfSignedPEM produces a fresh ECDSA P-256 cert+key pair
// covering the given DNS names. Used by every vendor-e2e test as
// the "deploy this cert and verify" fixture.
//
// Per frozen decision 0.10: tests use known-good self-signed certs
// generated at test-init time. ACME-flavoured tests opt in via a
// fixture-mode flag (not used in the current vendor-edge surface).
func generateSelfSignedPEM(t *testing.T, dnsNames ...string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return
}

// dialAndVerifyCert opens a TLS connection to addr (InsecureSkipVerify
// — we're verifying SAN+SubjectCN, not chain trust against the
// system root store) and returns the leaf cert. Used by every
// vendor-edge test's post-deploy verification.
func dialAndVerifyCert(t *testing.T, addr string, timeout time.Duration) *x509.Certificate {
	t.Helper()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional — we verify the leaf cert below
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("TLS dial %s: %v", addr, err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		t.Fatalf("no peer certs from %s", addr)
	}
	return chain[0]
}

// httpProbe makes an HTTP request to url with a context timeout,
// returns the response body. Used by the Caddy admin-API
// vendor-edge tests + general health-check helpers.
func httpProbe(t *testing.T, url string, timeout time.Duration) (int, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// writeCertVolumeFiles writes the given cert/key PEM into the
// shared docker volume the sidecar bind-mounts at /etc/<vendor>/certs.
// Tests use this when the connector itself isn't being exercised
// — e.g., bootstrapping the initial cert before the test rotates it.
//
// hostPath is computed from the volume's known docker-compose mount
// target. If the host path doesn't exist (CI runs in containerized
// docker-in-docker; volume internal), tests fall back to docker exec.
func writeCertVolumeFiles(t *testing.T, hostPath string, certPEM, keyPEM string) {
	t.Helper()
	if hostPath == "" {
		t.Skip("hostPath empty — sidecar volume not host-mounted")
	}
	if err := os.WriteFile(hostPath+"/cert.pem", []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(hostPath+"/key.pem", []byte(keyPEM), 0640); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// expect helps test bodies stay compact.
func expect(t *testing.T, got, want any, msg string) {
	t.Helper()
	if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}
