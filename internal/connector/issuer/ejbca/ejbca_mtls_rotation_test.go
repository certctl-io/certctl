package ejbca_test

// Top-10 fix #1 of the 2026-05-03 issuer-coverage audit. Pre-fix,
// ejbca.New called tls.LoadX509KeyPair once at construction; rotating
// the client cert+key on disk required a server restart to take
// effect. Post-fix, ejbca.New constructs an mtlscache.Cache and the
// hot-path getHTTPClient calls RefreshIfStale before every API
// request — operators rotating quarterly per security policy no
// longer pay the deploy outage.
//
// This test pins the rotation behaviour end-to-end: write certA,
// make one mTLS request, write certB at the same paths, advance
// mtime, make a second request, assert the leaf cert presented on
// the wire flipped from certA to certB.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer/ejbca"
)

// TestEJBCA_MTLSKeypairRotation_PicksUpNewCertWithoutRestart verifies
// the mtlscache wiring catches a hot-rotated keypair. Sequence:
//
//  1. Generate caA + caB roots (different CAs so the server can tell
//     which client cert was presented by inspecting the issuer DN).
//  2. Sign clientA against caA, clientB against caB.
//  3. Spin up an httptest TLS server that requires a client cert
//     signed by caA OR caB (ClientCAs pool with both roots) and
//     records which CA actually signed the presented client cert.
//  4. Write clientA's cert+key to {certPath, keyPath}.
//  5. Construct ejbca.Connector via production New (mTLS mode).
//  6. Make request #1 → server records "presented cert from caA".
//  7. Overwrite {certPath, keyPath} with clientB's cert+key. Advance
//     mtime via os.Chtimes (ext4 mtime granularity is 1s; advancing
//     by 2s defeats the no-op cheap path).
//  8. Make request #2 → server records "presented cert from caB".
//  9. Assert the two recorded issuers differ — the cache picked up
//     the rotation without ejbca.New re-running.
func TestEJBCA_MTLSKeypairRotation_PicksUpNewCertWithoutRestart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	caA, caACert, caAKey := mustCA(t, "EJBCA-RotationTest-CA-A")
	caB, caBCert, caBKey := mustCA(t, "EJBCA-RotationTest-CA-B")

	// Sign one leaf cert per CA; both have CN="ejbca-rotation-client"
	// so the only distinguishing feature on the wire is the issuer DN.
	leafA, leafAKey := mustLeafSignedBy(t, caACert, caAKey)
	leafB, leafBKey := mustLeafSignedBy(t, caBCert, caBKey)

	// httptest TLS server with a ClientCAs pool that trusts BOTH
	// roots. The handler captures the issuer DN of the presented
	// cert into a thread-safe slice the test inspects after the
	// requests complete.
	pool := x509.NewCertPool()
	pool.AddCert(caACert)
	pool.AddCert(caBCert)
	var (
		mu              sync.Mutex
		seenIssuerDNs   []string
		seenCommonNames []string
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		mu.Lock()
		seenIssuerDNs = append(seenIssuerDNs, leaf.Issuer.String())
		seenCommonNames = append(seenCommonNames, leaf.Subject.CommonName)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// Step 4 — write clientA initially.
	mustWriteKeypair(t, certPath, keyPath, leafA, leafAKey)

	// Step 5 — construct via production New().
	cfg := &ejbca.Config{
		APIUrl:         srv.URL,
		AuthMode:       "mtls",
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
		CAName:         "Management CA",
	}
	conn, err := ejbca.New(cfg, logger)
	if err != nil {
		t.Fatalf("ejbca.New: %v", err)
	}

	// To talk to httptest's self-signed server cert, mutate the cached
	// transport's RootCAs to trust the test server. The Certificates
	// field (the client cert) stays intact — that's the field we're
	// proving rotates without a New() re-run.
	httpClient := ejbca.HTTPClientForTest(conn)
	tr := httpClient.Transport.(*http.Transport)
	srvPool := x509.NewCertPool()
	srvPool.AddCert(srv.Certificate())
	tr.TLSClientConfig.RootCAs = srvPool

	// Step 6 — first request via the production code path.
	clientA, err := ejbca.GetHTTPClientForTest(conn)
	if err != nil {
		t.Fatalf("getHTTPClient (req 1): %v", err)
	}
	// Re-apply the server-cert trust pool to the freshly-returned
	// client's transport (cache rebuild would have wiped any prior
	// mutation, but on the cheap path this is a no-op since the same
	// transport pointer is returned).
	if trA, ok := clientA.Transport.(*http.Transport); ok && trA.TLSClientConfig.RootCAs == nil {
		trA.TLSClientConfig.RootCAs = srvPool
	}
	if _, err := clientA.Get(srv.URL); err != nil {
		t.Fatalf("request 1: %v", err)
	}

	// Step 7 — overwrite the keypair with leafB, advance mtime.
	mustWriteKeypair(t, certPath, keyPath, leafB, leafBKey)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}

	// Step 8 — second request. RefreshIfStale should rebuild the
	// transport with leafB's keypair. The rebuild creates a new
	// transport whose RootCAs is unset, so re-apply.
	clientB, err := ejbca.GetHTTPClientForTest(conn)
	if err != nil {
		t.Fatalf("getHTTPClient (req 2): %v", err)
	}
	if trB, ok := clientB.Transport.(*http.Transport); ok && trB.TLSClientConfig.RootCAs == nil {
		trB.TLSClientConfig.RootCAs = srvPool
	}
	if _, err := clientB.Get(srv.URL); err != nil {
		t.Fatalf("request 2: %v", err)
	}

	// Step 9 — assert.
	mu.Lock()
	defer mu.Unlock()
	if len(seenIssuerDNs) != 2 {
		t.Fatalf("expected exactly 2 server-side observations, got %d: %v", len(seenIssuerDNs), seenIssuerDNs)
	}
	if seenIssuerDNs[0] == seenIssuerDNs[1] {
		t.Fatalf("issuer DN unchanged across rotation: req1=%q req2=%q — cache did not pick up the new keypair",
			seenIssuerDNs[0], seenIssuerDNs[1])
	}
	if want := caA.String(); seenIssuerDNs[0] != want {
		t.Errorf("req 1 issuer = %q, want %q (caA)", seenIssuerDNs[0], want)
	}
	if want := caB.String(); seenIssuerDNs[1] != want {
		t.Errorf("req 2 issuer = %q, want %q (caB)", seenIssuerDNs[1], want)
	}
}

// --- test helpers ------------------------------------------------------

// mustCA generates a self-signed CA cert + key. Returns the parsed CA
// pkix.Name, the parsed cert, and the private key.
func mustCA(t *testing.T, commonName string) (pkix.Name, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key gen: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return template.Subject, cert, key
}

// mustLeafSignedBy generates a leaf cert+key, signed by the supplied
// CA. Both rotation halves share the same Subject CN so the
// distinguishing field on the wire is exclusively the Issuer DN.
func mustLeafSignedBy(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key gen: %v", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ejbca-rotation-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf, leafKey
}

func mustWriteKeypair(t *testing.T, certPath, keyPath string, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey) {
	t.Helper()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}
