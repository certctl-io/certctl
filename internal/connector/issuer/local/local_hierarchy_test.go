package local

import (
	"context"
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

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

// fakeChainAssembler is a tiny in-memory ChainAssembler for the
// hierarchy unit tests. It maps a leafCAID to a pre-built chain PEM
// (leaf-first ordering, matching what *service.IntermediateCAService
// produces in production via WalkAncestry).
type fakeChainAssembler struct {
	chains map[string]string
}

func (f *fakeChainAssembler) AssembleChain(ctx context.Context, leafCAID string) (string, error) {
	if c, ok := f.chains[leafCAID]; ok {
		return c, nil
	}
	return "", os.ErrNotExist
}

// hierarchyTestFixture builds a self-signed root cert+key in memory,
// writes them to disk under a fresh tempdir, and returns the paths
// + parsed PEM. Both single- and tree-mode connectors load from this
// pair so the signing path is identical and the only thing that can
// differ is chain assembly.
type hierarchyTestFixture struct {
	tempDir string
	certPEM string
	keyPEM  string
	cert    *x509.Certificate
}

func newHierarchyTestFixture(t *testing.T) *hierarchyTestFixture {
	t.Helper()
	tempDir := t.TempDir()
	if err := os.Chmod(tempDir, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}

	// Mint a self-signed root cert + key in process.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subj := pkix.Name{CommonName: "Hierarchy Test Root"}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		Issuer:                subj,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return &hierarchyTestFixture{
		tempDir: tempDir,
		certPEM: certPEM,
		keyPEM:  keyPEM,
		cert:    cert,
	}
}

// makeCSRPEM returns a fresh ECDSA CSR PEM for the given CN. Used by
// both connectors so the signing inputs are identical.
func makeCSRPEM(t *testing.T, cn string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("csr keygen: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestLocal_HierarchyMode_SingleVsTree_ByteIdentical is the LOAD-
// BEARING backwards-compat pin (Rank 8 commit 3). Two connectors
// configured against the SAME on-disk CA cert+key produce
// byte-identical IssuanceResult.ChainPEM bytes:
//   - Connector A: pre-Rank-8 single-sub-CA mode (HierarchyMode unset).
//     ChainPEM = c.caCertPEM (the historical path).
//   - Connector B: tree mode wired against an in-memory ChainAssembler
//     whose AssembleChain returns the SAME PEM bytes for a 1-level
//     tree.
//
// Operators on single mode who never touch HierarchyMode keep getting
// byte-identical wire bytes; operators who flip to tree mode and
// register the same CA as the active root see no change in the bytes
// returned. This guarantees zero behavioral drift for unmigrated
// deployments.
func TestLocal_HierarchyMode_SingleVsTree_ByteIdentical(t *testing.T) {
	fx := newHierarchyTestFixture(t)
	ctx := context.Background()

	// Connector A — single-sub-CA mode (historical path).
	connA := New(&Config{
		CACommonName: "ignored",
		ValidityDays: 90,
		CACertPath:   filepath.Join(fx.tempDir, "ca.crt"),
		CAKeyPath:    filepath.Join(fx.tempDir, "ca.key"),
	}, newSilentLogger())

	// Connector B — tree mode wired against an in-memory chain
	// assembler that returns the SAME root cert PEM (1-level tree).
	connB := New(&Config{
		CACommonName: "ignored",
		ValidityDays: 90,
		CACertPath:   filepath.Join(fx.tempDir, "ca.crt"),
		CAKeyPath:    filepath.Join(fx.tempDir, "ca.key"),
	}, newSilentLogger())
	connB.SetHierarchyMode("tree")
	connB.SetChainAssembler(&fakeChainAssembler{
		chains: map[string]string{
			"ica-root-1": fx.certPEM, // matches single-mode caCertPEM byte-for-byte
		},
	})
	connB.SetTreeIssuingCAID("ica-root-1")

	csrPEM := makeCSRPEM(t, "leaf.example.com")

	resA, err := connA.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "leaf.example.com",
		CSRPEM:     csrPEM,
		SANs:       []string{"leaf.example.com"},
	})
	if err != nil {
		t.Fatalf("connA.IssueCertificate: %v", err)
	}
	resB, err := connB.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "leaf.example.com",
		CSRPEM:     csrPEM,
		SANs:       []string{"leaf.example.com"},
	})
	if err != nil {
		t.Fatalf("connB.IssueCertificate: %v", err)
	}

	// The load-bearing assertion: ChainPEM byte-identical between modes.
	if resA.ChainPEM != resB.ChainPEM {
		t.Fatalf("ChainPEM differs between single and tree modes\nsingle:\n%q\ntree:\n%q",
			resA.ChainPEM, resB.ChainPEM)
	}
	// And the chain MUST match the on-disk root cert bytes — i.e., the
	// pin verifies a real fact about the wire format, not just internal
	// consistency.
	if resA.ChainPEM != fx.certPEM {
		t.Fatalf("ChainPEM does not match on-disk root cert PEM\ngot:\n%q\nwant:\n%q",
			resA.ChainPEM, fx.certPEM)
	}
}

// TestLocal_HierarchyMode_Tree_LeafChainIncludesAllAncestors pins
// the multi-level tree case: a leaf issued under the deepest CA in a
// 4-level hierarchy carries a ChainPEM containing every ancestor up
// through the root. This is what tree mode buys operators in exchange
// for the migration overhead.
func TestLocal_HierarchyMode_Tree_LeafChainIncludesAllAncestors(t *testing.T) {
	fx := newHierarchyTestFixture(t)
	ctx := context.Background()

	// Build a synthetic 4-level chain (root → policy → issuingA →
	// issuingB-leaf-CA). The actual cert content doesn't matter for
	// this test — we just need 4 distinct CERTIFICATE blocks. Using
	// the same root cert 4x with marker comments would NOT work
	// because the connector returns the PEM verbatim. Mint 4 fresh
	// self-signed certs with distinct subjects so we can verify
	// ordering.
	type leveledCert struct {
		pem  string
		cert *x509.Certificate
	}
	mintCert := func(cn string) *leveledCert {
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		subj := pkix.Name{CommonName: cn}
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               subj,
			Issuer:                subj,
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		c, _ := x509.ParseCertificate(der)
		return &leveledCert{
			pem:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			cert: c,
		}
	}
	root := mintCert("Hierarchy Root CA")
	policy := mintCert("Hierarchy Policy CA")
	issuingA := mintCert("Hierarchy Issuing A")
	issuingB := mintCert("Hierarchy Issuing B")

	// Stitch the chain leaf-to-root (matches AssembleChain output).
	chainPEM := issuingB.pem + issuingA.pem + policy.pem + root.pem

	conn := New(&Config{
		CACommonName: "ignored",
		ValidityDays: 90,
		CACertPath:   filepath.Join(fx.tempDir, "ca.crt"),
		CAKeyPath:    filepath.Join(fx.tempDir, "ca.key"),
	}, newSilentLogger())
	conn.SetHierarchyMode("tree")
	conn.SetChainAssembler(&fakeChainAssembler{
		chains: map[string]string{
			"ica-issuing-b": chainPEM,
		},
	})
	conn.SetTreeIssuingCAID("ica-issuing-b")

	csrPEM := makeCSRPEM(t, "deep-leaf.example.com")
	res, err := conn.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "deep-leaf.example.com",
		CSRPEM:     csrPEM,
		SANs:       []string{"deep-leaf.example.com"},
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	if got, want := strings.Count(res.ChainPEM, "BEGIN CERTIFICATE"), 4; got != want {
		t.Fatalf("expected %d CERTIFICATE blocks, got %d:\n%s", want, got, res.ChainPEM)
	}
	// Verify leaf-first ordering by parsing each block.
	rest := []byte(res.ChainPEM)
	wantSubjects := []string{
		"Hierarchy Issuing B",
		"Hierarchy Issuing A",
		"Hierarchy Policy CA",
		"Hierarchy Root CA",
	}
	for i := 0; i < 4; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			t.Fatalf("expected block %d, got nil", i)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse block %d: %v", i, err)
		}
		if c.Subject.CommonName != wantSubjects[i] {
			t.Fatalf("block %d: expected CN=%q, got %q", i, wantSubjects[i], c.Subject.CommonName)
		}
	}
}

// TestLocal_HierarchyMode_FallsBackToSingleWhenWiringIncomplete pins
// the defensive fallback: hierarchyMode set to "tree" but
// ChainAssembler is nil → the connector falls back to the historical
// c.caCertPEM. Defense in depth: a misconfigured operator still gets
// a working issuance, not a nil-deref panic.
func TestLocal_HierarchyMode_FallsBackToSingleWhenWiringIncomplete(t *testing.T) {
	fx := newHierarchyTestFixture(t)
	ctx := context.Background()

	conn := New(&Config{
		CACommonName: "ignored",
		ValidityDays: 90,
		CACertPath:   filepath.Join(fx.tempDir, "ca.crt"),
		CAKeyPath:    filepath.Join(fx.tempDir, "ca.key"),
	}, newSilentLogger())
	// Tree mode declared, but ChainAssembler + treeIssuingCAID are unset.
	conn.SetHierarchyMode("tree")

	csrPEM := makeCSRPEM(t, "fallback.example.com")
	res, err := conn.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "fallback.example.com",
		CSRPEM:     csrPEM,
		SANs:       []string{"fallback.example.com"},
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if res.ChainPEM != fx.certPEM {
		t.Fatalf("expected fallback to caCertPEM, got %q", res.ChainPEM)
	}
}
