package signer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/crypto/signer"
)

// ---------------------------------------------------------------------------
// Algorithm + SignatureAlgorithm mapping
// ---------------------------------------------------------------------------

func TestSignatureAlgorithm_Mapping(t *testing.T) {
	cases := []struct {
		alg  signer.Algorithm
		want x509.SignatureAlgorithm
	}{
		{signer.AlgorithmRSA2048, x509.SHA256WithRSA},
		{signer.AlgorithmRSA3072, x509.SHA256WithRSA},
		{signer.AlgorithmRSA4096, x509.SHA256WithRSA},
		{signer.AlgorithmECDSAP256, x509.ECDSAWithSHA256},
		{signer.AlgorithmECDSAP384, x509.ECDSAWithSHA384},
	}
	for _, tc := range cases {
		t.Run(string(tc.alg), func(t *testing.T) {
			if got := signer.SignatureAlgorithm(tc.alg); got != tc.want {
				t.Fatalf("SignatureAlgorithm(%q) = %v, want %v", tc.alg, got, tc.want)
			}
		})
	}

	// Unknown should map to UnknownSignatureAlgorithm.
	if got := signer.SignatureAlgorithm(signer.Algorithm("bogus")); got != x509.UnknownSignatureAlgorithm {
		t.Fatalf("unknown algorithm should map to UnknownSignatureAlgorithm, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Wrap / algorithmFromKey: every supported key shape + several rejected ones
// ---------------------------------------------------------------------------

func TestWrap_RSA_AllSupportedSizes(t *testing.T) {
	cases := []struct {
		bits int
		want signer.Algorithm
	}{
		{2048, signer.AlgorithmRSA2048},
		{3072, signer.AlgorithmRSA3072},
		// 4096 omitted: too slow for short tests; covered indirectly via Generate
	}
	for _, tc := range cases {
		k, err := rsa.GenerateKey(rand.Reader, tc.bits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(%d): %v", tc.bits, err)
		}
		s, err := signer.Wrap(k)
		if err != nil {
			t.Fatalf("Wrap RSA-%d: %v", tc.bits, err)
		}
		if got := s.Algorithm(); got != tc.want {
			t.Fatalf("RSA-%d Algorithm = %q, want %q", tc.bits, got, tc.want)
		}
		if s.Public() == nil {
			t.Fatalf("RSA-%d Public() returned nil", tc.bits)
		}
	}
}

func TestWrap_ECDSA_AllSupportedCurves(t *testing.T) {
	cases := []struct {
		curve elliptic.Curve
		want  signer.Algorithm
	}{
		{elliptic.P256(), signer.AlgorithmECDSAP256},
		{elliptic.P384(), signer.AlgorithmECDSAP384},
	}
	for _, tc := range cases {
		k, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(%s): %v", tc.curve.Params().Name, err)
		}
		s, err := signer.Wrap(k)
		if err != nil {
			t.Fatalf("Wrap %s: %v", tc.curve.Params().Name, err)
		}
		if got := s.Algorithm(); got != tc.want {
			t.Fatalf("%s Algorithm = %q, want %q", tc.curve.Params().Name, got, tc.want)
		}
	}
}

func TestWrap_RejectsNilSigner(t *testing.T) {
	_, err := signer.Wrap(nil)
	if err == nil {
		t.Fatal("Wrap(nil) should return error")
	}
}

func TestWrap_RejectsRSA1024(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(1024): %v", err)
	}
	_, err = signer.Wrap(k)
	if err == nil {
		t.Fatal("Wrap RSA-1024 should error")
	}
	if !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Fatalf("Wrap RSA-1024 should wrap ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestWrap_RejectsECDSAP224(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P-224): %v", err)
	}
	_, err = signer.Wrap(k)
	if err == nil {
		t.Fatal("Wrap ECDSA P-224 should error")
	}
	if !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Fatalf("Wrap ECDSA P-224 should wrap ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestWrap_RejectsEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	_, err = signer.Wrap(priv)
	if err == nil {
		t.Fatal("Wrap Ed25519 should error (not in supported enum)")
	}
	if !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Fatalf("Wrap Ed25519 should wrap ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestWrap_PreservesSignBehavior(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	s, err := signer.Wrap(k)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	digest := sha256.Sum256([]byte("hello world"))
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&k.PublicKey, digest[:], sig) {
		t.Fatal("Wrap'd signer produced signature that does not verify")
	}
}

// ---------------------------------------------------------------------------
// parsePrivateKey via the exported ParsePrivateKey: all three PEM block types
// ---------------------------------------------------------------------------

func TestParsePrivateKey_PKCS1_RSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	got, err := signer.ParsePrivateKey(block)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if _, ok := got.(*rsa.PrivateKey); !ok {
		t.Fatalf("ParsePrivateKey returned %T, want *rsa.PrivateKey", got)
	}
}

func TestParsePrivateKey_SEC1_ECDSA(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	got, err := signer.ParsePrivateKey(block)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if _, ok := got.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("ParsePrivateKey returned %T, want *ecdsa.PrivateKey", got)
	}
}

func TestParsePrivateKey_PKCS8_RSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	got, err := signer.ParsePrivateKey(block)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if _, ok := got.(*rsa.PrivateKey); !ok {
		t.Fatalf("ParsePrivateKey returned %T, want *rsa.PrivateKey", got)
	}
}

func TestParsePrivateKey_PKCS8_ECDSA(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	got, err := signer.ParsePrivateKey(block)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if _, ok := got.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("ParsePrivateKey returned %T, want *ecdsa.PrivateKey", got)
	}
}

func TestParsePrivateKey_PKCS8_Ed25519_AcceptedByParser(t *testing.T) {
	// Ed25519 satisfies crypto.Signer, so parsePrivateKey returns it
	// successfully — Wrap is the layer that rejects it (ErrUnsupportedAlgorithm).
	// This pin confirms the separation: parsing never silently rejects a
	// valid PKCS#8 key just because Wrap won't accept it.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	got, err := signer.ParsePrivateKey(block)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if _, ok := got.(ed25519.PrivateKey); !ok {
		t.Fatalf("ParsePrivateKey returned %T, want ed25519.PrivateKey", got)
	}
}

func TestParsePrivateKey_UnsupportedBlockType(t *testing.T) {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}
	_, err := signer.ParsePrivateKey(block)
	if err == nil {
		t.Fatal("ParsePrivateKey on CERTIFICATE block should error")
	}
	if !strings.Contains(err.Error(), "unsupported private key type") {
		t.Fatalf("error should say 'unsupported private key type', got %q", err.Error())
	}
}

func TestParsePrivateKey_PKCS8_BadBytes(t *testing.T) {
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not pkcs8")}
	_, err := signer.ParsePrivateKey(block)
	if err == nil {
		t.Fatal("ParsePrivateKey on garbage PKCS#8 should error")
	}
}

// ---------------------------------------------------------------------------
// FileDriver.Load
// ---------------------------------------------------------------------------

func writePEMKey(t *testing.T, dir string, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, "key.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

func TestFileDriver_Load_Roundtrip_RSA(t *testing.T) {
	dir := t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	path := writePEMKey(t, dir, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k))

	d := &signer.FileDriver{}
	s, err := d.Load(context.Background(), path)
	if err != nil {
		t.Fatalf("FileDriver.Load: %v", err)
	}
	if s.Algorithm() != signer.AlgorithmRSA2048 {
		t.Fatalf("Algorithm = %q, want RSA-2048", s.Algorithm())
	}
}

func TestFileDriver_Load_Roundtrip_ECDSA_PKCS8(t *testing.T) {
	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	path := writePEMKey(t, dir, "PRIVATE KEY", der)

	d := &signer.FileDriver{}
	s, err := d.Load(context.Background(), path)
	if err != nil {
		t.Fatalf("FileDriver.Load: %v", err)
	}
	if s.Algorithm() != signer.AlgorithmECDSAP256 {
		t.Fatalf("Algorithm = %q, want ECDSA-P256", s.Algorithm())
	}
}

func TestFileDriver_Load_EmptyPath(t *testing.T) {
	d := &signer.FileDriver{}
	_, err := d.Load(context.Background(), "")
	if err == nil {
		t.Fatal("Load(\"\") should error")
	}
}

func TestFileDriver_Load_NonExistentPath(t *testing.T) {
	d := &signer.FileDriver{}
	_, err := d.Load(context.Background(), "/no/such/path.pem")
	if err == nil {
		t.Fatal("Load(non-existent) should error")
	}
}

func TestFileDriver_Load_NotPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	d := &signer.FileDriver{}
	_, err := d.Load(context.Background(), path)
	if err == nil {
		t.Fatal("Load(non-PEM) should error")
	}
	if !strings.Contains(err.Error(), "is not PEM") {
		t.Fatalf("error should say 'is not PEM', got %q", err.Error())
	}
}

func TestFileDriver_Load_UnsupportedKey(t *testing.T) {
	dir := t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 1024) // unsupported bit size
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	path := writePEMKey(t, dir, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k))

	d := &signer.FileDriver{}
	_, err = d.Load(context.Background(), path)
	if err == nil {
		t.Fatal("Load RSA-1024 key should error (Wrap rejects)")
	}
}

func TestFileDriver_Load_CtxCancelled(t *testing.T) {
	dir := t.TempDir()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	path := writePEMKey(t, dir, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := &signer.FileDriver{}
	_, err := d.Load(ctx, path)
	if err == nil {
		t.Fatal("Load with cancelled ctx should error")
	}
}

// ---------------------------------------------------------------------------
// FileDriver.Generate
// ---------------------------------------------------------------------------

func TestFileDriver_Generate_RequiresDirHardener(t *testing.T) {
	d := &signer.FileDriver{} // no DirHardener
	_, _, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err == nil {
		t.Fatal("Generate without DirHardener should error")
	}
	if !strings.Contains(err.Error(), "DirHardener is required") {
		t.Fatalf("error should mention DirHardener, got %q", err.Error())
	}
}

func TestFileDriver_Generate_AppliesDirHardener(t *testing.T) {
	dir := t.TempDir()
	var calledWith []string
	d := &signer.FileDriver{
		DirHardener: func(d string) error {
			calledWith = append(calledWith, d)
			return nil
		},
		GenerateOutPath: func(_ signer.Algorithm) (string, error) {
			return filepath.Join(dir, "gen.key"), nil
		},
	}
	_, path, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if path != filepath.Join(dir, "gen.key") {
		t.Fatalf("path = %q, want %q", path, filepath.Join(dir, "gen.key"))
	}
	if len(calledWith) != 1 || calledWith[0] != dir {
		t.Fatalf("DirHardener called with %v, want [%q]", calledWith, dir)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("generated key file should exist: %v", err)
	}
}

func TestFileDriver_Generate_DirHardenerErrorPropagates(t *testing.T) {
	d := &signer.FileDriver{
		DirHardener: func(_ string) error { return errors.New("simulated harden failure") },
		GenerateOutPath: func(_ signer.Algorithm) (string, error) {
			return "/tmp/should-not-be-written.key", nil
		},
	}
	_, _, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err == nil {
		t.Fatal("Generate should fail when DirHardener returns error")
	}
	if !strings.Contains(err.Error(), "simulated harden failure") {
		t.Fatalf("error should propagate harden failure, got %q", err.Error())
	}
	if _, err := os.Stat("/tmp/should-not-be-written.key"); err == nil {
		t.Fatal("file should NOT have been written when harden failed")
	}
}

func TestFileDriver_Generate_AppliesECMarshaler(t *testing.T) {
	dir := t.TempDir()
	var marshalerCalled bool
	d := &signer.FileDriver{
		DirHardener: func(string) error { return nil },
		GenerateOutPath: func(_ signer.Algorithm) (string, error) {
			return filepath.Join(dir, "gen.key"), nil
		},
		Marshaler: func(k *ecdsa.PrivateKey) ([]byte, error) {
			marshalerCalled = true
			der, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
		},
	}
	_, _, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !marshalerCalled {
		t.Fatal("Marshaler should have been called for ECDSA Generate")
	}
}

func TestFileDriver_Generate_AppliesRSAMarshaler(t *testing.T) {
	dir := t.TempDir()
	var rsaCalled bool
	d := &signer.FileDriver{
		DirHardener: func(string) error { return nil },
		GenerateOutPath: func(_ signer.Algorithm) (string, error) {
			return filepath.Join(dir, "gen.key"), nil
		},
		RSAMarshaler: func(k *rsa.PrivateKey) ([]byte, error) {
			rsaCalled = true
			return pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(k),
			}), nil
		},
	}
	_, _, err := d.Generate(context.Background(), signer.AlgorithmRSA2048)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !rsaCalled {
		t.Fatal("RSAMarshaler should have been called for RSA Generate")
	}
}

func TestFileDriver_Generate_DefaultMarshalers(t *testing.T) {
	dir := t.TempDir()
	d := &signer.FileDriver{
		DirHardener: func(string) error { return nil },
		GenerateOutPath: func(a signer.Algorithm) (string, error) {
			return filepath.Join(dir, string(a)+".key"), nil
		},
	}
	for _, alg := range []signer.Algorithm{signer.AlgorithmRSA2048, signer.AlgorithmECDSAP256} {
		s, path, err := d.Generate(context.Background(), alg)
		if err != nil {
			t.Fatalf("Generate(%s): %v", alg, err)
		}
		if s.Algorithm() != alg {
			t.Fatalf("Algorithm = %q, want %q", s.Algorithm(), alg)
		}
		// Round-trip: load via the same driver, verify bytes parse.
		loaded, err := d.Load(context.Background(), path)
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}
		if loaded.Algorithm() != alg {
			t.Fatalf("Loaded Algorithm = %q, want %q", loaded.Algorithm(), alg)
		}
	}
}

func TestFileDriver_Generate_RejectsUnknownAlgorithm(t *testing.T) {
	d := &signer.FileDriver{
		DirHardener: func(string) error { return nil },
	}
	_, _, err := d.Generate(context.Background(), signer.Algorithm("ed25519"))
	if err == nil {
		t.Fatal("Generate with unknown algorithm should error")
	}
	if !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Fatalf("error should wrap ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestFileDriver_Generate_CtxCancelled(t *testing.T) {
	d := &signer.FileDriver{
		DirHardener: func(string) error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := d.Generate(ctx, signer.AlgorithmECDSAP256)
	if err == nil {
		t.Fatal("Generate with cancelled ctx should error")
	}
}

func TestFileDriver_Generate_RSAMarshalerError(t *testing.T) {
	d := &signer.FileDriver{
		DirHardener:     func(string) error { return nil },
		GenerateOutPath: func(_ signer.Algorithm) (string, error) { return "/tmp/x", nil },
		RSAMarshaler:    func(*rsa.PrivateKey) ([]byte, error) { return nil, errors.New("boom") },
	}
	_, _, err := d.Generate(context.Background(), signer.AlgorithmRSA2048)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected RSAMarshaler error to surface, got %v", err)
	}
}

func TestFileDriver_Generate_ECMarshalerError(t *testing.T) {
	d := &signer.FileDriver{
		DirHardener:     func(string) error { return nil },
		GenerateOutPath: func(_ signer.Algorithm) (string, error) { return "/tmp/x", nil },
		Marshaler:       func(*ecdsa.PrivateKey) ([]byte, error) { return nil, errors.New("ec-boom") },
	}
	_, _, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err == nil || !strings.Contains(err.Error(), "ec-boom") {
		t.Fatalf("expected Marshaler error to surface, got %v", err)
	}
}

func TestFileDriver_Generate_OutPathError(t *testing.T) {
	d := &signer.FileDriver{
		DirHardener: func(string) error { return nil },
		GenerateOutPath: func(_ signer.Algorithm) (string, error) {
			return "", errors.New("path-resolve-failure")
		},
	}
	_, _, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err == nil || !strings.Contains(err.Error(), "path-resolve-failure") {
		t.Fatalf("expected GenerateOutPath error to surface, got %v", err)
	}
}

func TestFileDriver_Name(t *testing.T) {
	d := &signer.FileDriver{}
	if d.Name() != "file" {
		t.Fatalf("Name = %q, want \"file\"", d.Name())
	}
}

// ---------------------------------------------------------------------------
// MemoryDriver
// ---------------------------------------------------------------------------

func TestMemoryDriver_Name(t *testing.T) {
	d := signer.NewMemoryDriver()
	if d.Name() != "memory" {
		t.Fatalf("Name = %q, want \"memory\"", d.Name())
	}
}

func TestMemoryDriver_GenerateAndLoad(t *testing.T) {
	d := signer.NewMemoryDriver()
	for _, alg := range []signer.Algorithm{
		signer.AlgorithmRSA2048,
		signer.AlgorithmECDSAP256,
		signer.AlgorithmECDSAP384,
	} {
		s1, ref, err := d.Generate(context.Background(), alg)
		if err != nil {
			t.Fatalf("Generate(%s): %v", alg, err)
		}
		if s1.Algorithm() != alg {
			t.Fatalf("Generated Algorithm = %q, want %q", s1.Algorithm(), alg)
		}
		s2, err := d.Load(context.Background(), ref)
		if err != nil {
			t.Fatalf("Load(%q): %v", ref, err)
		}
		if s2.Algorithm() != alg {
			t.Fatalf("Loaded Algorithm = %q, want %q", s2.Algorithm(), alg)
		}
	}
}

func TestMemoryDriver_Generate_IndependentRefs(t *testing.T) {
	d := signer.NewMemoryDriver()
	_, ref1, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err != nil {
		t.Fatalf("Generate#1: %v", err)
	}
	_, ref2, err := d.Generate(context.Background(), signer.AlgorithmECDSAP256)
	if err != nil {
		t.Fatalf("Generate#2: %v", err)
	}
	if ref1 == ref2 {
		t.Fatalf("two Generate calls produced the same ref %q", ref1)
	}
}

func TestMemoryDriver_Load_EmptyRef(t *testing.T) {
	d := signer.NewMemoryDriver()
	_, err := d.Load(context.Background(), "")
	if err == nil {
		t.Fatal("Load(\"\") should error")
	}
}

func TestMemoryDriver_Load_UnknownRef(t *testing.T) {
	d := signer.NewMemoryDriver()
	_, err := d.Load(context.Background(), "mem-9999")
	if err == nil {
		t.Fatal("Load(unknown) should error")
	}
}

func TestMemoryDriver_Generate_CtxCancelled(t *testing.T) {
	d := signer.NewMemoryDriver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := d.Generate(ctx, signer.AlgorithmECDSAP256)
	if err == nil {
		t.Fatal("Generate with cancelled ctx should error")
	}
}

func TestMemoryDriver_Generate_RejectsUnknownAlgorithm(t *testing.T) {
	d := signer.NewMemoryDriver()
	_, _, err := d.Generate(context.Background(), signer.Algorithm("nope"))
	if err == nil {
		t.Fatal("Generate(unknown alg) should error")
	}
	if !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestMemoryDriver_Adopt(t *testing.T) {
	d := signer.NewMemoryDriver()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := d.Adopt("my-test-key", k); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	s, err := d.Load(context.Background(), "my-test-key")
	if err != nil {
		t.Fatalf("Load adopted key: %v", err)
	}
	if s.Algorithm() != signer.AlgorithmECDSAP256 {
		t.Fatalf("Algorithm = %q, want ECDSA-P256", s.Algorithm())
	}
}

func TestMemoryDriver_Adopt_RejectsEmptyRef(t *testing.T) {
	d := signer.NewMemoryDriver()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := d.Adopt("", k); err == nil {
		t.Fatal("Adopt(\"\") should error")
	}
}

func TestMemoryDriver_Adopt_RejectsNilKey(t *testing.T) {
	d := signer.NewMemoryDriver()
	if err := d.Adopt("ref", nil); err == nil {
		t.Fatal("Adopt(nil) should error")
	}
}

func TestMemoryDriver_Adopt_RejectsDuplicateRef(t *testing.T) {
	d := signer.NewMemoryDriver()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := d.Adopt("ref", k); err != nil {
		t.Fatalf("first Adopt: %v", err)
	}
	if err := d.Adopt("ref", k); err == nil {
		t.Fatal("duplicate Adopt should error")
	}
}

// ---------------------------------------------------------------------------
// Cross-driver behavior pin: Algorithm always matches the public key
// ---------------------------------------------------------------------------

func TestSigner_AlgorithmMatchesKey(t *testing.T) {
	d := signer.NewMemoryDriver()
	for _, alg := range []signer.Algorithm{
		signer.AlgorithmRSA2048,
		signer.AlgorithmECDSAP256,
		signer.AlgorithmECDSAP384,
	} {
		s, _, err := d.Generate(context.Background(), alg)
		if err != nil {
			t.Fatalf("Generate(%s): %v", alg, err)
		}
		// Re-derive Algorithm from the public key directly and confirm it matches.
		if alg == signer.AlgorithmRSA2048 {
			rk, ok := s.Public().(*rsa.PublicKey)
			if !ok || rk.N.BitLen() != 2048 {
				t.Fatalf("expected RSA-2048 public key, got %T", s.Public())
			}
		}
		if alg == signer.AlgorithmECDSAP256 {
			ek, ok := s.Public().(*ecdsa.PublicKey)
			if !ok || ek.Curve != elliptic.P256() {
				t.Fatalf("expected ECDSA-P256 public key")
			}
		}
		if alg == signer.AlgorithmECDSAP384 {
			ek, ok := s.Public().(*ecdsa.PublicKey)
			if !ok || ek.Curve != elliptic.P384() {
				t.Fatalf("expected ECDSA-P384 public key")
			}
		}
	}
}
