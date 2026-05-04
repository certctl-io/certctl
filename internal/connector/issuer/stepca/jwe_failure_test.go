package stepca

// Bundle L.B (Coverage Audit Closure) — StepCA failure-mode + JWE coverage.
//
// Pre-Bundle-L coverage on this package was 52.1%, with the following 0%
// hotspots dragging the headline number down:
//
//   - decryptProvisionerKey  0%   (~110 LoC)  — JWE PBES2-HS256+A128KW + A128GCM
//   - jwkToECDSA            0%   (~40  LoC)  — JWK -> *ecdsa.PrivateKey
//   - aesKeyUnwrap          0%   (~40  LoC)  — RFC 3394 AES Key Unwrap
//   - loadProvisionerKey    0%   (~30  LoC)  — file read + delegate to decrypt
//
// This file pins all four functions via a hermetic test-side AES Key Wrap
// implementation that constructs a valid step-ca-shaped JWE in-test, then
// asserts decryptProvisionerKey round-trips back to the original key.
// Plus the negative-path matrix (malformed JSON, unsupported alg, wrong
// password, bad base64, bad curve, etc.).
//
// Mirrors Bundle J's hermetic-via-stdlib pattern: no external JOSE library,
// no live step-ca call.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

// quietLogger returns a slog.Logger writing to io.Discard at error level.
// Avoids polluting test output during failure-mode tests.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// ---------------------------------------------------------------------------
// JWE construction helpers (test-side implementation of AES Key Wrap +
// PBES2-HS256+A128KW + A128GCM, mirroring step-ca's provisioner key format)
// ---------------------------------------------------------------------------

// aesKeyWrap is the inverse of aesKeyUnwrap (decrypt-side function in jwe.go).
// RFC 3394 AES Key Wrap. Used only by test fixtures to build a valid JWE.
func aesKeyWrap(t *testing.T, kek, plaintext []byte) []byte {
	t.Helper()
	if len(plaintext)%8 != 0 {
		t.Fatalf("aesKeyWrap: plaintext len %d not multiple of 8", len(plaintext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatalf("aesKeyWrap: NewCipher: %v", err)
	}
	n := len(plaintext) / 8

	// A = 0xA6A6A6A6A6A6A6A6
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i)
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			for k := 0; k < 8; k++ {
				a[k] = buf[k] ^ tBytes[k]
			}
			copy(r[i-1], buf[8:])
		}
	}
	out := make([]byte, 0, (n+1)*8)
	out = append(out, a...)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out
}

// buildJWE constructs a valid step-ca-shaped JWE for the given password +
// EC key. Mirrors decryptProvisionerKey's exact format expectations.
func buildJWE(t *testing.T, password string, key *ecdsa.PrivateKey, kid string) []byte {
	t.Helper()
	// 1. Build the JWK and serialize to JSON (this is the "plaintext" of the JWE)
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()
	dBytes := key.D.Bytes()
	// Pad to fixed-size for P-256 (32 bytes)
	pad := func(b []byte, size int) []byte {
		if len(b) >= size {
			return b
		}
		out := make([]byte, size)
		copy(out[size-len(b):], b)
		return out
	}
	xBytes = pad(xBytes, 32)
	yBytes = pad(yBytes, 32)
	dBytes = pad(dBytes, 32)

	jwk := jwkEC{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		D:   base64.RawURLEncoding.EncodeToString(dBytes),
		Kid: kid,
	}
	plaintext, err := json.Marshal(&jwk)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}

	// 2. Generate PBKDF2 salt + iteration count
	p2s := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, p2s); err != nil {
		t.Fatalf("salt: %v", err)
	}
	const p2c = 100000
	const alg = "PBES2-HS256+A128KW"
	const enc = "A128GCM"

	// 3. Derive KEK via PBKDF2(password, alg || 0x00 || p2s, p2c)
	algBytes := []byte(alg)
	salt := make([]byte, len(algBytes)+1+len(p2s))
	copy(salt, algBytes)
	salt[len(algBytes)] = 0x00
	copy(salt[len(algBytes)+1:], p2s)
	kek := pbkdf2.Key([]byte(password), salt, p2c, 16, sha256.New)

	// 4. Generate CEK (16 bytes for A128GCM)
	cek := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, cek); err != nil {
		t.Fatalf("cek: %v", err)
	}

	// 5. Wrap CEK with KEK (AES-128 Key Wrap)
	encryptedKey := aesKeyWrap(t, kek, cek)

	// 6. Build protected header + AAD
	header := jweHeader{
		Alg: alg,
		Enc: enc,
		Cty: "jwk+json",
		P2s: base64.RawURLEncoding.EncodeToString(p2s),
		P2c: p2c,
	}
	headerJSON, err := json.Marshal(&header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	aad := []byte(protectedB64)

	// 7. AES-GCM encrypt the JWK plaintext
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatalf("iv: %v", err)
	}
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	// sealed = ciphertext || tag
	tagOffset := len(sealed) - gcm.Overhead()
	ciphertext := sealed[:tagOffset]
	tag := sealed[tagOffset:]

	// 8. Assemble JWE JSON
	jwe := jweJSON{
		Protected:    protectedB64,
		EncryptedKey: base64.RawURLEncoding.EncodeToString(encryptedKey),
		IV:           base64.RawURLEncoding.EncodeToString(iv),
		Ciphertext:   base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:          base64.RawURLEncoding.EncodeToString(tag),
	}
	out, err := json.Marshal(&jwe)
	if err != nil {
		t.Fatalf("marshal jwe: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------------
// decryptProvisionerKey — happy path (round-trip) + negative paths
// ---------------------------------------------------------------------------

// TestDecryptProvisionerKey_RoundTrip pins the full JWE pipeline.
// Constructs a valid JWE for a known EC key + password, then decrypts and
// asserts every field of the recovered key matches the original. Hits all
// four 0%-coverage functions in one shot:
//   - decryptProvisionerKey
//   - aesKeyUnwrap
//   - jwkToECDSA
//   - (loadProvisionerKey via TestLoadProvisionerKey_RoundTrip below)
func TestDecryptProvisionerKey_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	password := "correct-horse-battery-staple"
	kid := "test-kid-12345"

	jweBlob := buildJWE(t, password, key, kid)

	got, gotKid, err := decryptProvisionerKey(jweBlob, password)
	if err != nil {
		t.Fatalf("decryptProvisionerKey: %v", err)
	}
	if gotKid != kid {
		t.Errorf("kid = %q; want %q", gotKid, kid)
	}
	if got.D.Cmp(key.D) != 0 {
		t.Errorf("private scalar D mismatch")
	}
	if got.X.Cmp(key.X) != 0 {
		t.Errorf("public X mismatch")
	}
	if got.Y.Cmp(key.Y) != 0 {
		t.Errorf("public Y mismatch")
	}
}

func TestDecryptProvisionerKey_MalformedJSON(t *testing.T) {
	_, _, err := decryptProvisionerKey([]byte(`{not json`), "anything")
	if err == nil || !strings.Contains(err.Error(), "parse JWE JSON") {
		t.Fatalf("expected JWE JSON parse error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_BadProtectedB64(t *testing.T) {
	jwe := jweJSON{
		Protected:    "!!!not-base64!!!",
		EncryptedKey: "AA",
		IV:           "AA",
		Ciphertext:   "AA",
		Tag:          "AA",
	}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "decode JWE protected header") {
		t.Fatalf("expected protected header decode error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_MalformedHeaderJSON(t *testing.T) {
	jwe := jweJSON{
		Protected: base64.RawURLEncoding.EncodeToString([]byte("{not-json")),
	}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "parse JWE header") {
		t.Fatalf("expected header parse error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_UnsupportedAlg(t *testing.T) {
	header := jweHeader{Alg: "RSA-OAEP", Enc: "A128GCM"}
	hb, _ := json.Marshal(&header)
	jwe := jweJSON{Protected: base64.RawURLEncoding.EncodeToString(hb)}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "unsupported JWE algorithm") {
		t.Fatalf("expected unsupported alg error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_UnsupportedEnc(t *testing.T) {
	header := jweHeader{Alg: "PBES2-HS256+A128KW", Enc: "A256CBC"}
	hb, _ := json.Marshal(&header)
	jwe := jweJSON{Protected: base64.RawURLEncoding.EncodeToString(hb)}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "unsupported JWE encryption") {
		t.Fatalf("expected unsupported enc error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_BadP2sB64(t *testing.T) {
	header := jweHeader{Alg: "PBES2-HS256+A128KW", Enc: "A128GCM", P2s: "!!!", P2c: 1000}
	hb, _ := json.Marshal(&header)
	jwe := jweJSON{Protected: base64.RawURLEncoding.EncodeToString(hb)}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "decode PBKDF2 salt") {
		t.Fatalf("expected p2s decode error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_BadEncryptedKeyB64(t *testing.T) {
	header := jweHeader{Alg: "PBES2-HS256+A128KW", Enc: "A128GCM", P2s: "AAAA", P2c: 1000}
	hb, _ := json.Marshal(&header)
	jwe := jweJSON{
		Protected:    base64.RawURLEncoding.EncodeToString(hb),
		EncryptedKey: "!!!",
	}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "decode encrypted key") {
		t.Fatalf("expected encrypted key decode error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_BadIVB64(t *testing.T) {
	header := jweHeader{Alg: "PBES2-HS256+A128KW", Enc: "A128GCM", P2s: "AAAA", P2c: 1000}
	hb, _ := json.Marshal(&header)
	jwe := jweJSON{
		Protected:    base64.RawURLEncoding.EncodeToString(hb),
		EncryptedKey: "AAAA",
		IV:           "!!!",
	}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "decode IV") {
		t.Fatalf("expected IV decode error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_BadCiphertextB64(t *testing.T) {
	header := jweHeader{Alg: "PBES2-HS256+A128KW", Enc: "A128GCM", P2s: "AAAA", P2c: 1000}
	hb, _ := json.Marshal(&header)
	jwe := jweJSON{
		Protected:    base64.RawURLEncoding.EncodeToString(hb),
		EncryptedKey: "AAAA",
		IV:           "AAAA",
		Ciphertext:   "!!!",
	}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "decode ciphertext") {
		t.Fatalf("expected ciphertext decode error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_BadTagB64(t *testing.T) {
	header := jweHeader{Alg: "PBES2-HS256+A128KW", Enc: "A128GCM", P2s: "AAAA", P2c: 1000}
	hb, _ := json.Marshal(&header)
	jwe := jweJSON{
		Protected:    base64.RawURLEncoding.EncodeToString(hb),
		EncryptedKey: "AAAA",
		IV:           "AAAA",
		Ciphertext:   "AAAA",
		Tag:          "!!!",
	}
	body, _ := json.Marshal(&jwe)
	_, _, err := decryptProvisionerKey(body, "anything")
	if err == nil || !strings.Contains(err.Error(), "decode tag") {
		t.Fatalf("expected tag decode error, got: %v", err)
	}
}

func TestDecryptProvisionerKey_WrongPassword(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	jweBlob := buildJWE(t, "right-password", key, "kid")

	_, _, err = decryptProvisionerKey(jweBlob, "wrong-password")
	if err == nil {
		t.Fatal("expected error on wrong password")
	}
	// Wrong password causes integrity check failure during AES Key Unwrap.
	if !strings.Contains(err.Error(), "AES key unwrap failed") &&
		!strings.Contains(err.Error(), "GCM decryption failed") {
		t.Errorf("error %q should mention AES key unwrap or GCM failure", err)
	}
}

// ---------------------------------------------------------------------------
// aesKeyUnwrap — negative paths
// ---------------------------------------------------------------------------

func TestAESKeyUnwrap_TooShort(t *testing.T) {
	_, err := aesKeyUnwrap(make([]byte, 16), make([]byte, 16))
	if err == nil || !strings.Contains(err.Error(), "invalid ciphertext length") {
		t.Fatalf("expected length error, got: %v", err)
	}
}

func TestAESKeyUnwrap_NotMultipleOf8(t *testing.T) {
	_, err := aesKeyUnwrap(make([]byte, 16), make([]byte, 25))
	if err == nil || !strings.Contains(err.Error(), "invalid ciphertext length") {
		t.Fatalf("expected length error, got: %v", err)
	}
}

func TestAESKeyUnwrap_BadKEKSize(t *testing.T) {
	// AES requires 16/24/32-byte keys. 17 bytes = invalid.
	_, err := aesKeyUnwrap(make([]byte, 17), make([]byte, 24))
	if err == nil || !strings.Contains(err.Error(), "AES cipher") {
		t.Fatalf("expected AES cipher error, got: %v", err)
	}
}

func TestAESKeyUnwrap_BadIntegrityCheck(t *testing.T) {
	// Provide all-zero ciphertext; the unwrapped IV will not be 0xA6...A6.
	_, err := aesKeyUnwrap(make([]byte, 16), make([]byte, 24))
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("expected integrity check error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// jwkToECDSA — negative paths
// ---------------------------------------------------------------------------

func TestJwkToECDSA_UnsupportedCurve(t *testing.T) {
	jwk := &jwkEC{Crv: "secp192r1"}
	_, err := jwkToECDSA(jwk)
	if err == nil || !strings.Contains(err.Error(), "unsupported curve") {
		t.Fatalf("expected unsupported curve error, got: %v", err)
	}
}

func TestJwkToECDSA_BadXB64(t *testing.T) {
	jwk := &jwkEC{Crv: "P-256", X: "!!!", Y: "AA", D: "AA"}
	_, err := jwkToECDSA(jwk)
	if err == nil || !strings.Contains(err.Error(), "decode JWK x") {
		t.Fatalf("expected x decode error, got: %v", err)
	}
}

func TestJwkToECDSA_BadYB64(t *testing.T) {
	jwk := &jwkEC{Crv: "P-384", X: "AA", Y: "!!!", D: "AA"}
	_, err := jwkToECDSA(jwk)
	if err == nil || !strings.Contains(err.Error(), "decode JWK y") {
		t.Fatalf("expected y decode error, got: %v", err)
	}
}

func TestJwkToECDSA_BadDB64(t *testing.T) {
	jwk := &jwkEC{Crv: "P-521", X: "AA", Y: "AA", D: "!!!"}
	_, err := jwkToECDSA(jwk)
	if err == nil || !strings.Contains(err.Error(), "decode JWK d") {
		t.Fatalf("expected d decode error, got: %v", err)
	}
}

func TestJwkToECDSA_AllSupportedCurves(t *testing.T) {
	for _, crv := range []string{"P-256", "P-384", "P-521"} {
		jwk := &jwkEC{Crv: crv, X: "AA", Y: "AA", D: "AA"}
		key, err := jwkToECDSA(jwk)
		if err != nil {
			t.Errorf("crv=%s: %v", crv, err)
			continue
		}
		if key == nil {
			t.Errorf("crv=%s: returned nil key", crv)
		}
	}
}

// ---------------------------------------------------------------------------
// loadProvisionerKey — happy + missing-file
// ---------------------------------------------------------------------------

func TestLoadProvisionerKey_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	password := "test-password"
	kid := "stepca-test-kid"
	jweBlob := buildJWE(t, password, key, kid)

	dir := t.TempDir()
	path := filepath.Join(dir, "provisioner.json")
	if err := os.WriteFile(path, jweBlob, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	c := &Connector{
		config: &Config{
			ProvisionerKeyPath:  path,
			ProvisionerPassword: password,
		},
		logger: quietLogger(),
	}
	gotKey, gotKid, err := c.loadProvisionerKey()
	if err != nil {
		t.Fatalf("loadProvisionerKey: %v", err)
	}
	if gotKid != kid {
		t.Errorf("kid = %q; want %q", gotKid, kid)
	}
	if gotKey.D.Cmp(key.D) == 0 == false {
		t.Errorf("private scalar mismatch")
	}
}

func TestLoadProvisionerKey_FileNotFound(t *testing.T) {
	c := &Connector{
		config: &Config{
			ProvisionerKeyPath:  "/nonexistent/path/provisioner.json",
			ProvisionerPassword: "x",
		},
		logger: quietLogger(),
	}
	_, _, err := c.loadProvisionerKey()
	if err == nil {
		t.Fatal("expected file-not-found error")
	}
}

// ---------------------------------------------------------------------------
// IssueCertificate / RevokeCertificate failure modes via httptest.Server
// ---------------------------------------------------------------------------

// preWiredStepCAConnector returns a step-ca connector with the given URL,
// using an ephemeral provisioner key so IssueCertificate / RevokeCertificate
// can produce a valid token without needing a real key file.
func preWiredStepCAConnector(t *testing.T, url string) *Connector {
	t.Helper()
	return New(&Config{
		CAURL:           url,
		ProvisionerName: "test-provisioner",
		// ProvisionerKeyPath intentionally empty -> ephemeral key
	}, quietLogger())
}

// minimalCSRPEM returns a syntactically valid CSR PEM. Used as test input
// for IssueCertificate failure modes that should NOT depend on CSR
// validation (we want the failure to come from the upstream HTTP response,
// not from CSR parsing).
const minimalCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIH4MIGgAgEAMBoxGDAWBgNVBAMMD3Rlc3QuZXhhbXBsZS5jb20wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAATctzj78qjxwoTYDjBzZ7iC1cnaSPjEr/m3rT4xPCA0
QqL5bfjRoIN6sH9HX8AKqL7cNWxbdQepZx7TAR1eb6DjoCgwJgYJKoZIhvcNAQkO
MRkwFzAVBgNVHREEDjAMggp0LmV4YW1wbGUwCgYIKoZIzj0EAwIDSAAwRQIhAOMW
KcW6Z3MzKQT7YCePO1l9oZSDqXqJYJV6BEmjcpAJAiBNqcPDt0qRR1aUH9qFZQzP
GuQvbz9HKkPxmXcnkBOjIw==
-----END CERTIFICATE REQUEST-----`

func TestIssueCertificate_NetworkError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close()

	c := preWiredStepCAConnector(t, url)
	_, err := c.IssueCertificate(t.Context(), issuer.IssuanceRequest{
		CommonName: "test",
		CSRPEM:     minimalCSRPEM,
	})
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "sign request failed") {
		t.Errorf("error %q should mention 'sign request failed'", err)
	}
}

func TestIssueCertificate_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"upstream boom"}`)
	}))
	defer ts.Close()

	c := preWiredStepCAConnector(t, ts.URL)
	_, err := c.IssueCertificate(t.Context(), issuer.IssuanceRequest{
		CommonName: "test",
		CSRPEM:     minimalCSRPEM,
	})
	if err == nil {
		t.Fatal("expected error on 5xx")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error %q should mention 'status 500'", err)
	}
}

func TestIssueCertificate_401Unauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid token"}`)
	}))
	defer ts.Close()

	c := preWiredStepCAConnector(t, ts.URL)
	_, err := c.IssueCertificate(t.Context(), issuer.IssuanceRequest{
		CommonName: "test",
		CSRPEM:     minimalCSRPEM,
	})
	if err == nil {
		t.Fatal("expected 401 to error")
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Errorf("error %q should mention 'status 401'", err)
	}
}

func TestIssueCertificate_403Forbidden(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	c := preWiredStepCAConnector(t, ts.URL)
	_, err := c.IssueCertificate(t.Context(), issuer.IssuanceRequest{
		CommonName: "test",
		CSRPEM:     minimalCSRPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected 403 error, got: %v", err)
	}
}

func TestRevokeCertificate_NetworkError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close()

	c := preWiredStepCAConnector(t, url)
	err := c.RevokeCertificate(t.Context(), issuer.RevocationRequest{
		Serial: "ABCD1234",
	})
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "revoke request failed") {
		t.Errorf("error %q should mention 'revoke request failed'", err)
	}
}

func TestRevokeCertificate_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
	}))
	defer ts.Close()

	c := preWiredStepCAConnector(t, ts.URL)
	err := c.RevokeCertificate(t.Context(), issuer.RevocationRequest{
		Serial: "ABCD",
	})
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestRevokeCertificate_403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	c := preWiredStepCAConnector(t, ts.URL)
	err := c.RevokeCertificate(t.Context(), issuer.RevocationRequest{Serial: "ABCD"})
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected 403 error, got: %v", err)
	}
}
