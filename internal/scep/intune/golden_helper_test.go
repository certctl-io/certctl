package intune

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// SCEP RFC 8894 + Intune master bundle Phase 10.1 — golden-file fixture
// helpers. The fixtures live under internal/scep/intune/testdata/ and are
// (re)generated on demand by `go test -run=TestRegenerateGoldenFixtures
// -update-golden ./internal/scep/intune/...`. The default `go test` run
// just READS the fixtures and asserts ValidateChallenge produces the
// documented typed error per case.
//
// Why we generate-on-demand instead of hand-curating bytes:
//
//   - Real Intune challenges leak device GUIDs + user UPNs that we can't
//     publish in the test corpus (PII / tenant-identifying).
//   - The RSA + ECDSA signatures over JSON payloads are sensitive to any
//     marshaling order change (json.Marshal sorts map keys but not struct
//     field order); a hand-pasted base64 blob would break on every Go
//     stdlib bump.
//   - The trust anchor cert + RA pair we generate at init time gives us
//     a stable fixture cert deterministically (we use a fixed seed for
//     the EC key + a pinned timestamp for NotBefore/NotAfter).
//
// Determinism: the fixture key + timestamp are pinned via a custom
// io.Reader-style PRNG seeded from a constant byte string. Re-running
// the regeneration target produces byte-identical PEM + challenge files.

// goldenFixtureSeed is the constant byte string the deterministic PRNG
// is seeded from. Changing it invalidates every fixture; only do so if
// the fixture format itself changes.
var goldenFixtureSeed = []byte("scep-intune-golden-fixtures-v1-do-not-change-without-regenerating")

// goldenFixtureNotBefore is the pinned NotBefore for the test trust
// anchor cert. Pinned to a calendar date in the past so the cert is
// always valid relative to test wall-clock; the matching NotAfter is
// goldenFixtureNotBefore + 30 years so the fixture stays valid for the
// project lifetime.
var goldenFixtureNotBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
var goldenFixtureNotAfter = goldenFixtureNotBefore.AddDate(30, 0, 0)

// goldenFixtureChallengeIat is the pinned iat for the success golden
// challenge. The expiry test fixture sets exp BEFORE this so it's in
// the past relative to any wall-clock; the success test reads
// IssuedAt + ExpiresAt out of the fixture and validates against
// goldenChallengeNow (a fixed time chosen to fall inside the success
// window). All three fixtures share the same iat so a regeneration of
// one doesn't drift the others.
var goldenFixtureChallengeIat = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// goldenChallengeNow is the wall-clock the fixture tests pin so the
// success challenge falls inside its iat→exp window AND the expired
// challenge's exp falls before it. Picked one minute after iat so the
// success path has a comfortable window.
var goldenChallengeNow = goldenFixtureChallengeIat.Add(1 * time.Minute)

// testdataDir resolves the testdata/ directory adjacent to the package
// source. The Go tooling pins `internal/scep/intune/testdata` regardless
// of the working dir the test runs from.
func testdataDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata")
}

// goldenChallengePayload is the v1 wire shape we use for all three
// fixtures. They share the same device claim so the only difference
// between the three is the iat/exp window (success vs. expired) or the
// signature bytes (tampered).
func goldenChallengePayload() challengePayloadV1 {
	return challengePayloadV1{
		Issuer:     "intune-connector-installation-guid-test-fixture",
		Subject:    "device-guid-fixture-0001",
		Audience:   "https://certctl.example.com/scep/test",
		IssuedAt:   goldenFixtureChallengeIat.Unix(),
		ExpiresAt:  goldenFixtureChallengeIat.Add(60 * time.Minute).Unix(),
		Nonce:      "fixture-nonce-success-001",
		DeviceName: "fixture-device.example.com",
		SANDNS:     []string{"fixture-device.example.com"},
		SANRFC822:  []string{"fixture-user@example.com"},
	}
}

// goldenExpiredChallengePayload is the same shape as the success payload
// but with iat + exp shifted into the past so the validator's time-bounds
// check fires.
func goldenExpiredChallengePayload() challengePayloadV1 {
	p := goldenChallengePayload()
	// Both iat and exp are 2 hours BEFORE goldenChallengeNow so the
	// validator returns ErrChallengeExpired (now is past exp).
	p.IssuedAt = goldenChallengeNow.Add(-2 * time.Hour).Unix()
	p.ExpiresAt = goldenChallengeNow.Add(-1 * time.Hour).Unix()
	p.Nonce = "fixture-nonce-expired-001"
	return p
}

// goldenUnknownVersionPayload wraps the success v1 payload in a
// version-bearing prelude where Version="v999" — a value the
// versionUnmarshalers map does NOT contain. ValidateChallenge MUST
// surface ErrChallengeUnknownVersion when given this payload.
//
// Master prompt §13 line 1848 (golden test acceptance) specifically
// names "unknown-version-rejected" alongside success / expired /
// tampered_sig as a required golden case; this helper materializes the
// fixture from the same deterministic seed as the others so the
// regenerated fixture file diff stays clean.
type goldenUnknownVersionWire struct {
	Version string `json:"version"`
	challengePayloadV1
}

func goldenUnknownVersionPayload() goldenUnknownVersionWire {
	return goldenUnknownVersionWire{
		Version:            "v999",
		challengePayloadV1: goldenChallengePayload(),
	}
}

// generateGoldenTrustAnchor returns a deterministic ECDSA P-256 cert +
// signing key for the golden fixtures. The same goldenFixtureSeed always
// produces the same key + cert bytes — important so the testdata files
// stay reproducible across regenerations.
//
// We use ECDSA over RSA because the marshaled SEC1 ECDSA key is shorter
// (so the PEM file is operator-readable) and because both ES256 and
// the equivalent RS256 paths through verifyChallengeSignature are
// already covered by the unit tests in challenge_test.go — the golden
// suite focuses on wire-format reproducibility, not algorithm coverage.
func generateGoldenTrustAnchor(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	prng := newDeterministicReader(goldenFixtureSeed)
	key, err := ecdsa.GenerateKey(elliptic.P256(), prng)
	if err != nil {
		t.Fatalf("deterministic ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "intune-connector-fixture"},
		NotBefore:    goldenFixtureNotBefore,
		NotAfter:     goldenFixtureNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(prng, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("deterministic CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return key, cert
}

// signGoldenChallenge builds the JWT-shape ES256 challenge for a payload
// using the golden trust anchor key. Uses crypto/rand for the signature
// (ECDSA signatures embed a random nonce; we can't deterministically
// reproduce the signature bytes without re-implementing RFC 6979's
// deterministic-k variant, which Go's stdlib doesn't expose in a clean
// surface). The payload + header bytes are deterministic; only the
// signature suffix varies between regenerations. ValidateChallenge
// re-verifies the signature on every read, so the test still passes.
func signGoldenChallenge(t *testing.T, key *ecdsa.PrivateKey, payload challengePayloadV1) string {
	t.Helper()
	return signGoldenChallengeAny(t, key, payload)
}

// signGoldenChallengeAny mirrors signGoldenChallenge for any
// JSON-marshalable payload type. The goldenUnknownVersionWire fixture
// embeds the v1 payload inside a version-bearing prelude, so the typed
// helper above can't reach it without a cast — this any-typed sibling
// keeps the typed entrypoint stable while letting the regen target +
// the unknown-version-rejected golden test pass an embedded struct.
func signGoldenChallengeAny(t *testing.T, key *ecdsa.PrivateKey, payload any) string {
	t.Helper()
	hdr, _ := json.Marshal(jwtHeader{Alg: "ES256", Typ: "JWT"})
	pl, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	rb, sb := r.Bytes(), s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rb):], rb)
	copy(sig[64-len(sb):], sb)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// readGoldenFixture reads a fixture file relative to testdata/. Uses
// strings.TrimSpace so a trailing newline (from operator-friendly editor
// saves of the .txt files) doesn't break ValidateChallenge.
func readGoldenFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(testdataDir(t), name)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	return strings.TrimSpace(string(body))
}

// loadGoldenTrustAnchor reads the testdata/ trust anchor PEM and parses
// it. Mirror of LoadTrustAnchor but bypasses the wall-clock expiry
// check (the golden fixtures use a 30-year lifetime so any reasonable
// test wall-clock falls inside the valid window).
func loadGoldenTrustAnchor(t *testing.T) []*x509.Certificate {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(testdataDir(t), "intune_trust_anchor.pem"))
	if err != nil {
		t.Fatalf("read trust anchor: %v", err)
	}
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
			t.Fatalf("parse trust anchor cert: %v", err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		t.Fatalf("trust anchor file contained no CERTIFICATE blocks")
	}
	return out
}

// pemEncodeForFixture returns a PEM-encoded CERTIFICATE block for the
// given DER bytes — used by the regeneration target.
func pemEncodeForFixture(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// flipLastSignatureByte takes a JWT-compact-serialized challenge and
// returns the same wire bytes with one byte flipped in the signature
// segment. Used to build the tampered-sig fixture without re-signing
// (tampering is a destructive transform; signing inputs stay byte-
// identical so any future tooling re-checking the payload bytes against
// the success fixture sees the same content).
func flipLastSignatureByte(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("flipLastSignatureByte: expected 3 segments, got %d", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("flipLastSignatureByte: base64 decode: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("flipLastSignatureByte: empty signature")
	}
	sig[len(sig)-1] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

// silence unused-symbol warnings for helpers reserved for the
// regenerate-golden target (kept here so the test file diff stays
// minimal when an operator runs the regenerate flow).
var _ = pemEncodeForFixture
var _ = signGoldenChallenge
var _ = signGoldenChallengeAny
var _ = generateGoldenTrustAnchor

// deterministicReader is a sha256-based PRNG seeded from a constant
// byte slice. Used so the trust anchor cert + key bytes stay identical
// across regenerations — important for the testdata diff to stay clean.
//
// Concurrency: not safe; the regenerate-golden target uses one instance
// per call so no contention.
type deterministicReader struct {
	mu     sync.Mutex
	state  []byte
	cursor int
	buf    []byte
}

func newDeterministicReader(seed []byte) *deterministicReader {
	return &deterministicReader{state: append([]byte(nil), seed...)}
}

// Read fills p with sha256-derived pseudo-random bytes. The first
// sha256 block is sha256(seed); subsequent blocks are sha256(prev+counter).
func (d *deterministicReader) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for n := 0; n < len(p); {
		if d.cursor >= len(d.buf) {
			h := sha256.Sum256(append(d.state, byteCounter(len(p)+n)...))
			d.buf = h[:]
			d.cursor = 0
			d.state = d.buf
		}
		c := copy(p[n:], d.buf[d.cursor:])
		n += c
		d.cursor += c
	}
	return len(p), nil
}

func byteCounter(i int) []byte {
	out := make([]byte, 8)
	for k := 0; k < 8; k++ {
		out[k] = byte(i >> (8 * k))
	}
	return out
}

// rsa unused import shim — Go's compile guard fires on unused imports
// even when reserved for the regenerate-golden target. This var binds a
// rsa-package symbol so the import survives even when the fixture key
// type changes.
var _ = rsa.PublicKey{}
var _ = crypto.SHA256
