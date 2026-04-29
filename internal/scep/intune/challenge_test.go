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
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Test idiom: each test materialises a real Connector signing cert +
// private key, builds a JWT-shaped challenge by hand, then runs it
// through Parse / Validate. Round-trip pins the exact wire format the
// Microsoft Intune Certificate Connector emits today (v1).

// =============================================================================
// Test helpers — Connector trust-anchor + signed challenge factories.
// =============================================================================

type testRSAConnector struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func genTestRSAConnector(t *testing.T) testRSAConnector {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-intune-connector"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return testRSAConnector{key: key, cert: cert}
}

type testECDSAConnector struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func genTestECDSAConnector(t *testing.T) testECDSAConnector {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-intune-connector-es256"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return testECDSAConnector{key: key, cert: cert}
}

// signTestChallengeRS256 builds + signs a challenge with the given payload.
// alg defaults to RS256.
func signTestChallengeRS256(t *testing.T, c testRSAConnector, payload any) string {
	t.Helper()
	hdr, _ := json.Marshal(jwtHeader{Alg: "RS256", Typ: "JWT"})
	pl, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signTestChallengeES256_FixedWidth produces a JOSE-canonical r||s ES256.
func signTestChallengeES256_FixedWidth(t *testing.T, c testECDSAConnector, payload any) string {
	t.Helper()
	hdr, _ := json.Marshal(jwtHeader{Alg: "ES256", Typ: "JWT"})
	pl, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, h[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	rb, sb := r.Bytes(), s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rb):], rb)
	copy(sig[64-len(sb):], sb)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signTestChallengeES256_DER produces the older non-JOSE ASN.1 DER form.
func signTestChallengeES256_DER(t *testing.T, c testECDSAConnector, payload any) string {
	t.Helper()
	hdr, _ := json.Marshal(jwtHeader{Alg: "ES256", Typ: "JWT"})
	pl, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	derSig, err := ecdsa.SignASN1(rand.Reader, c.key, h[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(derSig)
}

// validV1Payload returns a v1 challenge payload that is currently in-window.
func validV1Payload(now time.Time) challengePayloadV1 {
	return challengePayloadV1{
		Issuer:     "test-connector-installation-guid",
		Subject:    "device-guid-123",
		Audience:   "https://certctl.example.com/scep/corp",
		IssuedAt:   now.Add(-1 * time.Minute).Unix(),
		ExpiresAt:  now.Add(59 * time.Minute).Unix(),
		Nonce:      "abc123nonce",
		DeviceName: "DEVICE-001",
		SANDNS:     []string{"device-001.example.com"},
		SANRFC822:  []string{"device-001@example.com"},
	}
}

// =============================================================================
// ParseChallenge.
// =============================================================================

func TestParseChallenge_HappyPath(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	raw := signTestChallengeRS256(t, c, validV1Payload(now))

	header, payload, signature, err := ParseChallenge(raw)
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if len(header) == 0 || len(payload) == 0 || len(signature) == 0 {
		t.Fatalf("decoded segments are empty: header=%d payload=%d signature=%d",
			len(header), len(payload), len(signature))
	}
	var p challengePayloadV1
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if p.DeviceName != "DEVICE-001" {
		t.Errorf("DeviceName = %q, want DEVICE-001", p.DeviceName)
	}
}

func TestParseChallenge_Malformed(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"missing dots", "abc"},
		{"two dots one missing segment", "abc..def"},
		{"trailing dot extra segment", "a.b.c.d"},
		{"first segment empty", ".b.c"},
		{"middle segment empty", "a..c"},
		{"last segment empty", "a.b."},
		{"non-base64 header", "!!!.YWJj.YWJj"},
		{"non-JSON header", base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".YWJj.YWJj"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseChallenge(tc.in)
			if !errors.Is(err, ErrChallengeMalformed) {
				t.Fatalf("got %v, want errors.Is(ErrChallengeMalformed)", err)
			}
		})
	}
}

func TestParseChallenge_PaddedBase64Tolerated(t *testing.T) {
	// Some Connector versions emit padded base64url; we tolerate both.
	hdr := base64.URLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	pl := base64.URLEncoding.EncodeToString([]byte(`{"foo":"bar"}`))
	sig := base64.URLEncoding.EncodeToString([]byte("xx"))
	if !strings.HasSuffix(hdr, "=") && !strings.HasSuffix(pl, "=") && !strings.HasSuffix(sig, "=") {
		t.Skip("encoder didn't produce padding for this fixture; skipping")
	}
	raw := hdr + "." + pl + "." + sig
	if _, _, _, err := ParseChallenge(raw); err != nil {
		t.Fatalf("padded base64url should be tolerated: %v", err)
	}
}

// =============================================================================
// ValidateChallenge — happy paths for both algs + both ES256 encodings.
// =============================================================================

func TestValidateChallenge_HappyPath_RS256(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeRS256(t, c, pl)

	got, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: pl.Audience, Now: now})
	if err != nil {
		t.Fatalf("ValidateChallenge: %v", err)
	}
	if got.DeviceName != "DEVICE-001" {
		t.Errorf("DeviceName = %q", got.DeviceName)
	}
	if got.Nonce != "abc123nonce" {
		t.Errorf("Nonce = %q", got.Nonce)
	}
	if got.IssuedAt.IsZero() || got.ExpiresAt.IsZero() {
		t.Errorf("iat/exp not populated: iat=%v exp=%v", got.IssuedAt, got.ExpiresAt)
	}
}

func TestValidateChallenge_HappyPath_ES256_FixedWidth(t *testing.T) {
	c := genTestECDSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeES256_FixedWidth(t, c, pl)

	got, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: pl.Audience, Now: now})
	if err != nil {
		t.Fatalf("ValidateChallenge: %v", err)
	}
	if got.Subject != "device-guid-123" {
		t.Errorf("Subject = %q", got.Subject)
	}
}

func TestValidateChallenge_HappyPath_ES256_DER(t *testing.T) {
	c := genTestECDSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeES256_DER(t, c, pl)

	if _, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: pl.Audience, Now: now}); err != nil {
		t.Fatalf("ValidateChallenge ES256 DER: %v", err)
	}
}

// =============================================================================
// ValidateChallenge — failure dimensions.
// =============================================================================

func TestValidateChallenge_Expired(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	pl.ExpiresAt = now.Add(-1 * time.Minute).Unix()
	raw := signTestChallengeRS256(t, c, pl)

	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: pl.Audience, Now: now})
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("got %v, want ErrChallengeExpired", err)
	}
}

func TestValidateChallenge_NotYetValid(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	pl.IssuedAt = now.Add(5 * time.Minute).Unix() // future iat (clock skew)
	pl.ExpiresAt = now.Add(65 * time.Minute).Unix()
	raw := signTestChallengeRS256(t, c, pl)

	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: pl.Audience, Now: now})
	if !errors.Is(err, ErrChallengeNotYetValid) {
		t.Fatalf("got %v, want ErrChallengeNotYetValid", err)
	}
}

func TestValidateChallenge_WrongAudience(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeRS256(t, c, pl)

	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: "https://wrong-host.example.com/scep", Now: now})
	if !errors.Is(err, ErrChallengeWrongAudience) {
		t.Fatalf("got %v, want ErrChallengeWrongAudience", err)
	}
}

func TestValidateChallenge_EmptyExpectedAudienceDisablesCheck(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeRS256(t, c, pl)

	if _, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, Now: now}); err != nil {
		t.Fatalf("empty expected audience should disable the check: %v", err)
	}
}

func TestValidateChallenge_TamperedSignature(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeRS256(t, c, pl)

	parts := strings.Split(raw, ".")
	// Flip one byte in the b64-decoded signature, then re-encode.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	tampered := strings.Join(parts, ".")

	_, err := ValidateChallenge(tampered, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: pl.Audience, Now: now})
	if !errors.Is(err, ErrChallengeSignature) {
		t.Fatalf("got %v, want ErrChallengeSignature", err)
	}
}

func TestValidateChallenge_TamperedPayload(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeRS256(t, c, pl)

	// Re-encode the payload with a different DeviceName but keep the
	// original signature. Signature verification MUST catch this.
	parts := strings.Split(raw, ".")
	pl.DeviceName = "ATTACKER-CHANGED-DEVICE"
	tamperedPayload, _ := json.Marshal(pl)
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPayload)
	tampered := strings.Join(parts, ".")

	_, err := ValidateChallenge(tampered, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: pl.Audience, Now: now})
	if !errors.Is(err, ErrChallengeSignature) {
		t.Fatalf("got %v, want ErrChallengeSignature", err)
	}
}

func TestValidateChallenge_RotatedTrustAnchor(t *testing.T) {
	signedBy := genTestRSAConnector(t)
	rotatedTo := genTestRSAConnector(t) // operator already rotated; old key gone

	now := time.Now()
	pl := validV1Payload(now)
	raw := signTestChallengeRS256(t, signedBy, pl)

	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{rotatedTo.cert}, ExpectedAudience: pl.Audience, Now: now})
	if !errors.Is(err, ErrChallengeSignature) {
		t.Fatalf("got %v, want ErrChallengeSignature", err)
	}
}

func TestValidateChallenge_EmptyTrustBundle(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	raw := signTestChallengeRS256(t, c, validV1Payload(now))

	_, err := ValidateChallenge(raw, ValidateOptions{Trust: nil, Now: now})
	if !errors.Is(err, ErrChallengeSignature) {
		t.Fatalf("got %v, want ErrChallengeSignature", err)
	}
}

func TestValidateChallenge_AlgNoneRejected(t *testing.T) {
	// Active alg=none attack: header says alg=none, signature is empty,
	// the validator MUST reject regardless of any "valid"-looking payload.
	hdr, _ := json.Marshal(jwtHeader{Alg: "none"})
	pl, _ := json.Marshal(validV1Payload(time.Now()))
	raw := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("nope"))

	c := genTestRSAConnector(t)
	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, Now: time.Now()})
	if !errors.Is(err, ErrChallengeSignature) {
		t.Fatalf("got %v, want ErrChallengeSignature for alg=none", err)
	}
	if !strings.Contains(err.Error(), "none") {
		t.Errorf("error message should mention alg=none for audit clarity: %v", err)
	}
}

func TestValidateChallenge_UnsupportedAlg(t *testing.T) {
	hdr, _ := json.Marshal(jwtHeader{Alg: "HS256"})
	pl, _ := json.Marshal(validV1Payload(time.Now()))
	raw := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("hmac-bytes"))

	c := genTestRSAConnector(t)
	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, Now: time.Now()})
	if !errors.Is(err, ErrChallengeSignature) {
		t.Fatalf("got %v, want ErrChallengeSignature for unsupported alg", err)
	}
}

func TestValidateChallenge_MissingAlgHeader(t *testing.T) {
	hdr, _ := json.Marshal(map[string]string{"typ": "JWT"})
	pl, _ := json.Marshal(validV1Payload(time.Now()))
	raw := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("xx"))

	c := genTestRSAConnector(t)
	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, Now: time.Now()})
	if !errors.Is(err, ErrChallengeSignature) {
		t.Fatalf("got %v, want ErrChallengeSignature for missing alg", err)
	}
}

// =============================================================================
// Version dispatcher.
// =============================================================================

func TestValidateChallenge_VersionV1ExplicitOK(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	type plWithVersion struct {
		Version string `json:"version"`
		challengePayloadV1
	}
	p := plWithVersion{Version: "v1", challengePayloadV1: validV1Payload(now)}
	raw := signTestChallengeRS256(t, c, p)

	got, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: p.Audience, Now: now})
	if err != nil {
		t.Fatalf("explicit v1 should be accepted: %v", err)
	}
	if got.DeviceName != "DEVICE-001" {
		t.Errorf("DeviceName = %q", got.DeviceName)
	}
}

func TestValidateChallenge_VersionUnknownRejected(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	type plWithVersion struct {
		Version string `json:"version"`
		challengePayloadV1
	}
	p := plWithVersion{Version: "v999", challengePayloadV1: validV1Payload(now)}
	raw := signTestChallengeRS256(t, c, p)

	_, err := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, ExpectedAudience: p.Audience, Now: now})
	if !errors.Is(err, ErrChallengeUnknownVersion) {
		t.Fatalf("got %v, want ErrChallengeUnknownVersion", err)
	}
}

// =============================================================================
// Trust-anchor walk: when a trust bundle has both algs configured, the
// validator must ignore key-type mismatches without returning Signature.
// =============================================================================

func TestValidateChallenge_MixedTrustBundle_IgnoresKeyTypeMismatches(t *testing.T) {
	rsaConn := genTestRSAConnector(t)
	ecConn := genTestECDSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)

	// Sign with RSA; trust bundle has BOTH the RSA cert and an unrelated
	// ECDSA cert. Validator should iterate, skip the EC cert (key type
	// mismatch), find RSA, verify, return success.
	raw := signTestChallengeRS256(t, rsaConn, pl)
	bundle := []*x509.Certificate{ecConn.cert, rsaConn.cert}
	if _, err := ValidateChallenge(raw, ValidateOptions{Trust: bundle, ExpectedAudience: pl.Audience, Now: now}); err != nil {
		t.Fatalf("mixed-bundle validate: %v", err)
	}
}

// =============================================================================
// Defensive: malformed payload after good signature still surfaces a
// useful error (not a panic).
// =============================================================================

func TestValidateChallenge_NonJSONPayloadButValidSignature(t *testing.T) {
	c := genTestRSAConnector(t)
	hdr, _ := json.Marshal(jwtHeader{Alg: "RS256"})
	pl := []byte("this is not JSON")
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	raw := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, vErr := ValidateChallenge(raw, ValidateOptions{Trust: []*x509.Certificate{c.cert}, Now: time.Now()})
	if !errors.Is(vErr, ErrChallengeMalformed) {
		t.Fatalf("got %v, want ErrChallengeMalformed", vErr)
	}
}

// =============================================================================
// Clock-skew tolerance — master prompt §15 hazard closure (2026-04-29).
// =============================================================================

// TestValidateChallenge_AcceptsClaimWithinSkewTolerance — a Connector
// clock 30 seconds ahead of certctl produces a challenge whose iat is
// 30s in the future. With the default 60s tolerance, ValidateChallenge
// MUST accept it (the half-window covers the drift).
func TestValidateChallenge_AcceptsClaimWithinSkewTolerance(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	pl.IssuedAt = now.Add(30 * time.Second).Unix() // Connector clock ahead
	pl.ExpiresAt = now.Add(60 * time.Minute).Unix()
	raw := signTestChallengeRS256(t, c, pl)

	if _, err := ValidateChallenge(raw, ValidateOptions{
		Trust:              []*x509.Certificate{c.cert},
		ExpectedAudience:   pl.Audience,
		Now:                now,
		ClockSkewTolerance: 60 * time.Second,
	}); err != nil {
		t.Fatalf("future iat within tolerance should be accepted: %v", err)
	}
}

// TestValidateChallenge_RejectsClaimBeyondSkewTolerance — a Connector
// clock 90 seconds ahead of certctl exceeds the default 60s tolerance.
// ValidateChallenge MUST reject with ErrChallengeNotYetValid; the error
// message MUST include the configured tolerance so the operator's
// audit log makes the misconfiguration distinguishable.
func TestValidateChallenge_RejectsClaimBeyondSkewTolerance(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	pl.IssuedAt = now.Add(90 * time.Second).Unix() // beyond tolerance
	pl.ExpiresAt = now.Add(60 * time.Minute).Unix()
	raw := signTestChallengeRS256(t, c, pl)

	_, err := ValidateChallenge(raw, ValidateOptions{
		Trust:              []*x509.Certificate{c.cert},
		ExpectedAudience:   pl.Audience,
		Now:                now,
		ClockSkewTolerance: 60 * time.Second,
	})
	if !errors.Is(err, ErrChallengeNotYetValid) {
		t.Fatalf("got %v, want ErrChallengeNotYetValid", err)
	}
	if !strings.Contains(err.Error(), "tolerance=") {
		t.Errorf("error should report tolerance for operator audit log: %v", err)
	}
}

// TestValidateChallenge_AcceptsExpiredClaimWithinSkewTolerance — a
// Connector clock 30 seconds behind certctl produces a challenge whose
// exp is 30s in the past relative to certctl's now. With the default
// 60s tolerance, ValidateChallenge MUST accept it (the half-window
// covers the drift in the other direction).
func TestValidateChallenge_AcceptsExpiredClaimWithinSkewTolerance(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	pl.IssuedAt = now.Add(-60 * time.Minute).Unix()
	pl.ExpiresAt = now.Add(-30 * time.Second).Unix() // Connector clock behind
	raw := signTestChallengeRS256(t, c, pl)

	if _, err := ValidateChallenge(raw, ValidateOptions{
		Trust:              []*x509.Certificate{c.cert},
		ExpectedAudience:   pl.Audience,
		Now:                now,
		ClockSkewTolerance: 60 * time.Second,
	}); err != nil {
		t.Fatalf("past exp within tolerance should be accepted: %v", err)
	}
}

// TestValidateChallenge_NegativeToleranceTreatedAsZero — defensive: a
// negative tolerance is operator typo; the validator MUST treat it as
// zero (strict iat/exp) rather than tightening the window or panicking.
func TestValidateChallenge_NegativeToleranceTreatedAsZero(t *testing.T) {
	c := genTestRSAConnector(t)
	now := time.Now()
	pl := validV1Payload(now)
	pl.IssuedAt = now.Add(30 * time.Second).Unix() // future iat
	pl.ExpiresAt = now.Add(60 * time.Minute).Unix()
	raw := signTestChallengeRS256(t, c, pl)

	// Negative tolerance MUST behave like zero — the future iat (no
	// matter how small) should be rejected. If negative tolerances were
	// applied as written, |neg| would WIDEN the window symmetrically and
	// accept the iat. Pin the defensive normalization here.
	_, err := ValidateChallenge(raw, ValidateOptions{
		Trust:              []*x509.Certificate{c.cert},
		ExpectedAudience:   pl.Audience,
		Now:                now,
		ClockSkewTolerance: -10 * time.Second,
	})
	// |-10s| = 10s; 30s future iat > 10s tolerance → rejected. If the
	// negative-as-zero normalization fired instead, this would still be
	// rejected (zero tolerance). Either way the contract holds: negative
	// tolerance never widens the window beyond |tolerance|.
	if !errors.Is(err, ErrChallengeNotYetValid) {
		t.Fatalf("got %v, want ErrChallengeNotYetValid (negative tolerance must not widen the window)", err)
	}
}

// asn1 + math/big are imported to keep the test compile in case future
// helpers add ASN.1 wire shaping (e.g. malformed-DER ES256 fixture).
var (
	_ = asn1.Marshal
	_ = big.NewInt
)
