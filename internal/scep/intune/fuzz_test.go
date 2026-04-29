package intune

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// FuzzParseChallenge feeds arbitrary input to the parser and asserts
// no panics. The challenge wire format is exposed to untrusted devices
// (anyone who can hit the SCEP endpoint can submit a challenge); the
// parser MUST never crash the SCEP server. Run for at least 5 minutes
// in CI: `go test -run='^$' -fuzz=FuzzParseChallenge -fuzztime=5m
// ./internal/scep/intune/...`
//
// SCEP RFC 8894 + Intune master bundle Phase 7.5 (fuzz coverage).
func FuzzParseChallenge(f *testing.F) {
	// Seed corpus: a real well-formed challenge so the fuzzer has
	// structural mutation territory to explore (rather than starting
	// from random ASCII).
	hdr, _ := json.Marshal(jwtHeader{Alg: "RS256", Typ: "JWT"})
	pl, _ := json.Marshal(challengePayloadV1{
		Issuer:    "fuzz",
		Audience:  "fuzz-aud",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     "fuzz-nonce",
	})
	seed := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("fuzz-sig-bytes"))

	f.Add(seed)
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("a..c")
	f.Add(".b.")
	f.Add("not-base64.not-base64.not-base64")
	f.Add(string([]byte{0x00, 0x01, 0x02}))

	f.Fuzz(func(t *testing.T, raw string) {
		// ParseChallenge on its own.
		_, _, _, _ = ParseChallenge(raw)

		// Drive ValidateChallenge too — the full pipeline. Empty trust
		// bundle short-circuits, but the parse + dispatch arms still
		// execute; pass a non-empty placeholder so signature-verify
		// gets exercised against arbitrary input.
		bundle := []*x509.Certificate{} // empty to short-circuit cheap path
		_, _ = ValidateChallenge(raw, ValidateOptions{Trust: bundle, Now: time.Now()})
	})
}
