package pkcs7

import "testing"

// FuzzParseSignedData / FuzzParseSignerInfos are the panic-safety fuzzers
// for the SignedData parser path used by the SCEP RFC 8894 handler.
//
// SCEP RFC 8894 + Intune master bundle Phase 2.5. Each parser certctl
// adds gets a Fuzz target so attacker-controlled wire bytes cannot
// crash the server (availability bug). Errors are expected for arbitrary
// inputs; only panics are bugs.

func FuzzParseSignedData(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{0x30, 0x82, 0x05, 0x01, 0x02, 0x03})
	// A short SEQUENCE that LOOKS like a ContentInfo with a signedData OID
	// but is too truncated to actually decode.
	f.Add([]byte{0x30, 0x0e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSignedData(data)
	})
}

func FuzzParseSignerInfos(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSignerInfos(data)
	})
}

// FuzzVerifySignerInfoSignature stresses the verification path with an
// arbitrary SignerInfo body (including signature, auth-attrs, cert
// reference). The verification is expected to fail for arbitrary inputs;
// the invariant the fuzzer enforces is no-panic.
//
// The test feeds the input bytes through ParseSignedData first so the
// fuzz exercises the same parse → SignerInfo extraction → verify path
// the production handler runs. Skip-on-parse-error is acceptable —
// fuzzing a parse failure adds zero value here; the parse fuzzer above
// already covers that path.
func FuzzVerifySignerInfoSignature(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		sd, err := ParseSignedData(data)
		if err != nil || sd == nil {
			return // covered by FuzzParseSignedData
		}
		for _, si := range sd.SignerInfos {
			_ = si.VerifySignature() // invariant: no panic
		}
	})
}
