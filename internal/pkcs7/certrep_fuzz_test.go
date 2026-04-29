package pkcs7

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
)

// FuzzBuildCertRepPKIMessage stresses the CertRep builder with attacker-
// controlled transactionID + nonce + signerCert bytes. The invariants are:
//   1. No panic for arbitrary inputs.
//   2. When build succeeds AND status is success, the output parses back
//      via ParseSignedData (round-trip soundness — the prompt's required
//      fuzz invariant).
//
// SCEP RFC 8894 + Intune master bundle Phase 3.3.
//
// The fuzzer holds the RA pair constant (one-time setup) and lets the
// fuzz engine vary the unstable inputs. Errors from BuildCertRepPKIMessage
// are expected for malformed signerCert bytes; only a panic = bug.

func FuzzBuildCertRepPKIMessage(f *testing.F) {
	// Seed: empty everything (should error cleanly via the nil-args gate).
	f.Add("", []byte{}, []byte{})
	// Seed: minimal inputs that exercise the failure-path code (no
	// SignerCert needed because Status=Failure short-circuits the
	// EnvelopedData build).
	f.Add("txn-1", make([]byte, 16), []byte{})

	// One-time setup: RA pair stays constant across fuzz iterations.
	raKey, raCert := genTestRSARAFuzz()
	if raKey == nil {
		f.Skip("test RA pair generation failed; environment lacks crypto/rand?")
	}

	f.Fuzz(func(t *testing.T, transactionID string, senderNonce []byte, signerCert []byte) {
		req := &domain.SCEPRequestEnvelope{
			MessageType:   domain.SCEPMessageTypePKCSReq,
			TransactionID: transactionID,
			SenderNonce:   senderNonce,
			SignerCert:    signerCert,
		}
		// Failure path: never needs SignerCert. No panic, no requirement
		// on output (the failure shape is correct by construction).
		respFail := &domain.SCEPResponseEnvelope{
			Status:         domain.SCEPStatusFailure,
			FailInfo:       domain.SCEPFailBadRequest,
			TransactionID:  transactionID,
			RecipientNonce: senderNonce,
		}
		_, _ = BuildCertRepPKIMessage(req, respFail, raCert, raKey)

		// Success path with arbitrary signerCert bytes: most inputs will
		// fail to parse as a real cert; that's fine, BuildCertRep returns
		// an error rather than panicking. When build succeeds (rare for
		// random bytes), assert the output parses back.
		respSuccess := &domain.SCEPResponseEnvelope{
			Status:         domain.SCEPStatusSuccess,
			TransactionID:  transactionID,
			RecipientNonce: senderNonce,
			Result: &domain.SCEPEnrollResult{
				CertPEM: minimalIssuedCertPEMFuzz(raKey),
			},
		}
		out, err := BuildCertRepPKIMessage(req, respSuccess, raCert, raKey)
		if err != nil {
			return // expected for arbitrary signerCert; no panic = ok
		}
		// Build succeeded — verify round-trip soundness.
		sd, err := ParseSignedData(out)
		if err != nil {
			t.Errorf("BuildCertRepPKIMessage produced output that fails ParseSignedData: %v", err)
			return
		}
		if len(sd.SignerInfos) == 0 {
			t.Errorf("BuildCertRepPKIMessage produced output with no signerInfos")
		}
	})
}

// genTestRSARAFuzz materialises a one-time RA pair for the fuzz seed
// setup. Mirrors genTestRSARA from the round-trip tests but doesn't
// take *testing.T (called from f.Fuzz setup, not a test body).
func genTestRSARAFuzz() (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz-ra"},
		Issuer:       pkix.Name{CommonName: "fuzz-ra"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil
	}
	return key, cert
}

// minimalIssuedCertPEMFuzz returns a tiny self-signed PEM cert reusing
// the RA key. Avoids per-fuzz-iter rsa.GenerateKey overhead (which would
// dominate the fuzz throughput).
func minimalIssuedCertPEMFuzz(key *rsa.PrivateKey) string {
	// We construct on demand since the issued cert template doesn't
	// matter beyond being a parseable PEM-wrapped DER cert.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "fuzz-issued"},
		Issuer:       pkix.Name{CommonName: "fuzz-issued"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return ""
	}
	return "-----BEGIN CERTIFICATE-----\n" +
		derToBase64Fuzz(der) +
		"-----END CERTIFICATE-----\n"
}

func derToBase64Fuzz(der []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	pad := (3 - len(der)%3) % 3
	padded := append(append([]byte{}, der...), make([]byte, pad)...)
	for i := 0; i < len(padded); i += 3 {
		v := uint32(padded[i])<<16 | uint32(padded[i+1])<<8 | uint32(padded[i+2])
		out = append(out, enc[v>>18&0x3f], enc[v>>12&0x3f], enc[v>>6&0x3f], enc[v&0x3f])
	}
	for i := 0; i < pad; i++ {
		out[len(out)-1-i] = '='
	}
	// Wrap at 64 chars per PEM convention.
	var wrapped []byte
	for i := 0; i < len(out); i += 64 {
		end := i + 64
		if end > len(out) {
			end = len(out)
		}
		wrapped = append(wrapped, out[i:end]...)
		wrapped = append(wrapped, '\n')
	}
	return string(wrapped)
}
