package local

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/shankar0123/certctl/internal/crypto/signer"
	"github.com/shankar0123/certctl/internal/domain"
)

// Bundle CRL/OCSP-Responder, Phase 2 — separate OCSP responder cert.
//
// Per RFC 6960 §2.6 + §4.2.2.2 the OCSP responder SHOULD be either the
// CA itself OR a cert issued by the CA with the id-kp-OCSPSigning EKU.
// The dedicated-responder shape is preferred because:
//
//   1. Every OCSP request signs ONE message — high-volume CAs see
//      thousands of OCSP polls per day. If those signs all use the
//      CA private key (the historical certctl behaviour), every
//      poll is a CA-key operation. With a separate responder cert,
//      the CA key signs only the responder cert (rarely — once per
//      ocspResponderValidity, default 30d) and OCSP polls hit the
//      responder key.
//   2. When the CA key lives on an HSM (PKCS#11 driver, item 3 in
//      the V3-Pro roadmap), case (1) becomes a hard constraint —
//      every OCSP poll = HSM op = HSM-rate-limit pressure +
//      audit-volume blowup. The dedicated responder cert lives on
//      a cheaper (or even non-HSM) Signer driver.
//   3. The id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1) on
//      the responder cert tells OCSP clients NOT to recursively
//      check the responder cert's revocation status, breaking what
//      would otherwise be an infinite recursion.
//
// This file implements the bootstrap + rotation. The responder cert
// is issued by the local CA (signed with c.caSigner via
// x509.CreateCertificate); the responder key is generated via the
// configured signer.Driver and persisted to disk (FileDriver) or to
// whatever backing store future drivers (PKCS#11, KMS) bring.
//
// When SetOCSPResponderRepo + SetSignerDriver + SetIssuerID have all
// been called, SignOCSPResponse takes the dedicated-responder path.
// Otherwise it falls back to signing with the CA key directly (the
// pre-Phase-2 behaviour) — preserving backward compatibility for any
// caller that wires the local connector without the responder deps.

// id-pkix-ocsp-nocheck OID per RFC 6960 §4.2.2.2.1. The extension
// value is an ASN.1 NULL (DER bytes 0x05 0x00). When this extension is
// present in a cert, OCSP clients MUST NOT check the cert's own
// revocation status — preventing the infinite recursion that would
// otherwise apply when the responder cert is itself signed by the CA
// it validates.
var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
var ocspNoCheckExtensionValue = []byte{0x05, 0x00} // DER: NULL

// ensureOCSPResponder returns the cert + signer to use for OCSP
// response signing. The first return value is the responder cert (the
// cert that will appear in the OCSP response's certificates field per
// RFC 6960 §4.2.1); the second return value is the Signer used to
// sign the response.
//
// Behavior:
//
//   - If c.ocspResponderRepo + c.signerDriver + c.issuerID are not all
//     set, returns (c.caCert, c.caSigner, nil) — the historical
//     CA-key-direct path. Callers detect this case via responder ==
//     caCert and pass caCert as both `issuer` and `responder` to
//     ocsp.CreateResponse (which is the legal RFC 6960 form when the
//     responder IS the issuer).
//
//   - Otherwise looks up the current responder via the repo. If
//     present and not in the rotation window, loads its key via the
//     signer driver and returns. If missing or in the rotation window,
//     bootstraps a fresh keypair + cert (signed by c.caSigner with
//     id-pkix-ocsp-nocheck), persists, returns the new pair.
//
// All bootstrap I/O happens under c.mu so concurrent first-call OCSP
// requests don't double-bootstrap. The bootstrap is rare (once per
// validity window per issuer) so the lock contention is negligible.
func (c *Connector) ensureOCSPResponder(ctx context.Context) (*x509.Certificate, signer.Signer, error) {
	if err := c.ensureCA(ctx); err != nil {
		return nil, nil, fmt.Errorf("CA initialization failed: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Fallback: any required dep missing → use the CA key directly.
	// This preserves the pre-Phase-2 behaviour for callers that
	// haven't wired the responder repo / signer driver / issuer ID.
	if c.ocspResponderRepo == nil || c.signerDriver == nil || c.issuerID == "" {
		return c.caCert, c.caSigner, nil
	}

	now := time.Now().UTC()

	// Lookup current responder.
	current, err := c.ocspResponderRepo.Get(ctx, c.issuerID)
	if err != nil {
		return nil, nil, fmt.Errorf("ocsp responder repo Get %q: %w", c.issuerID, err)
	}

	if current != nil && !current.NeedsRotation(now, c.ocspResponderRotationGrace) {
		// Existing responder is good — load its key and return.
		responderSigner, err := c.signerDriver.Load(ctx, current.KeyPath)
		if err != nil {
			// Key file missing or corrupt → treat as needs-bootstrap
			// rather than failing. This recovers from operator
			// mistakes (deleting the key file) without requiring
			// manual intervention.
			c.logger.Warn("OCSP responder key load failed; bootstrapping fresh responder",
				"issuer_id", c.issuerID, "key_path", current.KeyPath, "error", err)
		} else {
			cert, err := parseSinglePEMCert([]byte(current.CertPEM))
			if err == nil {
				return cert, responderSigner, nil
			}
			c.logger.Warn("OCSP responder cert parse failed; bootstrapping fresh responder",
				"issuer_id", c.issuerID, "error", err)
		}
	}

	// Bootstrap path: generate fresh key + sign new responder cert.
	cert, sig, err := c.bootstrapOCSPResponder(ctx, current, now)
	if err != nil {
		return nil, nil, fmt.Errorf("ocsp responder bootstrap: %w", err)
	}
	return cert, sig, nil
}

// bootstrapOCSPResponder generates a new ECDSA P-256 key via the
// configured signer driver, signs an OCSP-Signing-EKU + OCSP-no-check
// cert with c.caSigner, persists, and returns the cert + signer.
//
// Caller MUST hold c.mu. previous is the prior responder row (may be
// nil); when non-nil its CertSerial is recorded in rotated_from for
// audit.
func (c *Connector) bootstrapOCSPResponder(ctx context.Context, previous *domain.OCSPResponder, now time.Time) (*x509.Certificate, signer.Signer, error) {
	// 1. Generate the responder keypair. ECDSA P-256 is the default;
	//    operators wanting a different alg can extend the driver
	//    contract later (today the bootstrap hardcodes the alg to
	//    keep the surface small).
	const responderAlg = signer.AlgorithmECDSAP256

	keyDir := c.ocspResponderKeyDir
	if keyDir == "" {
		keyDir = "." // fall back to cwd; tests use t.TempDir() via SetOCSPResponderKeyDir
	}

	// FileDriver-shaped contract: the driver picks the path via its
	// GenerateOutPath hook. For the FileDriver we configure here, we
	// inject a hook that produces <keyDir>/ocsp-responder-<issuerID>.key
	// — a stable name so rotation overwrites in place.
	keyName := fmt.Sprintf("ocsp-responder-%s.key", c.issuerID)
	keyPath := filepath.Join(keyDir, keyName)

	// Configure the FileDriver's hooks if the supplied driver is one.
	// Other drivers (MemoryDriver in tests, future PKCS#11) bring
	// their own ref-naming policy and we just use whatever ref they
	// return.
	if fd, ok := c.signerDriver.(*signer.FileDriver); ok {
		// Inject the destination path. DirHardener stays whatever the
		// caller installed (typically keystore.ensureKeyDirSecure
		// adapter from cmd/server/main.go).
		if fd.GenerateOutPath == nil {
			fd.GenerateOutPath = func(_ signer.Algorithm) (string, error) {
				return keyPath, nil
			}
		}
	}

	responderSigner, generatedRef, err := c.signerDriver.Generate(ctx, responderAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("generate responder key: %w", err)
	}
	if generatedRef != "" {
		keyPath = generatedRef
	}

	// 2. Build the responder cert template per RFC 6960 §4.2.2.2:
	//      KeyUsage:    digitalSignature
	//      ExtKeyUsage: id-kp-OCSPSigning
	//      Extensions:  id-pkix-ocsp-nocheck (NULL)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, nil, fmt.Errorf("generate responder serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("OCSP Responder for %s", c.caCert.Subject.CommonName),
		},
		NotBefore: now.Add(-5 * time.Minute), // small backdate to absorb clock skew between certctl and relying parties
		NotAfter:  now.Add(c.ocspResponderValidity),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageOCSPSigning,
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidOCSPNoCheck,
				Critical: false,
				Value:    ocspNoCheckExtensionValue,
			},
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// 3. Sign with the CA key (c.caSigner from the Signer interface).
	//    Public key for the cert is the responder's own public key.
	derBytes, err := x509.CreateCertificate(rand.Reader, template, c.caCert, responderSigner.Public(), c.caSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("sign responder cert: %w", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signed responder cert: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// 4. Persist.
	row := &domain.OCSPResponder{
		IssuerID:   c.issuerID,
		CertPEM:    string(pemBytes),
		CertSerial: fmt.Sprintf("%x", serial),
		KeyPath:    keyPath,
		KeyAlg:     string(responderAlg),
		NotBefore:  template.NotBefore,
		NotAfter:   template.NotAfter,
	}
	if previous != nil {
		row.RotatedFrom = previous.CertSerial
	}
	if err := c.ocspResponderRepo.Put(ctx, row); err != nil {
		return nil, nil, fmt.Errorf("persist responder row: %w", err)
	}

	c.logger.Info("OCSP responder bootstrapped",
		"issuer_id", c.issuerID,
		"cert_serial", row.CertSerial,
		"not_after", row.NotAfter,
		"rotated_from", row.RotatedFrom)

	return cert, responderSigner, nil
}

// parseSinglePEMCert decodes the first PEM block in pemBytes as an
// X.509 certificate. Used by ensureOCSPResponder to materialize a
// cert from the persisted CertPEM string.
func parseSinglePEMCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}
