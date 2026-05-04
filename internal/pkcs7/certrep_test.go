package pkcs7

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// SCEP RFC 8894 Phase 3.1: round-trip tests for BuildCertRepPKIMessage.
//
// Each test materialises real RA + device pairs, calls
// BuildCertRepPKIMessage with success/failure/pending shapes, then
// parses the result back via ParseSignedData + EnvelopedData.Decrypt
// to assert the wire bytes are recoverable. This catches drift between
// the build-side encoding and the parse-side decoding without needing
// a real SCEP client.

func TestBuildCertRepPKIMessage_Success_RoundTrip(t *testing.T) {
	raKey, raCert := genTestRSARA(t)
	deviceKey, deviceCert := genTestRSARA(t) // device transient cert (RSA pub for KTRI)

	// Synthesise an issued cert (the thing we want the device to receive).
	issuedPEM := selfSignedCertPEM(t, "issued.example.com")

	req := &domain.SCEPRequestEnvelope{
		MessageType:   domain.SCEPMessageTypePKCSReq,
		TransactionID: "txn-roundtrip-success",
		SenderNonce:   []byte("0123456789abcdef"),
		SignerCert:    deviceCert.Raw,
	}
	resp := &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusSuccess,
		TransactionID:  req.TransactionID,
		RecipientNonce: req.SenderNonce,
		Result: &domain.SCEPEnrollResult{
			CertPEM: issuedPEM,
		},
	}

	pkiMessage, err := BuildCertRepPKIMessage(req, resp, raCert, raKey)
	if err != nil {
		t.Fatalf("BuildCertRepPKIMessage: %v", err)
	}

	// Parse it back.
	sd, err := ParseSignedData(pkiMessage)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("len(SignerInfos) = %d, want 1", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]
	if err := si.VerifySignature(); err != nil {
		t.Fatalf("VerifySignature(RA signature on CertRep): %v", err)
	}

	// Auth-attr round-trip.
	mt, _ := si.GetMessageType()
	if mt != domain.SCEPMessageTypeCertRep {
		t.Errorf("messageType = %d, want CertRep (3)", mt)
	}
	tid, _ := si.GetTransactionID()
	if tid != req.TransactionID {
		t.Errorf("transactionID = %q, want %q", tid, req.TransactionID)
	}
	// recipientNonce echoes the request's senderNonce.
	rn, _ := si.attrOctetString(OIDSCEPRecipientNonce)
	if !bytes.Equal(rn, req.SenderNonce) {
		t.Errorf("recipientNonce = %q, want %q", rn, req.SenderNonce)
	}
	// senderNonce is server-generated; verify it's 16 bytes.
	sn, _ := si.GetSenderNonce()
	if len(sn) != 16 {
		t.Errorf("senderNonce len = %d, want 16", len(sn))
	}
	// pkiStatus = "0" (Success).
	status, _ := si.attrPrintableString(OIDSCEPPKIStatus)
	if status != string(domain.SCEPStatusSuccess) {
		t.Errorf("pkiStatus = %q, want %q", status, domain.SCEPStatusSuccess)
	}

	// EncapContent should be a parseable EnvelopedData. Decrypt it with
	// the device's RSA key and pull out the inner certs-only PKCS#7;
	// confirm the issued cert is in the chain.
	if len(sd.EncapContent) == 0 {
		t.Fatal("encapContent empty for SUCCESS response")
	}
	env, err := ParseEnvelopedData(sd.EncapContent)
	if err != nil {
		t.Fatalf("ParseEnvelopedData(encapContent): %v", err)
	}
	innerCertsOnly, err := env.Decrypt(deviceKey, deviceCert)
	if err != nil {
		t.Fatalf("EnvelopedData.Decrypt with device key: %v", err)
	}
	// innerCertsOnly is a degenerate PKCS#7 SignedData carrying the
	// issued cert(s). Use parseSignedDataForCSR's SignedData parsing
	// pattern via ParseSignedData to recover the cert.
	innerSD, err := ParseSignedData(innerCertsOnly)
	if err != nil {
		t.Fatalf("ParseSignedData(innerCertsOnly): %v", err)
	}
	if len(innerSD.Certificates) == 0 {
		t.Fatal("inner certs-only PKCS#7 carries no certs")
	}
	if innerSD.Certificates[0].Subject.CommonName != "issued.example.com" {
		t.Errorf("issued cert CN = %q, want issued.example.com", innerSD.Certificates[0].Subject.CommonName)
	}
}

func TestBuildCertRepPKIMessage_Failure_NoEncapContent(t *testing.T) {
	raKey, raCert := genTestRSARA(t)
	_, deviceCert := genTestRSARA(t)

	req := &domain.SCEPRequestEnvelope{
		MessageType:   domain.SCEPMessageTypePKCSReq,
		TransactionID: "txn-roundtrip-failure",
		SenderNonce:   []byte("nonce-failure-12"),
		SignerCert:    deviceCert.Raw,
	}
	resp := &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusFailure,
		FailInfo:       domain.SCEPFailBadMessageCheck,
		TransactionID:  req.TransactionID,
		RecipientNonce: req.SenderNonce,
	}

	pkiMessage, err := BuildCertRepPKIMessage(req, resp, raCert, raKey)
	if err != nil {
		t.Fatalf("BuildCertRepPKIMessage(failure): %v", err)
	}
	sd, err := ParseSignedData(pkiMessage)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	si := sd.SignerInfos[0]
	if err := si.VerifySignature(); err != nil {
		t.Fatalf("VerifySignature(failure response): %v", err)
	}
	// pkiStatus = "2", failInfo = "1" (BadMessageCheck).
	status, _ := si.attrPrintableString(OIDSCEPPKIStatus)
	if status != string(domain.SCEPStatusFailure) {
		t.Errorf("pkiStatus = %q, want %q", status, domain.SCEPStatusFailure)
	}
	failInfo, _ := si.attrPrintableString(OIDSCEPFailInfo)
	if failInfo != string(domain.SCEPFailBadMessageCheck) {
		t.Errorf("failInfo = %q, want %q", failInfo, domain.SCEPFailBadMessageCheck)
	}
	// encapContent is empty for failure.
	if len(sd.EncapContent) != 0 {
		t.Errorf("encapContent non-empty for FAILURE: %d bytes", len(sd.EncapContent))
	}
}

func TestBuildCertRepPKIMessage_FreshSenderNonceEachCall(t *testing.T) {
	raKey, raCert := genTestRSARA(t)
	_, deviceCert := genTestRSARA(t)
	req := &domain.SCEPRequestEnvelope{
		TransactionID: "txn-nonce", SenderNonce: []byte("0123456789abcdef"),
		SignerCert: deviceCert.Raw,
	}
	resp := &domain.SCEPResponseEnvelope{
		Status: domain.SCEPStatusFailure, FailInfo: domain.SCEPFailBadAlg,
		TransactionID: req.TransactionID, RecipientNonce: req.SenderNonce,
	}
	a, _ := BuildCertRepPKIMessage(req, resp, raCert, raKey)
	b, _ := BuildCertRepPKIMessage(req, resp, raCert, raKey)
	sdA, _ := ParseSignedData(a)
	sdB, _ := ParseSignedData(b)
	nonceA, _ := sdA.SignerInfos[0].GetSenderNonce()
	nonceB, _ := sdB.SignerInfos[0].GetSenderNonce()
	if bytes.Equal(nonceA, nonceB) {
		t.Errorf("senderNonce must be fresh per response, got identical: %x", nonceA)
	}
}

func TestBuildCertRepPKIMessage_RejectsNonRSADeviceCert(t *testing.T) {
	raKey, raCert := genTestRSARA(t)
	_, deviceCert := genTestECDSASigner(t) // device cert with ECDSA pubkey — RSA required for KTRI

	req := &domain.SCEPRequestEnvelope{
		TransactionID: "txn-ec-device", SenderNonce: []byte("nonce-1234567890"),
		SignerCert: deviceCert.Raw,
	}
	resp := &domain.SCEPResponseEnvelope{
		Status:        domain.SCEPStatusSuccess,
		TransactionID: req.TransactionID, RecipientNonce: req.SenderNonce,
		Result: &domain.SCEPEnrollResult{CertPEM: selfSignedCertPEM(t, "ec-issued.example.com")},
	}
	_, err := BuildCertRepPKIMessage(req, resp, raCert, raKey)
	if err == nil {
		t.Fatal("BuildCertRepPKIMessage with ECDSA device cert: want error, got nil")
	}
	if !strings.Contains(err.Error(), "RSA public key") {
		t.Errorf("error should mention RSA, got: %v", err)
	}
}

func TestBuildCertRepPKIMessage_NilArgs_Refuses(t *testing.T) {
	if _, err := BuildCertRepPKIMessage(nil, nil, nil, nil); err == nil {
		t.Error("BuildCertRepPKIMessage(nil,nil,nil,nil) = nil, want error")
	}
}

// --- helpers -------------------------------------------------------------

// selfSignedCertPEM creates a fresh RSA self-signed cert with the given CN
// and returns it PEM-encoded — used as the 'issued' cert in success-path
// CertRep round-trip tests.
func selfSignedCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(testRand(), 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xCAFE),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(testRand(), tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// testRand returns the system random source. Wrapped here so tests can be
// adapted to a deterministic source if golden-file tests need it later.
func testRand() io.Reader { return rand.Reader }
