package domain

// SCEPEnrollResult holds the result of a SCEP (RFC 8894) enrollment operation.
type SCEPEnrollResult struct {
	CertPEM  string `json:"cert_pem"`  // PEM-encoded signed certificate
	ChainPEM string `json:"chain_pem"` // PEM-encoded CA chain
}

// SCEPMessageType identifies the type of SCEP PKI message.
type SCEPMessageType int

const (
	// SCEPMessageTypeCertRep is the server's response to PKCSReq / RenewalReq /
	// GetCertInitial. RFC 8894 §3.3.2. Wire-encoded as the messageType
	// authenticated attribute on the outbound CertRep PKIMessage; clients pivot
	// on this value to decide whether to extract a cert from the EnvelopedData
	// (Status=Success), surface a failInfo (Status=Failure), or poll
	// (Status=Pending).
	SCEPMessageTypeCertRep SCEPMessageType = 3
	// SCEPMessageTypeRenewalReq is re-enrollment with an existing valid cert.
	// RFC 8894 §3.3.1.2. Distinct from PKCSReq because the signerInfo is signed
	// by the existing cert (proving possession), not by a transient self-signed
	// device key. The service-side handler must verify the signing cert chains
	// to a trusted CA and is not yet revoked or expired.
	SCEPMessageTypeRenewalReq SCEPMessageType = 17
	// SCEPMessageTypePKCSReq is a PKCS#10 certificate request (initial enrollment).
	// RFC 8894 §3.3.1.
	SCEPMessageTypePKCSReq SCEPMessageType = 19
	// SCEPMessageTypeGetCertInitial is a polling request for a pending certificate.
	// RFC 8894 §3.3.3. Used when the prior PKCSReq returned Status=Pending and
	// the client is checking whether the request has been approved.
	SCEPMessageTypeGetCertInitial SCEPMessageType = 20
)

// SCEPPKIStatus represents the status of a SCEP PKI operation.
type SCEPPKIStatus string

const (
	// SCEPStatusSuccess indicates the request was granted.
	SCEPStatusSuccess SCEPPKIStatus = "0"
	// SCEPStatusFailure indicates the request was rejected.
	SCEPStatusFailure SCEPPKIStatus = "2"
	// SCEPStatusPending indicates the request is pending manual approval.
	SCEPStatusPending SCEPPKIStatus = "3"
)

// SCEPFailInfo represents the reason for a SCEP failure.
type SCEPFailInfo string

const (
	SCEPFailBadAlg          SCEPFailInfo = "0" // Unrecognized or unsupported algorithm
	SCEPFailBadMessageCheck SCEPFailInfo = "1" // Integrity check failed
	SCEPFailBadRequest      SCEPFailInfo = "2" // Transaction not permitted or supported
	SCEPFailBadTime         SCEPFailInfo = "3" // Message time field was not sufficiently close to system time
	SCEPFailBadCertID       SCEPFailInfo = "4" // No certificate could be identified matching the provided criteria
)

// SCEPRequestEnvelope carries the parsed RFC 8894 PKIMessage authenticated
// attributes from the inbound signerInfo (RFC 8894 §3.2.1.2). Populated by
// the handler when a request comes in over the new RFC-8894 path; consumed
// by the service to thread transactionID + nonces through to the CertRep
// response and the audit trail.
//
// Fields mirror the SCEP attributes RFC 8894 §3.2.1.2 enumerates:
//   - messageType: which SCEP operation (PKCSReq / RenewalReq / GetCertInitial)
//   - transactionID: client-chosen identifier; server MUST echo verbatim in CertRep
//   - senderNonce: 16-byte client nonce; server MUST echo as recipientNonce
//   - signerCert: the device's transient self-signed cert (PKCSReq) or its
//     existing valid cert (RenewalReq) — the public key in this cert is what
//     the server encrypts the CertRep EnvelopedData to.
//
// The MVP fall-through path (handler::extractCSRFromPKCS7) does not populate
// this struct; it stays nil and the service layer routes to the legacy
// PKCSReq method that synthesizes a transactionID from the CSR's CommonName.
type SCEPRequestEnvelope struct {
	MessageType   SCEPMessageType // PKCSReq (19), RenewalReq (17), GetCertInitial (20)
	TransactionID string          // client-chosen ID; echoed verbatim in CertRep response
	SenderNonce   []byte          // 16-byte client nonce; echoed as recipientNonce
	SignerCert    []byte          // DER of the device's signing cert (for CertRep encryption)
}

// SCEPResponseEnvelope is what the service hands back to the handler so the
// handler can build the CertRep PKIMessage. The handler is responsible for
// computing the new senderNonce and signing the response with the RA cert/key
// loaded at startup (see SCEPConfig.RACertPath / RAKeyPath).
//
// Status semantics (RFC 8894 §3.3.2.1):
//   - SCEPStatusSuccess: Result is non-nil and contains the issued cert + chain
//   - SCEPStatusFailure: FailInfo identifies the rejection reason; Result is nil
//   - SCEPStatusPending: request is queued for manual approval; Result is nil
//     (client polls via GetCertInitial)
type SCEPResponseEnvelope struct {
	Status         SCEPPKIStatus
	FailInfo       SCEPFailInfo      // populated only when Status == SCEPStatusFailure
	TransactionID  string            // echo of request.TransactionID
	RecipientNonce []byte            // echo of request.SenderNonce
	Result         *SCEPEnrollResult // populated only when Status == SCEPStatusSuccess
}
