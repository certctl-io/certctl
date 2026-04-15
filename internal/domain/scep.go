package domain

// SCEPEnrollResult holds the result of a SCEP (RFC 8894) enrollment operation.
type SCEPEnrollResult struct {
	CertPEM  string `json:"cert_pem"`  // PEM-encoded signed certificate
	ChainPEM string `json:"chain_pem"` // PEM-encoded CA chain
}

// SCEPMessageType identifies the type of SCEP PKI message.
type SCEPMessageType int

const (
	// SCEPMessageTypePKCSReq is a PKCS#10 certificate request (initial enrollment).
	SCEPMessageTypePKCSReq SCEPMessageType = 19
	// SCEPMessageTypeGetCertInitial is a polling request for a pending certificate.
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
	SCEPFailBadAlg       SCEPFailInfo = "0" // Unrecognized or unsupported algorithm
	SCEPFailBadMessageCheck SCEPFailInfo = "1" // Integrity check failed
	SCEPFailBadRequest   SCEPFailInfo = "2" // Transaction not permitted or supported
	SCEPFailBadTime      SCEPFailInfo = "3" // Message time field was not sufficiently close to system time
	SCEPFailBadCertID    SCEPFailInfo = "4" // No certificate could be identified matching the provided criteria
)
