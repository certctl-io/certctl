package domain

// ESTEnrollResult holds the result of an EST (RFC 7030) enrollment operation.
type ESTEnrollResult struct {
	CertPEM  string `json:"cert_pem"`  // PEM-encoded signed certificate
	ChainPEM string `json:"chain_pem"` // PEM-encoded CA chain
}
