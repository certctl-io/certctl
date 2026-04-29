package domain

// ESTEnrollResult holds the result of an EST (RFC 7030) enrollment operation.
type ESTEnrollResult struct {
	CertPEM  string `json:"cert_pem"`  // PEM-encoded signed certificate
	ChainPEM string `json:"chain_pem"` // PEM-encoded CA chain
}

// ESTServerKeygenResult holds the result of an EST RFC 7030 §4.4
// server-keygen flow. The handler emits CertPEM as the
// `application/pkcs7-mime; smime-type=certs-only` part of the multipart
// response and EncryptedKey as the `application/pkcs7-mime;
// smime-type=enveloped-data` part. The plaintext private key bytes never
// reach this struct — they're zeroized inside ESTService.SimpleServerKeygen
// after the EnvelopedData wrap.
//
// EST RFC 7030 hardening master bundle Phase 5.
type ESTServerKeygenResult struct {
	CertPEM      string `json:"cert_pem"`
	ChainPEM     string `json:"chain_pem"`
	EncryptedKey []byte `json:"encrypted_key"` // CMS EnvelopedData DER (NOT JSON-friendly; serializer flag)
}
