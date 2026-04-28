// Package signer abstracts the act of producing cryptographic signatures
// over digests on behalf of a certificate authority. It exists so that
// downstream code (leaf-cert issuance, CRL generation, OCSP response
// signing, SSH CA cert signing — anything that today does
// x509.CreateCertificate(... caKey)) sees a single interface and does
// not need to know whether the underlying private key lives on disk, in
// a PKCS#11 token, in an HSM, or in a cloud KMS.
//
// The Signer interface deliberately embeds the stdlib crypto.Signer
// (Sign + Public) and adds a single method, Algorithm, that returns a
// value callers can switch on to pick the matching x509.SignatureAlgorithm
// without reflecting on the concrete key type. This is the only certctl-
// specific addition; everything else is stdlib-compatible — any
// crypto.Signer wrapped by this package's Wrap helper becomes a Signer
// without per-key-type boilerplate at the call site.
//
// Driver implementations live in this package today (FileDriver,
// MemoryDriver). HSM-backed drivers (PKCS#11, cloud KMS) land in
// follow-on packages (e.g., internal/crypto/signer/pkcs11) and consume
// this interface unchanged. Adding a driver does not require modifying
// any existing call site or any other driver.
//
// Threat-model note: Signer wraps a crypto.Signer; the bytes-in-process
// hygiene (heap zeroization, no swap, no core-dump exposure) is the
// underlying driver's responsibility, not this package's. The L-014
// carve-out documented at the top of internal/connector/issuer/local/
// local.go applies to FileDriver-backed signers; alternative drivers
// (PKCS#11, KMS) close that disk-exposure leg of the threat model
// because the key never leaves the token / KMS.
package signer
