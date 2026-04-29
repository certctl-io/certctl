// Package intune handles the Microsoft Intune dynamic-challenge format
// embedded in SCEP CSR challengePassword attributes when the SCEP server
// is sitting behind the Microsoft Intune Certificate Connector.
//
// SCEP RFC 8894 + Intune master bundle Phase 7.
//
// Architecture context:
//
//	Intune cloud
//	  ↓ (device cert request)
//	Intune Certificate Connector (on customer infra)
//	  ↓ (SCEP CSR with challenge signed by Connector)
//	certctl SCEP server     ← THIS PACKAGE validates the Connector's signed challenge
//	  ↓ (issue cert)
//	issuer connector (local CA, Vault, EJBCA, etc.)
//
// The Connector's signed challenge is a JWT-like blob (compact
// serialization, header.payload.signature) where the payload is a JSON
// object containing the device + user claim, the expected CN + SANs,
// expiry, and a nonce. The signature is over header+"."+payload using
// the Connector's installation signing key — the operator extracts that
// key's certificate and configures it as certctl's trust anchor at
// startup.
//
// This package does NOT call Microsoft's API directly. The Connector
// already did that; this package validates the Connector's attestation.
//
// What this package is NOT:
//
//   - NOT a full JWT (JOSE) implementation. It parses + verifies one
//     specific format with a fixed set of supported algorithms (RS256,
//     ES256). No JWKS fetch, no JKU header trust, no kid-based key
//     rotation — the operator-supplied trust bundle IS the trust
//     anchor, and the validator tries each cert in the bundle until
//     one verifies.
//   - NOT a generic SCEP-shape detector. The handler dispatches to this
//     package only when the configured SCEPProfile has IntuneEnabled=true
//     AND the inbound challengePassword "looks Intune-shaped" (length +
//     dot-count heuristic landed in Phase 8).
//   - NOT a Microsoft API client. The Connector's role is to talk to
//     Microsoft; certctl's role is to validate the Connector's signed
//     attestation. The replacement target this whole bundle eliminates
//     is NDES, NOT the Connector.
//
// References:
//
//   - https://learn.microsoft.com/en-us/mem/intune/protect/certificate-connector-overview
//   - https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
//   - smallstep/step-ca Intune integration (community reverse-engineering of the format)
//   - HashiCorp Vault PKI Intune integration (same)
//
// The format details land in this package from a combination of
// Microsoft's published Connector behavior + community implementations
// that have reverse-engineered the JWT shape. Cite the implementation
// references in the parser code's doc comment when you change format.
package intune
