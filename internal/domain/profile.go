package domain

import (
	"encoding/asn1"
	"time"
)

// CertificateProfile defines an enrollment profile that controls what kinds of
// certificates can be issued: allowed key algorithms, maximum TTL, permitted EKUs,
// required SAN patterns, and optional SPIFFE URI SANs for workload identity.
type CertificateProfile struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	Description          string             `json:"description"`
	AllowedKeyAlgorithms []KeyAlgorithmRule `json:"allowed_key_algorithms"`
	MaxTTLSeconds        int                `json:"max_ttl_seconds"`
	AllowedEKUs          []string           `json:"allowed_ekus"`
	RequiredSANPatterns  []string           `json:"required_san_patterns"`
	SPIFFEURIPattern     string             `json:"spiffe_uri_pattern"`
	AllowShortLived      bool               `json:"allow_short_lived"`
	// MustStaple, when true, causes the local issuer to add the RFC 7633
	// must-staple extension (id-pe-tlsfeature, OID 1.3.6.1.5.5.7.1.24) to
	// every certificate issued under this profile. Browsers + modern TLS
	// libraries that see this extension MUST fail-closed on missing OCSP
	// stapling responses — defense against revocation-bypass via OCSP
	// blackholing.
	//
	// Default: false. Operators opt in once they've confirmed their TLS
	// reverse proxy / load balancer staples OCSP responses (NGINX,
	// HAProxy, Envoy, etc. all support stapling but it requires explicit
	// config). Setting must-staple by default would break customer
	// deployments where the TLS path doesn't staple — browsers hard-fail.
	//
	// Recommended for: Intune-deployed device certs (modern TLS clients);
	// SCEP profiles serving general/legacy clients (ChromeOS, IoT) should
	// stay false until the TLS path is verified.
	MustStaple bool `json:"must_staple"`

	// RequiredCSRAttributes is the per-profile hint list the EST `csrattrs`
	// endpoint (RFC 7030 §4.5) returns to enrolling clients. Values are
	// short string keys that map to ASN.1 ObjectIdentifiers via
	// AttributeStringToOID — example: ["serialNumber", "deviceSerialNumber"]
	// to push the device serial into the issued cert's Subject DN for
	// IoT bootstrapping. Defaults empty (the EST handler then returns
	// 204-No-Content per RFC 7030 §4.5.2 — the legacy stub behavior).
	//
	// EKU strings already live in AllowedEKUs above and are added to the
	// csrattrs response automatically — RequiredCSRAttributes covers the
	// non-EKU attribute hints (RFC 5280 distinguished-name attributes,
	// RFC 5912 CMC attributes, etc.). Keeping the two concept slices
	// separate matches how operators think: "what EKUs do I need" vs
	// "what extra subject attributes do I need".
	//
	// Unknown keys are tolerated at marshal time (logged + dropped) so a
	// new key on a forward-version certctl doesn't force every profile
	// edit to round-trip through the validator.
	//
	// EST RFC 7030 hardening master bundle Phase 6.
	RequiredCSRAttributes []string `json:"required_csr_attributes,omitempty"`

	// ACMEAuthMode picks the per-profile ACME server auth posture.
	// "trust_authenticated" (default): JWS-authenticated client is
	// trusted to issue for any identifier the profile policy allows
	// (no out-of-band identifier proof). "challenge": full HTTP-01 +
	// DNS-01 + TLS-ALPN-01 validation per RFC 8555 §8 (Phase 3).
	// One certctl-server can serve both modes simultaneously by
	// having multiple profiles with different values; the column is
	// read at request time, not cached at server start.
	//
	// Backed by certificate_profiles.acme_auth_mode added in
	// migration 000025_acme_server. Empty string in Go ≡ DB default
	// "trust_authenticated".
	ACMEAuthMode string `json:"acme_auth_mode,omitempty"`

	// RequiresApproval, when true, gates issuance + renewal of any
	// certificate bound to this profile on a parallel ApprovalRequest
	// row. The renewal-loop tick creates the job at
	// JobStatusAwaitingApproval; the scheduler does NOT dispatch
	// until ApprovalService.Approve transitions the request to
	// approved. Compliance customers (PCI-DSS Level 1, FedRAMP
	// Moderate / High, SOC 2 Type II, HIPAA) configure this on
	// production-tier profiles to satisfy the two-person integrity
	// procurement question.
	//
	// Defaults to false for back-compat — the unattended renewal
	// path remains the default for non-compliance customers.
	//
	// Backed by certificate_profiles.requires_approval added in
	// migration 000027_approval_workflow. Rank 7 of the 2026-05-03
	// deep-research deliverable.
	RequiresApproval bool `json:"requires_approval,omitempty"`

	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// KeyAlgorithmRule defines an allowed key algorithm and its minimum key size.
type KeyAlgorithmRule struct {
	Algorithm string `json:"algorithm"` // "RSA", "ECDSA", "Ed25519"
	MinSize   int    `json:"min_size"`  // RSA: 2048/4096, ECDSA: 256/384, Ed25519: 0 (fixed)
}

// IsShortLived returns true if this profile's max TTL is under 1 hour (3600 seconds).
// Short-lived certs use expiry as revocation — no CRL/OCSP needed.
func (p *CertificateProfile) IsShortLived() bool {
	return p.AllowShortLived && p.MaxTTLSeconds > 0 && p.MaxTTLSeconds < 3600
}

// DefaultKeyAlgorithms returns sensible defaults for profiles without explicit rules.
func DefaultKeyAlgorithms() []KeyAlgorithmRule {
	return []KeyAlgorithmRule{
		{Algorithm: "ECDSA", MinSize: 256},
		{Algorithm: "RSA", MinSize: 2048},
	}
}

// DefaultEKUs returns the default extended key usages.
func DefaultEKUs() []string {
	return []string{"serverAuth"}
}

// Supported key algorithm constants for validation.
const (
	KeyAlgorithmRSA     = "RSA"
	KeyAlgorithmECDSA   = "ECDSA"
	KeyAlgorithmEd25519 = "Ed25519"
)

// ValidKeyAlgorithms is the set of recognized key algorithm names.
var ValidKeyAlgorithms = map[string]bool{
	KeyAlgorithmRSA:     true,
	KeyAlgorithmECDSA:   true,
	KeyAlgorithmEd25519: true,
}

// ValidEKUs is the set of recognized extended key usage names.
var ValidEKUs = map[string]bool{
	"serverAuth":      true,
	"clientAuth":      true,
	"codeSigning":     true,
	"emailProtection": true,
	"timeStamping":    true,
}

// EKUStringToOID maps an EKU short-name (as used in
// CertificateProfile.AllowedEKUs) to the corresponding RFC 5280 §4.2.1.12
// id-kp-* OID. Returns ok=false for unknown names so the EST csrattrs
// path can drop unrecognized hints rather than emit garbage OIDs.
//
// EST RFC 7030 hardening master bundle Phase 6.2.
func EKUStringToOID(name string) (asn1.ObjectIdentifier, bool) {
	oid, ok := ekuOIDByName[name]
	return oid, ok
}

// AttributeStringToOID maps a Subject DN / CMC attribute short-name
// (as used in CertificateProfile.RequiredCSRAttributes) to the
// corresponding ASN.1 OID. Returns ok=false for unknown names. The
// known set is intentionally small at GA — operators add new keys via
// PR review rather than free-form strings, so a typo trips a validator
// + the EST csrattrs response stays self-describing.
//
// EST RFC 7030 hardening master bundle Phase 6.2.
func AttributeStringToOID(name string) (asn1.ObjectIdentifier, bool) {
	oid, ok := attributeOIDByName[name]
	return oid, ok
}

// ekuOIDByName is the lookup table EKUStringToOID consults. OIDs
// registered in RFC 5280 §4.2.1.12 + RFC 3280 + Microsoft.
var ekuOIDByName = map[string]asn1.ObjectIdentifier{
	"serverAuth":      {1, 3, 6, 1, 5, 5, 7, 3, 1},
	"clientAuth":      {1, 3, 6, 1, 5, 5, 7, 3, 2},
	"codeSigning":     {1, 3, 6, 1, 5, 5, 7, 3, 3},
	"emailProtection": {1, 3, 6, 1, 5, 5, 7, 3, 4},
	"timeStamping":    {1, 3, 6, 1, 5, 5, 7, 3, 8},
	"ocspSigning":     {1, 3, 6, 1, 5, 5, 7, 3, 9},
	// Microsoft EKUs commonly required for AD smartcard / Intune device
	// auth. Not in ValidEKUs above (which only enumerates the broadly
	// portable names), but devices enrolling for these targets need
	// csrattrs to advertise them.
	"smartCardLogon":          {1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
	"documentSigning":         {1, 3, 6, 1, 4, 1, 311, 10, 3, 12},
	"encryptingFileSystem":    {1, 3, 6, 1, 4, 1, 311, 10, 3, 4},
	"keyRecoveryAgent":        {1, 3, 6, 1, 4, 1, 311, 21, 6},
	"ocspNoCheck":             {1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
	"anyExtendedKeyUsage":     {2, 5, 29, 37, 0},
	"ipsecIKE":                {1, 3, 6, 1, 5, 5, 7, 3, 17},
	"machineEAP":              {1, 3, 6, 1, 5, 5, 7, 3, 13},
	"kerberosClientAuth":      {1, 3, 6, 1, 5, 2, 3, 4},
	"kerberosKeyDistribution": {1, 3, 6, 1, 5, 2, 3, 5},
}

// attributeOIDByName covers the Subject DN / CMC attribute hints the
// EST csrattrs endpoint can advertise. Sourced from RFC 5280
// §4.1.2.6 + RFC 5912 (CMC) + RFC 5280 §4.1.2.4. Limited surface on
// purpose; PRs can extend.
var attributeOIDByName = map[string]asn1.ObjectIdentifier{
	// RFC 5280 §4.1.2.6 — distinguished-name attributes commonly
	// requested for IoT bootstrap.
	"commonName":             {2, 5, 4, 3},
	"surname":                {2, 5, 4, 4},
	"serialNumber":           {2, 5, 4, 5},
	"countryName":            {2, 5, 4, 6},
	"localityName":           {2, 5, 4, 7},
	"stateOrProvinceName":    {2, 5, 4, 8},
	"organizationName":       {2, 5, 4, 10},
	"organizationalUnitName": {2, 5, 4, 11},
	"title":                  {2, 5, 4, 12},
	// CSR attributes from RFC 2985 §5.4 — challengePassword is
	// already used by SCEP profiles; emailAddress + extensionRequest
	// are the standard PKCS#10 carriers.
	"challengePassword": {1, 2, 840, 113549, 1, 9, 7},
	"emailAddress":      {1, 2, 840, 113549, 1, 9, 1},
	"extensionRequest":  {1, 2, 840, 113549, 1, 9, 14},
	// Device-identity attributes that show up in IoT / MDM
	// enrollment flows.
	"deviceSerialNumber":  {1, 3, 6, 1, 4, 1, 311, 21, 14}, // Microsoft Intune device serial
	"unstructuredName":    {1, 2, 840, 113549, 1, 9, 2},
	"unstructuredAddress": {1, 2, 840, 113549, 1, 9, 8},
}
