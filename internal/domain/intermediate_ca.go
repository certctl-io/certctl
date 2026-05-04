package domain

import "time"

// IntermediateCA represents a non-root CA in a multi-level hierarchy.
// One row per certificate (root, policy, issuing) — the parent_ca_id
// FK to itself encodes the tree shape; the owning_issuer_id FK groups
// every CA under one Issuer config row.
//
// Lifecycle:
//
//	created (CreateRoot or CreateChild)
//	   │
//	   ▼
//	active (issuing certs)
//	   │
//	   ▼
//	retiring  (drain — children still active; this CA stops issuing
//	           NEW children but existing children continue)
//	   │
//	   ▼
//	retired   (terminal — no issuance, OCSP responder
//	           keeps responding for already-issued leaves until expiry)
//
// Closes the multi-level CA hierarchy gap for FedRAMP boundary-CA,
// financial-services policy-CA, and OT network-CA deployments where
// regulator-mandated certificate-policy separation requires multiple
// layers (root → policy → issuing).
//
// Defense in depth: NEVER persist the CA private key bytes in this
// row. KeyDriverID is a reference (filesystem path / KMS key ID /
// HSM slot) to the signer.Driver instance that owns the key. A SQL-
// injection or row-leak surface must NEVER expose key bytes; only
// the reference can leak.
type IntermediateCA struct {
	ID                string              `json:"id"`                     // ica-<slug>
	OwningIssuerID    string              `json:"owning_issuer_id"`       // FK issuers.id
	ParentCAID        *string             `json:"parent_ca_id,omitempty"` // nil for root, FK to self otherwise
	Name              string              `json:"name"`                   // operator-supplied label
	Subject           string              `json:"subject"`                // distinguished name (CN + O + OU + ...)
	State             IntermediateCAState `json:"state"`                  // active / retiring / retired
	CertPEM           string              `json:"cert_pem"`               // this CA's cert (PEM)
	KeyDriverID       string              `json:"key_driver_id"`          // signer.Driver instance ID
	NotBefore         time.Time           `json:"not_before"`
	NotAfter          time.Time           `json:"not_after"`
	PathLenConstraint *int                `json:"path_len_constraint,omitempty"` // RFC 5280 §4.2.1.9; nil = no constraint
	NameConstraints   []NameConstraint    `json:"name_constraints,omitempty"`    // RFC 5280 §4.2.1.10
	OCSPResponderURL  string              `json:"ocsp_responder_url,omitempty"`  // AIA stamping for issued leaves
	Metadata          map[string]string   `json:"metadata,omitempty"`            // policy_id, compliance_tier, owner_team
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
}

// IntermediateCAState is the closed enum of CA-row lifecycle states.
type IntermediateCAState string

const (
	// IntermediateCAStateActive is the issuing state — the CA can sign
	// new children + new leaves under it.
	IntermediateCAStateActive IntermediateCAState = "active"

	// IntermediateCAStateRetiring is the drain state — no new children;
	// existing children keep issuing until they themselves retire.
	IntermediateCAStateRetiring IntermediateCAState = "retiring"

	// IntermediateCAStateRetired is the terminal state — no issuance
	// at all; OCSP responder keeps responding for already-issued leaves
	// until natural expiry.
	IntermediateCAStateRetired IntermediateCAState = "retired"
)

// IsValidIntermediateCAState reports whether s is a closed-enum value.
func IsValidIntermediateCAState(s IntermediateCAState) bool {
	switch s {
	case IntermediateCAStateActive, IntermediateCAStateRetiring, IntermediateCAStateRetired:
		return true
	}
	return false
}

// IsTerminal reports whether s is the immutable terminal state.
func (s IntermediateCAState) IsTerminal() bool {
	return s == IntermediateCAStateRetired
}

// NameConstraint encodes RFC 5280 §4.2.1.10 — Permitted + Excluded
// subtrees. Critical extension when set on the CA cert; the local
// adapter renders this onto the CA's cert at CreateChild time. The
// service layer enforces subset semantics: a child's permitted set
// MUST be a subset of the parent's permitted set + the child's
// excluded set MUST be a superset of the parent's excluded set.
type NameConstraint struct {
	Permitted []string `json:"permitted,omitempty"` // e.g., "example.com" → all DNS subtrees ending in example.com
	Excluded  []string `json:"excluded,omitempty"`
}

// HierarchyMode picks the per-issuer CA-hierarchy posture, stored on
// the Issuer row. Three values are possible (the database default is
// "single" — back-compat byte-identical for unmigrated rows):
//
//   - HierarchyModeSingle (default, pre-Rank-8 historical) — sub-CA
//     mode loads a pre-signed cert+key from disk via local.Config.
//     CACertPath / local.Config.CAKeyPath. Existing operators upgrade
//     with no behavior change.
//   - HierarchyModeTree — the issuer's CAs are managed via the
//     intermediate_cas table; chain assembly walks the parent_ca_id
//     FK from the issuing leaf-CA up to the root + attaches the
//     assembled chain to every IssuanceResult.
//
// The local connector reads this from the Issuer row at issue time;
// empty string is treated as HierarchyModeSingle.
const (
	HierarchyModeSingle = "single"
	HierarchyModeTree   = "tree"
)
