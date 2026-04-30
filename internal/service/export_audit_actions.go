package service

// Production hardening II Phase 7 — typed audit-action codes for the
// cert-export surface.
//
// Naming contract: every code is `cert_export_<format>` where
// <format> ∈ {pem, pkcs12} for the success cases and `_failed` for
// the error cases. Operators grep the audit log on these exact strings
// to find every export event for compliance + breach-investigation
// purposes.
//
// Pre-Phase-7 the audit log carried inline strings ("export_pem" /
// "export_pkcs12"). Those bare codes are PRESERVED for back-compat
// with existing audit-log analysers; the new typed constants are
// emitted alongside via the split-emit pattern (mirrors the EST
// hardening bundle's est_audit_actions.go split-emit at
// internal/service/est.go::processEnrollment).
//
// All four codes appear in the troubleshooting matrix in
// docs/security.md::Production-grade security posture per the Phase
// 10 documentation deliverable.
const (
	// AuditActionCertExportPEM is emitted when ExportPEM succeeds.
	// Detail map carries: serial, has_private_key (always false in
	// V2 — cert-only export is the only V2 path), actor_kind.
	AuditActionCertExportPEM = "cert_export_pem"

	// AuditActionCertExportPEMWithKey is reserved for a future bundle
	// that adds a key-bearing PEM export path. V2 never emits this
	// constant; it exists in the type system so a future bundle
	// doesn't need to add a constant + a schema migration in the
	// same commit. Operators that want to alert on key-bearing
	// exports can configure the alert today and have it fire when
	// the future bundle ships.
	AuditActionCertExportPEMWithKey = "cert_export_pem_with_key"

	// AuditActionCertExportPKCS12 is emitted when ExportPKCS12
	// succeeds. Detail map carries: serial, has_private_key (always
	// false in V2 — the trust-store mode of pkcs12.Modern is the
	// only V2 path; cert+key bundle is a V3-Pro deferral), cipher
	// ("AES-256-CBC-PBE2" — the cipher pkcs12.Modern produces),
	// actor_kind.
	AuditActionCertExportPKCS12 = "cert_export_pkcs12"

	// AuditActionCertExportFailed is emitted when an export attempt
	// fails (any error path before the response is written). Detail
	// map carries: serial (when known), error (string form). Lets
	// operators alert on sustained export failures (corrupt cert
	// chain, missing version, repository error).
	AuditActionCertExportFailed = "cert_export_failed"
)

// Cipher identifier emitted in the PKCS#12 export audit detail.
// Pinned here so a future dependency upgrade that silently changes
// the underlying go-pkcs12 default is caught by the audit drift
// review (operator notices the value diverging from what's
// advertised in docs/security.md).
//
// pkcs12.Modern (the SSLMate library) produces AES-256-CBC PBE2
// with SHA-256 KDF. Documented in github.com/SSLMate/go-pkcs12 v0.7+.
const PKCS12CipherModernAES256 = "AES-256-CBC-PBE2-SHA256"
