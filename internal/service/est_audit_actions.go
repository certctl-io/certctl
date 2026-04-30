package service

// EST RFC 7030 hardening master bundle Phase 11.3 — typed audit action
// codes. Each maps to a unique counter label so operators grep the
// audit log on these exact strings.
//
// Naming contract: every code is `est_<flow>_<outcome>` where
//
//	<flow>    = simple_enroll | simple_reenroll | server_keygen | auth_failed_<mode> | rate_limited | csr_policy_violation | bulk_revoke | trust_anchor_reloaded
//	<outcome> = success | failed   (only on the three success/failure-paired flows)
//
// Pre-Phase-11 the audit log carried bare action codes (est_simple_enroll
// without the _success suffix). The GUI activity-tab filter chips
// (web/src/pages/ESTAdminPage.tsx) match by `startsWith()` after the
// Phase 11 cutover so both old + new strings continue to render under
// the right chip.
const (
	// Three success/failure-paired enrollment flows. The success codes
	// share a prefix with the legacy bare codes so a deployment running
	// the old audit-log analyser continues to find every enrollment.
	AuditActionESTSimpleEnrollSuccess   = "est_simple_enroll_success"
	AuditActionESTSimpleEnrollFailed    = "est_simple_enroll_failed"
	AuditActionESTSimpleReEnrollSuccess = "est_simple_reenroll_success"
	AuditActionESTSimpleReEnrollFailed  = "est_simple_reenroll_failed"
	AuditActionESTServerKeygenSuccess   = "est_server_keygen_success"
	AuditActionESTServerKeygenFailed    = "est_server_keygen_failed"

	// Per-mode auth-failure codes. Emitted by the handler at the auth-
	// gate trip points so operators can filter "Basic-auth failures
	// from this source IP" cleanly.
	AuditActionESTAuthFailedBasic          = "est_auth_failed_basic"
	AuditActionESTAuthFailedMTLS           = "est_auth_failed_mtls"
	AuditActionESTAuthFailedChannelBinding = "est_auth_failed_channel_binding"

	// Operational events.
	AuditActionESTRateLimited         = "est_rate_limited"
	AuditActionESTCSRPolicyViolation  = "est_csr_policy_violation"
	AuditActionESTBulkRevoke          = "est_bulk_revoke"
	AuditActionESTTrustAnchorReloaded = "est_trust_anchor_reloaded"
)
