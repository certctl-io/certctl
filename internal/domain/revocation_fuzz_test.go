package domain

import (
	"testing"
)

func FuzzIsValidRevocationReason(f *testing.F) {
	f.Add("keyCompromise")
	f.Add("unspecified")
	f.Add("caCompromise")
	f.Add("affiliationChanged")
	f.Add("superseded")
	f.Add("cessationOfOperation")
	f.Add("certificateHold")
	f.Add("privilegeWithdrawn")
	f.Add("")
	f.Add("invalid-reason")
	f.Add("KeyCompromise")
	f.Add("key_compromise")
	f.Add("KEY_COMPROMISE")
	f.Add("keycompromise")
	f.Add("reason; DROP TABLE")
	f.Add("reason\" OR \"1\"=\"1")
	f.Add("unspecified\x00injection")
	f.Fuzz(func(t *testing.T, reason string) {
		// Should never panic, only return bool
		_ = IsValidRevocationReason(reason)
	})
}

func FuzzCRLReasonCode(f *testing.F) {
	f.Add("keyCompromise")
	f.Add("unspecified")
	f.Add("caCompromise")
	f.Add("affiliationChanged")
	f.Add("superseded")
	f.Add("cessationOfOperation")
	f.Add("certificateHold")
	f.Add("privilegeWithdrawn")
	f.Add("")
	f.Add("invalid-reason")
	f.Add("reason\" OR \"1\"=\"1")
	f.Fuzz(func(t *testing.T, reason string) {
		// Should never panic, always return a reasonable code
		code := CRLReasonCode(RevocationReason(reason))
		// Valid codes should be 0-9 with gaps (no 7, no 8)
		if code < 0 || code > 9 {
			t.Errorf("CRLReasonCode returned invalid code: %d", code)
		}
		// For invalid reason, should default to 0
		if !IsValidRevocationReason(reason) && code != 0 {
			t.Errorf("CRLReasonCode should return 0 for invalid reason %q, got %d", reason, code)
		}
	})
}
