package config

// Bundle O.2 (Coverage Audit Closure) — fuzz target for ParseNamedAPIKeys.
//
// ParseNamedAPIKeys is a hand-rolled parser for the
// CERTCTL_API_KEYS_NAMED env-var format ("name:key:admin,name2:key2").
// Hand-rolled parsers without fuzz coverage are a routine source of
// silent crashes — bundle O adds a target that pins "no panic on any
// input" + "either valid result or error".

import "testing"

func FuzzParseNamedAPIKeys(f *testing.F) {
	// Seed corpus covers the documented happy paths plus boundary cases:
	//   - simple name:key
	//   - name:key:admin (admin flag)
	//   - dual-key rotation (same name, two keys)
	//   - empty
	//   - ":" / "name:" / ":key" (degenerate)
	//   - whitespace
	//   - admin flag spelling variants
	//   - extra colons (4-segment input)
	seeds := []string{
		"alice:KEY1:admin",
		"alice:OLD:admin,alice:NEW:admin",
		"alice:OLD,alice:NEW",
		"",
		":",
		"name:",
		":key",
		"   alice : KEY1 : admin   ",
		"alice:KEY1:Admin",     // wrong-case admin (rejected)
		"alice:KEY1:not-admin", // wrong word (rejected)
		"a:b:c:d",              // 4 segments (rejected)
		"alice:KEY1,bob:KEY2,charlie:KEY3:admin",
		// Adversarial: name with characters that should be rejected
		"al/ice:KEY1",
		"al ice:KEY1",
		"alice@host:KEY1",
		// Long input
		"verylongkeynameabcdefghijklmnopqrstuvwxyz1234567890:long-key-value-1234567890abcdef:admin",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Invariant: must not panic. Either returns a valid []NamedAPIKey
		// or an error. The function is allowed to produce an empty result
		// for whitespace-only or comma-only inputs.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %q: %v", input, r)
			}
		}()
		_, _ = ParseNamedAPIKeys(input)
	})
}
