// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildDirectory_FullMeta(t *testing.T) {
	d := BuildDirectory(
		"https://server/acme/profile/prof-corp",
		"https://example.com/tos",
		"https://example.com",
		[]string{"example.com"},
		true,
		false,
	)
	if got, want := d.NewNonce, "https://server/acme/profile/prof-corp/new-nonce"; got != want {
		t.Errorf("NewNonce = %q, want %q", got, want)
	}
	if got, want := d.NewAccount, "https://server/acme/profile/prof-corp/new-account"; got != want {
		t.Errorf("NewAccount = %q, want %q", got, want)
	}
	if got, want := d.NewOrder, "https://server/acme/profile/prof-corp/new-order"; got != want {
		t.Errorf("NewOrder = %q, want %q", got, want)
	}
	if got, want := d.RevokeCert, "https://server/acme/profile/prof-corp/revoke-cert"; got != want {
		t.Errorf("RevokeCert = %q, want %q", got, want)
	}
	if got, want := d.KeyChange, "https://server/acme/profile/prof-corp/key-change"; got != want {
		t.Errorf("KeyChange = %q, want %q", got, want)
	}
	if d.RenewalInfo != "" {
		t.Errorf("RenewalInfo should be empty when ariEnabled=false; got %q", d.RenewalInfo)
	}
	if d.Meta == nil {
		t.Fatal("Meta should be populated when any meta field is set")
	}
	if d.Meta.TermsOfService != "https://example.com/tos" {
		t.Errorf("TermsOfService = %q", d.Meta.TermsOfService)
	}
	if d.Meta.Website != "https://example.com" {
		t.Errorf("Website = %q", d.Meta.Website)
	}
	if !d.Meta.ExternalAccountRequired {
		t.Error("ExternalAccountRequired should be true")
	}
	if len(d.Meta.CAAIdentities) != 1 || d.Meta.CAAIdentities[0] != "example.com" {
		t.Errorf("CAAIdentities = %v", d.Meta.CAAIdentities)
	}
}

func TestBuildDirectory_NoMeta(t *testing.T) {
	d := BuildDirectory("https://server/acme/profile/prof-corp", "", "", nil, false, false)
	if d.Meta != nil {
		t.Errorf("Meta should be nil when all meta fields zero; got %+v", d.Meta)
	}
}

func TestBuildDirectory_EABRequiredOnly(t *testing.T) {
	d := BuildDirectory("https://server/acme/profile/prof-corp", "", "", nil, true, false)
	if d.Meta == nil {
		t.Fatal("Meta should be populated when EAB is required")
	}
	if !d.Meta.ExternalAccountRequired {
		t.Error("ExternalAccountRequired should be true")
	}
	if d.Meta.TermsOfService != "" || d.Meta.Website != "" || len(d.Meta.CAAIdentities) != 0 {
		t.Errorf("only EAB should be set; meta = %+v", d.Meta)
	}
}

func TestBuildDirectory_ARIEnabled(t *testing.T) {
	d := BuildDirectory("https://server/acme/profile/prof-corp", "", "", nil, false, true)
	if d.RenewalInfo == "" {
		t.Fatal("RenewalInfo should be populated when ariEnabled=true")
	}
	if !strings.HasSuffix(d.RenewalInfo, "/renewal-info") {
		t.Errorf("RenewalInfo = %q; expected suffix /renewal-info", d.RenewalInfo)
	}
}

func TestBuildDirectory_JSONShape(t *testing.T) {
	// RFC 8555 §7.1.1 dictates the JSON field names. A regression here
	// would break every ACME client.
	d := BuildDirectory("https://server/acme/profile/prof-corp", "", "", nil, false, false)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		`"newNonce":"https://server/acme/profile/prof-corp/new-nonce"`,
		`"newAccount":"https://server/acme/profile/prof-corp/new-account"`,
		`"newOrder":"https://server/acme/profile/prof-corp/new-order"`,
		`"revokeCert":"https://server/acme/profile/prof-corp/revoke-cert"`,
		`"keyChange":"https://server/acme/profile/prof-corp/key-change"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON missing %q\nGot: %s", want, got)
		}
	}
	// renewalInfo + meta should be omitted.
	if strings.Contains(got, "renewalInfo") {
		t.Errorf("renewalInfo should be omitted when ARI disabled; got %s", got)
	}
	if strings.Contains(got, `"meta"`) {
		t.Errorf("meta should be omitted when no fields set; got %s", got)
	}
}
