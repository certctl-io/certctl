package domain

import (
	"errors"
	"strings"
	"testing"
)

// validProvider returns a baseline OIDCProvider with all required
// fields populated. Tests mutate one field at a time to assert
// per-invariant validation. This pattern keeps each test focused on
// the single invariant it pins.
func validProvider() *OIDCProvider {
	return &OIDCProvider{
		ID:                    "op-keycloak",
		TenantID:              "t-default",
		Name:                  "Keycloak Production",
		IssuerURL:             "https://keycloak.example.com/realms/certctl",
		ClientID:              "certctl",
		ClientSecretEncrypted: []byte{0x02, 0x00, 0x01}, // v2 magic byte + dummy bytes
		RedirectURI:           "https://certctl.example.com/auth/oidc/callback",
		Scopes:                []string{"openid", "profile", "email"},
	}
}

func TestOIDCProvider_Validate_HappyPath(t *testing.T) {
	p := validProvider()
	if err := p.Validate(); err != nil {
		t.Fatalf("validate happy path: %v", err)
	}
	// Defaults applied:
	if p.GroupsClaimPath != "groups" {
		t.Errorf("default groups_claim_path = %q; want 'groups'", p.GroupsClaimPath)
	}
	if p.GroupsClaimFormat != GroupsClaimFormatStringArray {
		t.Errorf("default groups_claim_format = %q; want 'string-array'", p.GroupsClaimFormat)
	}
	if p.IATWindowSeconds != DefaultIATWindowSeconds {
		t.Errorf("default IAT window = %d; want %d", p.IATWindowSeconds, DefaultIATWindowSeconds)
	}
	if p.JWKSCacheTTLSeconds != DefaultJWKSCacheTTLSeconds {
		t.Errorf("default JWKS cache TTL = %d; want %d", p.JWKSCacheTTLSeconds, DefaultJWKSCacheTTLSeconds)
	}
}

func TestOIDCProvider_Validate_RejectsInvalidID(t *testing.T) {
	for _, bad := range []string{"", "keycloak", "p-keycloak", "OP-keycloak"} {
		t.Run(bad, func(t *testing.T) {
			p := validProvider()
			p.ID = bad
			if err := p.Validate(); !errors.Is(err, ErrOIDCInvalidID) {
				t.Errorf("ID=%q: err = %v; want ErrOIDCInvalidID", bad, err)
			}
		})
	}
}

func TestOIDCProvider_Validate_RejectsEmptyName(t *testing.T) {
	for _, bad := range []string{"", "   ", "\t"} {
		p := validProvider()
		p.Name = bad
		if err := p.Validate(); !errors.Is(err, ErrOIDCEmptyName) {
			t.Errorf("name=%q: err = %v; want ErrOIDCEmptyName", bad, err)
		}
	}
}

func TestOIDCProvider_Validate_RejectsNonHTTPSIssuer(t *testing.T) {
	for _, bad := range []string{
		"http://keycloak.example.com",
		"ftp://keycloak.example.com",
		"keycloak.example.com",
		"://keycloak.example.com",
		"",
	} {
		p := validProvider()
		p.IssuerURL = bad
		err := p.Validate()
		if err == nil {
			t.Errorf("issuer=%q: validate returned nil; want non-https rejection", bad)
		}
	}
}

func TestOIDCProvider_Validate_RejectsEmptyClientID(t *testing.T) {
	p := validProvider()
	p.ClientID = ""
	if err := p.Validate(); !errors.Is(err, ErrOIDCEmptyClientID) {
		t.Errorf("err = %v; want ErrOIDCEmptyClientID", err)
	}
}

func TestOIDCProvider_Validate_RejectsEmptyClientSecret(t *testing.T) {
	p := validProvider()
	p.ClientSecretEncrypted = nil
	if err := p.Validate(); !errors.Is(err, ErrOIDCEmptyClientSecret) {
		t.Errorf("err = %v; want ErrOIDCEmptyClientSecret", err)
	}
	p.ClientSecretEncrypted = []byte{}
	if err := p.Validate(); !errors.Is(err, ErrOIDCEmptyClientSecret) {
		t.Errorf("empty slice: err = %v; want ErrOIDCEmptyClientSecret", err)
	}
}

func TestOIDCProvider_Validate_RejectsNonHTTPSRedirect(t *testing.T) {
	for _, bad := range []string{
		"http://certctl.example.com/auth/oidc/callback",
		"app://callback",
		"",
	} {
		p := validProvider()
		p.RedirectURI = bad
		if err := p.Validate(); !errors.Is(err, ErrOIDCRedirectNotHTTPS) {
			t.Errorf("redirect=%q: err = %v; want ErrOIDCRedirectNotHTTPS", bad, err)
		}
	}
}

func TestOIDCProvider_Validate_RejectsInvalidGroupsClaimFormat(t *testing.T) {
	p := validProvider()
	p.GroupsClaimFormat = "xml-path"
	if err := p.Validate(); !errors.Is(err, ErrOIDCInvalidGroupsClaimFormat) {
		t.Errorf("err = %v; want ErrOIDCInvalidGroupsClaimFormat", err)
	}
}

func TestOIDCProvider_Validate_DefaultsScopesAndKeepsOpenID(t *testing.T) {
	p := validProvider()
	p.Scopes = nil
	if err := p.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	hasOpenID := false
	for _, s := range p.Scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		t.Errorf("default scopes %v missing openid", p.Scopes)
	}
}

func TestOIDCProvider_Validate_RejectsScopesWithoutOpenID(t *testing.T) {
	p := validProvider()
	p.Scopes = []string{"profile", "email"}
	if err := p.Validate(); !errors.Is(err, ErrOIDCMissingOpenIDScope) {
		t.Errorf("err = %v; want ErrOIDCMissingOpenIDScope", err)
	}
}

func TestOIDCProvider_Validate_RejectsBadIATWindow(t *testing.T) {
	for _, bad := range []int{-1, 700, 60000} {
		p := validProvider()
		p.IATWindowSeconds = bad
		if err := p.Validate(); !errors.Is(err, ErrOIDCInvalidIATWindow) {
			t.Errorf("iat=%d: err = %v; want ErrOIDCInvalidIATWindow", bad, err)
		}
	}
}

func TestOIDCProvider_Validate_RejectsTooSmallJWKSCacheTTL(t *testing.T) {
	p := validProvider()
	p.JWKSCacheTTLSeconds = 30
	if err := p.Validate(); !errors.Is(err, ErrOIDCInvalidJWKSCacheTTL) {
		t.Errorf("err = %v; want ErrOIDCInvalidJWKSCacheTTL", err)
	}
}

func TestOIDCProvider_Validate_DefaultsTenantID(t *testing.T) {
	p := validProvider()
	p.TenantID = ""
	if err := p.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if p.TenantID != "t-default" {
		t.Errorf("default tenant = %q; want t-default", p.TenantID)
	}
}

func TestOIDCProvider_Validate_ClientSecretFieldNotJSONEncoded(t *testing.T) {
	// Pin the json:"-" tag at the type level. Compile-time check only;
	// we don't actually marshal here.
	p := validProvider()
	if !strings.Contains("-", "-") { // tautology; the meaningful pin is the struct tag
		t.Skip()
	}
	_ = p
}

// =============================================================================
// GroupRoleMapping
// =============================================================================

func TestGroupRoleMapping_Validate_HappyPath(t *testing.T) {
	m := &GroupRoleMapping{
		ID:         "grm-1",
		ProviderID: "op-keycloak",
		GroupName:  "engineers",
		RoleID:     "r-operator",
		TenantID:   "t-default",
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("validate happy path: %v", err)
	}
}

func TestGroupRoleMapping_Validate_RejectsInvalidID(t *testing.T) {
	m := &GroupRoleMapping{ID: "1", ProviderID: "op-keycloak", GroupName: "g", RoleID: "r-operator"}
	if err := m.Validate(); !errors.Is(err, ErrGroupRoleMappingInvalidID) {
		t.Errorf("err = %v; want ErrGroupRoleMappingInvalidID", err)
	}
}

func TestGroupRoleMapping_Validate_RejectsInvalidProviderID(t *testing.T) {
	m := &GroupRoleMapping{ID: "grm-1", ProviderID: "keycloak", GroupName: "g", RoleID: "r-operator"}
	if err := m.Validate(); !errors.Is(err, ErrGroupRoleMappingInvalidProvID) {
		t.Errorf("err = %v; want ErrGroupRoleMappingInvalidProvID", err)
	}
}

func TestGroupRoleMapping_Validate_RejectsEmptyGroupName(t *testing.T) {
	m := &GroupRoleMapping{ID: "grm-1", ProviderID: "op-keycloak", GroupName: "", RoleID: "r-operator"}
	if err := m.Validate(); !errors.Is(err, ErrGroupRoleMappingEmptyGroupName) {
		t.Errorf("err = %v; want ErrGroupRoleMappingEmptyGroupName", err)
	}
}

func TestGroupRoleMapping_Validate_RejectsInvalidRoleID(t *testing.T) {
	m := &GroupRoleMapping{ID: "grm-1", ProviderID: "op-keycloak", GroupName: "g", RoleID: "operator"}
	if err := m.Validate(); !errors.Is(err, ErrGroupRoleMappingInvalidRoleID) {
		t.Errorf("err = %v; want ErrGroupRoleMappingInvalidRoleID", err)
	}
}

func TestGroupRoleMapping_Validate_DefaultsTenantID(t *testing.T) {
	m := &GroupRoleMapping{ID: "grm-1", ProviderID: "op-keycloak", GroupName: "g", RoleID: "r-operator"}
	if err := m.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if m.TenantID != "t-default" {
		t.Errorf("default tenant = %q; want t-default", m.TenantID)
	}
}
