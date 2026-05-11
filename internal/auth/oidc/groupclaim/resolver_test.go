package groupclaim

import (
	"errors"
	"reflect"
	"testing"
)

// =============================================================================
// Happy-path tests covering the documented IdP shapes.
// =============================================================================

// TestResolve_OktaStyleStringArray pins the most common shape:
// {"groups": ["engineers", "platform-admins"]}.
func TestResolve_OktaStyleStringArray(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{"engineers", "platform-admins"},
	}
	got, err := Resolve(claims, "groups")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"engineers", "platform-admins"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestResolve_KeycloakNestedRoles pins the dot-path walk:
// {"realm_access": {"roles": ["admin", "user"]}}.
func TestResolve_KeycloakNestedRoles(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
	}
	got, err := Resolve(claims, "realm_access.roles")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"admin", "user"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestResolve_Auth0NamespacedClaim pins the URL-shape literal-key path:
// {"https://your-namespace/groups": ["engineers"]}.
func TestResolve_Auth0NamespacedClaim(t *testing.T) {
	claims := map[string]interface{}{
		"https://your-namespace/groups": []interface{}{"engineers"},
	}
	got, err := Resolve(claims, "https://your-namespace/groups")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"engineers"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestResolve_HTTPSchemeAlsoTreatedAsLiteral pins that http:// (not just
// https://) triggers the URL-shape path treatment. Some on-prem IdPs
// use http for namespaced claims in dev environments.
func TestResolve_HTTPSchemeAlsoTreatedAsLiteral(t *testing.T) {
	claims := map[string]interface{}{
		"http://internal.example.com/groups": []interface{}{"role-a"},
	}
	got, err := Resolve(claims, "http://internal.example.com/groups")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0] != "role-a" {
		t.Errorf("got %v, want [role-a]", got)
	}
}

// TestResolve_SingleStringWrapped pins the normalization: some IdPs
// return a single role as a bare string rather than a one-element
// array. The resolver wraps it.
func TestResolve_SingleStringWrapped(t *testing.T) {
	claims := map[string]interface{}{
		"role": "admin",
	}
	got, err := Resolve(claims, "role")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"admin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestResolve_AlreadyStringSlice covers the rare case where a caller
// pre-coerced []interface{} to []string. The resolver returns a copy.
func TestResolve_AlreadyStringSlice(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []string{"a", "b"},
	}
	got, err := Resolve(claims, "groups")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("got %v, want [a b]", got)
	}
	// Mutating the result must NOT mutate the input claim.
	got[0] = "MUTATED"
	if claims["groups"].([]string)[0] == "MUTATED" {
		t.Errorf("Resolve returned a slice aliased to the input; mutation leaked back")
	}
}

// TestResolve_EmptyArrayReturnsEmpty pins the documented edge: an IdP
// that returns an empty groups claim is NOT a resolver error; the
// caller (Phase 3 service) decides fail-closed semantics.
func TestResolve_EmptyArrayReturnsEmpty(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{},
	}
	got, err := Resolve(claims, "groups")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want []", got)
	}
}

// TestResolve_DeeplyNestedPath pins a 3-segment walk works.
func TestResolve_DeeplyNestedPath(t *testing.T) {
	claims := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": []interface{}{"deep"},
			},
		},
	}
	got, err := Resolve(claims, "a.b.c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0] != "deep" {
		t.Errorf("got %v, want [deep]", got)
	}
}

// =============================================================================
// Negative paths — every fail-closed branch.
// =============================================================================

func TestResolve_EmptyPathRejected(t *testing.T) {
	_, err := Resolve(map[string]interface{}{"groups": []interface{}{"x"}}, "")
	if !errors.Is(err, ErrPathEmpty) {
		t.Errorf("err = %v; want ErrPathEmpty", err)
	}
}

func TestResolve_MissingKeyRejected(t *testing.T) {
	claims := map[string]interface{}{"other": "thing"}
	_, err := Resolve(claims, "groups")
	if !errors.Is(err, ErrSegmentMissing) {
		t.Errorf("err = %v; want ErrSegmentMissing", err)
	}
}

func TestResolve_MissingNestedKeyRejected(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{"other": "thing"},
	}
	_, err := Resolve(claims, "realm_access.roles")
	if !errors.Is(err, ErrSegmentMissing) {
		t.Errorf("err = %v; want ErrSegmentMissing", err)
	}
}

func TestResolve_NonObjectIntermediateRejected(t *testing.T) {
	// "realm_access" resolves to a string, not an object; can't walk
	// further into it.
	claims := map[string]interface{}{
		"realm_access": "not-an-object",
	}
	_, err := Resolve(claims, "realm_access.roles")
	if !errors.Is(err, ErrSegmentNotObject) {
		t.Errorf("err = %v; want ErrSegmentNotObject", err)
	}
}

func TestResolve_RejectsBoolValue(t *testing.T) {
	claims := map[string]interface{}{"groups": true}
	_, err := Resolve(claims, "groups")
	if !errors.Is(err, ErrInvalidValueType) {
		t.Errorf("err = %v; want ErrInvalidValueType", err)
	}
}

func TestResolve_RejectsNumberValue(t *testing.T) {
	claims := map[string]interface{}{"groups": 42}
	_, err := Resolve(claims, "groups")
	if !errors.Is(err, ErrInvalidValueType) {
		t.Errorf("err = %v; want ErrInvalidValueType", err)
	}
}

func TestResolve_RejectsObjectValue(t *testing.T) {
	claims := map[string]interface{}{"groups": map[string]interface{}{"x": "y"}}
	_, err := Resolve(claims, "groups")
	if !errors.Is(err, ErrInvalidValueType) {
		t.Errorf("err = %v; want ErrInvalidValueType", err)
	}
}

func TestResolve_RejectsNilValue(t *testing.T) {
	claims := map[string]interface{}{"groups": nil}
	_, err := Resolve(claims, "groups")
	if !errors.Is(err, ErrInvalidValueType) {
		t.Errorf("err = %v; want ErrInvalidValueType", err)
	}
}

func TestResolve_RejectsArrayWithNonStringElement(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{"a", 42, "c"}, // 42 is not a string
	}
	_, err := Resolve(claims, "groups")
	if !errors.Is(err, ErrInvalidValueType) {
		t.Errorf("err = %v; want ErrInvalidValueType", err)
	}
}

// TestResolve_URLShapeWithDotsInPathTreatedAsLiteral pins the
// disambiguation: a URL-shape path like
// `https://example.com/team.id` must NOT be split on the dot in
// "team.id"; it's a single literal key.
func TestResolve_URLShapeWithDotsInPathTreatedAsLiteral(t *testing.T) {
	claims := map[string]interface{}{
		"https://example.com/team.id": []interface{}{"sales"},
	}
	got, err := Resolve(claims, "https://example.com/team.id")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0] != "sales" {
		t.Errorf("got %v, want [sales]", got)
	}
}
