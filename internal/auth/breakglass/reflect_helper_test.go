package breakglass

import (
	"encoding/json"
	"reflect"
)

// reflectJSONTag returns the `json` struct tag for the named field on
// v. Pins that BreakglassCredential.PasswordHash carries `json:"-"`
// so a misconfigured handler that marshals the row directly cannot
// wire-leak the Argon2id hash. Test-only.
func reflectJSONTag(v interface{}, fieldName string) string {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return ""
	}
	field, ok := rv.Type().FieldByName(fieldName)
	if !ok {
		return ""
	}
	return field.Tag.Get("json")
}

// jsonMarshalImpl is the test-only json.Marshal wrapper used by the
// PasswordHash JSON-tag belt-and-braces test in service_test.go.
func jsonMarshalImpl(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
