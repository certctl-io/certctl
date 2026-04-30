package nginx_test

import "encoding/base64"

// base64StdDecode is the test helper that nginx_atomic_test.go's
// fingerprintOfPEM calls. Kept in its own file so the std-library
// import is isolated from the bulk test file.
func base64StdDecode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
