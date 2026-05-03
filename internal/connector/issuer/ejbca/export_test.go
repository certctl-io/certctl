package ejbca

import "net/http"

// HTTPClientForTest exposes the connector's internal *http.Client to the
// external ejbca_test package. The mTLS-wiring tests need to inspect
// Transport.TLSClientConfig.Certificates to assert the cert was loaded;
// that field is unexported, so we provide this test-only accessor.
//
// The "_test.go" suffix means this file is only compiled during `go test`,
// so production builds don't expose the internal httpClient field.
func HTTPClientForTest(c *Connector) *http.Client {
	return c.httpClient
}

// GetHTTPClientForTest exposes the per-call hot-path getHTTPClient
// helper so the rotation test can drive the production code path
// (which calls RefreshIfStale on the mtls cache before returning
// the client). Production callers reach this same path implicitly
// via IssueCertificate / RevokeCertificate / GetOrderStatus.
func GetHTTPClientForTest(c *Connector) (*http.Client, error) {
	return c.getHTTPClient()
}
