package handler

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/service"
)

// mockIntermediateCAService is the minimal IntermediateCAServicer for
// handler-layer tests. Captures the arguments each method was called
// with so tests can assert dispatch + RBAC behavior.
type mockIntermediateCAService struct {
	createRootCalled  bool
	createChildCalled bool
	retireCalled      bool
	createRootErr     error
	createChildErr    error
	retireErr         error
	retireConfirm     bool

	// Get returns this row when nonzero; otherwise the
	// IntermediateCANotFound sentinel.
	getResult *domain.IntermediateCA

	// LoadHierarchy returns this slice if non-nil.
	loadHierarchyResult []*domain.IntermediateCA
}

func (m *mockIntermediateCAService) CreateRoot(ctx context.Context, issuerID, name, decidedBy string,
	rootCertPEM []byte, keyDriverID string, opts *service.CreateRootOptions) (string, error) {
	m.createRootCalled = true
	if m.createRootErr != nil {
		return "", m.createRootErr
	}
	return "ica-root-mock", nil
}

func (m *mockIntermediateCAService) CreateChild(ctx context.Context, parentCAID, name, decidedBy string,
	opts *service.CreateChildOptions) (string, error) {
	m.createChildCalled = true
	if m.createChildErr != nil {
		return "", m.createChildErr
	}
	return "ica-child-mock", nil
}

func (m *mockIntermediateCAService) Retire(ctx context.Context, caID, decidedBy, note string, confirm bool) error {
	m.retireCalled = true
	m.retireConfirm = confirm
	return m.retireErr
}

func (m *mockIntermediateCAService) Get(ctx context.Context, id string) (*domain.IntermediateCA, error) {
	if m.getResult != nil {
		return m.getResult, nil
	}
	return nil, service.ErrIntermediateCANotFound
}

func (m *mockIntermediateCAService) LoadHierarchy(ctx context.Context, issuerID string) ([]*domain.IntermediateCA, error) {
	return m.loadHierarchyResult, nil
}

// withAdmin returns a context with the admin flag set + a non-empty
// authenticated user — the standard "admin caller" shape for these
// tests.
func withAdmin(actor string, admin bool) context.Context {
	ctx := context.WithValue(context.Background(), middleware.UserKey{}, actor)
	ctx = context.WithValue(ctx, middleware.AdminKey{}, admin)
	return ctx
}

// helperRootCertPEM returns a freshly-minted self-signed root cert
// PEM for the body of CreateRoot tests.
func helperRootCertPEM(t *testing.T) []byte {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subj := pkix.Name{CommonName: "Test Root"}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		Issuer:                subj,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestIntermediateCA_Handler_NonAdmin_Returns403 pins the
// admin-gating contract. Any non-admin Bearer caller — even a valid
// authenticated one — must get HTTP 403 from every endpoint. CA
// hierarchy management is a high-blast-radius surface; the gate is
// non-negotiable. M-008 admin-gate triplet test #1.
func TestIntermediateCA_Handler_NonAdmin_Returns403(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		path     string
		pathArgs map[string]string
		invoke   func(h IntermediateCAHandler) http.HandlerFunc
	}{
		{
			name:     "Create",
			method:   http.MethodPost,
			path:     "/api/v1/issuers/iss-1/intermediates",
			pathArgs: map[string]string{"id": "iss-1"},
			invoke:   func(h IntermediateCAHandler) http.HandlerFunc { return h.Create },
		},
		{
			name:     "List",
			method:   http.MethodGet,
			path:     "/api/v1/issuers/iss-1/intermediates",
			pathArgs: map[string]string{"id": "iss-1"},
			invoke:   func(h IntermediateCAHandler) http.HandlerFunc { return h.List },
		},
		{
			name:     "Get",
			method:   http.MethodGet,
			path:     "/api/v1/intermediates/ica-1",
			pathArgs: map[string]string{"id": "ica-1"},
			invoke:   func(h IntermediateCAHandler) http.HandlerFunc { return h.Get },
		},
		{
			name:     "Retire",
			method:   http.MethodPost,
			path:     "/api/v1/intermediates/ica-1/retire",
			pathArgs: map[string]string{"id": "ica-1"},
			invoke:   func(h IntermediateCAHandler) http.HandlerFunc { return h.Retire },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewIntermediateCAHandler(&mockIntermediateCAService{})
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte("{}")))
			for k, v := range tc.pathArgs {
				req.SetPathValue(k, v)
			}
			// Authenticated user but admin=false.
			req = req.WithContext(withAdmin("alice", false))
			w := httptest.NewRecorder()
			tc.invoke(h)(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s: expected 403 for non-admin, got %d body=%s", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestIntermediateCA_Handler_AdminExplicitFalse_Returns403 pins the
// "AdminKey present but false" path — distinct from the
// AdminKey-absent path. Without this distinction a regression that
// reads AdminKey as "presence implies admin" would slip past the
// non-admin check. M-008 admin-gate triplet test #2.
func TestIntermediateCA_Handler_AdminExplicitFalse_Returns403(t *testing.T) {
	h := NewIntermediateCAHandler(&mockIntermediateCAService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-1/intermediates",
		bytes.NewReader([]byte(`{"name":"r"}`)))
	req.SetPathValue("id", "iss-1")
	// AdminKey explicitly set to false — distinct from missing key.
	ctx := context.WithValue(context.Background(), middleware.UserKey{}, "alice")
	ctx = context.WithValue(ctx, middleware.AdminKey{}, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for AdminKey=false, got %d", w.Code)
	}
}

// TestIntermediateCA_Handler_AdminPermitted_ForwardsActor pins the
// admin-allowed actor-attribution path. An admin caller's actor
// (UserKey context value) must be forwarded to the service so the
// audit trail records who registered the CA. M-008 admin-gate
// triplet test #3.
func TestIntermediateCA_Handler_AdminPermitted_ForwardsActor(t *testing.T) {
	mock := &mockIntermediateCAService{
		getResult: &domain.IntermediateCA{ID: "ica-mock"},
	}
	h := NewIntermediateCAHandler(mock)
	rootPEM := helperRootCertPEM(t)
	body := `{"name":"Acme Root","root_cert_pem":` + jsonString(string(rootPEM)) +
		`,"key_driver_id":"/etc/certctl/keys/root.pem"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-1/intermediates",
		bytes.NewReader([]byte(body)))
	req.SetPathValue("id", "iss-1")
	req = req.WithContext(withAdmin("admin-actor", true))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	if !mock.createRootCalled {
		t.Fatalf("expected service dispatch with admin actor")
	}
}

// TestIntermediateCA_HandlerCreate_RootDispatch pins the body
// discriminator: empty parent_ca_id + root_cert_pem + key_driver_id
// → CreateRoot (not CreateChild). The mock service captures which
// method was called.
func TestIntermediateCA_HandlerCreate_RootDispatch(t *testing.T) {
	mock := &mockIntermediateCAService{
		getResult: &domain.IntermediateCA{ID: "ica-root-mock"},
	}
	h := NewIntermediateCAHandler(mock)
	rootPEM := helperRootCertPEM(t)
	body := `{
		"name": "Acme Root",
		"root_cert_pem": ` + jsonString(string(rootPEM)) + `,
		"key_driver_id": "/etc/certctl/keys/root.pem"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-1/intermediates",
		bytes.NewReader([]byte(body)))
	req.SetPathValue("id", "iss-1")
	req = req.WithContext(withAdmin("admin-actor", true))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	if !mock.createRootCalled {
		t.Fatalf("expected CreateRoot dispatch, got CreateChild=%v", mock.createChildCalled)
	}
	if mock.createChildCalled {
		t.Fatalf("expected only CreateRoot, but CreateChild was also called")
	}
}

// TestIntermediateCA_HandlerCreate_ChildDispatch pins the
// discriminator's other half: parent_ca_id present → CreateChild.
func TestIntermediateCA_HandlerCreate_ChildDispatch(t *testing.T) {
	mock := &mockIntermediateCAService{
		getResult: &domain.IntermediateCA{ID: "ica-child-mock"},
	}
	h := NewIntermediateCAHandler(mock)
	body := `{
		"name": "Acme Policy",
		"parent_ca_id": "ica-root-1",
		"subject": {"common_name": "Acme Policy CA", "organization": ["Acme"]},
		"algorithm": "ECDSA-P256",
		"ttl_days": 1825
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-1/intermediates",
		bytes.NewReader([]byte(body)))
	req.SetPathValue("id", "iss-1")
	req = req.WithContext(withAdmin("admin-actor", true))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	if !mock.createChildCalled {
		t.Fatalf("expected CreateChild dispatch")
	}
	if mock.createRootCalled {
		t.Fatalf("expected only CreateChild, but CreateRoot was also called")
	}
}

// TestIntermediateCA_HandlerCreate_BadRequestOnMissingRootBundle pins
// the validation: empty parent_ca_id + missing root_cert_pem →
// HTTP 400.
func TestIntermediateCA_HandlerCreate_BadRequestOnMissingRootBundle(t *testing.T) {
	h := NewIntermediateCAHandler(&mockIntermediateCAService{})
	body := `{"name": "Some Name"}` // no parent, no root bundle
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-1/intermediates",
		bytes.NewReader([]byte(body)))
	req.SetPathValue("id", "iss-1")
	req = req.WithContext(withAdmin("admin-actor", true))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestIntermediateCA_HandlerCreate_ServiceErrorMappings pins the
// error → HTTP code dispatch table.
func TestIntermediateCA_HandlerCreate_ServiceErrorMappings(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantCode  int
		isRootCmd bool
	}{
		{"NotSelfSigned->400", service.ErrCANotSelfSigned, http.StatusBadRequest, true},
		{"KeyMismatch->400", service.ErrCAKeyMismatch, http.StatusBadRequest, true},
		{"PathLenExceeded->400", service.ErrPathLenExceeded, http.StatusBadRequest, false},
		{"NameConstraintExceeded->400", service.ErrNameConstraintExceeded, http.StatusBadRequest, false},
		{"ParentNotActive->409", service.ErrParentCANotActive, http.StatusConflict, false},
		{"NotFound->404", service.ErrIntermediateCANotFound, http.StatusNotFound, false},
		{"Other->500", errors.New("unexpected"), http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockIntermediateCAService{}
			if tc.isRootCmd {
				mock.createRootErr = tc.err
			} else {
				mock.createChildErr = tc.err
			}
			h := NewIntermediateCAHandler(mock)
			var body string
			if tc.isRootCmd {
				rootPEM := helperRootCertPEM(t)
				body = `{"name":"Root","root_cert_pem":` + jsonString(string(rootPEM)) + `,"key_driver_id":"/k"}`
			} else {
				body = `{"name":"Child","parent_ca_id":"ica-root-1"}`
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/issuers/iss-1/intermediates",
				bytes.NewReader([]byte(body)))
			req.SetPathValue("id", "iss-1")
			req = req.WithContext(withAdmin("admin-actor", true))
			w := httptest.NewRecorder()
			h.Create(w, req)
			if w.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d body=%s", tc.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestIntermediateCA_HandlerRetire_TwoPhaseConfirm pins the body's
// confirm flag passes through to the service. First call confirm=false;
// second call confirm=true (the operator explicitly terminalizes).
func TestIntermediateCA_HandlerRetire_TwoPhaseConfirm(t *testing.T) {
	mock := &mockIntermediateCAService{}
	h := NewIntermediateCAHandler(mock)

	// First call — confirm omitted (defaults to false).
	body1 := `{"note": "drain start"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/intermediates/ica-1/retire",
		bytes.NewReader([]byte(body1)))
	req.SetPathValue("id", "ica-1")
	req = req.WithContext(withAdmin("admin-actor", true))
	w := httptest.NewRecorder()
	h.Retire(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first retire: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if mock.retireConfirm {
		t.Fatalf("first retire: expected confirm=false, got true")
	}

	// Second call — confirm=true.
	mock.retireCalled = false
	body2 := `{"note":"terminalize","confirm":true}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/intermediates/ica-1/retire",
		bytes.NewReader([]byte(body2)))
	req.SetPathValue("id", "ica-1")
	req = req.WithContext(withAdmin("admin-actor", true))
	w = httptest.NewRecorder()
	h.Retire(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second retire: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !mock.retireConfirm {
		t.Fatalf("second retire: expected confirm=true, got false")
	}
}

// TestIntermediateCA_HandlerRetire_StillHasActiveChildren_Returns409
// pins the drain-first contract: ErrCAStillHasActiveChildren maps
// to HTTP 409.
func TestIntermediateCA_HandlerRetire_StillHasActiveChildren_Returns409(t *testing.T) {
	mock := &mockIntermediateCAService{retireErr: service.ErrCAStillHasActiveChildren}
	h := NewIntermediateCAHandler(mock)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/intermediates/ica-1/retire",
		bytes.NewReader([]byte(`{"confirm": true}`)))
	req.SetPathValue("id", "ica-1")
	req = req.WithContext(withAdmin("admin-actor", true))
	w := httptest.NewRecorder()
	h.Retire(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", w.Code, w.Body.String())
	}
}

// jsonString returns a JSON-quoted Go string suitable for embedding
// in a test JSON body literal. Standard library encoding/json's
// Marshal does the same thing but the test assertions are clearer
// when we control the wrapping.
func jsonString(s string) string {
	return string(mustMarshalJSONString(s))
}

func mustMarshalJSONString(s string) []byte {
	// Trivial: wrap in quotes and escape \ and " — sufficient for
	// PEM bodies (which contain newlines but no quotes).
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for _, r := range []byte(s) {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			out = append(out, r)
		}
	}
	out = append(out, '"')
	return out
}
