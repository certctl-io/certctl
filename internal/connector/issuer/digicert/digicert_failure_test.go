package digicert_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer/digicert"
)

// Bundle N.A/B-extended: digicert failure-mode round-out (81.0% → ≥85%).
// Targets GetOrderStatus / downloadCertificate / parsePEMBundle uncovered
// branches.

func buildDigicertConnector(t *testing.T, baseURL string) *digicert.Connector {
	t.Helper()
	c := digicert.New(nil, slog.Default())
	cfg := digicert.Config{APIKey: "k", OrgID: "1", ProductType: "ssl_basic", BaseURL: baseURL}
	raw, _ := json.Marshal(cfg)
	if err := c.ValidateConfig(context.Background(), raw); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	return c
}

func TestDigicert_GetOrderStatus_404_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user/me":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"code":"order_not_found"}]}`))
		}
	}))
	defer srv.Close()
	c := buildDigicertConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "missing-order")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 error, got %v", err)
	}
}

func TestDigicert_GetOrderStatus_MalformedJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user/me":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{not valid json`))
		}
	}))
	defer srv.Close()
	c := buildDigicertConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "bad-order")
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestDigicert_GetOrderStatus_IssuedButCertIDMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user/me":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"issued","certificate":{"id":0}}`))
		}
	}))
	defer srv.Close()
	c := buildDigicertConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "issued-no-cert-id")
	if err == nil || !strings.Contains(err.Error(), "certificate_id is missing") {
		t.Errorf("expected 'certificate_id is missing' error, got %v", err)
	}
}

func TestDigicert_GetOrderStatus_PendingProcessingDeniedUnknown(t *testing.T) {
	cases := []struct {
		name       string
		status     string
		wantStatus string
	}{
		{"pending", "pending", "pending"},
		{"processing", "processing", "pending"},
		{"rejected", "rejected", "failed"},
		{"denied", "denied", "failed"},
		{"unknown", "frobnicating", "pending"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/user/me":
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"id":1}`))
				default:
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"status":"` + tc.status + `"}`))
				}
			}))
			defer srv.Close()
			c := buildDigicertConnector(t, srv.URL)
			st, err := c.GetOrderStatus(context.Background(), "order-x")
			if err != nil {
				t.Fatalf("GetOrderStatus: %v", err)
			}
			if st.Status != tc.wantStatus {
				t.Errorf("expected status=%q for input=%q, got %q", tc.wantStatus, tc.status, st.Status)
			}
		})
	}
}

func TestDigicert_DownloadCertificate_Non200_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user/me":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1}`))
		case strings.Contains(r.URL.Path, "/certificate/"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"code":"forbidden"}]}`))
		default:
			// /order/certificate/<id> returns issued with cert_id 7
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"issued","certificate":{"id":7}}`))
		}
	}))
	defer srv.Close()
	c := buildDigicertConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "order-y")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 download error, got %v", err)
	}
}

func TestDigicert_DownloadCertificate_MalformedPEM_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user/me":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1}`))
		case strings.Contains(r.URL.Path, "/certificate/") && strings.Contains(r.URL.Path, "/download/"):
			// Returns junk that won't decode as PEM
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not a pem bundle"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"issued","certificate":{"id":42}}`))
		}
	}))
	defer srv.Close()
	c := buildDigicertConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "order-z")
	if err == nil {
		t.Errorf("expected error from malformed PEM bundle, got nil")
	}
}
