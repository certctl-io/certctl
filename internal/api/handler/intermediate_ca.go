package handler

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/crypto/signer"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/service"
)

// IntermediateCAServicer is the handler-facing surface of
// *service.IntermediateCAService. Defined here (handler-defined service
// interface, dependency inversion) so the handler stays decoupled
// from the concrete service type and tests can mock it without
// pulling the full service-layer dependency graph.
//
// Rank 8 of the 2026-05-03 deep-research deliverable, commit 4 of 5 —
// the API + RBAC layer.
type IntermediateCAServicer interface {
	CreateRoot(ctx context.Context, issuerID, name, decidedBy string,
		rootCertPEM []byte, keyDriverID string, opts *service.CreateRootOptions) (string, error)
	CreateChild(ctx context.Context, parentCAID, name, decidedBy string,
		opts *service.CreateChildOptions) (string, error)
	Retire(ctx context.Context, caID, decidedBy, note string, confirm bool) error
	Get(ctx context.Context, id string) (*domain.IntermediateCA, error)
	LoadHierarchy(ctx context.Context, issuerID string) ([]*domain.IntermediateCA, error)
}

// IntermediateCAHandler serves the admin-gated CA hierarchy endpoints.
// All routes are pinned at /api/v1/issuers/{id}/intermediates and
// /api/v1/intermediates/{id}.
//
// Admin gate: every method calls middleware.IsAdmin first and surfaces
// HTTP 403 for non-admin Bearer callers (M-003 admin-gating pattern,
// matches AdminCRLCacheHandler / AdminESTHandler / AdminSCEPIntuneHandler).
// CA hierarchy management is a high-blast-radius surface — adding a
// child CA mints a new sub-CA cert that becomes a trust root for every
// downstream leaf. Operators expect this gated behind admin role.
type IntermediateCAHandler struct {
	svc IntermediateCAServicer
}

// NewIntermediateCAHandler constructs the handler.
func NewIntermediateCAHandler(svc IntermediateCAServicer) IntermediateCAHandler {
	return IntermediateCAHandler{svc: svc}
}

// createIntermediateBody is the JSON body shape for POST
// /api/v1/issuers/{id}/intermediates. ParentCAID is optional —
// when absent OR empty AND RootCertPEM/KeyDriverID are present, the
// endpoint registers an operator-supplied root CA. Otherwise it
// signs a child under the named parent.
type createIntermediateBody struct {
	Name              string                  `json:"name"`
	ParentCAID        string                  `json:"parent_ca_id,omitempty"` // empty = create root
	RootCertPEM       string                  `json:"root_cert_pem,omitempty"`
	KeyDriverID       string                  `json:"key_driver_id,omitempty"`
	Subject           subjectBody             `json:"subject,omitempty"`
	Algorithm         string                  `json:"algorithm,omitempty"` // ECDSA-P256, RSA-3072, ...
	TTLDays           int                     `json:"ttl_days,omitempty"`
	PathLenConstraint *int                    `json:"path_len_constraint,omitempty"`
	NameConstraints   []domain.NameConstraint `json:"name_constraints,omitempty"`
	OCSPResponderURL  string                  `json:"ocsp_responder_url,omitempty"`
	Metadata          map[string]string       `json:"metadata,omitempty"`
}

// subjectBody is the wire shape for an X.509 subject. Matches the
// pkix.Name fields exposed via the GUI's hierarchy form.
type subjectBody struct {
	CommonName         string   `json:"common_name"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
}

func (s subjectBody) toPKIX() pkix.Name {
	return pkix.Name{
		CommonName:         s.CommonName,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Country:            s.Country,
		Locality:           s.Locality,
		Province:           s.Province,
	}
}

// retireBody is the JSON body shape for POST
// /api/v1/intermediates/{id}/retire. Two-phase: first call (Confirm
// false) transitions active → retiring; second call (Confirm true)
// transitions retiring → retired and refuses if active children
// remain.
type retireBody struct {
	Note    string `json:"note,omitempty"`
	Confirm bool   `json:"confirm,omitempty"`
}

// Create handles POST /api/v1/issuers/{id}/intermediates. Admin-gated.
// Discriminator on body shape: when ParentCAID is empty AND
// RootCertPEM + KeyDriverID are present → CreateRoot; otherwise →
// CreateChild under the named parent.
func (h IntermediateCAHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	issuerID := r.PathValue("id")
	if issuerID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "issuer id required", requestID)
		return
	}
	actor, _ := r.Context().Value(middleware.UserKey{}).(string)
	if actor == "" {
		ErrorWithRequestID(w, http.StatusUnauthorized,
			"authentication required", requestID)
		return
	}

	var body createIntermediateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, "invalid JSON body", requestID)
		return
	}
	if body.Name == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "name required", requestID)
		return
	}

	var (
		newID string
		err   error
	)
	if body.ParentCAID == "" {
		// Root CA registration path.
		if body.RootCertPEM == "" || body.KeyDriverID == "" {
			ErrorWithRequestID(w, http.StatusBadRequest,
				"root_cert_pem + key_driver_id required when parent_ca_id is empty",
				requestID)
			return
		}
		opts := &service.CreateRootOptions{
			OCSPResponderURL: body.OCSPResponderURL,
			Metadata:         body.Metadata,
		}
		newID, err = h.svc.CreateRoot(r.Context(), issuerID, body.Name, actor,
			[]byte(body.RootCertPEM), body.KeyDriverID, opts)
	} else {
		// Child CA signing path.
		alg := signer.Algorithm(body.Algorithm)
		if alg == "" {
			alg = signer.AlgorithmECDSAP256
		}
		ttl := time.Duration(body.TTLDays) * 24 * time.Hour
		opts := &service.CreateChildOptions{
			Subject:           body.Subject.toPKIX(),
			Algorithm:         alg,
			TTL:               ttl,
			PathLenConstraint: body.PathLenConstraint,
			NameConstraints:   body.NameConstraints,
			OCSPResponderURL:  body.OCSPResponderURL,
			Metadata:          body.Metadata,
		}
		newID, err = h.svc.CreateChild(r.Context(), body.ParentCAID, body.Name, actor, opts)
	}
	if err != nil {
		switch {
		case errors.Is(err, service.ErrIntermediateCANotFound):
			ErrorWithRequestID(w, http.StatusNotFound, err.Error(), requestID)
		case errors.Is(err, service.ErrCANotSelfSigned),
			errors.Is(err, service.ErrCAKeyMismatch),
			errors.Is(err, service.ErrPathLenExceeded),
			errors.Is(err, service.ErrNameConstraintExceeded),
			errors.Is(err, service.ErrInvalidCertPEM):
			ErrorWithRequestID(w, http.StatusBadRequest, err.Error(), requestID)
		case errors.Is(err, service.ErrParentCANotActive):
			ErrorWithRequestID(w, http.StatusConflict, err.Error(), requestID)
		default:
			ErrorWithRequestID(w, http.StatusInternalServerError,
				"Failed to create intermediate CA", requestID)
		}
		return
	}

	created, err := h.svc.Get(r.Context(), newID)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError,
			"created but failed to fetch", requestID)
		return
	}
	JSON(w, http.StatusCreated, created)
}

// List handles GET /api/v1/issuers/{id}/intermediates. Admin-gated.
// Returns the flat list for the issuer; callers render the tree from
// each row's parent_ca_id.
func (h IntermediateCAHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	issuerID := r.PathValue("id")
	if issuerID == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "issuer id required", requestID)
		return
	}
	rows, err := h.svc.LoadHierarchy(r.Context(), issuerID)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError,
			"Failed to list intermediate CAs", requestID)
		return
	}
	JSON(w, http.StatusOK, map[string]interface{}{"data": rows})
}

// Get handles GET /api/v1/intermediates/{id}. Admin-gated.
func (h IntermediateCAHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "id required", requestID)
		return
	}
	ca, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrIntermediateCANotFound) {
			ErrorWithRequestID(w, http.StatusNotFound, err.Error(), requestID)
			return
		}
		ErrorWithRequestID(w, http.StatusInternalServerError,
			"Failed to get intermediate CA", requestID)
		return
	}
	JSON(w, http.StatusOK, ca)
}

// Retire handles POST /api/v1/intermediates/{id}/retire. Admin-gated.
// Two-phase: first call (Confirm=false) sets state to retiring;
// second call (Confirm=true) sets to retired. Refuses if the CA has
// active children — drain-first semantics.
func (h IntermediateCAHandler) Retire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}
	requestID := middleware.GetRequestID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "id required", requestID)
		return
	}
	actor, _ := r.Context().Value(middleware.UserKey{}).(string)
	if actor == "" {
		ErrorWithRequestID(w, http.StatusUnauthorized,
			"authentication required", requestID)
		return
	}

	body := retireBody{}
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			ErrorWithRequestID(w, http.StatusBadRequest,
				"invalid JSON body", requestID)
			return
		}
	}

	if err := h.svc.Retire(r.Context(), id, actor, body.Note, body.Confirm); err != nil {
		switch {
		case errors.Is(err, service.ErrIntermediateCANotFound):
			ErrorWithRequestID(w, http.StatusNotFound, err.Error(), requestID)
		case errors.Is(err, service.ErrCAStillHasActiveChildren):
			ErrorWithRequestID(w, http.StatusConflict, err.Error(), requestID)
		default:
			ErrorWithRequestID(w, http.StatusInternalServerError,
				err.Error(), requestID)
		}
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"id":         id,
		"decided_by": actor,
		"confirmed":  body.Confirm,
	})
}
