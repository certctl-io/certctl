package azurekv

// sdk_client.go isolates the imports of github.com/Azure/azure-sdk-for-go/
// sdk/azidentity + sdk/security/keyvault/azcertificates so that
// NewWithClient (the test path) compiles without dragging the SDK
// transitive deps into test binaries.
//
// The production New() path is the only caller of buildSDKClient.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

// sdkClient is the production KeyVaultClient implementation backed by
// *azcertificates.Client. Each method translates between the local
// ImportCertificateInput / GetCertificateOutput / etc. shapes and the
// SDK-typed equivalents.
type sdkClient struct {
	client *azcertificates.Client
}

// buildSDKClient constructs an *azcertificates.Client wrapped in
// sdkClient. The credential chain is selected by credMode:
//
//	"" / "default"       — DefaultAzureCredential
//	"managed_identity"   — ManagedIdentityCredential
//	"client_secret"      — ClientSecretCredential (env vars only)
//	"workload_identity"  — WorkloadIdentityCredential
//
// Any error from credential construction or client init bubbles up
// to the caller (typically ValidateConfig or New).
func buildSDKClient(ctx context.Context, vaultURL, credMode string) (KeyVaultClient, error) {
	cred, err := buildCredential(credMode)
	if err != nil {
		return nil, fmt.Errorf("Azure credential init: %w", err)
	}

	clientOpts := &azcertificates.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: &http.Client{Timeout: 30 * time.Second},
			Retry: policy.RetryOptions{
				MaxRetries: 3,
			},
		},
	}
	client, err := azcertificates.NewClient(vaultURL, cred, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("azcertificates.NewClient: %w", err)
	}
	return &sdkClient{client: client}, nil
}

func buildCredential(credMode string) (azcore.TokenCredential, error) {
	switch credMode {
	case "", CredModeDefault:
		return azidentity.NewDefaultAzureCredential(nil)
	case CredModeManagedIdentity:
		return azidentity.NewManagedIdentityCredential(nil)
	case CredModeClientSecret:
		return azidentity.NewEnvironmentCredential(nil)
	case CredModeWorkloadIdentity:
		return azidentity.NewWorkloadIdentityCredential(nil)
	default:
		return nil, fmt.Errorf("unsupported credential_mode %q", credMode)
	}
}

func (s *sdkClient) ImportCertificate(ctx context.Context, in *ImportCertificateInput) (*ImportCertificateOutput, error) {
	tagsPtr := make(map[string]*string, len(in.Tags))
	for k, v := range in.Tags {
		v := v // capture
		tagsPtr[k] = &v
	}
	resp, err := s.client.ImportCertificate(ctx, in.CertificateName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: ptrTo(in.PFXBase64),
		Tags:                     tagsPtr,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azcertificates ImportCertificate: %w", err)
	}
	out := &ImportCertificateOutput{}
	if resp.ID != nil {
		out.KID = string(*resp.ID)
		// Version ID is the last path segment: .../certificates/<name>/<version>.
		out.VersionID = lastPathSegment(out.KID)
	}
	return out, nil
}

func (s *sdkClient) GetCertificate(ctx context.Context, in *GetCertificateInput) (*GetCertificateOutput, error) {
	resp, err := s.client.GetCertificate(ctx, in.CertificateName, in.Version, nil)
	if err != nil {
		return nil, fmt.Errorf("azcertificates GetCertificate: %w", err)
	}
	out := &GetCertificateOutput{
		CERBytes: resp.CER,
	}
	if resp.ID != nil {
		out.VersionID = lastPathSegment(string(*resp.ID))
	}
	if resp.Attributes != nil {
		if resp.Attributes.NotBefore != nil {
			out.NotBefore = *resp.Attributes.NotBefore
		}
		if resp.Attributes.Expires != nil {
			out.NotAfter = *resp.Attributes.Expires
		}
	}
	// Parse serial from the CER bytes; Key Vault doesn't expose it
	// directly on the response struct.
	if len(resp.CER) > 0 {
		if cert, parseErr := x509.ParseCertificate(resp.CER); parseErr == nil {
			out.Serial = serialFromX509(cert)
		}
	}
	// X509Thumbprint is also available; we use Serial for parity with
	// the AWS ACM connector's verify path.
	return out, nil
}

func (s *sdkClient) ListVersions(ctx context.Context, in *ListVersionsInput) (*ListVersionsOutput, error) {
	out := &ListVersionsOutput{}
	pager := s.client.NewListCertificatePropertiesVersionsPager(in.CertificateName, nil)
	max := in.MaxItems
	if max == 0 {
		max = 100
	}
	for pager.More() && int32(len(out.Versions)) < max {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azcertificates ListVersions: %w", err)
		}
		for _, v := range page.Value {
			vs := VersionSummary{}
			if v.ID != nil {
				vs.VersionID = lastPathSegment(string(*v.ID))
			}
			if v.Attributes != nil {
				if v.Attributes.NotBefore != nil {
					vs.NotBefore = *v.Attributes.NotBefore
				}
				if v.Attributes.Enabled != nil {
					vs.Enabled = *v.Attributes.Enabled
				}
			}
			out.Versions = append(out.Versions, vs)
			if int32(len(out.Versions)) >= max {
				break
			}
		}
	}
	return out, nil
}

// ptrTo is a helper for the SDK's heavy use of *T parameters.
func ptrTo[T any](v T) *T { return &v }

// lastPathSegment returns everything after the final '/' in a URI.
// Used to extract the Key Vault version ID from a cert KID.
func lastPathSegment(uri string) string {
	for i := len(uri) - 1; i >= 0; i-- {
		if uri[i] == '/' {
			return uri[i+1:]
		}
	}
	return uri
}

// serialFromX509 formats an x509.Certificate's SerialNumber to match
// the colon-separated lowercase-hex shape the Azure SDK emits + the
// AWS ACM connector uses for cross-cloud parity.
func serialFromX509(cert *x509.Certificate) string {
	hex := fmt.Sprintf("%x", cert.SerialNumber)
	if len(hex)%2 == 1 {
		hex = "0" + hex
	}
	out := make([]byte, 0, len(hex)+(len(hex)/2)-1)
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[i], hex[i+1])
	}
	return string(out)
}

// Compile-time assertion: *sdkClient implements KeyVaultClient.
var _ KeyVaultClient = (*sdkClient)(nil)

// _ = pem keeps the import stable across refactors that drop and
// re-add PEM-handling code paths.
var _ = pem.Decode
