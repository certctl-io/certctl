package awsacmpca_test

// Top-10 fix #4 of the 2026-05-03 issuer-coverage audit. AWSACMPCA is
// usually the first-deployed issuer in enterprise pilots — diligence
// reviews dig hard into IAM-error / cloud-error coverage. Pre-fix,
// awsacmpca_test.go covered the happy path and a few generic
// connector-level error paths (TestNew_ErrorPaths) but did not pin
// behaviour against the AWS SDK v2's typed error values that real
// production traffic surfaces.
//
// The five tests below pin the operator-visible contract for each
// major SDK error class: every test injects a typed error via the
// existing mockACMPCAClient seam from awsacmpca_test.go, calls the
// connector, and asserts that
//
//   1. the error is non-nil,
//   2. errors.As against the SDK's typed error value succeeds (so the
//      wrap chain via fmt.Errorf("...%w", err) is intact and upstream
//      retry/classification logic can still introspect the typed
//      value), and
//   3. an operator-actionable substring is present in the surfaced
//      message (e.g. the missing CA ARN, the validation issue, the
//      throttling-class marker).
//
// Notes on SDK error mapping:
//
//   * AccessDenied is NOT modeled as a generated *types.Access*
//     value in service/acmpca/types/errors.go (read it locally to
//     confirm). Real production traffic surfaces it as a smithy
//     APIError with Code="AccessDeniedException", which the AWS SDK
//     v2 deserialises into *smithy.GenericAPIError. The first test
//     uses that shape.
//
//   * RequestInProgressException IS a generated typed value and is
//     used by AWS PCA to mean "your request is already being handled,
//     resubmit after a delay". The test asserts the connector
//     surfaces it as a wrapped error (operator decides what to do
//     with the typed value upstream); this is a contract test, not a
//     retry-policy test (per the spec's "out of scope" note: no new
//     retry logic in this commit).
//
// Test-only commit. No production code changes.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	smithy "github.com/aws/smithy-go"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/awsacmpca"
)

// failureTestLogger returns a debug-level slog logger writing to stdout.
// Mirrors the per-test logger in awsacmpca_test.go to keep failure logs
// easy to grep when a test regresses.
func failureTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// failureTestConfig returns a minimal valid awsacmpca.Config sufficient
// for IssueCertificate / RevokeCertificate / GetCACertPEM call sites.
// All five tests use the same shape — extracted to avoid copy-paste.
func failureTestConfig() awsacmpca.Config {
	return awsacmpca.Config{
		Region: "us-east-1",
		CAArn:  "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
	}
}

// TestAWSACMPCA_Issue_AccessDenied_OperatorActionableError pins the
// behaviour when the IAM principal calling certctl lacks the
// acm-pca:IssueCertificate permission. AWS surfaces this as a smithy
// APIError with Code="AccessDeniedException"; the SDK does not
// generate a typed *types.AccessDeniedException value.
func TestAWSACMPCA_Issue_AccessDenied_OperatorActionableError(t *testing.T) {
	ctx := context.Background()
	_, csrPEM := generateTestCertAndCSR(t)

	sdkErr := &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "User: arn:aws:iam::123456789012:user/certctl is not authorized to perform: acm-pca:IssueCertificate on resource: arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/missing",
		Fault:   smithy.FaultClient,
	}
	mock := &mockACMPCAClient{issueCertificateErr: sdkErr}

	cfg := failureTestConfig()
	c := awsacmpca.NewWithClient(&cfg, mock, failureTestLogger())

	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from access-denied IssueCertificate, got nil")
	}

	var gotSDK *smithy.GenericAPIError
	if !errors.As(err, &gotSDK) {
		t.Fatalf("wrap chain broke — errors.As against *smithy.GenericAPIError failed; err=%v", err)
	}
	if gotSDK.ErrorCode() != "AccessDeniedException" {
		t.Errorf("expected ErrorCode=AccessDeniedException, got %q", gotSDK.ErrorCode())
	}

	msg := err.Error()
	if !strings.Contains(msg, "AccessDenied") {
		t.Errorf("operator-actionable substring missing — message must mention AccessDenied; got: %s", msg)
	}
	if !strings.Contains(msg, "not authorized") {
		t.Errorf("operator-actionable substring missing — message must mention 'not authorized'; got: %s", msg)
	}
	if !strings.Contains(msg, "IssueCertificate failed") {
		t.Errorf("connector wrap missing — expected 'IssueCertificate failed: ...' framing; got: %s", msg)
	}
}

// TestAWSACMPCA_Issue_ResourceNotFound_NamesTheMissingCAArn pins the
// behaviour when the configured CA ARN does not exist. The SDK's
// *types.ResourceNotFoundException carries the ARN in its message;
// the connector must preserve that ARN through the wrap chain so an
// operator reading the error can identify which CA was missing.
func TestAWSACMPCA_Issue_ResourceNotFound_NamesTheMissingCAArn(t *testing.T) {
	ctx := context.Background()
	_, csrPEM := generateTestCertAndCSR(t)

	missingArn := "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/deadbeef-dead-beef-dead-beefdeadbeef"
	sdkErr := &acmpcatypes.ResourceNotFoundException{
		Message: aws.String("Could not find Certificate Authority " + missingArn),
	}
	mock := &mockACMPCAClient{issueCertificateErr: sdkErr}

	cfg := failureTestConfig()
	c := awsacmpca.NewWithClient(&cfg, mock, failureTestLogger())

	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from resource-not-found IssueCertificate, got nil")
	}

	var gotSDK *acmpcatypes.ResourceNotFoundException
	if !errors.As(err, &gotSDK) {
		t.Fatalf("wrap chain broke — errors.As against *types.ResourceNotFoundException failed; err=%v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, missingArn) {
		t.Errorf("operator-actionable substring missing — message must name the missing CA ARN %q; got: %s", missingArn, msg)
	}
	if !strings.Contains(msg, "ResourceNotFoundException") {
		t.Errorf("expected ResourceNotFoundException in surfaced message; got: %s", msg)
	}
}

// TestAWSACMPCA_Issue_Throttling_RetryableSurfacePreserved pins the
// behaviour when ACM PCA throttles a burst of issuance calls. Real
// traffic surfaces ThrottlingException via *smithy.GenericAPIError;
// the connector must preserve the typed value so any upstream retry
// layer can recognise the retryable class. (Per the spec's "out of
// scope" note: this commit does not add retry logic.)
func TestAWSACMPCA_Issue_Throttling_RetryableSurfacePreserved(t *testing.T) {
	ctx := context.Background()
	_, csrPEM := generateTestCertAndCSR(t)

	sdkErr := &smithy.GenericAPIError{
		Code:    "ThrottlingException",
		Message: "Rate exceeded",
		Fault:   smithy.FaultServer,
	}
	mock := &mockACMPCAClient{issueCertificateErr: sdkErr}

	cfg := failureTestConfig()
	c := awsacmpca.NewWithClient(&cfg, mock, failureTestLogger())

	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from throttled IssueCertificate, got nil")
	}

	var gotSDK *smithy.GenericAPIError
	if !errors.As(err, &gotSDK) {
		t.Fatalf("wrap chain broke — errors.As against *smithy.GenericAPIError failed; err=%v", err)
	}
	if gotSDK.ErrorCode() != "ThrottlingException" {
		t.Errorf("expected ErrorCode=ThrottlingException, got %q", gotSDK.ErrorCode())
	}
	if gotSDK.ErrorFault() != smithy.FaultServer {
		t.Errorf("expected FaultServer (retryable class) preserved through wrap; got %v", gotSDK.ErrorFault())
	}

	msg := err.Error()
	if !strings.Contains(msg, "Throttling") {
		t.Errorf("operator-actionable substring missing — message must mention Throttling; got: %s", msg)
	}
}

// TestAWSACMPCA_Issue_MalformedCSR_TerminalNotRetryable pins the
// behaviour when the CSR submitted to ACM PCA is invalid (e.g.
// unsupported key algorithm, malformed DER, key size below CA's
// policy floor). This is a terminal class — operators must fix the
// CSR, not retry. The connector must preserve the typed value so
// upstream classification can distinguish "fix and resubmit" from
// "wait and retry".
func TestAWSACMPCA_Issue_MalformedCSR_TerminalNotRetryable(t *testing.T) {
	ctx := context.Background()
	_, csrPEM := generateTestCertAndCSR(t)

	sdkErr := &acmpcatypes.MalformedCSRException{
		Message: aws.String("CSR has an unsupported public key algorithm: RSA-1024 below CA policy minimum 2048"),
	}
	mock := &mockACMPCAClient{issueCertificateErr: sdkErr}

	cfg := failureTestConfig()
	c := awsacmpca.NewWithClient(&cfg, mock, failureTestLogger())

	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from malformed-CSR IssueCertificate, got nil")
	}

	var gotSDK *acmpcatypes.MalformedCSRException
	if !errors.As(err, &gotSDK) {
		t.Fatalf("wrap chain broke — errors.As against *types.MalformedCSRException failed; err=%v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, "MalformedCSR") {
		t.Errorf("expected MalformedCSR in surfaced message; got: %s", msg)
	}
	if !strings.Contains(msg, "unsupported public key algorithm") {
		t.Errorf("operator-actionable substring missing — message must name the validation issue; got: %s", msg)
	}
}

// TestAWSACMPCA_Issue_RequestInProgress_TerminalForCurrentAttempt pins
// the behaviour when ACM PCA reports the previous IssueCertificate
// for this idempotency key is still in flight. The SDK has a
// generated *types.RequestInProgressException for this case. The
// connector must preserve the typed value through the wrap chain so
// upstream logic (scheduler, ACME finalize, MCP tool) can decide
// whether to re-issue with a fresh idempotency key or wait. This
// commit pins ONLY the wrap-and-surface contract; classification as
// retryable/terminal is upstream's responsibility (per the spec's
// "out of scope" note).
func TestAWSACMPCA_Issue_RequestInProgress_TerminalForCurrentAttempt(t *testing.T) {
	ctx := context.Background()
	_, csrPEM := generateTestCertAndCSR(t)

	sdkErr := &acmpcatypes.RequestInProgressException{
		Message: aws.String("Your request is already in progress; resubmit after the current attempt completes"),
	}
	mock := &mockACMPCAClient{issueCertificateErr: sdkErr}

	cfg := failureTestConfig()
	c := awsacmpca.NewWithClient(&cfg, mock, failureTestLogger())

	_, err := c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: "app.example.com",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected error from request-in-progress IssueCertificate, got nil")
	}

	var gotSDK *acmpcatypes.RequestInProgressException
	if !errors.As(err, &gotSDK) {
		t.Fatalf("wrap chain broke — errors.As against *types.RequestInProgressException failed; err=%v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, "RequestInProgress") {
		t.Errorf("expected RequestInProgress in surfaced message; got: %s", msg)
	}
	if !strings.Contains(msg, "in progress") {
		t.Errorf("operator-actionable substring missing — message must mention 'in progress'; got: %s", msg)
	}
}
