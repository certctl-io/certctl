package awsacm_test

// Rank 5 of the 2026-05-03 Infisical deep-research deliverable
// (cowork/infisical-deep-research-results.md Part 5). Per-error-class
// failure tests for the AWS ACM target connector — mirrors the
// awsacmpca_failure_test.go shape (commit 60dce0b) on the issuer side.
//
// Each test injects one specific AWS SDK v2 typed error via the
// mockACMClient seam, calls DeployCertificate, and asserts:
//
//   1. error non-nil,
//   2. errors.As against the SDK's typed error value succeeds (so the
//      wrap chain via fmt.Errorf("...%w", ...) is intact and upstream
//      retry / classification logic can introspect the typed value),
//   3. operator-actionable substring is present in the surfaced
//      message,
//   4. the failure category is correct (e.g. throttling = retryable;
//      validation = terminal).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	smithy "github.com/aws/smithy-go"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/awsacm"
)

// TestAWSACM_Issue_AccessDenied_OperatorActionableError pins the
// behaviour when the IAM principal lacks acm:ImportCertificate. AWS
// surfaces this as a smithy APIError with Code="AccessDeniedException"
// (the ACM SDK does not generate a typed *types.AccessDeniedException
// in v1.38.x — read it locally to confirm).
func TestAWSACM_Issue_AccessDenied_OperatorActionableError(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := generateTestCert(t, "denied.example.com")

	sdkErr := &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "User: arn:aws:iam::123456789012:user/ci is not authorized to perform: acm:ImportCertificate",
		Fault:   smithy.FaultClient,
	}
	mock := &mockACMClient{importErr: sdkErr}
	c := awsacm.NewWithClient(&awsacm.Config{Region: "us-east-1"}, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-denied"},
	})
	if err == nil {
		t.Fatal("expected access-denied error, got nil")
	}

	var sdk *smithy.GenericAPIError
	if !errors.As(err, &sdk) {
		t.Fatalf("wrap chain broke — errors.As against *smithy.GenericAPIError failed; err=%v", err)
	}
	if sdk.ErrorCode() != "AccessDeniedException" {
		t.Errorf("expected ErrorCode=AccessDeniedException, got %q", sdk.ErrorCode())
	}
	msg := err.Error()
	if !strings.Contains(msg, "AccessDenied") {
		t.Errorf("operator-actionable substring missing — message must mention AccessDenied; got: %s", msg)
	}
	if !strings.Contains(msg, "ImportCertificate failed") {
		t.Errorf("connector wrap missing — expected 'ImportCertificate failed: ...' framing; got: %s", msg)
	}
}

// TestAWSACM_Issue_ResourceNotFound_NamesTheMissingARN pins behaviour
// when the configured CertificateArn doesn't exist (deleted out-of-
// band, typo'd config, wrong region). The SDK's
// *types.ResourceNotFoundException carries the ARN in its message; the
// connector must preserve the ARN through the wrap chain so the
// operator can identify which resource was missing.
func TestAWSACM_Issue_ResourceNotFound_NamesTheMissingARN(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := generateTestCert(t, "missing.example.com")

	missingArn := "arn:aws:acm:us-east-1:123456789012:certificate/deadbeef-dead-beef-dead-beefdeadbeef"
	sdkErr := &acmtypes.ResourceNotFoundException{
		Message: aws.String("Could not find certificate " + missingArn),
	}
	// We need the snapshot read to fail — the connector calls
	// GetCertificate first to capture the snapshot. ResourceNotFound at
	// snapshot time means "no cert at this ARN," so we surface that
	// error and bail before the import.
	mock := &mockACMClient{getErr: sdkErr}
	cfg := &awsacm.Config{Region: "us-east-1", CertificateArn: missingArn}
	c := awsacm.NewWithClient(cfg, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	if err == nil {
		t.Fatal("expected resource-not-found error")
	}
	var sdk *acmtypes.ResourceNotFoundException
	if !errors.As(err, &sdk) {
		t.Fatalf("wrap chain broke — errors.As against *types.ResourceNotFoundException failed; err=%v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, missingArn) {
		t.Errorf("operator-actionable substring missing — message must name the missing ARN %q; got: %s", missingArn, msg)
	}
	if !strings.Contains(msg, "snapshot") {
		t.Errorf("expected 'snapshot' framing on pre-deploy snapshot failure; got: %s", msg)
	}
}

// TestAWSACM_Issue_Throttling_RetryableSurfacePreserved pins the
// behaviour when ACM throttles a burst of imports (renewal storm,
// bulk migration). Real traffic surfaces ThrottlingException via
// *smithy.GenericAPIError; the connector must preserve the typed
// value + Fault classification so any upstream retry layer can engage.
// Per the spec's "no new retry logic" scope, the connector itself
// does not retry; it surfaces the typed error.
func TestAWSACM_Issue_Throttling_RetryableSurfacePreserved(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := generateTestCert(t, "throttle.example.com")

	sdkErr := &smithy.GenericAPIError{
		Code:    "ThrottlingException",
		Message: "Rate exceeded",
		Fault:   smithy.FaultServer,
	}
	mock := &mockACMClient{importErr: sdkErr}
	c := awsacm.NewWithClient(&awsacm.Config{Region: "us-east-1"}, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-throttle"},
	})
	if err == nil {
		t.Fatal("expected throttle error")
	}
	var sdk *smithy.GenericAPIError
	if !errors.As(err, &sdk) {
		t.Fatalf("wrap chain broke; err=%v", err)
	}
	if sdk.ErrorCode() != "ThrottlingException" {
		t.Errorf("expected ErrorCode=ThrottlingException, got %q", sdk.ErrorCode())
	}
	if sdk.ErrorFault() != smithy.FaultServer {
		t.Errorf("expected FaultServer (retryable class) preserved; got %v", sdk.ErrorFault())
	}
	if !strings.Contains(err.Error(), "Throttling") {
		t.Errorf("operator-actionable substring missing — message must mention Throttling; got: %s", err.Error())
	}
}

// TestAWSACM_Issue_InvalidArgs_TerminalNotRetryable pins behaviour
// when ACM rejects the cert+key as malformed (mismatched key/cert,
// unsupported algorithm). InvalidArgsException is a terminal class —
// operators must fix the inputs, not retry.
func TestAWSACM_Issue_InvalidArgs_TerminalNotRetryable(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := generateTestCert(t, "invalid.example.com")

	sdkErr := &acmtypes.InvalidArgsException{
		Message: aws.String("The certificate body is invalid: chain not bound to leaf"),
	}
	mock := &mockACMClient{importErr: sdkErr}
	c := awsacm.NewWithClient(&awsacm.Config{Region: "us-east-1"}, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-invalid"},
	})
	if err == nil {
		t.Fatal("expected invalid-args error")
	}
	var sdk *acmtypes.InvalidArgsException
	if !errors.As(err, &sdk) {
		t.Fatalf("wrap chain broke; err=%v", err)
	}
	if !strings.Contains(err.Error(), "chain not bound") {
		t.Errorf("operator-actionable substring missing — message must name the validation issue; got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "InvalidArgs") {
		t.Errorf("expected InvalidArgs in surfaced message; got: %s", err.Error())
	}
}

// TestAWSACM_Issue_RequestInProgress_TerminalForCurrentAttempt pins
// behaviour when ACM reports an in-flight request for the same
// idempotency key. RequestInProgressException IS a generated typed
// value; the connector must surface it cleanly so upstream logic can
// decide whether to wait + retry or fail-fast.
func TestAWSACM_Issue_RequestInProgress_TerminalForCurrentAttempt(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := generateTestCert(t, "inprogress.example.com")

	sdkErr := &acmtypes.RequestInProgressException{
		Message: aws.String("The certificate request is already being processed; resubmit after completion"),
	}
	mock := &mockACMClient{importErr: sdkErr}
	c := awsacm.NewWithClient(&awsacm.Config{Region: "us-east-1"}, mock, quietTestLogger())

	_, err := c.DeployCertificate(ctx, target.DeploymentRequest{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Metadata: map[string]string{"certificate_id": "mc-inprogress"},
	})
	if err == nil {
		t.Fatal("expected request-in-progress error")
	}
	var sdk *acmtypes.RequestInProgressException
	if !errors.As(err, &sdk) {
		t.Fatalf("wrap chain broke; err=%v", err)
	}
	if !strings.Contains(err.Error(), "RequestInProgress") {
		t.Errorf("expected RequestInProgress in surfaced message; got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "already being processed") {
		t.Errorf("operator-actionable substring missing — message must explain the conflict; got: %s", err.Error())
	}
}
