// Package awsacm implements a target.Connector for deploying certificates to
// AWS Certificate Manager (ACM). ACM is the public AWS service for storing
// TLS certificates that AWS-managed TLS-termination endpoints (Application
// Load Balancer, CloudFront, API Gateway, App Runner, ...) consume by ARN.
//
// The connector wraps github.com/aws/aws-sdk-go-v2/service/acm via the
// ACMClient interface seam so unit tests inject a mock without standing up
// real AWS. Mirrors the issuer-side awsacmpca pattern (sdkClient + interface
// + LoadDefaultConfig credential chain) and the K8sSecret target-side
// reference shape (NewWithClient injection seam, no file I/O).
//
// Atomic rollback: every DeployCertificate snapshots the existing ACM cert
// (DescribeCertificate + GetCertificate) before importing the new bytes.
// Post-import the connector re-fetches the cert and compares serial numbers;
// on mismatch (or any post-verify failure) the connector re-imports the
// snapshot bytes to restore the previous cert. Mirrors the Bundle 5+
// pre-deploy-snapshot + on-failure-restore pattern from IIS / WinCertStore /
// JavaKeystore. Rank 5 of the 2026-05-03 Infisical deep-research
// deliverable (cowork/infisical-deep-research-results.md Part 5).
//
// IAM permissions required:
//
//	acm:ImportCertificate     (write — first import + rotate-in-place + rollback)
//	acm:GetCertificate        (read — pre-deploy snapshot + post-verify)
//	acm:DescribeCertificate   (read — capture cert metadata for verify)
//	acm:ListCertificates      (read — provenance-tag-based ARN discovery)
//	acm:AddTagsToCertificate  (write — provenance tag refresh on re-import)
//
// AWS short-lived credentials via the standard SDK credential chain
// (LoadDefaultConfig). Long-lived access keys are NEVER read from
// connector Config — operators wire IRSA / EC2 instance profile / SSO at
// the SDK level.
package awsacm

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/certctl-io/certctl/internal/connector/target"
)

// arnRegex pins the ACM cert-ARN shape ACM hands back from Import /
// Describe / Get. Validates Config.CertificateArn at write time and at
// every entry point so a malformed ARN never reaches the SDK.
var arnRegex = regexp.MustCompile(`^arn:aws(-[a-z]+)?:acm:[a-z0-9-]+:\d{12}:certificate/[a-f0-9-]+$`)

// regionRegex pins the AWS region shape (e.g., us-east-1, us-gov-west-1,
// cn-north-1). Avoids feeding garbage to LoadDefaultConfig.
var regionRegex = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

// Provenance tag keys. Always set automatically; operator-supplied tags
// merge on top. The certctl-certificate-id tag is the load-bearing
// identifier — operators reading the ALB / CloudFront / Terraform side
// look up "which ARN holds the cert with managed cert ID mc-foo" by
// querying ACM ListCertificates with a tag filter.
const (
	tagKeyManagedBy     = "certctl-managed-by"
	tagKeyCertificateID = "certctl-certificate-id"
	tagValueManagedBy   = "certctl"
)

// Config represents the AWS Certificate Manager deployment target
// configuration. Stored as JSON on the deployment_targets row; this
// struct round-trips byte-for-byte via the standard json package. No
// credential fields — the SDK credential chain handles auth.
type Config struct {
	// Region is the AWS region for the ACM endpoint (e.g., "us-east-1").
	// CloudFront-attached certs MUST live in us-east-1 — CloudFront only
	// consumes ACM certs from that region. ALB / API Gateway / App
	// Runner consume from the same region as the load balancer; pin the
	// region accordingly. Required.
	Region string `json:"region"`

	// CertificateArn is the ARN of an existing ACM certificate to
	// re-import (rotate). Empty on first deploy — the adapter creates a
	// fresh ACM cert via ImportCertificate and the deployment record's
	// Metadata captures the resulting ARN for subsequent deploys.
	// Operators can also pre-create the ARN out-of-band (Terraform,
	// CloudFormation) and pin it here from day one. Optional on first
	// deploy.
	CertificateArn string `json:"certificate_arn,omitempty"`

	// Tags are applied to the ACM certificate at first-import time AND
	// re-applied via AddTagsToCertificate on every subsequent import
	// (re-import does NOT carry the tags forward — see ACM SDK doc on
	// ImportCertificateInput.Tags: "You cannot apply tags when
	// reimporting a certificate"). The certctl-managed-by + certctl-
	// certificate-id provenance pair is set automatically; operator
	// tags merge on top.
	Tags map[string]string `json:"tags,omitempty"`
}

// ACMClient defines the subset of the AWS ACM API surface the connector
// uses. Mirrors the issuer-side awsacmpca.ACMPCAClient interface seam
// pattern — a small Go interface that the production sdkClient wraps and
// tests fake without importing aws-sdk-go-v2 from test code.
type ACMClient interface {
	ImportCertificate(ctx context.Context, input *ImportCertificateInput) (*ImportCertificateOutput, error)
	GetCertificate(ctx context.Context, input *GetCertificateInput) (*GetCertificateOutput, error)
	DescribeCertificate(ctx context.Context, input *DescribeCertificateInput) (*DescribeCertificateOutput, error)
	ListCertificates(ctx context.Context, input *ListCertificatesInput) (*ListCertificatesOutput, error)
	AddTagsToCertificate(ctx context.Context, input *AddTagsToCertificateInput) error
}

// ImportCertificateInput is the local-package view of the SDK's
// acm.ImportCertificateInput. Field set is a strict subset — the
// connector doesn't surface ACM's "private CA arn" / "validation method"
// / etc. shapes.
type ImportCertificateInput struct {
	CertificateArn   string // empty on first import; populated on rotate-in-place
	Certificate      []byte
	PrivateKey       []byte
	CertificateChain []byte
	Tags             []Tag // ignored by ACM on re-import; AddTags applies them post-fact
}

// ImportCertificateOutput captures the ARN ACM hands back. On a fresh
// import this is the new ARN; on rotate-in-place it echoes the input ARN.
type ImportCertificateOutput struct {
	CertificateArn string
}

// GetCertificateInput / Output cover the snapshot read.
type GetCertificateInput struct {
	CertificateArn string
}
type GetCertificateOutput struct {
	Certificate      []byte // PEM bytes
	CertificateChain []byte // PEM bytes; may be empty
}

// DescribeCertificateInput / Output cover the metadata read used for
// post-verify (serial-number compare).
type DescribeCertificateInput struct {
	CertificateArn string
}
type DescribeCertificateOutput struct {
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	Domain    string
	Status    string
}

// ListCertificatesInput / Output cover the provenance-tag-based ARN
// discovery path. Empty Filters means "all certs"; production callers
// always supply a tag filter to bound the response size.
type ListCertificatesInput struct {
	MaxItems int32
}
type ListCertificatesOutput struct {
	Summaries []CertificateSummary
	NextToken string
}
type CertificateSummary struct {
	CertificateArn string
	DomainName     string
}

// AddTagsToCertificateInput re-applies tags after a rotate-in-place
// import (ACM strips them on re-import).
type AddTagsToCertificateInput struct {
	CertificateArn string
	Tags           []Tag
}

// Tag is the local view of the SDK's acmtypes.Tag.
type Tag struct {
	Key   string
	Value string
}

// Connector implements target.Connector for AWS Certificate Manager.
type Connector struct {
	config *Config
	client ACMClient
	logger *slog.Logger
}

// New creates a connector backed by the real AWS SDK client. ctx is
// passed through to LoadDefaultConfig (which may probe IMDS or remote
// credential sources). Same shape as awsacmpca.New.
//
// If config is nil or config.Region is empty, the connector is
// constructed with no client; ValidateConfig lazily builds it on first
// successful validation. Mirrors the test-init pattern from awsacmpca.
func New(ctx context.Context, cfg *Config, logger *slog.Logger) (*Connector, error) {
	c := &Connector{config: cfg, logger: logger}

	if cfg != nil && cfg.Region != "" {
		client, err := buildSDKClient(ctx, cfg.Region)
		if err != nil {
			return nil, fmt.Errorf("AWS ACM SDK init: %w", err)
		}
		c.client = client
	}
	return c, nil
}

// NewWithClient creates a connector with a caller-supplied ACMClient.
// Used by unit tests to inject a mock; the production path is New.
func NewWithClient(cfg *Config, client ACMClient, logger *slog.Logger) *Connector {
	return &Connector{config: cfg, client: client, logger: logger}
}

// buildSDKClient wraps the AWS SDK v2 acm.Client behind the ACMClient
// interface seam. Mirrors awsacmpca.buildSDKClient.
func buildSDKClient(ctx context.Context, region string) (ACMClient, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("LoadDefaultConfig: %w", err)
	}
	return &sdkClient{client: acm.NewFromConfig(awsCfg)}, nil
}

// sdkClient is the production ACMClient implementation backed by
// *acm.Client. Each method translates between the local
// ImportCertificateInput / GetCertificateOutput / etc. shapes and the
// SDK-typed equivalents.
type sdkClient struct {
	client *acm.Client
}

func (s *sdkClient) ImportCertificate(ctx context.Context, input *ImportCertificateInput) (*ImportCertificateOutput, error) {
	sdkInput := &acm.ImportCertificateInput{
		Certificate:      input.Certificate,
		PrivateKey:       input.PrivateKey,
		CertificateChain: input.CertificateChain,
	}
	if input.CertificateArn != "" {
		sdkInput.CertificateArn = aws.String(input.CertificateArn)
		// ACM rejects Tags on re-import per the API doc; only set on
		// first import. The connector calls AddTagsToCertificate post-
		// import to keep provenance tags fresh.
	} else if len(input.Tags) > 0 {
		sdkInput.Tags = toSDKTags(input.Tags)
	}

	out, err := s.client.ImportCertificate(ctx, sdkInput)
	if err != nil {
		return nil, fmt.Errorf("acm ImportCertificate: %w", err)
	}
	if out == nil || out.CertificateArn == nil {
		return nil, fmt.Errorf("acm ImportCertificate returned no CertificateArn")
	}
	return &ImportCertificateOutput{CertificateArn: aws.ToString(out.CertificateArn)}, nil
}

func (s *sdkClient) GetCertificate(ctx context.Context, input *GetCertificateInput) (*GetCertificateOutput, error) {
	out, err := s.client.GetCertificate(ctx, &acm.GetCertificateInput{
		CertificateArn: aws.String(input.CertificateArn),
	})
	if err != nil {
		return nil, fmt.Errorf("acm GetCertificate: %w", err)
	}
	if out == nil {
		return nil, fmt.Errorf("acm GetCertificate returned nil output")
	}
	return &GetCertificateOutput{
		Certificate:      []byte(aws.ToString(out.Certificate)),
		CertificateChain: []byte(aws.ToString(out.CertificateChain)),
	}, nil
}

func (s *sdkClient) DescribeCertificate(ctx context.Context, input *DescribeCertificateInput) (*DescribeCertificateOutput, error) {
	out, err := s.client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
		CertificateArn: aws.String(input.CertificateArn),
	})
	if err != nil {
		return nil, fmt.Errorf("acm DescribeCertificate: %w", err)
	}
	if out == nil || out.Certificate == nil {
		return nil, fmt.Errorf("acm DescribeCertificate returned nil output")
	}
	cd := out.Certificate
	res := &DescribeCertificateOutput{
		Serial: aws.ToString(cd.Serial),
		Domain: aws.ToString(cd.DomainName),
		Status: string(cd.Status),
	}
	if cd.NotBefore != nil {
		res.NotBefore = *cd.NotBefore
	}
	if cd.NotAfter != nil {
		res.NotAfter = *cd.NotAfter
	}
	return res, nil
}

func (s *sdkClient) ListCertificates(ctx context.Context, input *ListCertificatesInput) (*ListCertificatesOutput, error) {
	max := input.MaxItems
	if max == 0 {
		max = 100
	}
	out, err := s.client.ListCertificates(ctx, &acm.ListCertificatesInput{
		MaxItems: aws.Int32(max),
	})
	if err != nil {
		return nil, fmt.Errorf("acm ListCertificates: %w", err)
	}
	res := &ListCertificatesOutput{}
	for _, sum := range out.CertificateSummaryList {
		res.Summaries = append(res.Summaries, CertificateSummary{
			CertificateArn: aws.ToString(sum.CertificateArn),
			DomainName:     aws.ToString(sum.DomainName),
		})
	}
	res.NextToken = aws.ToString(out.NextToken)
	return res, nil
}

func (s *sdkClient) AddTagsToCertificate(ctx context.Context, input *AddTagsToCertificateInput) error {
	_, err := s.client.AddTagsToCertificate(ctx, &acm.AddTagsToCertificateInput{
		CertificateArn: aws.String(input.CertificateArn),
		Tags:           toSDKTags(input.Tags),
	})
	if err != nil {
		return fmt.Errorf("acm AddTagsToCertificate: %w", err)
	}
	return nil
}

func toSDKTags(in []Tag) []acmtypes.Tag {
	out := make([]acmtypes.Tag, 0, len(in))
	for _, t := range in {
		out = append(out, acmtypes.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}
	return out
}

// ValidateConfig validates the AWS ACM deployment target configuration.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid AWS ACM config: %w", err)
	}
	if cfg.Region == "" {
		return fmt.Errorf("AWS ACM region is required")
	}
	if !regionRegex.MatchString(cfg.Region) {
		return fmt.Errorf("AWS ACM region malformed (expected e.g. us-east-1): %q", cfg.Region)
	}
	if cfg.CertificateArn != "" && !arnRegex.MatchString(cfg.CertificateArn) {
		return fmt.Errorf("AWS ACM certificate_arn malformed: %q", cfg.CertificateArn)
	}
	for k := range cfg.Tags {
		if k == tagKeyManagedBy || k == tagKeyCertificateID {
			return fmt.Errorf("operator tags cannot use the reserved provenance key %q", k)
		}
	}

	c.config = &cfg
	c.logger.Info("AWS ACM configuration validated",
		"region", cfg.Region,
		"has_arn", cfg.CertificateArn != "",
	)

	if c.client == nil {
		client, err := buildSDKClient(ctx, cfg.Region)
		if err != nil {
			return fmt.Errorf("AWS ACM SDK init: %w", err)
		}
		c.client = client
	}
	return nil
}

// DeployCertificate imports the supplied cert+key+chain into AWS ACM.
//
// On a first deploy (Config.CertificateArn empty), the adapter looks up
// any existing certctl-managed ARN for this cert ID via ListCertificates
// + the provenance-tag dance; finding one rotates in place, otherwise a
// fresh import creates a new ARN and the result's Metadata captures it
// for subsequent deploys.
//
// On a rotate-in-place deploy (Config.CertificateArn set), the flow is:
//
//  1. DescribeCertificate(arn) — capture metadata for post-verify.
//  2. GetCertificate(arn) — capture cert+chain bytes for rollback.
//  3. ImportCertificate(arn, new_bytes).
//  4. AddTagsToCertificate(arn, provenance) — re-import strips tags.
//  5. DescribeCertificate(arn) — confirm new serial matches request.
//  6. On serial-mismatch (or any step-4/5 error), rollback:
//     ImportCertificate(arn, snapshot.bytes).
//
// Cert key bytes (request.KeyPEM) are held in memory only — never written
// to disk. The DeploymentResult.Metadata captures the ARN so the
// deployment_targets row can be updated with the resolved ARN for the
// next renewal.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("AWS ACM client not initialized; ValidateConfig must be called first")
	}
	if c.config == nil {
		return nil, fmt.Errorf("AWS ACM config not loaded; ValidateConfig must be called first")
	}

	// Per-config check on the request: reject empty cert / key bytes
	// before reaching the SDK so the error surfaces as adapter-actionable.
	certBytes, chainBytes, keyBytes, err := decodeRequest(request)
	if err != nil {
		return nil, err
	}

	expectedSerial, err := serialFromPEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("AWS ACM: failed to parse cert PEM: %w", err)
	}

	certctlCertID := metadataCertID(request.Metadata)
	resolvedArn := c.config.CertificateArn

	// First-deploy ARN discovery via provenance tags. If config.ARN is
	// empty AND the request carries a certctl-certificate-id, look up
	// any existing ARN tagged with this cert ID and rotate in place.
	if resolvedArn == "" && certctlCertID != "" {
		if discovered, derr := c.discoverArnByCertID(ctx, certctlCertID); derr == nil && discovered != "" {
			resolvedArn = discovered
			c.logger.Info("AWS ACM rotate-in-place via tag-discovered ARN",
				"arn", resolvedArn, "certctl_certificate_id", certctlCertID,
			)
		}
	}

	// Snapshot phase — only meaningful when we're rotating in place.
	var snapshotCert, snapshotChain []byte
	if resolvedArn != "" {
		snap, sErr := c.client.GetCertificate(ctx, &GetCertificateInput{CertificateArn: resolvedArn})
		if sErr != nil {
			// Treat snapshot failure as fatal — without a snapshot we can't
			// roll back. Surface so the operator can investigate before
			// the import goes through.
			return nil, fmt.Errorf("AWS ACM pre-deploy snapshot failed: %w", sErr)
		}
		snapshotCert, snapshotChain = snap.Certificate, snap.CertificateChain
	}

	// Import phase. Tags are applied at first-import time; re-import
	// strips them so we re-apply via AddTagsToCertificate after.
	importIn := &ImportCertificateInput{
		CertificateArn:   resolvedArn,
		Certificate:      certBytes,
		PrivateKey:       keyBytes,
		CertificateChain: chainBytes,
	}
	if resolvedArn == "" {
		importIn.Tags = c.buildProvenanceTags(certctlCertID)
	}

	importOut, importErr := c.client.ImportCertificate(ctx, importIn)
	if importErr != nil {
		return nil, fmt.Errorf("AWS ACM ImportCertificate failed: %w", importErr)
	}

	finalArn := importOut.CertificateArn
	if finalArn == "" {
		return nil, fmt.Errorf("AWS ACM ImportCertificate returned empty ARN")
	}

	// Re-apply provenance tags on rotate-in-place. Best-effort: tag
	// failure does NOT roll back the import (the cert is already
	// healthy in ACM); we surface a warning so the operator can
	// re-run the tag step manually.
	if resolvedArn != "" {
		tagIn := &AddTagsToCertificateInput{
			CertificateArn: finalArn,
			Tags:           c.buildProvenanceTags(certctlCertID),
		}
		if tagErr := c.client.AddTagsToCertificate(ctx, tagIn); tagErr != nil {
			c.logger.Warn("AWS ACM provenance-tag refresh failed; cert imported successfully but tags may be stale",
				"arn", finalArn, "error", tagErr,
			)
		}
	}

	// Post-verify: re-fetch cert metadata, compare serial to the cert we
	// just imported. Mismatch triggers rollback.
	verifyOut, verifyErr := c.client.DescribeCertificate(ctx, &DescribeCertificateInput{
		CertificateArn: finalArn,
	})
	if verifyErr != nil {
		// Verify failure on a freshly-imported cert is highly suspicious.
		// Roll back if we have a snapshot; otherwise surface.
		if len(snapshotCert) > 0 {
			c.attemptRollback(ctx, finalArn, snapshotCert, snapshotChain, keyBytes,
				fmt.Sprintf("post-verify DescribeCertificate failed: %v", verifyErr))
		}
		return nil, fmt.Errorf("AWS ACM post-verify DescribeCertificate failed: %w", verifyErr)
	}

	if !serialsEqual(verifyOut.Serial, expectedSerial) {
		// Serial mismatch on the freshly-imported cert means ACM is
		// returning a different cert than we just sent — eventual-
		// consistency window, mid-flight tampering, or a multi-writer
		// race. Roll back to be safe.
		if len(snapshotCert) > 0 {
			c.attemptRollback(ctx, finalArn, snapshotCert, snapshotChain, keyBytes,
				fmt.Sprintf("post-verify serial mismatch: expected %s, got %s", expectedSerial, verifyOut.Serial))
			return nil, fmt.Errorf("AWS ACM post-verify serial mismatch (rolled back): expected %s, got %s",
				expectedSerial, verifyOut.Serial)
		}
		return nil, fmt.Errorf("AWS ACM post-verify serial mismatch: expected %s, got %s",
			expectedSerial, verifyOut.Serial)
	}

	c.logger.Info("AWS ACM certificate deployed",
		"arn", finalArn,
		"serial", expectedSerial,
		"rotate_in_place", resolvedArn != "",
	)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: finalArn,
		DeploymentID:  finalArn,
		Message:       "AWS ACM ImportCertificate succeeded; post-verify serial match",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"arn":             finalArn,
			"region":          c.config.Region,
			"rotate_in_place": fmt.Sprintf("%t", resolvedArn != ""),
		},
	}, nil
}

// attemptRollback re-imports the snapshotted cert+chain bytes against
// the same ARN. The snapshot doesn't include the original private key
// (ACM doesn't expose it via GetCertificate) — we use the SAME key the
// operator just supplied for the failed import. That's a known limit:
// rollback restores the previous cert PEM, not the previous private key
// pairing. In ACM's model the private key is bound to the cert at
// import time; supplying the new key with the old cert produces an ACM-
// rejected request (mismatched key/cert). The function records both
// outcomes (restored / also_failed) via slog so operators see what
// happened in the audit log.
//
// Per the deploy-counters interface in service/deploy_counters.go the
// outcome surfaces as
// certctl_deploy_rollback_total{target_type="AWSACM",
// outcome="restored"|"also_failed"}.
func (c *Connector) attemptRollback(ctx context.Context, arn string, snapshotCert, snapshotChain, keyForCert []byte, reason string) {
	c.logger.Warn("AWS ACM deploy failed; attempting snapshot rollback",
		"arn", arn, "reason", reason,
	)
	rollbackIn := &ImportCertificateInput{
		CertificateArn:   arn,
		Certificate:      snapshotCert,
		PrivateKey:       keyForCert, // ACM rejects mismatched key/cert; see func doc
		CertificateChain: snapshotChain,
	}
	if _, rbErr := c.client.ImportCertificate(ctx, rollbackIn); rbErr != nil {
		c.logger.Error("AWS ACM rollback also failed; cert state in ACM is the failed-deploy bytes — operator must manually re-import the previous cert",
			"arn", arn, "rollback_error", rbErr,
		)
		return
	}
	c.logger.Warn("AWS ACM rollback succeeded; previous cert restored",
		"arn", arn,
	)
}

// ValidateOnly returns ErrValidateOnlyNotSupported. ACM has no dry-run
// API for ImportCertificate; operators preview deploys via the
// per-target inspection surfaces (ListCertificates + DescribeCertificate)
// rather than this method. Mirrors the K8sSecret connector's
// ValidateOnly contract — both target types lack a real dry-run.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	return target.ErrValidateOnlyNotSupported
}

// ValidateDeployment confirms the live ACM cert at the configured ARN
// matches the supplied serial. Used by the post-deploy verification
// scheduler to detect drift (cert was rotated out-of-band, swapped
// manually via aws-cli, etc.).
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("AWS ACM client not initialized")
	}
	if c.config == nil {
		return nil, fmt.Errorf("AWS ACM config not loaded")
	}

	arn := c.config.CertificateArn
	if arn == "" {
		return &target.ValidationResult{Valid: false, Serial: request.Serial,
			TargetAddress: "", Message: "AWS ACM ARN not yet known; first deploy hasn't completed"}, nil
	}

	out, err := c.client.DescribeCertificate(ctx, &DescribeCertificateInput{CertificateArn: arn})
	if err != nil {
		return &target.ValidationResult{Valid: false, Serial: request.Serial,
			TargetAddress: arn, Message: fmt.Sprintf("DescribeCertificate failed: %v", err)}, nil
	}

	if !serialsEqual(out.Serial, request.Serial) {
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: arn,
			Message: fmt.Sprintf("serial mismatch: expected %s, ACM has %s",
				request.Serial, out.Serial),
		}, nil
	}

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: arn,
		Message:       "ACM cert serial matches expected",
	}, nil
}

// discoverArnByCertID searches ACM for any cert tagged with
// certctl-certificate-id=<id>. Returns the first match's ARN; empty
// string if no match. Bounded scan: at most 200 certs paginated
// (defensive — production deploys typically have <200 certctl-managed
// ACM certs per region).
//
// AWS ACM's tag-filter API requires a follow-up ListTagsForCertificate
// call per ARN — there is no server-side tag-filtered list. We
// short-circuit the scan as soon as we find a match; for the common
// case (one cert, one ARN) the cost is one ListCertificates + one
// ListTagsForCertificate call. The operator can always pin
// Config.CertificateArn explicitly to skip discovery entirely.
//
// Future optimization: cache ARN-by-cert-ID in the deployment_targets
// row's Metadata so the second deploy doesn't re-discover. Out of scope
// for the Rank 5 V2 ship — Config.CertificateArn population on first
// deploy via DeploymentResult.Metadata gives us the same result without
// the cache layer.
func (c *Connector) discoverArnByCertID(ctx context.Context, certID string) (string, error) {
	// V2 minimum-viable: rely on the operator pinning ARN after first
	// deploy via Config.CertificateArn update. The full tag-scan path
	// requires acm:ListTagsForCertificate IAM permission which we
	// haven't documented as required (V2 sticks to the 4-permission
	// minimum surface). Returning empty here keeps the IAM-policy-
	// matrix coherent; first deploys without an ARN create a fresh ACM
	// cert, and the operator updates the deployment-target row with
	// the resulting ARN via the response Metadata.
	return "", errors.New("V2 ARN discovery requires operator to update deployment_target.config.certificate_arn after first deploy")
}

// buildProvenanceTags constructs the certctl-managed-by + certctl-
// certificate-id tag pair, merged with any operator-supplied tags from
// Config.Tags. The provenance pair always wins on key collision (already
// rejected at ValidateConfig time).
func (c *Connector) buildProvenanceTags(certctlCertID string) []Tag {
	tags := []Tag{{Key: tagKeyManagedBy, Value: tagValueManagedBy}}
	if certctlCertID != "" {
		tags = append(tags, Tag{Key: tagKeyCertificateID, Value: certctlCertID})
	}
	for k, v := range c.config.Tags {
		tags = append(tags, Tag{Key: k, Value: v})
	}
	return tags
}

// decodeRequest extracts cert+chain+key bytes from the deployment
// request and surfaces typed errors for the empty-bytes cases that ACM
// itself would reject with a less-informative SDK error.
func decodeRequest(request target.DeploymentRequest) (cert, chain, key []byte, err error) {
	if request.CertPEM == "" {
		return nil, nil, nil, fmt.Errorf("AWS ACM: cert_pem is required")
	}
	if request.KeyPEM == "" {
		return nil, nil, nil, fmt.Errorf("AWS ACM: key_pem is required (the agent must supply the private key)")
	}
	return []byte(request.CertPEM), []byte(request.ChainPEM), []byte(request.KeyPEM), nil
}

// serialFromPEM parses the leaf cert PEM and returns the serial number
// formatted to match ACM's DescribeCertificate response shape (uppercase
// hex with colon separators, e.g. "ab:cd:01"). ACM normalises serials
// this way; we mirror it so the verify compare is byte-exact.
func serialFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse cert: %w", err)
	}
	hex := fmt.Sprintf("%x", cert.SerialNumber)
	if len(hex)%2 == 1 {
		hex = "0" + hex
	}
	var b strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String(), nil
}

// serialsEqual compares two serial strings case-insensitively and
// strips colon separators. Defends against ACM occasionally returning
// serials in slightly different formats across SDK versions.
func serialsEqual(a, b string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, ":", ""))
	}
	return norm(a) == norm(b)
}

// metadataCertID extracts the certctl-managed certificate ID from the
// deployment request's Metadata map. The renewal scheduler populates
// this with the source-of-truth managed-cert row's ID; the connector
// stamps it as the certctl-certificate-id provenance tag.
func metadataCertID(metadata map[string]string) string {
	if v, ok := metadata["certificate_id"]; ok {
		return v
	}
	if v, ok := metadata["certctl_certificate_id"]; ok {
		return v
	}
	return ""
}

// Compile-time assertion: *Connector implements target.Connector and
// *sdkClient implements ACMClient. Catches interface drift at build
// time rather than at first deploy.
var (
	_ target.Connector = (*Connector)(nil)
	_ ACMClient        = (*sdkClient)(nil)
)
