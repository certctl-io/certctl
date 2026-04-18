package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/tlsprobe"
	"github.com/shankar0123/certctl/internal/validation"
)

// SentinelAgentID is the agent ID used for network-discovered certificates.
// This allows the existing discovery dedup constraint (fingerprint, agent_id, source_path)
// to work without schema changes.
const SentinelAgentID = "server-scanner"

// NetworkScanService manages active TLS scanning of network endpoints.
type NetworkScanService struct {
	networkScanRepo  repository.NetworkScanRepository
	discoveryService *DiscoveryService
	auditService     *AuditService
	logger           *slog.Logger
	concurrency      int
}

// NewNetworkScanService creates a new network scan service.
func NewNetworkScanService(
	networkScanRepo repository.NetworkScanRepository,
	discoveryService *DiscoveryService,
	auditService *AuditService,
	logger *slog.Logger,
) *NetworkScanService {
	return &NetworkScanService{
		networkScanRepo:  networkScanRepo,
		discoveryService: discoveryService,
		auditService:     auditService,
		logger:           logger,
		concurrency:      50,
	}
}

// ListTargets returns all network scan targets.
func (s *NetworkScanService) ListTargets(ctx context.Context) ([]*domain.NetworkScanTarget, error) {
	return s.networkScanRepo.List(ctx)
}

// GetTarget retrieves a network scan target by ID.
func (s *NetworkScanService) GetTarget(ctx context.Context, id string) (*domain.NetworkScanTarget, error) {
	return s.networkScanRepo.Get(ctx, id)
}

// maxCIDRHostBits is the maximum number of host bits allowed in a CIDR range.
// A /20 network has 12 host bits = 4096 IPs max. This prevents operators from
// accidentally creating scan targets that would exhaust server resources.
const maxCIDRHostBits = 12

// validateCIDRs validates a list of CIDRs for syntax correctness and size limits.
// Each CIDR must be a valid CIDR notation or plain IP address, and no single CIDR
// may be larger than /20 (4096 IPs). This validation runs at API request time so
// operators get an immediate 400 error instead of a silent truncation at scan time.
func validateCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as plain IP (single host)
			if ip := net.ParseIP(cidr); ip == nil {
				return fmt.Errorf("invalid CIDR or IP: %s", cidr)
			}
			continue // Single IPs are always valid size
		}
		// Enforce /20 size cap at API level
		ones, bits := ipNet.Mask.Size()
		hostBits := bits - ones
		if hostBits > maxCIDRHostBits {
			return fmt.Errorf("CIDR %s is too large (/%d has %d host bits, max /%d with %d host bits = 4096 IPs)",
				cidr, ones, hostBits, bits-maxCIDRHostBits, maxCIDRHostBits)
		}
	}
	return nil
}

// CreateTarget creates a new network scan target.
func (s *NetworkScanService) CreateTarget(ctx context.Context, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error) {
	if target.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if len(target.CIDRs) == 0 {
		return nil, fmt.Errorf("at least one CIDR is required")
	}
	// Validate CIDRs (syntax + /20 size cap)
	if err := validateCIDRs(target.CIDRs); err != nil {
		return nil, err
	}
	if len(target.Ports) == 0 {
		target.Ports = []int64{443}
	}
	if target.ScanIntervalHours == 0 {
		target.ScanIntervalHours = 6
	}
	if target.TimeoutMs == 0 {
		target.TimeoutMs = 5000
	}
	target.ID = generateID("nst")
	target.Enabled = true
	target.CreatedAt = time.Now()
	target.UpdatedAt = time.Now()

	if err := s.networkScanRepo.Create(ctx, target); err != nil {
		return nil, err
	}

	s.auditService.RecordEvent(ctx, "operator", domain.ActorTypeUser,
		"network_scan_target_created", "network_scan_target", target.ID,
		map[string]interface{}{
			"name":  target.Name,
			"cidrs": target.CIDRs,
			"ports": target.Ports,
		})

	return target, nil
}

// UpdateTarget updates an existing network scan target.
func (s *NetworkScanService) UpdateTarget(ctx context.Context, id string, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error) {
	existing, err := s.networkScanRepo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if target.Name != "" {
		existing.Name = target.Name
	}
	if len(target.CIDRs) > 0 {
		// Validate new CIDRs (syntax + /20 size cap)
		if err := validateCIDRs(target.CIDRs); err != nil {
			return nil, err
		}
		existing.CIDRs = target.CIDRs
	}
	if len(target.Ports) > 0 {
		existing.Ports = target.Ports
	}
	if target.ScanIntervalHours > 0 {
		existing.ScanIntervalHours = target.ScanIntervalHours
	}
	if target.TimeoutMs > 0 {
		existing.TimeoutMs = target.TimeoutMs
	}
	// Always update enabled field (it's a boolean, so 0-value is meaningful)
	existing.Enabled = target.Enabled

	if err := s.networkScanRepo.Update(ctx, existing); err != nil {
		return nil, err
	}

	return existing, nil
}

// DeleteTarget removes a network scan target.
func (s *NetworkScanService) DeleteTarget(ctx context.Context, id string) error {
	if err := s.networkScanRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete network scan target: %w", err)
	}

	s.auditService.RecordEvent(ctx, "operator", domain.ActorTypeUser,
		"network_scan_target_deleted", "network_scan_target", id, nil)

	return nil
}

// ScanAllTargets runs the active TLS scan for all enabled targets.
// This is called by the scheduler on the configured interval.
func (s *NetworkScanService) ScanAllTargets(ctx context.Context) error {
	targets, err := s.networkScanRepo.ListEnabled(ctx)
	if err != nil {
		return fmt.Errorf("list enabled targets: %w", err)
	}

	if len(targets) == 0 {
		if s.logger != nil {
			s.logger.Debug("no enabled network scan targets")
		}
		return nil
	}

	if s.logger != nil {
		s.logger.Info("starting network scan", "targets", len(targets))
	}

	for _, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.scanTarget(ctx, target)
	}

	return nil
}

// TriggerScan runs an immediate scan for a specific target.
func (s *NetworkScanService) TriggerScan(ctx context.Context, targetID string) (*domain.DiscoveryScan, error) {
	target, err := s.networkScanRepo.Get(ctx, targetID)
	if err != nil {
		return nil, err
	}
	return s.scanTarget(ctx, target), nil
}

// scanTarget scans a single network target and feeds results into the discovery pipeline.
func (s *NetworkScanService) scanTarget(ctx context.Context, target *domain.NetworkScanTarget) *domain.DiscoveryScan {
	startTime := time.Now()
	if s.logger != nil {
		s.logger.Info("scanning network target",
			"target_id", target.ID,
			"name", target.Name,
			"cidrs", target.CIDRs,
			"ports", target.Ports)
	}

	// Expand CIDRs to individual IPs
	endpoints := s.expandEndpoints(target.CIDRs, target.Ports)
	if s.logger != nil {
		s.logger.Debug("expanded endpoints", "count", len(endpoints))
	}

	// Scan endpoints concurrently
	timeout := time.Duration(target.TimeoutMs) * time.Millisecond
	results := s.scanEndpoints(ctx, endpoints, timeout)

	// Collect discovered cert entries and per-endpoint errors.
	//
	// M-9 (operator-observability): before this fix, scanErrors was declared
	// but never appended to, so the "errors" count in the summary Info log
	// and the Errors field on the DiscoveryReport were always zero/nil —
	// silently hiding per-endpoint failures from operators and from the
	// downstream scan history record. Per-endpoint failures are still logged
	// at Debug (sweep scans generate high connection-refused noise by design
	// — most hosts in a CIDR won't have TLS on the probed port), but the
	// aggregate count and the report's Errors field now reflect reality so
	// operators can see, via the scan summary and the stored scan record,
	// how many endpoints failed without having to enable Debug logging.
	entries, scanErrors := s.collectScanResults(results)

	scanDuration := time.Since(startTime)
	if s.logger != nil {
		s.logger.Info("network target scan completed",
			"target_id", target.ID,
			"endpoints_scanned", len(endpoints),
			"certificates_found", len(entries),
			"errors", len(scanErrors),
			"duration_ms", scanDuration.Milliseconds())
	}

	// Update scan results on target
	s.networkScanRepo.UpdateScanResults(ctx, target.ID, time.Now(),
		int(scanDuration.Milliseconds()), len(entries))

	// Feed into discovery pipeline if we found certs
	if len(entries) == 0 {
		return nil
	}

	// Build directories list from CIDRs for the scan record
	dirs := make([]string, len(target.CIDRs))
	copy(dirs, target.CIDRs)

	report := &domain.DiscoveryReport{
		AgentID:        SentinelAgentID,
		Directories:    dirs,
		Certificates:   entries,
		Errors:         scanErrors,
		ScanDurationMs: int(scanDuration.Milliseconds()),
	}

	scan, err := s.discoveryService.ProcessDiscoveryReport(ctx, report)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to process network scan report",
				"target_id", target.ID,
				"error", err)
		}
		return nil
	}

	return scan
}

// expandEndpoints converts CIDR ranges and ports into a list of "ip:port" endpoints.
// Filters out reserved IP ranges and logs warnings.
func (s *NetworkScanService) expandEndpoints(cidrs []string, ports []int64) []string {
	var endpoints []string

	for _, cidr := range cidrs {
		ips := expandCIDR(cidr)
		if ips == nil || len(ips) == 0 {
			if s.logger != nil {
				s.logger.Warn("CIDR range filtered (reserved or too large)",
					"cidr", cidr)
			}
			continue
		}
		for _, ip := range ips {
			for _, port := range ports {
				endpoints = append(endpoints, fmt.Sprintf("%s:%d", ip, port))
			}
		}
	}

	return endpoints
}

// The reserved-IP filter used by expandCIDR previously lived here as an
// unexported isReservedIP helper. It has been moved to
// internal/validation.IsReservedIP so the webhook notifier can share a single
// authoritative implementation (H-4, CWE-918). The behaviour is
// byte-identical with the previous helper — RFC 1918 is intentionally NOT
// filtered, matching certctl's self-hosted design. If you change the
// validation package's IsReservedIP, you are changing the network-scanner's
// behaviour; audit both code paths together.

// expandCIDR expands a CIDR notation or single IP into a list of IPs.
// Limits expansion to /20 (4096 IPs) to prevent accidental huge scans.
// Filters out reserved IP ranges (via validation.IsReservedIP) to prevent
// SSRF amplification via network-scan targets pointed at cloud metadata or
// loopback.
func expandCIDR(cidr string) []string {
	// Try as CIDR first
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		if singleIP := net.ParseIP(cidr); singleIP != nil {
			if validation.IsReservedIP(singleIP) {
				return nil
			}
			return []string{singleIP.String()}
		}
		return nil
	}

	// Count network size and cap at /20
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits > 12 { // More than 4096 hosts
		return nil // Skip overly large networks
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		// Skip reserved IPs
		if validation.IsReservedIP(ip) {
			continue
		}

		// Copy IP before appending (net.IP is a mutable slice)
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy.String())
	}

	// Remove network and broadcast for IPv4 /31 and larger
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips
}

// incrementIP increments an IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// collectScanResults partitions per-endpoint scan results into discovered
// certificate entries and a list of per-endpoint error strings.
//
// M-9 (operator-observability): the summary Info log and the DiscoveryReport
// both report the count of endpoints that failed to probe. Before this helper
// existed, the caller accumulated entries but never populated the errors
// slice, so the aggregate error count was always zero and the scan record's
// Errors field was always nil — silently hiding per-endpoint failures.
//
// Per-endpoint errors remain logged at Debug (sweep scans generate high
// connection-refused noise by design — most hosts in a CIDR won't have TLS
// on the probed port). Aggregation surfaces the count at Info, preserving
// Debug-level detail for operators who want it without creating log spam
// at default verbosity.
func (s *NetworkScanService) collectScanResults(results []domain.NetworkScanResult) ([]domain.DiscoveredCertEntry, []string) {
	var entries []domain.DiscoveredCertEntry
	var scanErrors []string
	for _, result := range results {
		if result.Error != "" {
			// Debug-level is intentional: a sweep scan of a /24 typically
			// produces 200+ connection-refused results, and logging each
			// at Warn would create log spam at default verbosity. The
			// aggregate count in the Info-level scan-completed log surfaces
			// the failure volume to operators; Debug provides the detail
			// when diagnosing a specific endpoint.
			if s.logger != nil {
				s.logger.Debug("scan endpoint error",
					"address", result.Address,
					"error", result.Error)
			}
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %s", result.Address, result.Error))
			continue
		}
		entries = append(entries, result.Certs...)
	}
	return entries, scanErrors
}

// scanEndpoints probes TLS endpoints concurrently and returns results.
func (s *NetworkScanService) scanEndpoints(ctx context.Context, endpoints []string, timeout time.Duration) []domain.NetworkScanResult {
	results := make([]domain.NetworkScanResult, len(endpoints))
	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	for i, endpoint := range endpoints {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = s.probeTLS(ctx, addr, timeout)
		}(i, endpoint)
	}
	wg.Wait()
	return results
}

// probeTLS connects to an endpoint, performs a TLS handshake, and extracts certificates.
func (s *NetworkScanService) probeTLS(ctx context.Context, address string, timeout time.Duration) domain.NetworkScanResult {
	startTime := time.Now()
	result := domain.NetworkScanResult{Address: address}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		// SECURITY NOTE: InsecureSkipVerify is intentionally set to true here.
		// The network scanner must discover ALL certificates including self-signed,
		// expired, and internal CA certificates. This setting is scoped to discovery
		// probing only — it is NEVER used for control-plane API calls, issuer
		// connector communication, or any operation that trusts the certificate.
		// The endpoint's certificate chain is extracted and analyzed, not validated.
		// See TICKET-016 for full security audit rationale.
		InsecureSkipVerify: true,
	})
	if err != nil {
		result.Error = err.Error()
		result.LatencyMs = int(time.Since(startTime).Milliseconds())
		return result
	}
	defer conn.Close()

	result.LatencyMs = int(time.Since(startTime).Milliseconds())

	// Extract certificates from TLS connection state
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		entry := tlsCertToEntry(cert, address)
		result.Certs = append(result.Certs, entry)
	}

	return result
}

// tlsCertToEntry converts an x509.Certificate from a TLS handshake into a DiscoveredCertEntry.
func tlsCertToEntry(cert *x509.Certificate, address string) domain.DiscoveredCertEntry {
	// Compute SHA-256 fingerprint using shared tlsprobe package
	fingerprint := tlsprobe.CertFingerprint(cert)

	// Encode as PEM
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemData := string(pem.EncodeToMemory(pemBlock))

	// Key algorithm and size using shared tlsprobe package
	keyAlg, keySize := tlsprobe.CertKeyInfo(cert)

	return domain.DiscoveredCertEntry{
		FingerprintSHA256: fingerprint,
		CommonName:        cert.Subject.CommonName,
		SANs:              cert.DNSNames,
		SerialNumber:      cert.SerialNumber.Text(16),
		IssuerDN:          cert.Issuer.String(),
		SubjectDN:         cert.Subject.String(),
		NotBefore:         cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
		KeyAlgorithm:      keyAlg,
		KeySize:           keySize,
		IsCA:              cert.IsCA,
		PEMData:           pemData,
		SourcePath:        address,
		SourceFormat:      "network",
	}
}
