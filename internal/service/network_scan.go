package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
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

// CreateTarget creates a new network scan target.
func (s *NetworkScanService) CreateTarget(ctx context.Context, target *domain.NetworkScanTarget) (*domain.NetworkScanTarget, error) {
	if target.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if len(target.CIDRs) == 0 {
		return nil, fmt.Errorf("at least one CIDR is required")
	}
	// Validate CIDRs
	for _, cidr := range target.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			// Try parsing as plain IP
			if ip := net.ParseIP(cidr); ip == nil {
				return nil, fmt.Errorf("invalid CIDR or IP: %s", cidr)
			}
		}
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
		// Validate new CIDRs
		for _, cidr := range target.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				if ip := net.ParseIP(cidr); ip == nil {
					return nil, fmt.Errorf("invalid CIDR or IP: %s", cidr)
				}
			}
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

	// Collect discovered cert entries
	var entries []domain.DiscoveredCertEntry
	var scanErrors []string
	for _, result := range results {
		if result.Error != "" {
			// Only log connection errors at debug level (many hosts won't have TLS)
			if s.logger != nil {
				s.logger.Debug("scan endpoint error",
					"address", result.Address,
					"error", result.Error)
			}
			continue
		}
		entries = append(entries, result.Certs...)
	}

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

// isReservedCIDR checks if an IP address falls within reserved ranges that should not be scanned.
// Filters out loopback, link-local (including cloud metadata), and multicast ranges.
// Does NOT filter RFC 1918 ranges since certctl is self-hosted and internal networks are a primary use case.
func isReservedIP(ip net.IP) bool {
	// Loopback: 127.0.0.0/8
	if ip.IsLoopback() {
		return true
	}

	// Link-local: 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
	if linkLocal := net.ParseIP("169.254.0.0"); linkLocal != nil {
		if _, linkLocalNet, _ := net.ParseCIDR("169.254.0.0/16"); linkLocalNet != nil {
			if linkLocalNet.Contains(ip) {
				return true
			}
		}
	}

	// Multicast: 224.0.0.0/4
	if multicast := net.ParseIP("224.0.0.0"); multicast != nil {
		if _, multicastNet, _ := net.ParseCIDR("224.0.0.0/4"); multicastNet != nil {
			if multicastNet.Contains(ip) {
				return true
			}
		}
	}

	// Broadcast: 255.255.255.255
	if ip.String() == "255.255.255.255" {
		return true
	}

	return false
}

// expandCIDR expands a CIDR notation or single IP into a list of IPs.
// Limits expansion to /20 (4096 IPs) to prevent accidental huge scans.
// Filters out reserved IP ranges to prevent SSRF attacks.
func expandCIDR(cidr string) []string {
	// Try as CIDR first
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		if singleIP := net.ParseIP(cidr); singleIP != nil {
			if isReservedIP(singleIP) {
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
		if isReservedIP(ip) {
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
	// Compute SHA-256 fingerprint
	fingerprintBytes := sha256.Sum256(cert.Raw)
	fingerprint := fmt.Sprintf("%x", fingerprintBytes)

	// Encode as PEM
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemData := string(pem.EncodeToMemory(pemBlock))

	// Key algorithm and size
	keyAlg, keySize := tlsCertKeyInfo(cert)

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

// tlsCertKeyInfo extracts key algorithm name and size from a certificate.
func tlsCertKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	default:
		switch cert.PublicKeyAlgorithm {
		case x509.Ed25519:
			return "Ed25519", 256
		default:
			return cert.PublicKeyAlgorithm.String(), 0
		}
	}
}
