// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Phase 9 ARCH-M2 closure Sprint 12 (2026-05-14): extracted from
// cmd/agent/main.go via the Option B sibling-file pattern.
//
// This file holds the filesystem DISCOVERY scan — the agent's
// outbound surface for reporting pre-existing certificates it
// finds on disk back to the control plane (POST /api/v1/agents/
// {id}/discoveries, a machine-to-machine flow NOT exposed via the
// MCP surface per the comment in
// internal/mcp/tools.go::RegisterTools):
//
//   - runDiscoveryScan: walks each configured discovery directory,
//     dispatches each candidate file to parsePEMFile or parseDERFile
//     depending on extension, batches the parsed entries, and POSTs
//     them in one report.
//   - parsePEMFile / parseDERFile: extract every X.509 certificate
//     from a candidate file in either encoding.
//   - certToEntry: project a parsed *x509.Certificate into the
//     discoveredCertEntry shape the control plane expects.
//   - discoveredCertEntry struct + sha256Sum + certKeyInfo helpers
//     consumed only by the discovery path; co-locating them keeps
//     this file self-contained.

// runDiscoveryScan walks configured directories, parses certificate files, and reports
// discovered certificates to the control plane.
// Supports PEM and DER encoded X.509 certificates.
func (a *Agent) runDiscoveryScan(ctx context.Context) {
	a.logger.Info("starting filesystem certificate discovery scan",
		"directories", a.config.DiscoveryDirs)

	startTime := time.Now()
	var certs []discoveredCertEntry
	var scanErrors []string

	for _, dir := range a.config.DiscoveryDirs {
		a.logger.Debug("scanning directory", "path", dir)

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("walk error at %s: %v", path, err))
				return nil // continue walking
			}
			if info.IsDir() {
				return nil
			}

			// Skip files larger than 1MB (unlikely to be a certificate)
			if info.Size() > 1*1024*1024 {
				return nil
			}

			// Check file extension
			ext := strings.ToLower(filepath.Ext(path))
			switch ext {
			case ".pem", ".crt", ".cer", ".cert":
				found := a.parsePEMFile(path)
				certs = append(certs, found...)
			case ".der":
				if entry, err := a.parseDERFile(path); err == nil {
					certs = append(certs, entry)
				} else {
					a.logger.Debug("skipping non-cert DER file", "path", path, "error", err)
				}
			default:
				// Try PEM parsing for extensionless files or unknown extensions
				if ext == "" || ext == ".key" {
					return nil // skip key files and extensionless
				}
				found := a.parsePEMFile(path)
				if len(found) > 0 {
					certs = append(certs, found...)
				}
			}
			return nil
		})
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("failed to walk %s: %v", dir, err))
		}
	}

	scanDuration := time.Since(startTime)
	a.logger.Info("discovery scan completed",
		"certificates_found", len(certs),
		"errors", len(scanErrors),
		"duration_ms", scanDuration.Milliseconds())

	if len(certs) == 0 && len(scanErrors) == 0 {
		a.logger.Debug("no certificates found and no errors, skipping report")
		return
	}

	// Build report payload
	entries := make([]map[string]interface{}, len(certs))
	for i, c := range certs {
		entries[i] = map[string]interface{}{
			"fingerprint_sha256": c.FingerprintSHA256,
			"common_name":        c.CommonName,
			"sans":               c.SANs,
			"serial_number":      c.SerialNumber,
			"issuer_dn":          c.IssuerDN,
			"subject_dn":         c.SubjectDN,
			"not_before":         c.NotBefore,
			"not_after":          c.NotAfter,
			"key_algorithm":      c.KeyAlgorithm,
			"key_size":           c.KeySize,
			"is_ca":              c.IsCA,
			"pem_data":           c.PEMData,
			"source_path":        c.SourcePath,
			"source_format":      c.SourceFormat,
		}
	}

	report := map[string]interface{}{
		"agent_id":         a.config.AgentID,
		"directories":      a.config.DiscoveryDirs,
		"certificates":     entries,
		"errors":           scanErrors,
		"scan_duration_ms": int(scanDuration.Milliseconds()),
	}

	// Submit to control plane
	path := fmt.Sprintf("/api/v1/agents/%s/discoveries", a.config.AgentID)
	resp, err := a.makeRequest(ctx, http.MethodPost, path, report)
	if err != nil {
		a.logger.Error("failed to submit discovery report", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("discovery report rejected",
			"status", resp.StatusCode,
			"body", string(body))
		return
	}

	a.logger.Info("discovery report submitted successfully",
		"certificates", len(certs),
		"errors", len(scanErrors))
}

// discoveredCertEntry holds parsed certificate metadata for reporting.
type discoveredCertEntry struct {
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	CommonName        string   `json:"common_name"`
	SANs              []string `json:"sans"`
	SerialNumber      string   `json:"serial_number"`
	IssuerDN          string   `json:"issuer_dn"`
	SubjectDN         string   `json:"subject_dn"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	KeyAlgorithm      string   `json:"key_algorithm"`
	KeySize           int      `json:"key_size"`
	IsCA              bool     `json:"is_ca"`
	PEMData           string   `json:"pem_data"`
	SourcePath        string   `json:"source_path"`
	SourceFormat      string   `json:"source_format"`
}

// parsePEMFile reads a file and extracts all X.509 certificates from PEM blocks.
func (a *Agent) parsePEMFile(path string) []discoveredCertEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		a.logger.Debug("failed to read file", "path", path, "error", err)
		return nil
	}

	var entries []discoveredCertEntry
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			a.logger.Debug("failed to parse certificate in PEM", "path", path, "error", err)
			continue
		}

		pemStr := string(pem.EncodeToMemory(block))
		entries = append(entries, certToEntry(cert, path, "PEM", pemStr))
	}
	return entries
}

// parseDERFile reads a DER-encoded certificate file.
func (a *Agent) parseDERFile(path string) (discoveredCertEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return discoveredCertEntry{}, fmt.Errorf("read failed: %w", err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return discoveredCertEntry{}, fmt.Errorf("parse failed: %w", err)
	}

	// Convert to PEM for storage
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}))
	return certToEntry(cert, path, "DER", pemStr), nil
}

// certToEntry converts a parsed x509.Certificate into a discoveredCertEntry.
func certToEntry(cert *x509.Certificate, path, format, pemData string) discoveredCertEntry {
	// Compute SHA-256 fingerprint
	fingerprint := fmt.Sprintf("%x", sha256Sum(cert.Raw))

	// Determine key algorithm and size
	keyAlg, keySize := certKeyInfo(cert)

	return discoveredCertEntry{
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
		SourcePath:        path,
		SourceFormat:      format,
	}
}

// sha256Sum returns the SHA-256 hash of data.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// certKeyInfo extracts key algorithm name and size from a certificate.
func certKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	default:
		switch cert.PublicKeyAlgorithm {
		case x509.Ed25519:
			return "Ed25519", 256
		default:
			return cert.PublicKeyAlgorithm.String(), 0
		}
	}
}
