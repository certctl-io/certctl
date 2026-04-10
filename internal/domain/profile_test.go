package domain

import (
	"testing"
	"time"
)

// TestIsShortLived_BelowThreshold tests that a certificate with MaxTTLSeconds
// below 3600 seconds and AllowShortLived=true returns true.
func TestIsShortLived_BelowThreshold(t *testing.T) {
	profile := &CertificateProfile{
		ID:              "prof-test-1",
		Name:            "Short-Lived",
		MaxTTLSeconds:   3599, // Just under 1 hour
		AllowShortLived: true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if !profile.IsShortLived() {
		t.Error("expected IsShortLived() to return true for MaxTTLSeconds=3599 with AllowShortLived=true")
	}
}

// TestIsShortLived_AtThreshold tests that a certificate with MaxTTLSeconds
// exactly at 3600 seconds returns false (threshold is exclusive: < 3600, not <=).
func TestIsShortLived_AtThreshold(t *testing.T) {
	profile := &CertificateProfile{
		ID:              "prof-test-2",
		Name:            "One-Hour",
		MaxTTLSeconds:   3600, // Exactly 1 hour
		AllowShortLived: true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if profile.IsShortLived() {
		t.Error("expected IsShortLived() to return false for MaxTTLSeconds=3600 (threshold is exclusive)")
	}
}

// TestIsShortLived_AboveThreshold tests that a certificate with MaxTTLSeconds
// well above 3600 seconds returns false.
func TestIsShortLived_AboveThreshold(t *testing.T) {
	profile := &CertificateProfile{
		ID:              "prof-test-3",
		Name:            "Standard",
		MaxTTLSeconds:   86400, // 24 hours
		AllowShortLived: true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if profile.IsShortLived() {
		t.Error("expected IsShortLived() to return false for MaxTTLSeconds=86400 (well above 1 hour)")
	}
}

// TestIsShortLived_FlagDisabled tests that even with MaxTTLSeconds below 3600,
// if AllowShortLived=false, the profile is not considered short-lived.
func TestIsShortLived_FlagDisabled(t *testing.T) {
	profile := &CertificateProfile{
		ID:              "prof-test-4",
		Name:            "Disabled-ShortLived",
		MaxTTLSeconds:   100, // Well below threshold
		AllowShortLived: false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if profile.IsShortLived() {
		t.Error("expected IsShortLived() to return false when AllowShortLived=false, regardless of MaxTTLSeconds")
	}
}

// TestIsShortLived_ZeroTTL tests that a certificate with MaxTTLSeconds=0
// returns false, since the method requires MaxTTLSeconds > 0.
func TestIsShortLived_ZeroTTL(t *testing.T) {
	profile := &CertificateProfile{
		ID:              "prof-test-5",
		Name:            "Zero-TTL",
		MaxTTLSeconds:   0,
		AllowShortLived: true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if profile.IsShortLived() {
		t.Error("expected IsShortLived() to return false when MaxTTLSeconds=0")
	}
}
