-- M11a: Certificate Profiles + Crypto Foundation
-- Named enrollment profiles defining allowed key types, max TTL, required SANs,
-- permitted EKUs, and optional SPIFFE URI SAN patterns.

-- Table: certificate_profiles
CREATE TABLE IF NOT EXISTS certificate_profiles (
  id TEXT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  description TEXT DEFAULT '',

  -- Crypto policy: which key algorithms and minimum sizes are allowed
  -- Example: [{"algorithm": "ECDSA", "min_size": 256}, {"algorithm": "RSA", "min_size": 2048}]
  allowed_key_algorithms JSONB NOT NULL DEFAULT '[{"algorithm": "ECDSA", "min_size": 256}, {"algorithm": "RSA", "min_size": 2048}]',

  -- Maximum certificate TTL in seconds (0 = no limit, uses issuer default)
  -- Short-lived: 300 (5 min), 3600 (1 hour). Standard: 7776000 (90 days), 4060800 (47 days)
  max_ttl_seconds INT NOT NULL DEFAULT 0,

  -- Permitted Extended Key Usages
  -- Example: ["serverAuth", "clientAuth"]
  allowed_ekus JSONB NOT NULL DEFAULT '["serverAuth"]',

  -- Required SAN patterns (regexes that issued certs must match)
  -- Example: [".*\\.example\\.com$", ".*\\.internal\\.example\\.com$"]
  required_san_patterns JSONB NOT NULL DEFAULT '[]',

  -- Optional SPIFFE URI SAN pattern for workload identity
  -- Example: "spiffe://example.com/workload/*"
  -- Empty string means no SPIFFE SAN will be minted
  spiffe_uri_pattern VARCHAR(512) DEFAULT '',

  -- Whether this profile allows short-lived certs (TTL < 1 hour)
  -- When true, expired certs under this profile skip CRL/OCSP (expiry = revocation)
  allow_short_lived BOOLEAN NOT NULL DEFAULT false,

  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certificate_profiles_name ON certificate_profiles(name);
CREATE INDEX IF NOT EXISTS idx_certificate_profiles_enabled ON certificate_profiles(enabled);

-- Add certificate_profile_id FK to managed_certificates (nullable for backward compat)
ALTER TABLE managed_certificates ADD COLUMN IF NOT EXISTS certificate_profile_id TEXT REFERENCES certificate_profiles(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_managed_certificates_profile_id ON managed_certificates(certificate_profile_id);

-- Add certificate_profile_id FK to renewal_policies (nullable — profile scoping on policies)
ALTER TABLE renewal_policies ADD COLUMN IF NOT EXISTS certificate_profile_id TEXT REFERENCES certificate_profiles(id) ON DELETE SET NULL;

-- Add key metadata to certificate_versions for audit / compliance
ALTER TABLE certificate_versions ADD COLUMN IF NOT EXISTS key_algorithm VARCHAR(50) DEFAULT '';
ALTER TABLE certificate_versions ADD COLUMN IF NOT EXISTS key_size INT DEFAULT 0;
