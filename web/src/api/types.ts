export interface Certificate {
  id: string;
  name: string;
  common_name: string;
  sans: string[];
  status: string;
  environment: string;
  issuer_id: string;
  owner_id: string;
  team_id: string;
  renewal_policy_id: string;
  certificate_profile_id: string;
  serial_number: string;
  fingerprint: string;
  key_algorithm: string;
  key_size: number;
  issued_at: string;
  expires_at: string;
  revoked_at?: string;
  revocation_reason?: string;
  tags: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export const REVOCATION_REASONS = [
  { value: 'unspecified', label: 'Unspecified' },
  { value: 'keyCompromise', label: 'Key Compromise' },
  { value: 'caCompromise', label: 'CA Compromise' },
  { value: 'affiliationChanged', label: 'Affiliation Changed' },
  { value: 'superseded', label: 'Superseded' },
  { value: 'cessationOfOperation', label: 'Cessation of Operation' },
  { value: 'certificateHold', label: 'Certificate Hold' },
  { value: 'privilegeWithdrawn', label: 'Privilege Withdrawn' },
] as const;

export interface CertificateVersion {
  id: string;
  certificate_id: string;
  version: number;
  serial_number: string;
  fingerprint: string;
  cert_pem: string;
  chain_pem: string;
  csr_pem: string;
  not_before: string;
  not_after: string;
  created_at: string;
}

export interface Agent {
  id: string;
  name: string;
  hostname: string;
  ip_address: string;
  os: string;
  architecture: string;
  status: string;
  version: string;
  last_heartbeat: string;
  last_heartbeat_at: string;
  capabilities: string[];
  tags: Record<string, string>;
  registered_at: string;
  created_at: string;
  updated_at: string;
}

export interface Job {
  id: string;
  certificate_id: string;
  type: string;
  status: string;
  attempts: number;
  max_attempts: number;
  error_message: string;
  scheduled_at: string;
  started_at: string;
  completed_at: string;
  created_at: string;
}

export interface Notification {
  id: string;
  type: string;
  channel: string;
  recipient: string;
  subject: string;
  message: string;
  status: string;
  certificate_id: string;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  actor: string;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  type: string;
  severity: string;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PolicyViolation {
  id: string;
  rule_id: string;
  certificate_id: string;
  severity: string;
  message: string;
  created_at: string;
}

export interface Issuer {
  id: string;
  name: string;
  type: string;
  config: Record<string, unknown>;
  status: string;
  created_at: string;
}

export interface Target {
  id: string;
  name: string;
  type: string;
  hostname: string;
  agent_id: string;
  config: Record<string, unknown>;
  status: string;
  created_at: string;
}

export interface KeyAlgorithmRule {
  algorithm: string;
  min_size: number;
}

export interface CertificateProfile {
  id: string;
  name: string;
  description: string;
  allowed_key_algorithms: KeyAlgorithmRule[];
  max_ttl_seconds: number;
  allowed_ekus: string[];
  required_san_patterns: string[];
  spiffe_uri_pattern: string;
  allow_short_lived: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface Owner {
  id: string;
  name: string;
  email: string;
  team_id: string;
  created_at: string;
  updated_at: string;
}

export interface Team {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface AgentGroup {
  id: string;
  name: string;
  description: string;
  match_os: string;
  match_architecture: string;
  match_ip_cidr: string;
  match_version: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AgentGroupMembership {
  agent_group_id: string;
  agent_id: string;
  membership_type: string;
  created_at: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
}
