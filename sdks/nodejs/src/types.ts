/**
 * Type definitions for Vault Agent Node.js SDK
 */

export enum SecretStatus {
  ACTIVE = 'active',
  EXPIRED = 'expired',
  ROTATED = 'rotated',
  DELETED = 'deleted',
}

export enum AuditEventType {
  SECRET_CREATE = 'secret_create',
  SECRET_READ = 'secret_read',
  SECRET_UPDATE = 'secret_update',
  SECRET_DELETE = 'secret_delete',
  SECRET_ROTATE = 'secret_rotate',
  POLICY_CREATE = 'policy_create',
  POLICY_UPDATE = 'policy_update',
  POLICY_DELETE = 'policy_delete',
  AUTH_LOGIN = 'auth_login',
  AUTH_LOGOUT = 'auth_logout',
  AUTH_FAILURE = 'auth_failure',
}

export interface SecretMetadata {
  id: string;
  name: string;
  metadata: Record<string, any>;
  tags: string[];
  created_at: string;
  updated_at: string;
  expires_at?: string;
  rotation_due?: string;
  version: number;
  created_by: string;
  access_count: number;
  last_accessed?: string;
  status: SecretStatus;
}

export interface Secret extends SecretMetadata {
  value: string;
}

export interface RotationPolicy {
  id: string;
  enabled: boolean;
  interval_days: number;
  max_usage_count?: number;
  rotator_type: string;
  rotator_config: Record<string, any>;
  notification_channels: string[];
}

export interface PolicyRule {
  id: string;
  resource: string;
  actions: string[];
  effect: 'allow' | 'deny';
  conditions: Record<string, any>;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  priority: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface Actor {
  type: string;
  id: string;
  name?: string;
}

export interface Resource {
  type: string;
  id?: string;
  name?: string;
}

export interface AuditEvent {
  id: string;
  vault_id: string;
  event_type: AuditEventType;
  actor: Actor;
  resource: Resource;
  action: string;
  result: string;
  context: Record<string, any>;
  timestamp: string;
  ip_address?: string;
  user_agent?: string;
}

export interface BackupInfo {
  id: string;
  name: string;
  backup_type: string;
  status: string;
  file_path?: string;
  file_size?: number;
  checksum?: string;
  created_at: string;
  completed_at?: string;
  expires_at?: string;
  metadata: Record<string, any>;
}

export interface VaultStatus {
  status: string;
  version: string;
  uptime: number;
  secrets_count: number;
  policies_count: number;
  last_backup?: string;
  storage_usage: Record<string, any>;
  performance_metrics: Record<string, any>;
}

export interface CloudProviderConfig {
  provider: 'aws' | 'azure' | 'gcp';
  region?: string;
  credentials: Record<string, any>;
  service_config: Record<string, any>;
}

export interface HybridConfig {
  enabled: boolean;
  primary_provider: string;
  fallback_providers: string[];
  sync_interval: number;
  conflict_resolution: 'primary_wins' | 'latest_wins' | 'manual';
  cloud_providers: Record<string, CloudProviderConfig>;
}

export interface CreateSecretRequest {
  name: string;
  value: string;
  metadata?: Record<string, any>;
  tags?: string[];
}

export interface UpdateSecretRequest {
  value?: string;
  metadata?: Record<string, any>;
  tags?: string[];
}

export interface ListSecretsOptions {
  tags?: string[];
  limit?: number;
  offset?: number;
}

export interface AuditQueryOptions {
  start_time?: string;
  end_time?: string;
  event_type?: string;
  limit?: number;
}