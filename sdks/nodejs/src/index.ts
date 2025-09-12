/**
 * Vault Agent Node.js SDK
 * 
 * Official Node.js SDK for interacting with Vault Agent instances.
 * Provides comprehensive secret management, authentication, and error handling
 * with TypeScript definitions and Promise-based API.
 */

export { VaultAgentClient } from './client';
export { 
  APIKeyAuth, 
  JWTAuth, 
  CertificateAuth, 
  OAuthAuth, 
  BasicAuth 
} from './auth';
export {
  VaultAgentError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  ConnectionError,
  ConfigurationError,
  CryptographyError,
  PolicyError,
  RotationError,
  BackupError,
} from './exceptions';
export {
  Secret,
  SecretMetadata,
  Policy,
  PolicyRule,
  AuditEvent,
  Actor,
  Resource,
  BackupInfo,
  VaultStatus,
  RotationPolicy,
  CloudProviderConfig,
  HybridConfig,
  SecretStatus,
  AuditEventType,
} from './types';
export { ClientConfig } from './config';
export { CloudIntegration } from './cloud';

// Version information
export const VERSION = '1.0.0';