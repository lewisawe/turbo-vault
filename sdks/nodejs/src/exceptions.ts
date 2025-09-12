/**
 * Exception classes for Vault Agent Node.js SDK
 */

export class VaultAgentError extends Error {
  public readonly code?: string;
  public readonly details?: Record<string, any>;
  public readonly requestId?: string;

  constructor(
    message: string,
    code?: string,
    details?: Record<string, any>,
    requestId?: string
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
    
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export class AuthenticationError extends VaultAgentError {
  constructor(message: string = 'Authentication failed', code?: string, details?: Record<string, any>) {
    super(message, code || 'AUTHENTICATION_ERROR', details);
  }
}

export class AuthorizationError extends VaultAgentError {
  constructor(message: string = 'Authorization failed', code?: string, details?: Record<string, any>) {
    super(message, code || 'AUTHORIZATION_ERROR', details);
  }
}

export class NotFoundError extends VaultAgentError {
  constructor(message: string = 'Resource not found', code?: string, details?: Record<string, any>) {
    super(message, code || 'NOT_FOUND', details);
  }
}

export class ValidationError extends VaultAgentError {
  constructor(message: string = 'Validation failed', code?: string, details?: Record<string, any>) {
    super(message, code || 'VALIDATION_ERROR', details);
  }
}

export class RateLimitError extends VaultAgentError {
  public readonly retryAfter?: number;

  constructor(
    message: string = 'Rate limit exceeded',
    retryAfter?: number,
    code?: string,
    details?: Record<string, any>
  ) {
    super(message, code || 'RATE_LIMIT_ERROR', details);
    this.retryAfter = retryAfter;
  }
}

export class ConnectionError extends VaultAgentError {
  constructor(message: string = 'Connection failed', code?: string, details?: Record<string, any>) {
    super(message, code || 'CONNECTION_ERROR', details);
  }
}

export class ConfigurationError extends VaultAgentError {
  constructor(message: string = 'Configuration error', code?: string, details?: Record<string, any>) {
    super(message, code || 'CONFIGURATION_ERROR', details);
  }
}

export class CryptographyError extends VaultAgentError {
  constructor(message: string = 'Cryptography error', code?: string, details?: Record<string, any>) {
    super(message, code || 'CRYPTOGRAPHY_ERROR', details);
  }
}

export class PolicyError extends VaultAgentError {
  constructor(message: string = 'Policy error', code?: string, details?: Record<string, any>) {
    super(message, code || 'POLICY_ERROR', details);
  }
}

export class RotationError extends VaultAgentError {
  constructor(message: string = 'Rotation error', code?: string, details?: Record<string, any>) {
    super(message, code || 'ROTATION_ERROR', details);
  }
}

export class BackupError extends VaultAgentError {
  constructor(message: string = 'Backup error', code?: string, details?: Record<string, any>) {
    super(message, code || 'BACKUP_ERROR', details);
  }
}

/**
 * Parse error response from API and throw appropriate exception
 */
export function parseErrorResponse(status: number, data: any, requestId?: string): never {
  const message = data?.message || data?.error || 'Unknown error';
  const code = data?.code;
  const details = data?.details;

  switch (status) {
    case 401:
      throw new AuthenticationError(message, code, details);
    case 403:
      throw new AuthorizationError(message, code, details);
    case 404:
      throw new NotFoundError(message, code, details);
    case 400:
      throw new ValidationError(message, code, details);
    case 429:
      const retryAfter = data?.retry_after ? parseInt(data.retry_after) : undefined;
      throw new RateLimitError(message, retryAfter, code, details);
    default:
      throw new VaultAgentError(`HTTP ${status}: ${message}`, code, details, requestId);
  }
}