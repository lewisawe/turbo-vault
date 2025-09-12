"""
Exception classes for Vault Agent SDK.
"""


class VaultAgentError(Exception):
    """Base exception for Vault Agent SDK."""
    
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class AuthenticationError(VaultAgentError):
    """Authentication failed."""
    pass


class AuthorizationError(VaultAgentError):
    """Authorization failed (insufficient permissions)."""
    pass


class NotFoundError(VaultAgentError):
    """Resource not found."""
    pass


class ValidationError(VaultAgentError):
    """Request validation failed."""
    pass


class RateLimitError(VaultAgentError):
    """Rate limit exceeded."""
    pass


class ConnectionError(VaultAgentError):
    """Connection to Vault Agent failed."""
    pass


class ConfigurationError(VaultAgentError):
    """Configuration error."""
    pass


class CryptographyError(VaultAgentError):
    """Cryptographic operation failed."""
    pass


class PolicyError(VaultAgentError):
    """Policy evaluation or enforcement error."""
    pass


class RotationError(VaultAgentError):
    """Secret rotation error."""
    pass


class BackupError(VaultAgentError):
    """Backup operation error."""
    pass