"""
Vault Agent Python SDK

Official Python SDK for interacting with Vault Agent instances.
Provides comprehensive secret management, authentication, and error handling.
"""

from .client import VaultAgentClient
from .auth import APIKeyAuth, JWTAuth, CertificateAuth
from .exceptions import (
    VaultAgentError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    ConnectionError,
)
from .models import Secret, SecretMetadata, Policy, AuditEvent
from .config import ClientConfig

__version__ = "1.0.0"
__author__ = "Vault Agent Team"
__email__ = "support@vault-agent.com"

__all__ = [
    "VaultAgentClient",
    "APIKeyAuth",
    "JWTAuth", 
    "CertificateAuth",
    "VaultAgentError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ValidationError",
    "RateLimitError",
    "ConnectionError",
    "Secret",
    "SecretMetadata",
    "Policy",
    "AuditEvent",
    "ClientConfig",
]