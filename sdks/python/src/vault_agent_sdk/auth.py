"""
Authentication methods for Vault Agent SDK.
"""

import base64
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class AuthMethod(ABC):
    """Base class for authentication methods."""
    
    @abstractmethod
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        pass


class APIKeyAuth(AuthMethod):
    """API Key authentication."""
    
    def __init__(self, api_key: str):
        """
        Initialize API key authentication.
        
        Args:
            api_key: The API key for authentication
        """
        self.api_key = api_key
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }


class JWTAuth(AuthMethod):
    """JWT token authentication."""
    
    def __init__(self, token: str):
        """
        Initialize JWT authentication.
        
        Args:
            token: The JWT token for authentication
        """
        self.token = token
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
    
    @classmethod
    def from_credentials(
        cls,
        username: str,
        password: str,
        secret_key: str,
        algorithm: str = "HS256",
        expires_in: int = 3600,
    ) -> "JWTAuth":
        """
        Create JWT token from username/password credentials.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            secret_key: Secret key for JWT signing
            algorithm: JWT algorithm (default: HS256)
            expires_in: Token expiration time in seconds
        
        Returns:
            JWTAuth instance with generated token
        """
        import time
        
        payload = {
            "sub": username,
            "iat": int(time.time()),
            "exp": int(time.time()) + expires_in,
        }
        
        token = jwt.encode(payload, secret_key, algorithm=algorithm)
        return cls(token)


class CertificateAuth(AuthMethod):
    """Client certificate authentication."""
    
    def __init__(
        self,
        cert_path: str,
        key_path: str,
        key_password: Optional[str] = None,
    ):
        """
        Initialize certificate authentication.
        
        Args:
            cert_path: Path to client certificate file
            key_path: Path to private key file
            key_password: Optional password for private key
        """
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)
        self.key_password = key_password
        
        # Load and validate certificate
        self._load_certificate()
    
    def _load_certificate(self) -> None:
        """Load and validate the client certificate."""
        try:
            # Load certificate
            with open(self.cert_path, "rb") as f:
                cert_data = f.read()
            
            self.certificate = x509.load_pem_x509_certificate(cert_data)
            
            # Load private key
            with open(self.key_path, "rb") as f:
                key_data = f.read()
            
            password = self.key_password.encode() if self.key_password else None
            self.private_key = serialization.load_pem_private_key(
                key_data, password=password
            )
            
        except Exception as e:
            raise ValueError(f"Failed to load certificate: {e}")
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        # For mTLS, the certificate is typically handled at the transport level
        # Here we provide the certificate fingerprint for identification
        fingerprint = self.certificate.fingerprint(
            self.certificate.signature_hash_algorithm
        )
        
        return {
            "X-Client-Cert-Fingerprint": fingerprint.hex(),
            "Content-Type": "application/json",
        }
    
    def get_cert_tuple(self) -> tuple:
        """Get certificate tuple for requests library."""
        return (str(self.cert_path), str(self.key_path))


class OAuthAuth(AuthMethod):
    """OAuth 2.0 authentication."""
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_url: str,
        scope: Optional[str] = None,
    ):
        """
        Initialize OAuth authentication.
        
        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            token_url: Token endpoint URL
            scope: Optional OAuth scope
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.scope = scope
        self._access_token: Optional[str] = None
    
    def _get_access_token(self) -> str:
        """Get or refresh access token."""
        import httpx
        
        if self._access_token:
            # TODO: Check token expiration
            return self._access_token
        
        # Request new token
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        
        if self.scope:
            data["scope"] = self.scope
        
        with httpx.Client() as client:
            response = client.post(self.token_url, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            self._access_token = token_data["access_token"]
            
        return self._access_token
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }


class BasicAuth(AuthMethod):
    """HTTP Basic authentication."""
    
    def __init__(self, username: str, password: str):
        """
        Initialize basic authentication.
        
        Args:
            username: Username for authentication
            password: Password for authentication
        """
        self.username = username
        self.password = password
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        credentials = f"{self.username}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        return {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
        }