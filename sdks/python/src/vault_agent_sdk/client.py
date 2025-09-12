"""
Vault Agent Client

Main client class for interacting with Vault Agent instances.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urljoin

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .auth import AuthMethod
from .config import ClientConfig
from .exceptions import (
    VaultAgentError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    ConnectionError as VaultConnectionError,
)
from .models import Secret, SecretMetadata, Policy, AuditEvent, BackupInfo

logger = logging.getLogger(__name__)


class VaultAgentClient:
    """
    Main client for interacting with Vault Agent instances.
    
    Supports both synchronous and asynchronous operations with comprehensive
    error handling, retry logic, and connection pooling.
    """
    
    def __init__(
        self,
        base_url: str,
        auth: AuthMethod,
        config: Optional[ClientConfig] = None,
    ):
        """
        Initialize the Vault Agent client.
        
        Args:
            base_url: Base URL of the Vault Agent instance
            auth: Authentication method to use
            config: Optional client configuration
        """
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.config = config or ClientConfig()
        
        # Initialize HTTP client with connection pooling
        self._client = httpx.Client(
            timeout=self.config.timeout,
            limits=httpx.Limits(
                max_keepalive_connections=self.config.max_connections,
                max_connections=self.config.max_connections,
            ),
            verify=self.config.verify_ssl,
        )
        
        # Initialize async HTTP client
        self._async_client = httpx.AsyncClient(
            timeout=self.config.timeout,
            limits=httpx.Limits(
                max_keepalive_connections=self.config.max_connections,
                max_connections=self.config.max_connections,
            ),
            verify=self.config.verify_ssl,
        )
        
        self._session_token: Optional[str] = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()
    
    def close(self):
        """Close the HTTP client."""
        self._client.close()
    
    async def aclose(self):
        """Close the async HTTP client."""
        await self._async_client.aclose()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True,
    )
    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> httpx.Response:
        """Make a synchronous HTTP request with retry logic."""
        url = urljoin(self.base_url, endpoint)
        headers = kwargs.pop("headers", {})
        
        # Add authentication headers
        auth_headers = self.auth.get_headers()
        headers.update(auth_headers)
        
        try:
            response = self._client.request(
                method=method,
                url=url,
                headers=headers,
                **kwargs,
            )
            self._handle_response(response)
            return response
        except httpx.RequestError as e:
            logger.error(f"Request failed: {e}")
            raise VaultConnectionError(f"Failed to connect to Vault Agent: {e}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True,
    )
    async def _make_async_request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> httpx.Response:
        """Make an asynchronous HTTP request with retry logic."""
        url = urljoin(self.base_url, endpoint)
        headers = kwargs.pop("headers", {})
        
        # Add authentication headers
        auth_headers = self.auth.get_headers()
        headers.update(auth_headers)
        
        try:
            response = await self._async_client.request(
                method=method,
                url=url,
                headers=headers,
                **kwargs,
            )
            self._handle_response(response)
            return response
        except httpx.RequestError as e:
            logger.error(f"Async request failed: {e}")
            raise VaultConnectionError(f"Failed to connect to Vault Agent: {e}")
    
    def _handle_response(self, response: httpx.Response) -> None:
        """Handle HTTP response and raise appropriate exceptions."""
        if response.status_code == 200:
            return
        
        try:
            error_data = response.json()
        except Exception:
            error_data = {"message": response.text}
        
        message = error_data.get("message", "Unknown error")
        
        if response.status_code == 401:
            raise AuthenticationError(message)
        elif response.status_code == 403:
            raise AuthorizationError(message)
        elif response.status_code == 404:
            raise NotFoundError(message)
        elif response.status_code == 400:
            raise ValidationError(message)
        elif response.status_code == 429:
            raise RateLimitError(message)
        else:
            raise VaultAgentError(f"HTTP {response.status_code}: {message}")
    
    # Secret Management Methods
    
    def create_secret(
        self,
        name: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Secret:
        """Create a new secret."""
        data = {
            "name": name,
            "value": value,
            "metadata": metadata or {},
            "tags": tags or [],
        }
        
        response = self._make_request("POST", "/api/v1/secrets", json=data)
        return Secret.model_validate(response.json())
    
    async def acreate_secret(
        self,
        name: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Secret:
        """Create a new secret (async)."""
        data = {
            "name": name,
            "value": value,
            "metadata": metadata or {},
            "tags": tags or [],
        }
        
        response = await self._make_async_request("POST", "/api/v1/secrets", json=data)
        return Secret.model_validate(response.json())
    
    def get_secret(self, secret_id: str) -> Secret:
        """Get a secret by ID."""
        response = self._make_request("GET", f"/api/v1/secrets/{secret_id}")
        return Secret.model_validate(response.json())
    
    async def aget_secret(self, secret_id: str) -> Secret:
        """Get a secret by ID (async)."""
        response = await self._make_async_request("GET", f"/api/v1/secrets/{secret_id}")
        return Secret.model_validate(response.json())
    
    def update_secret(
        self,
        secret_id: str,
        value: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Secret:
        """Update an existing secret."""
        data = {}
        if value is not None:
            data["value"] = value
        if metadata is not None:
            data["metadata"] = metadata
        if tags is not None:
            data["tags"] = tags
        
        response = self._make_request("PUT", f"/api/v1/secrets/{secret_id}", json=data)
        return Secret.model_validate(response.json())
    
    async def aupdate_secret(
        self,
        secret_id: str,
        value: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Secret:
        """Update an existing secret (async)."""
        data = {}
        if value is not None:
            data["value"] = value
        if metadata is not None:
            data["metadata"] = metadata
        if tags is not None:
            data["tags"] = tags
        
        response = await self._make_async_request("PUT", f"/api/v1/secrets/{secret_id}", json=data)
        return Secret.model_validate(response.json())
    
    def delete_secret(self, secret_id: str) -> None:
        """Delete a secret."""
        self._make_request("DELETE", f"/api/v1/secrets/{secret_id}")
    
    async def adelete_secret(self, secret_id: str) -> None:
        """Delete a secret (async)."""
        await self._make_async_request("DELETE", f"/api/v1/secrets/{secret_id}")
    
    def list_secrets(
        self,
        tags: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[SecretMetadata]:
        """List secrets (metadata only)."""
        params = {}
        if tags:
            params["tags"] = ",".join(tags)
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        
        response = self._make_request("GET", "/api/v1/secrets", params=params)
        data = response.json()
        return [SecretMetadata.model_validate(item) for item in data["secrets"]]
    
    async def alist_secrets(
        self,
        tags: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[SecretMetadata]:
        """List secrets (metadata only) (async)."""
        params = {}
        if tags:
            params["tags"] = ",".join(tags)
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        
        response = await self._make_async_request("GET", "/api/v1/secrets", params=params)
        data = response.json()
        return [SecretMetadata.model_validate(item) for item in data["secrets"]]
    
    # Policy Management Methods
    
    def create_policy(self, policy: Policy) -> Policy:
        """Create a new policy."""
        response = self._make_request("POST", "/api/v1/policies", json=policy.model_dump())
        return Policy.model_validate(response.json())
    
    async def acreate_policy(self, policy: Policy) -> Policy:
        """Create a new policy (async)."""
        response = await self._make_async_request("POST", "/api/v1/policies", json=policy.model_dump())
        return Policy.model_validate(response.json())
    
    def get_policy(self, policy_id: str) -> Policy:
        """Get a policy by ID."""
        response = self._make_request("GET", f"/api/v1/policies/{policy_id}")
        return Policy.model_validate(response.json())
    
    async def aget_policy(self, policy_id: str) -> Policy:
        """Get a policy by ID (async)."""
        response = await self._make_async_request("GET", f"/api/v1/policies/{policy_id}")
        return Policy.model_validate(response.json())
    
    # Audit Methods
    
    def get_audit_events(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[AuditEvent]:
        """Get audit events."""
        params = {}
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
        if event_type:
            params["event_type"] = event_type
        if limit:
            params["limit"] = limit
        
        response = self._make_request("GET", "/api/v1/audit/events", params=params)
        data = response.json()
        return [AuditEvent.model_validate(item) for item in data["events"]]
    
    async def aget_audit_events(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[AuditEvent]:
        """Get audit events (async)."""
        params = {}
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
        if event_type:
            params["event_type"] = event_type
        if limit:
            params["limit"] = limit
        
        response = await self._make_async_request("GET", "/api/v1/audit/events", params=params)
        data = response.json()
        return [AuditEvent.model_validate(item) for item in data["events"]]
    
    # Health and Status Methods
    
    def health_check(self) -> Dict[str, Any]:
        """Check vault agent health."""
        response = self._make_request("GET", "/api/v1/health")
        return response.json()
    
    async def ahealth_check(self) -> Dict[str, Any]:
        """Check vault agent health (async)."""
        response = await self._make_async_request("GET", "/api/v1/health")
        return response.json()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get Prometheus metrics."""
        response = self._make_request("GET", "/metrics")
        return {"metrics": response.text}
    
    async def aget_metrics(self) -> Dict[str, Any]:
        """Get Prometheus metrics (async)."""
        response = await self._make_async_request("GET", "/metrics")
        return {"metrics": response.text}