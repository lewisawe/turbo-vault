"""
Integration tests for Vault Agent Python SDK
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from vault_agent_sdk import (
    VaultAgentClient, 
    APIKeyAuth, 
    ClientConfig,
    AuthenticationError,
    NotFoundError
)

@pytest.fixture
def client_config():
    return ClientConfig(
        timeout=10,
        max_connections=5,
        verify_ssl=False
    )

@pytest.fixture
def auth():
    return APIKeyAuth("test-api-key")

@pytest.fixture
async def client(auth, client_config):
    async with VaultAgentClient(
        base_url="http://localhost:8200",
        auth=auth,
        config=client_config
    ) as client:
        yield client

@pytest.mark.asyncio
async def test_secret_lifecycle(client):
    """Test complete secret lifecycle"""
    # Create secret
    secret = await client.acreate_secret(
        name="test-secret",
        value="test-value",
        metadata={"test": "true"},
        tags=["integration-test"]
    )
    
    assert secret.name == "test-secret"
    assert secret.value == "test-value"
    assert secret.metadata["test"] == "true"
    assert "integration-test" in secret.tags
    
    # Get secret
    retrieved = await client.aget_secret(secret.id)
    assert retrieved.id == secret.id
    assert retrieved.value == "test-value"
    
    # Update secret
    updated = await client.aupdate_secret(
        secret.id,
        value="updated-value",
        metadata={"test": "true", "updated": "true"}
    )
    assert updated.value == "updated-value"
    assert updated.version > secret.version
    
    # List secrets
    secrets = await client.alist_secrets(tags=["integration-test"])
    assert len(secrets) >= 1
    assert any(s.id == secret.id for s in secrets)
    
    # Delete secret
    await client.adelete_secret(secret.id)
    
    # Verify deletion
    with pytest.raises(NotFoundError):
        await client.aget_secret(secret.id)

@pytest.mark.asyncio
async def test_authentication_error():
    """Test authentication error handling"""
    auth = APIKeyAuth("invalid-key")
    config = ClientConfig(verify_ssl=False)
    
    with patch('httpx.AsyncClient.request') as mock_request:
        mock_response = AsyncMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"message": "Invalid API key"}
        mock_request.return_value = mock_response
        
        async with VaultAgentClient("http://localhost:8200", auth, config) as client:
            with pytest.raises(AuthenticationError):
                await client.alist_secrets()

@pytest.mark.asyncio 
async def test_health_check(client):
    """Test health check endpoint"""
    with patch.object(client, '_make_async_request') as mock_request:
        mock_response = AsyncMock()
        mock_response.json.return_value = {
            "status": "healthy",
            "version": "1.0.0",
            "uptime": 3600
        }
        mock_request.return_value = mock_response
        
        health = await client.ahealth_check()
        assert health["status"] == "healthy"
        assert health["version"] == "1.0.0"