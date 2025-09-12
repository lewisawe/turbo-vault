#!/usr/bin/env python3
"""
Basic usage example for Vault Agent Python SDK
"""

import asyncio
from vault_agent_sdk import VaultAgentClient, APIKeyAuth, ClientConfig

async def main():
    # Configure client
    config = ClientConfig(
        timeout=30,
        max_connections=10,
        verify_ssl=True
    )
    
    # Initialize client with API key authentication
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Create a secret
        secret = await client.acreate_secret(
            name="database-password",
            value="super-secret-password",
            metadata={"environment": "production"},
            tags=["database", "production"]
        )
        print(f"Created secret: {secret.id}")
        
        # Retrieve the secret
        retrieved = await client.aget_secret(secret.id)
        print(f"Retrieved secret value: {retrieved.value}")
        
        # List secrets
        secrets = await client.alist_secrets(tags=["production"])
        print(f"Found {len(secrets)} production secrets")
        
        # Update secret
        updated = await client.aupdate_secret(
            secret.id,
            value="new-password",
            metadata={"environment": "production", "updated": "true"}
        )
        print(f"Updated secret to version {updated.version}")

if __name__ == "__main__":
    asyncio.run(main())