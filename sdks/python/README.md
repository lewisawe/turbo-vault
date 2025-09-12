# Vault Agent Python SDK

Official Python SDK for Vault Agent, providing comprehensive secret management, authentication, and error handling with async/await support.

## Installation

```bash
pip install vault-agent-sdk
```

## Quick Start

```python
import asyncio
from vault_agent_sdk import VaultAgentClient, APIKeyAuth

async def main():
    # Initialize client
    auth = APIKeyAuth("your-api-key")
    
    async with VaultAgentClient("https://vault.example.com", auth) as client:
        # Create a secret
        secret = await client.acreate_secret(
            name="database-password",
            value="super-secret-password",
            metadata={"environment": "production"}
        )
        
        # Retrieve the secret
        retrieved = await client.aget_secret(secret.id)
        print(f"Secret value: {retrieved.value}")

asyncio.run(main())
```

## Features

- **Async/Await Support**: Full asynchronous API with sync alternatives
- **Multiple Authentication Methods**: API keys, JWT tokens, client certificates, OAuth, Basic auth
- **Comprehensive Error Handling**: Typed exceptions with detailed error information
- **Automatic Retries**: Configurable retry logic with exponential backoff
- **Connection Pooling**: Efficient HTTP connection management
- **Caching**: Optional response caching for improved performance
- **Cloud Integration**: Hybrid deployments with AWS, Azure, and GCP
- **Type Safety**: Full type hints and Pydantic models

## Authentication

### API Key Authentication
```python
from vault_agent_sdk import APIKeyAuth

auth = APIKeyAuth("your-api-key")
```

### JWT Authentication
```python
from vault_agent_sdk import JWTAuth

# From existing token
auth = JWTAuth("your-jwt-token")

# From credentials
auth = JWTAuth.from_credentials(
    username="user",
    password="pass", 
    secret_key="secret"
)
```

### Certificate Authentication
```python
from vault_agent_sdk import CertificateAuth

auth = CertificateAuth(
    cert_path="/path/to/cert.pem",
    key_path="/path/to/key.pem",
    key_password="optional-password"
)
```

## Configuration

```python
from vault_agent_sdk import ClientConfig

config = ClientConfig(
    timeout=30,
    max_connections=10,
    verify_ssl=True,
    retry_max_attempts=3,
    cache_enabled=True,
    cache_ttl=300
)

client = VaultAgentClient(base_url, auth, config)
```

## Secret Management

### Create Secret
```python
secret = await client.acreate_secret(
    name="api-key",
    value="secret-value",
    metadata={"service": "web-app"},
    tags=["production", "api"]
)
```

### Retrieve Secret
```python
secret = await client.aget_secret("secret-id")
print(secret.value)
```

### Update Secret
```python
updated = await client.aupdate_secret(
    "secret-id",
    value="new-value",
    metadata={"updated": True}
)
```

### List Secrets
```python
secrets = await client.alist_secrets(
    tags=["production"],
    limit=50
)
```

### Secret Rotation
```python
rotated = await client.arotate_secret("secret-id")
```

## Policy Management

```python
from vault_agent_sdk import Policy, PolicyRule

policy = Policy(
    name="read-only-policy",
    rules=[
        PolicyRule(
            resource="secrets/*",
            actions=["read"],
            effect="allow"
        )
    ]
)

created_policy = await client.acreate_policy(policy)
```

## Audit Logging

```python
events = await client.aget_audit_events(
    start_time="2024-01-01T00:00:00Z",
    event_type="secret_read",
    limit=100
)

for event in events:
    print(f"{event.timestamp}: {event.action} by {event.actor.id}")
```

## Error Handling

```python
from vault_agent_sdk import (
    AuthenticationError,
    AuthorizationError, 
    NotFoundError,
    ValidationError,
    RateLimitError
)

try:
    secret = await client.aget_secret("invalid-id")
except NotFoundError:
    print("Secret not found")
except AuthenticationError:
    print("Authentication failed")
except RateLimitError as e:
    print(f"Rate limited, retry after {e.retry_after} seconds")
```

## Cloud Integration

```python
from vault_agent_sdk import HybridConfig, CloudProviderConfig

hybrid_config = HybridConfig(
    enabled=True,
    primary_provider="local",
    fallback_providers=["aws"],
    cloud_providers={
        "aws": CloudProviderConfig(
            provider="aws",
            region="us-east-1",
            credentials={"access_key": "...", "secret_key": "..."}
        )
    }
)

# Enable cloud integration
client.enable_cloud_integration(hybrid_config)
```

## Testing

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=vault_agent_sdk --cov-report=html
```

## Examples

See the `examples/` directory for complete usage examples:

- `basic_usage.py` - Basic secret operations
- `authentication.py` - Different authentication methods
- `async_operations.py` - Asynchronous operations
- `error_handling.py` - Error handling patterns
- `cloud_integration.py` - Hybrid cloud deployments

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: https://docs.vault-agent.com/python-sdk
- Issues: https://github.com/vault-agent/python-sdk/issues
- Email: support@vault-agent.com