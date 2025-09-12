# Vault Agent SDK Comprehensive Guide

This guide provides detailed information about the comprehensive SDK libraries for the Vault Agent platform, covering all supported programming languages and advanced features.

## Overview

The Vault Agent SDKs provide comprehensive secret management capabilities with support for:

- **Multi-language Support**: Python, Node.js, Go, Java, and .NET
- **Cloud Integration**: AWS Secrets Manager, Azure Key Vault, Google Cloud Secret Manager
- **Advanced Authentication**: API keys, JWT tokens, client certificates, mTLS
- **Policy Management**: Fine-grained access control and conditional policies
- **Audit & Compliance**: Comprehensive logging and event tracking
- **Performance Optimization**: Caching, connection pooling, retry logic
- **Backup & Recovery**: Automated backup and disaster recovery
- **Monitoring**: Health checks, metrics collection, and alerting

## Supported Languages

### Python SDK

**Installation:**
```bash
pip install vault-agent-sdk

# With cloud provider support
pip install vault-agent-sdk[cloud]
```

**Key Features:**
- Async/await support with `asyncio`
- Comprehensive error handling with custom exceptions
- Cloud provider integration (AWS, Azure, GCP)
- Pydantic models for type safety
- Retry logic with exponential backoff
- Connection pooling with `httpx`

**Quick Start:**
```python
import asyncio
from vault_agent_sdk import VaultAgentClient, APIKeyAuth, ClientConfig

async def main():
    config = ClientConfig(
        timeout=30,
        cache_enabled=True,
        verify_ssl=True
    )
    
    auth = APIKeyAuth("your-api-key")
    
    async with VaultAgentClient("https://vault.example.com", auth, config) as client:
        # Create a secret
        secret = await client.acreate_secret(
            name="database-password",
            value="super-secret-password",
            metadata={"environment": "production"},
            tags=["database", "critical"]
        )
        
        # Retrieve the secret
        retrieved = await client.aget_secret(secret.id)
        print(f"Secret value: {retrieved.value}")

asyncio.run(main())
```

### Node.js SDK

**Installation:**
```bash
npm install @vault-agent/sdk

# With TypeScript support (included)
npm install @vault-agent/sdk @types/node
```

**Key Features:**
- Full TypeScript support with type definitions
- Promise-based API with async/await
- Automatic retry with configurable policies
- Built-in caching with TTL support
- Cloud provider integration
- Comprehensive error handling

**Quick Start:**
```javascript
const { VaultAgentClient, APIKeyAuth } = require('@vault-agent/sdk');

async function main() {
  const auth = new APIKeyAuth('your-api-key');
  const client = new VaultAgentClient('https://vault.example.com', auth, {
    timeout: 30000,
    cacheEnabled: true,
    logLevel: 'info'
  });

  try {
    // Create a secret
    const secret = await client.createSecret({
      name: 'database-password',
      value: 'super-secret-password',
      metadata: { environment: 'production' },
      tags: ['database', 'critical']
    });

    // Retrieve the secret
    const retrieved = await client.getSecret(secret.id);
    console.log(`Secret value: ${retrieved.value}`);
  } finally {
    client.close();
  }
}

main().catch(console.error);
```

### Go SDK

**Installation:**
```bash
go get github.com/vault-agent/go-sdk
```

**Key Features:**
- Idiomatic Go patterns with context support
- Comprehensive error handling with typed errors
- Connection pooling and HTTP/2 support
- Built-in retry logic with circuit breaker
- Cloud provider integration
- Concurrent-safe operations

**Quick Start:**
```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    vaultagent "github.com/vault-agent/go-sdk"
)

func main() {
    auth := vaultagent.NewAPIKeyAuth("your-api-key")
    
    client, err := vaultagent.NewClient(
        "https://vault.example.com",
        auth,
        vaultagent.WithTimeout(30*time.Second),
        vaultagent.WithCache(true, 5*time.Minute, 1000),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Create a secret
    secret, err := client.CreateSecret(ctx, vaultagent.CreateSecretRequest{
        Name:  "database-password",
        Value: "super-secret-password",
        Metadata: map[string]interface{}{
            "environment": "production",
        },
        Tags: []string{"database", "critical"},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve the secret
    retrieved, err := client.GetSecret(ctx, secret.ID)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Secret value: %s\n", retrieved.Value)
}
```

### Java SDK

**Installation (Maven):**
```xml
<dependency>
    <groupId>com.vaultagent</groupId>
    <artifactId>vault-agent-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

**Installation (Gradle):**
```gradle
implementation 'com.vaultagent:vault-agent-sdk:1.0.0'
```

**Key Features:**
- Java 11+ compatibility
- Spring Boot integration and auto-configuration
- Reactive programming support with Project Reactor
- Comprehensive caching with Caffeine
- Cloud provider integration
- Async and sync API support

**Quick Start:**
```java
import com.vaultagent.sdk.VaultAgentClient;
import com.vaultagent.sdk.auth.APIKeyAuth;
import com.vaultagent.sdk.config.ClientConfig;
import com.vaultagent.sdk.model.*;

public class Example {
    public static void main(String[] args) {
        APIKeyAuth auth = new APIKeyAuth("your-api-key");
        ClientConfig config = ClientConfig.builder()
            .timeout(Duration.ofSeconds(30))
            .cacheEnabled(true)
            .build();
            
        try (VaultAgentClient client = new VaultAgentClient(
                "https://vault.example.com", auth, config)) {
            
            // Create a secret
            CreateSecretRequest request = CreateSecretRequest.builder()
                .name("database-password")
                .value("super-secret-password")
                .metadata(Map.of("environment", "production"))
                .tags(List.of("database", "critical"))
                .build();
                
            Secret secret = client.createSecret(request);
            
            // Retrieve the secret
            Secret retrieved = client.getSecret(secret.getId());
            System.out.println("Secret value: " + retrieved.getValue());
        }
    }
}
```

### .NET SDK

**Installation:**
```bash
dotnet add package VaultAgent.SDK
```

**Key Features:**
- .NET 6+ support with nullable reference types
- Dependency injection integration
- Async/await patterns throughout
- Polly integration for retry policies
- Cloud provider integration
- Memory caching support

**Quick Start:**
```csharp
using VaultAgent.SDK;
using VaultAgent.SDK.Auth;
using VaultAgent.SDK.Configuration;
using VaultAgent.SDK.Models;

var auth = new APIKeyAuth("your-api-key");
var config = new ClientConfig
{
    Timeout = TimeSpan.FromSeconds(30),
    CacheEnabled = true,
    VerifySSL = true
};

using var client = new VaultAgentClient("https://vault.example.com", auth, config);

// Create a secret
var secret = await client.CreateSecretAsync(new CreateSecretRequest
{
    Name = "database-password",
    Value = "super-secret-password",
    Metadata = new Dictionary<string, string>
    {
        ["environment"] = "production"
    },
    Tags = new[] { "database", "critical" }
});

// Retrieve the secret
var retrieved = await client.GetSecretAsync(secret.Id);
Console.WriteLine($"Secret value: {retrieved.Value}");
```

## Advanced Features

### Cloud Provider Integration

All SDKs support hybrid deployments with automatic synchronization to cloud providers:

**Supported Providers:**
- AWS Secrets Manager
- Azure Key Vault
- Google Cloud Secret Manager

**Configuration Example (Python):**
```python
from vault_agent_sdk import CloudConfig, CloudIntegration

cloud_configs = [
    CloudConfig(
        provider='aws',
        region='us-east-1',
        credentials={
            'access_key_id': 'your-access-key',
            'secret_access_key': 'your-secret-key'
        },
        sync_enabled=True,
        tags={'source': 'vault-agent', 'environment': 'production'}
    ),
    CloudConfig(
        provider='azure',
        credentials={
            'vault_url': 'https://your-vault.vault.azure.net/'
        },
        sync_enabled=True
    )
]

# Enable cloud integration
client.enable_cloud_integration(cloud_configs)

# Secrets will automatically sync to configured cloud providers
secret = await client.acreate_secret(
    name="synced-secret",
    value="secret-value"
)
```

### Policy Management

Create and manage fine-grained access policies:

```python
from vault_agent_sdk.models import Policy, PolicyRule, PolicyCondition

policy = Policy(
    name="production-database-policy",
    description="Access policy for production database secrets",
    rules=[
        PolicyRule(
            resource="secrets",
            actions=["read", "list"],
            conditions=[
                PolicyCondition(
                    field="tags",
                    operator="contains",
                    value="database"
                ),
                PolicyCondition(
                    field="metadata.environment",
                    operator="equals",
                    value="production"
                )
            ]
        )
    ],
    priority=100,
    enabled=True
)

created_policy = await client.acreate_policy(policy)
```

### Audit and Compliance

Comprehensive audit logging and event tracking:

```python
# Get audit events
events = await client.aget_audit_events(
    start_time=start_time.isoformat(),
    end_time=end_time.isoformat(),
    event_type="security",
    limit=100
)

# Analyze events
event_types = {}
for event in events:
    event_type = event.event_type
    event_types[event_type] = event_types.get(event_type, 0) + 1

print(f"Security events: {event_types}")
```

### Performance Optimization

Built-in caching and performance features:

```python
# Configure caching
config = ClientConfig(
    cache_enabled=True,
    cache_ttl=300,  # 5 minutes
    cache_max_size=1000,
    timeout=30,
    max_connections=10
)

# Concurrent operations
async def batch_retrieve(secret_ids):
    tasks = [client.aget_secret(sid) for sid in secret_ids]
    return await asyncio.gather(*tasks, return_exceptions=True)

secrets = await batch_retrieve(['secret1', 'secret2', 'secret3'])
```

### Backup and Recovery

Automated backup and disaster recovery:

```python
# Create comprehensive backup
backup = await client.acreate_backup(
    name=f"backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
    options={
        "include_secrets": True,
        "include_policies": True,
        "include_audit_logs": True,
        "compression": True,
        "encryption": True
    }
)

# List available backups
backups = await client.alist_backups()

# Restore from backup
await client.arestore_backup(backup.id, {
    "include_secrets": True,
    "include_policies": True
})
```

## Authentication Methods

### API Key Authentication

```python
from vault_agent_sdk import APIKeyAuth

auth = APIKeyAuth("your-api-key-here")
```

### JWT Token Authentication

```python
from vault_agent_sdk import JWTAuth

auth = JWTAuth("your-jwt-token-here")
```

### Client Certificate Authentication

```python
from vault_agent_sdk import CertificateAuth

auth = CertificateAuth(
    cert_file="/path/to/client.crt",
    key_file="/path/to/client.key",
    ca_file="/path/to/ca.crt"
)
```

## Error Handling

All SDKs provide comprehensive error handling with specific exception types:

```python
from vault_agent_sdk.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    ConnectionError
)

try:
    secret = await client.aget_secret("secret-id")
except AuthenticationError:
    print("Invalid credentials")
except AuthorizationError:
    print("Access denied")
except NotFoundError:
    print("Secret not found")
except ValidationError as e:
    print(f"Invalid request: {e}")
except RateLimitError:
    print("Rate limit exceeded")
except ConnectionError:
    print("Connection failed")
```

## Configuration Options

### Client Configuration

```python
from vault_agent_sdk import ClientConfig

config = ClientConfig(
    # Connection settings
    timeout=30,
    max_connections=10,
    verify_ssl=True,
    
    # Caching
    cache_enabled=True,
    cache_ttl=300,  # 5 minutes
    cache_max_size=1000,
    
    # Retry logic
    retry_max_attempts=3,
    retry_initial_delay=1.0,
    retry_max_delay=10.0,
    retry_backoff_factor=2.0,
    
    # Logging
    log_level="info",
    
    # Headers
    user_agent="MyApp/1.0.0",
    default_headers={"X-Custom-Header": "value"}
)
```

## Testing and Development

### Integration Tests

All SDKs include comprehensive integration tests:

```bash
# Python
pytest sdks/python/tests/test_comprehensive_integration.py -v

# Node.js
npm test -- --testPathPattern=comprehensive-integration

# Go
go test -v ./sdks/go/...

# Java
mvn test -Dtest=ComprehensiveIntegrationTest

# .NET
dotnet test --filter "Category=Integration"
```

### Performance Benchmarks

Run performance benchmarks to validate SDK performance:

```bash
# Python
pytest sdks/python/tests/test_comprehensive_integration.py::TestPerformanceBenchmarks -v

# Node.js
npm run test:benchmark

# Go
go test -bench=. -benchmem ./sdks/go/...
```

## Best Practices

### Security

1. **Use environment variables** for sensitive credentials
2. **Enable SSL verification** in production
3. **Rotate API keys** regularly
4. **Use least-privilege policies**
5. **Enable audit logging**

### Performance

1. **Enable caching** for frequently accessed secrets
2. **Use connection pooling** for high-throughput applications
3. **Implement retry logic** with exponential backoff
4. **Use batch operations** when possible
5. **Monitor cache hit rates**

### Reliability

1. **Handle all exception types** appropriately
2. **Implement circuit breaker patterns** for external dependencies
3. **Use health checks** to monitor vault agent status
4. **Set appropriate timeouts**
5. **Test offline scenarios**

## Migration Guide

### From HashiCorp Vault

If migrating from HashiCorp Vault, the SDKs provide similar patterns:

```python
# HashiCorp Vault
import hvac
client = hvac.Client(url='https://vault.example.com', token='token')
secret = client.secrets.kv.v2.read_secret_version(path='myapp/config')

# Vault Agent SDK
from vault_agent_sdk import VaultAgentClient, APIKeyAuth
client = VaultAgentClient('https://vault.example.com', APIKeyAuth('api-key'))
secret = await client.aget_secret('myapp-config')
```

### From AWS Secrets Manager

```python
# AWS Secrets Manager
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='myapp/config')

# Vault Agent SDK with AWS sync
from vault_agent_sdk import VaultAgentClient, CloudConfig
client = VaultAgentClient('https://vault.example.com', auth)
client.enable_cloud_integration([CloudConfig(provider='aws', ...)])
secret = await client.aget_secret('myapp-config')
```

## Support and Resources

- **Documentation**: [https://docs.vault-agent.com](https://docs.vault-agent.com)
- **GitHub Repository**: [https://github.com/vault-agent/sdks](https://github.com/vault-agent/sdks)
- **Issue Tracker**: [https://github.com/vault-agent/sdks/issues](https://github.com/vault-agent/sdks/issues)
- **Community Forum**: [https://community.vault-agent.com](https://community.vault-agent.com)
- **Security Issues**: security@vault-agent.com

## License

All SDKs are released under the MIT License. See individual SDK directories for specific license files.

## Contributing

We welcome contributions! Please see the CONTRIBUTING.md file in each SDK directory for guidelines on:

- Code style and formatting
- Testing requirements
- Pull request process
- Issue reporting
- Security vulnerability disclosure

## Changelog

See CHANGELOG.md in each SDK directory for version history and breaking changes.