# Comprehensive API Documentation

This comprehensive guide provides detailed documentation for the Vault Agent REST API, generated from the OpenAPI specification with interactive examples and best practices.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication](#authentication)
3. [API Reference](#api-reference)
4. [Error Handling](#error-handling)
5. [Rate Limiting](#rate-limiting)
6. [SDK Examples](#sdk-examples)
7. [Best Practices](#best-practices)
8. [Interactive Examples](#interactive-examples)

## Getting Started

The Vault Agent API provides a RESTful interface for managing secrets, policies, and system operations. All endpoints follow consistent patterns and return structured JSON responses.

### Base URL

```
https://your-vault-agent:8200/api/v1
```

### API Versioning

All API endpoints are versioned using the `/api/v1` prefix. Future versions will maintain backward compatibility for at least 12 months after release.

### Content Types

- **Request Content-Type**: `application/json`
- **Response Content-Type**: `application/json`
- **Character Encoding**: UTF-8

## Authentication

The Vault Agent API supports multiple authentication methods to accommodate different use cases and security requirements.

### API Key Authentication

The most common authentication method for programmatic access.

```bash
curl -H "X-API-Key: your-api-key-here" \
     https://your-vault-agent:8200/api/v1/secrets
```

**API Key Management:**
- Keys can be created through the web interface or CLI
- Each key can have specific permissions and expiration dates
- Keys should be rotated regularly (recommended: every 90 days)

### JWT Token Authentication

Suitable for temporary access and integration with identity providers.

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     https://your-vault-agent:8200/api/v1/secrets
```

**JWT Token Features:**
- Configurable expiration times
- Support for custom claims
- Integration with external identity providers (OIDC, SAML)

### Mutual TLS (mTLS) Authentication

Highest security authentication method using client certificates.

```bash
curl --cert client.crt --key client.key \
     --cacert ca.crt \
     https://your-vault-agent:8200/api/v1/secrets
```

**mTLS Configuration:**
- Requires valid client certificates signed by trusted CA
- Automatic certificate validation and revocation checking
- Suitable for service-to-service authentication

## API Reference

### Health and Status Endpoints

#### Health Check

Check the overall health status of the vault agent.

**Endpoint:** `GET /health`

**Authentication:** None required

**Response Example:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2025-09-13T10:00:00Z",
    "checks": {
      "database": "healthy",
      "encryption": "healthy",
      "control_plane": "connected"
    }
  },
  "request_id": "req-12345",
  "timestamp": "2025-09-13T10:00:00Z"
}
```

**Health Status Values:**
- `healthy`: All systems operational
- `degraded`: Some non-critical issues detected
- `unhealthy`: Critical issues requiring attention

#### System Metrics

Retrieve system performance and usage metrics.

**Endpoint:** `GET /api/v1/metrics`

**Authentication:** Required

**Response Example:**
```json
{
  "success": true,
  "data": {
    "total_secrets": 1250,
    "active_secrets": 1200,
    "expired_secrets": 50,
    "requests_per_sec": 45.2,
    "avg_response_time_ms": 12.5,
    "uptime": "72h30m15s",
    "last_updated": "2025-09-13T10:00:00Z"
  }
}
```

### Secret Management Endpoints

#### List Secrets

Retrieve metadata for secrets with optional filtering and pagination.

**Endpoint:** `GET /api/v1/secrets`

**Query Parameters:**
- `name_pattern` (string): Filter by name pattern (supports wildcards)
- `tags` (array): Filter by tags
- `status` (enum): Filter by status (active, deprecated, deleted, expired)
- `created_after` (datetime): Filter by creation date
- `created_by` (string): Filter by creator
- `page` (integer): Page number (default: 1)
- `per_page` (integer): Items per page (default: 20, max: 100)

**Example Request:**
```bash
curl -H "X-API-Key: your-api-key" \
     "https://your-vault-agent:8200/api/v1/secrets?name_pattern=database*&tags=production&page=1&per_page=50"
```

**Response Example:**
```json
{
  "success": true,
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "database-password",
      "description": "Database connection password",
      "metadata": {
        "environment": "production",
        "service": "api"
      },
      "tags": ["database", "production", "critical"],
      "created_at": "2025-09-13T10:00:00Z",
      "updated_at": "2025-09-13T10:00:00Z",
      "expires_at": "2025-12-31T23:59:59Z",
      "rotation_due": "2025-10-01T00:00:00Z",
      "version": 1,
      "created_by": "admin@example.com",
      "access_count": 42,
      "last_accessed": "2025-09-13T09:30:00Z",
      "status": "active"
    }
  ],
  "metadata": {
    "page": 1,
    "per_page": 50,
    "total": 1,
    "total_pages": 1
  }
}
```

#### Create Secret

Create a new secret with encrypted storage.

**Endpoint:** `POST /api/v1/secrets`

**Request Body:**
```json
{
  "name": "api-key-service-x",
  "value": "sk-1234567890abcdef",
  "description": "API key for external service integration",
  "metadata": {
    "service": "payment-gateway",
    "environment": "production",
    "owner": "platform-team"
  },
  "tags": ["api-key", "production", "payment"],
  "expires_at": "2025-12-31T23:59:59Z",
  "rotation_due": "2025-10-01T00:00:00Z"
}
```

**Response Example:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "name": "api-key-service-x",
    "description": "API key for external service integration",
    "metadata": {
      "service": "payment-gateway",
      "environment": "production",
      "owner": "platform-team"
    },
    "tags": ["api-key", "production", "payment"],
    "created_at": "2025-09-13T10:30:00Z",
    "updated_at": "2025-09-13T10:30:00Z",
    "expires_at": "2025-12-31T23:59:59Z",
    "rotation_due": "2025-10-01T00:00:00Z",
    "version": 1,
    "created_by": "admin@example.com",
    "access_count": 0,
    "last_accessed": null,
    "status": "active"
  }
}
```

#### Get Secret Metadata

Retrieve secret metadata without the actual value.

**Endpoint:** `GET /api/v1/secrets/{id}`

**Path Parameters:**
- `id` (UUID): Secret identifier

**Response Example:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "database-password",
    "description": "Database connection password",
    "metadata": {
      "environment": "production",
      "service": "api"
    },
    "tags": ["database", "production", "critical"],
    "created_at": "2025-09-13T10:00:00Z",
    "updated_at": "2025-09-13T10:00:00Z",
    "expires_at": "2025-12-31T23:59:59Z",
    "rotation_due": "2025-10-01T00:00:00Z",
    "version": 1,
    "created_by": "admin@example.com",
    "access_count": 42,
    "last_accessed": "2025-09-13T09:30:00Z",
    "status": "active"
  }
}
```

#### Get Secret Value

Retrieve the decrypted secret value (requires explicit request).

**Endpoint:** `GET /api/v1/secrets/{id}/value`

**Path Parameters:**
- `id` (UUID): Secret identifier

**Security Note:** This endpoint requires explicit access and logs all requests for audit purposes.

**Response Example:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "database-password",
    "value": "super-secure-password-123",
    "version": 1,
    "retrieved_at": "2025-09-13T10:30:00Z"
  }
}
```

#### Update Secret

Update an existing secret's value or metadata.

**Endpoint:** `PUT /api/v1/secrets/{id}`

**Path Parameters:**
- `id` (UUID): Secret identifier

**Request Body:**
```json
{
  "name": "database-password-updated",
  "value": "new-super-secure-password",
  "description": "Updated database connection password",
  "metadata": {
    "environment": "production",
    "service": "api",
    "updated_reason": "security_rotation"
  },
  "tags": ["database", "production", "critical", "updated"]
}
```

**Response Example:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "database-password-updated",
    "version": 2,
    "updated_at": "2025-09-13T10:35:00Z"
  }
}
```

#### Delete Secret

Permanently delete a secret and all its versions.

**Endpoint:** `DELETE /api/v1/secrets/{id}`

**Path Parameters:**
- `id` (UUID): Secret identifier

**Response Example:**
```json
{
  "success": true,
  "data": {
    "message": "Secret deleted successfully",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "deleted_at": "2025-09-13T10:40:00Z"
  }
}
```

#### Rotate Secret

Trigger manual rotation of a secret.

**Endpoint:** `POST /api/v1/secrets/{id}/rotate`

**Path Parameters:**
- `id` (UUID): Secret identifier

**Request Body:**
```json
{
  "new_value": "new-rotated-password",
  "reason": "Scheduled security rotation"
}
```

**Response Example:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "database-password",
    "version": 3,
    "rotated_at": "2025-09-13T10:45:00Z",
    "rotation_reason": "Scheduled security rotation"
  }
}
```

## Error Handling

The API uses standard HTTP status codes and provides detailed error information in a consistent format.

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters or body
- `401 Unauthorized`: Authentication required or invalid
- `403 Forbidden`: Access denied by authorization policies
- `404 Not Found`: Requested resource not found
- `409 Conflict`: Resource already exists or conflict detected
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Unexpected server error
- `503 Service Unavailable`: Service temporarily unavailable

### Error Response Format

All error responses follow this structure:

```json
{
  "success": false,
  "error": {
    "type": "validation",
    "code": "VALIDATION_FAILED",
    "message": "Request validation failed",
    "details": {
      "validation_errors": [
        {
          "field": "name",
          "message": "Name is required",
          "value": ""
        }
      ]
    }
  },
  "request_id": "req-12345",
  "timestamp": "2025-09-13T10:00:00Z"
}
```

### Error Types

- `validation`: Input validation errors
- `authentication`: Authentication failures
- `authorization`: Access control violations
- `not_found`: Resource not found
- `conflict`: Resource conflicts (e.g., duplicate names)
- `rate_limit`: Rate limiting violations
- `internal`: Internal server errors
- `unavailable`: Service temporarily unavailable

### Common Error Scenarios

#### Validation Errors (400)

```json
{
  "success": false,
  "error": {
    "type": "validation",
    "code": "INVALID_SECRET_NAME",
    "message": "Secret name contains invalid characters",
    "details": {
      "field": "name",
      "constraint": "alphanumeric_with_hyphens",
      "provided_value": "secret@name!"
    }
  }
}
```

#### Authentication Errors (401)

```json
{
  "success": false,
  "error": {
    "type": "authentication",
    "code": "INVALID_API_KEY",
    "message": "The provided API key is invalid or expired",
    "details": {
      "hint": "Check your API key and ensure it hasn't expired"
    }
  }
}
```

#### Authorization Errors (403)

```json
{
  "success": false,
  "error": {
    "type": "authorization",
    "code": "INSUFFICIENT_PERMISSIONS",
    "message": "You don't have permission to perform this action",
    "details": {
      "required_permission": "secrets:write",
      "resource": "secrets:production:database-password"
    }
  }
}
```

## Rate Limiting

The API implements rate limiting to ensure fair usage and system stability.

### Rate Limit Headers

All responses include rate limit information:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1694606400
X-RateLimit-Window: 60
```

### Rate Limit Tiers

- **Default**: 1000 requests per minute per API key
- **Burst**: 100 requests per second
- **Anonymous**: 100 requests per minute (health checks only)

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": {
    "type": "rate_limit",
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Please retry after 60 seconds.",
    "details": {
      "limit": 1000,
      "window": 60,
      "retry_after": 60
    }
  }
}
```

## SDK Examples

### Python SDK

```python
from vault_agent_sdk import VaultAgentClient, VaultAgentException

# Initialize client
client = VaultAgentClient(
    base_url="https://your-vault-agent:8200",
    api_key="your-api-key-here"
)

try:
    # Create a secret
    secret = client.secrets.create(
        name="database-password",
        value="super-secure-password",
        description="Production database password",
        metadata={
            "environment": "production",
            "service": "api-server"
        },
        tags=["database", "production", "critical"]
    )
    print(f"Created secret: {secret.id}")

    # List secrets with filtering
    secrets = client.secrets.list(
        name_pattern="database*",
        tags=["production"],
        page=1,
        per_page=50
    )
    print(f"Found {len(secrets)} secrets")

    # Get secret value
    value = client.secrets.get_value("database-password")
    print(f"Secret value: {value}")

    # Update secret
    updated_secret = client.secrets.update(
        "database-password",
        value="new-secure-password",
        metadata={"updated_at": "2025-09-13"}
    )
    print(f"Updated secret to version {updated_secret.version}")

    # Rotate secret
    rotated_secret = client.secrets.rotate(
        "database-password",
        new_value="rotated-password",
        reason="Scheduled rotation"
    )
    print(f"Rotated secret to version {rotated_secret.version}")

except VaultAgentException as e:
    print(f"Error: {e.message}")
    print(f"Error code: {e.code}")
    print(f"Request ID: {e.request_id}")
```

### Node.js SDK

```javascript
const { VaultAgentClient, VaultAgentError } = require('@vault-agent/sdk');

// Initialize client
const client = new VaultAgentClient({
  baseUrl: 'https://your-vault-agent:8200',
  apiKey: 'your-api-key-here'
});

async function manageSecrets() {
  try {
    // Create a secret
    const secret = await client.secrets.create({
      name: 'api-key-service',
      value: 'sk-1234567890abcdef',
      description: 'API key for external service',
      metadata: {
        service: 'payment-gateway',
        environment: 'production'
      },
      tags: ['api-key', 'production']
    });
    console.log(`Created secret: ${secret.id}`);

    // List secrets with filtering
    const secrets = await client.secrets.list({
      namePattern: 'api-key*',
      tags: ['production'],
      page: 1,
      perPage: 50
    });
    console.log(`Found ${secrets.length} secrets`);

    // Get secret value
    const value = await client.secrets.getValue('api-key-service');
    console.log(`Secret value: ${value}`);

    // Update secret
    const updatedSecret = await client.secrets.update('api-key-service', {
      value: 'sk-new-key-value',
      metadata: { updated_reason: 'security_rotation' }
    });
    console.log(`Updated secret to version ${updatedSecret.version}`);

    // Rotate secret
    const rotatedSecret = await client.secrets.rotate('api-key-service', {
      newValue: 'sk-rotated-key-value',
      reason: 'Scheduled rotation'
    });
    console.log(`Rotated secret to version ${rotatedSecret.version}`);

  } catch (error) {
    if (error instanceof VaultAgentError) {
      console.error(`API Error: ${error.message}`);
      console.error(`Error code: ${error.code}`);
      console.error(`Request ID: ${error.requestId}`);
    } else {
      console.error(`Unexpected error: ${error.message}`);
    }
  }
}

manageSecrets();
```

### Go SDK

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/vault-agent/go-sdk"
)

func main() {
    // Initialize client
    client := vaultagent.NewClient(&vaultagent.Config{
        BaseURL: "https://your-vault-agent:8200",
        APIKey:  "your-api-key-here",
    })

    ctx := context.Background()

    // Create a secret
    secret, err := client.Secrets.Create(ctx, &vaultagent.CreateSecretRequest{
        Name:        "jwt-secret",
        Value:       "super-secret-jwt-key",
        Description: "JWT signing key for authentication",
        Metadata: map[string]string{
            "service":     "auth-service",
            "environment": "production",
        },
        Tags: []string{"jwt", "production", "auth"},
    })
    if err != nil {
        log.Fatalf("Failed to create secret: %v", err)
    }
    fmt.Printf("Created secret: %s\n", secret.ID)

    // List secrets with filtering
    secrets, err := client.Secrets.List(ctx, &vaultagent.ListSecretsRequest{
        NamePattern: "jwt*",
        Tags:        []string{"production"},
        Page:        1,
        PerPage:     50,
    })
    if err != nil {
        log.Fatalf("Failed to list secrets: %v", err)
    }
    fmt.Printf("Found %d secrets\n", len(secrets))

    // Get secret value
    value, err := client.Secrets.GetValue(ctx, "jwt-secret")
    if err != nil {
        log.Fatalf("Failed to get secret value: %v", err)
    }
    fmt.Printf("Secret value: %s\n", value)

    // Update secret
    updatedSecret, err := client.Secrets.Update(ctx, "jwt-secret", &vaultagent.UpdateSecretRequest{
        Value: "new-jwt-secret-key",
        Metadata: map[string]string{
            "updated_reason": "key_rotation",
        },
    })
    if err != nil {
        log.Fatalf("Failed to update secret: %v", err)
    }
    fmt.Printf("Updated secret to version %d\n", updatedSecret.Version)

    // Rotate secret
    rotatedSecret, err := client.Secrets.Rotate(ctx, "jwt-secret", &vaultagent.RotateSecretRequest{
        NewValue: "rotated-jwt-secret-key",
        Reason:   "Scheduled rotation",
    })
    if err != nil {
        log.Fatalf("Failed to rotate secret: %v", err)
    }
    fmt.Printf("Rotated secret to version %d\n", rotatedSecret.Version)
}
```

### Java SDK

```java
import com.vaultagent.sdk.VaultAgentClient;
import com.vaultagent.sdk.config.ClientConfig;
import com.vaultagent.sdk.model.*;
import com.vaultagent.sdk.exception.VaultAgentException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class VaultAgentExample {
    public static void main(String[] args) {
        // Initialize client
        ClientConfig config = ClientConfig.builder()
            .baseUrl("https://your-vault-agent:8200")
            .apiKey("your-api-key-here")
            .build();
        
        VaultAgentClient client = new VaultAgentClient(config);

        try {
            // Create a secret
            Map<String, String> metadata = new HashMap<>();
            metadata.put("service", "user-service");
            metadata.put("environment", "production");

            CreateSecretRequest createRequest = CreateSecretRequest.builder()
                .name("user-service-db-password")
                .value("secure-database-password")
                .description("Database password for user service")
                .metadata(metadata)
                .tags(Arrays.asList("database", "production", "user-service"))
                .build();

            Secret secret = client.secrets().create(createRequest);
            System.out.println("Created secret: " + secret.getId());

            // List secrets with filtering
            var secrets = client.secrets().list(
                ListSecretsRequest.builder()
                    .namePattern("user-service*")
                    .tags(Arrays.asList("production"))
                    .page(1)
                    .perPage(50)
                    .build()
            );
            System.out.println("Found " + secrets.size() + " secrets");

            // Get secret value
            String value = client.secrets().getValue("user-service-db-password");
            System.out.println("Secret value: " + value);

            // Update secret
            UpdateSecretRequest updateRequest = UpdateSecretRequest.builder()
                .value("new-secure-database-password")
                .metadata(Map.of("updated_reason", "security_update"))
                .build();

            Secret updatedSecret = client.secrets().update("user-service-db-password", updateRequest);
            System.out.println("Updated secret to version " + updatedSecret.getVersion());

            // Rotate secret
            RotateSecretRequest rotateRequest = RotateSecretRequest.builder()
                .newValue("rotated-database-password")
                .reason("Scheduled rotation")
                .build();

            Secret rotatedSecret = client.secrets().rotate("user-service-db-password", rotateRequest);
            System.out.println("Rotated secret to version " + rotatedSecret.getVersion());

        } catch (VaultAgentException e) {
            System.err.println("API Error: " + e.getMessage());
            System.err.println("Error code: " + e.getErrorCode());
            System.err.println("Request ID: " + e.getRequestId());
        }
    }
}
```

## Best Practices

### Security Best Practices

1. **Use HTTPS**: Always use HTTPS in production environments
2. **Rotate API Keys**: Regularly rotate API keys (recommended: every 90 days)
3. **Principle of Least Privilege**: Grant minimal necessary permissions
4. **Audit Logging**: Monitor and review audit logs regularly
5. **Network Security**: Use network policies and firewalls to restrict access

### Performance Best Practices

1. **Caching**: Cache secret metadata when possible (avoid caching values)
2. **Pagination**: Use pagination for large result sets
3. **Filtering**: Use query parameters to filter results server-side
4. **Connection Pooling**: Reuse HTTP connections when making multiple requests
5. **Rate Limiting**: Implement client-side rate limiting to avoid hitting limits

### Error Handling Best Practices

1. **Retry Logic**: Implement exponential backoff for transient errors
2. **Circuit Breaker**: Use circuit breaker pattern for resilience
3. **Logging**: Log all API errors with request IDs for troubleshooting
4. **Graceful Degradation**: Handle API unavailability gracefully
5. **Monitoring**: Monitor error rates and response times

### Development Best Practices

1. **Environment Separation**: Use different vault agents for dev/staging/prod
2. **Configuration Management**: Store configuration in environment variables
3. **Testing**: Write comprehensive tests including error scenarios
4. **Documentation**: Document your integration and usage patterns
5. **Version Pinning**: Pin SDK versions in production applications

## Interactive Examples

### Using curl

#### Create and Manage a Secret

```bash
# Set variables
VAULT_URL="https://your-vault-agent:8200"
API_KEY="your-api-key-here"

# Create a secret
curl -X POST "$VAULT_URL/api/v1/secrets" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example-secret",
    "value": "my-secret-value",
    "description": "Example secret for testing",
    "metadata": {
      "environment": "development",
      "created_by": "curl-example"
    },
    "tags": ["example", "test"]
  }'

# Get secret metadata
curl -H "X-API-Key: $API_KEY" \
  "$VAULT_URL/api/v1/secrets/example-secret"

# Get secret value
curl -H "X-API-Key: $API_KEY" \
  "$VAULT_URL/api/v1/secrets/example-secret/value"

# Update secret
curl -X PUT "$VAULT_URL/api/v1/secrets/example-secret" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "value": "updated-secret-value",
    "metadata": {
      "environment": "development",
      "updated_by": "curl-example"
    }
  }'

# Delete secret
curl -X DELETE "$VAULT_URL/api/v1/secrets/example-secret" \
  -H "X-API-Key: $API_KEY"
```

#### Batch Operations

```bash
# List all production secrets
curl -H "X-API-Key: $API_KEY" \
  "$VAULT_URL/api/v1/secrets?tags=production&per_page=100"

# Search for database-related secrets
curl -H "X-API-Key: $API_KEY" \
  "$VAULT_URL/api/v1/secrets?name_pattern=*database*"

# Get secrets created in the last 7 days
WEEK_AGO=$(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ)
curl -H "X-API-Key: $API_KEY" \
  "$VAULT_URL/api/v1/secrets?created_after=$WEEK_AGO"
```

### OpenAPI Interactive Documentation

Access the interactive API documentation at:

```
https://your-vault-agent:8200/api/docs
```

This provides a web-based interface where you can:
- Explore all available endpoints
- Test API calls with your authentication credentials
- View request/response schemas
- Download the OpenAPI specification

### Postman Collection

Import the Postman collection for easy API testing:

1. Download the collection: `https://your-vault-agent:8200/api/postman-collection.json`
2. Import into Postman
3. Set environment variables:
   - `vault_url`: Your vault agent URL
   - `api_key`: Your API key
4. Start testing endpoints

---

*This documentation is automatically generated from the OpenAPI specification and updated with each release.*