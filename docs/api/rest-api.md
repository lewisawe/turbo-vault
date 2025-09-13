# REST API Reference

The Vault Agent provides a comprehensive REST API for managing secrets, policies, and system operations. This document provides detailed information about all available endpoints with examples.

## Base URL and Versioning

```
https://your-vault-agent:8200/api/v1
```

All API endpoints are versioned and use the `/api/v1` prefix. Future versions will maintain backward compatibility.

## Authentication

The API supports multiple authentication methods:

### API Key Authentication
```bash
curl -H "X-API-Key: your-api-key" \
     https://your-vault-agent:8200/api/v1/secrets
```

### JWT Token Authentication
```bash
curl -H "Authorization: Bearer your-jwt-token" \
     https://your-vault-agent:8200/api/v1/secrets
```

### Client Certificate Authentication
```bash
curl --cert client.crt --key client.key \
     https://your-vault-agent:8200/api/v1/secrets
```

## Common Response Format

All API responses follow a consistent format:

### Success Response
```json
{
  "success": true,
  "data": {
    // Response data here
  },
  "metadata": {
    "request_id": "req-12345",
    "timestamp": "2025-09-13T10:30:00Z",
    "version": "1.0.0"
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "type": "validation",
    "code": "INVALID_INPUT",
    "message": "Secret name is required",
    "details": {
      "field": "name",
      "constraint": "required"
    }
  },
  "metadata": {
    "request_id": "req-12345",
    "timestamp": "2025-09-13T10:30:00Z"
  }
}
```

## Secrets Management

### List Secrets

Retrieve metadata for all secrets (values are not included).

**Endpoint:** `GET /api/v1/secrets`

**Query Parameters:**
- `limit` (optional): Maximum number of results (default: 100, max: 1000)
- `offset` (optional): Number of results to skip (default: 0)
- `filter` (optional): Filter by name pattern (supports wildcards)
- `tags` (optional): Filter by tags (comma-separated)

**Example Request:**
```bash
curl -H "X-API-Key: your-api-key" \
     "https://your-vault-agent:8200/api/v1/secrets?limit=50&filter=db-*"
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "secrets": [
      {
        "id": "secret-123",
        "name": "db-password",
        "metadata": {
          "environment": "production",
          "service": "api"
        },
        "tags": ["database", "production"],
        "created_at": "2025-09-13T10:00:00Z",
        "updated_at": "2025-09-13T10:00:00Z",
        "expires_at": "2025-12-13T10:00:00Z",
        "rotation_due": "2025-10-13T10:00:00Z",
        "version": 1,
        "created_by": "admin",
        "access_count": 42,
        "last_accessed": "2025-09-13T09:45:00Z",
        "status": "active"
      }
    ],
    "total": 1,
    "limit": 50,
    "offset": 0
  }
}
```

### Get Secret Value

Retrieve the actual secret value (requires explicit request).

**Endpoint:** `GET /api/v1/secrets/{id}/value`

**Example Request:**
```bash
curl -H "X-API-Key: your-api-key" \
     https://your-vault-agent:8200/api/v1/secrets/secret-123/value
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "id": "secret-123",
    "name": "db-password",
    "value": "super-secure-password-123",
    "version": 1,
    "retrieved_at": "2025-09-13T10:30:00Z"
  }
}
```

### Create Secret

Create a new secret with optional metadata and policies.

**Endpoint:** `POST /api/v1/secrets`

**Request Body:**
```json
{
  "name": "api-key",
  "value": "sk-1234567890abcdef",
  "metadata": {
    "service": "payment-api",
    "environment": "production"
  },
  "tags": ["api", "production", "payment"],
  "expires_at": "2025-12-31T23:59:59Z",
  "rotation_policy": {
    "enabled": true,
    "interval": "30d",
    "rotator_type": "custom_script",
    "rotator_config": {
      "script_path": "/opt/rotators/api-key-rotator.sh"
    }
  }
}
```

**Example Request:**
```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -d @secret.json \
     https://your-vault-agent:8200/api/v1/secrets
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "id": "secret-456",
    "name": "api-key",
    "created_at": "2025-09-13T10:30:00Z",
    "version": 1,
    "status": "active"
  }
}
```

### Update Secret

Update an existing secret's value or metadata.

**Endpoint:** `PUT /api/v1/secrets/{id}`

**Request Body:**
```json
{
  "value": "new-secret-value",
  "metadata": {
    "updated_reason": "security_rotation"
  }
}
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "id": "secret-456",
    "version": 2,
    "updated_at": "2025-09-13T10:35:00Z"
  }
}
```

### Delete Secret

Permanently delete a secret and all its versions.

**Endpoint:** `DELETE /api/v1/secrets/{id}`

**Example Request:**
```bash
curl -X DELETE \
     -H "X-API-Key: your-api-key" \
     https://your-vault-agent:8200/api/v1/secrets/secret-456
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "id": "secret-456",
    "deleted_at": "2025-09-13T10:40:00Z"
  }
}
```

## Secret Rotation

### Trigger Manual Rotation

Force immediate rotation of a secret.

**Endpoint:** `POST /api/v1/secrets/{id}/rotate`

**Request Body (optional):**
```json
{
  "rotator_type": "custom_script",
  "notify_channels": ["email", "slack"]
}
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "rotation_id": "rot-789",
    "secret_id": "secret-123",
    "status": "in_progress",
    "started_at": "2025-09-13T10:45:00Z"
  }
}
```

### Get Rotation Status

Check the status of a rotation operation.

**Endpoint:** `GET /api/v1/rotations/{rotation_id}`

**Example Response:**
```json
{
  "success": true,
  "data": {
    "id": "rot-789",
    "secret_id": "secret-123",
    "status": "completed",
    "started_at": "2025-09-13T10:45:00Z",
    "completed_at": "2025-09-13T10:46:00Z",
    "old_version": 1,
    "new_version": 2
  }
}
```

## Policy Management

### List Policies

Retrieve all access control policies.

**Endpoint:** `GET /api/v1/policies`

**Example Response:**
```json
{
  "success": true,
  "data": {
    "policies": [
      {
        "id": "policy-123",
        "name": "production-secrets",
        "description": "Access control for production secrets",
        "rules": [
          {
            "resource": "secrets:production:*",
            "actions": ["read"],
            "effect": "allow"
          }
        ],
        "conditions": [
          {
            "type": "time_range",
            "config": {
              "start": "09:00",
              "end": "17:00",
              "timezone": "UTC"
            }
          }
        ],
        "enabled": true,
        "priority": 100
      }
    ]
  }
}
```

### Create Policy

Create a new access control policy.

**Endpoint:** `POST /api/v1/policies`

**Request Body:**
```json
{
  "name": "dev-team-policy",
  "description": "Development team access policy",
  "rules": [
    {
      "resource": "secrets:development:*",
      "actions": ["read", "create", "update"],
      "effect": "allow"
    }
  ],
  "conditions": [
    {
      "type": "user_group",
      "config": {
        "groups": ["developers", "devops"]
      }
    }
  ],
  "priority": 200
}
```

## System Operations

### Health Check

Check the health status of the vault agent.

**Endpoint:** `GET /api/v1/health`

**Example Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime": "72h30m15s",
    "components": {
      "database": {
        "status": "healthy",
        "response_time": "2ms"
      },
      "encryption": {
        "status": "healthy",
        "key_status": "active"
      },
      "control_plane": {
        "status": "connected",
        "last_heartbeat": "2025-09-13T10:29:45Z"
      }
    }
  }
}
```

### System Metrics

Retrieve system performance metrics.

**Endpoint:** `GET /api/v1/metrics`

**Example Response:**
```json
{
  "success": true,
  "data": {
    "requests": {
      "total": 150420,
      "rate_per_second": 45.2,
      "average_response_time": "12ms"
    },
    "secrets": {
      "total_count": 1250,
      "active_count": 1200,
      "expired_count": 50
    },
    "storage": {
      "size_bytes": 52428800,
      "free_space_bytes": 1073741824
    },
    "memory": {
      "used_bytes": 134217728,
      "available_bytes": 536870912
    }
  }
}
```

## Audit Logs

### Query Audit Events

Search and filter audit log events.

**Endpoint:** `GET /api/v1/audit/events`

**Query Parameters:**
- `start_time`: Start of time range (ISO 8601)
- `end_time`: End of time range (ISO 8601)
- `event_type`: Filter by event type
- `actor`: Filter by user/service
- `resource`: Filter by resource
- `limit`: Maximum results (default: 100)

**Example Request:**
```bash
curl -H "X-API-Key: your-api-key" \
     "https://your-vault-agent:8200/api/v1/audit/events?start_time=2025-09-13T00:00:00Z&event_type=secret_access"
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "events": [
      {
        "id": "audit-789",
        "timestamp": "2025-09-13T10:30:00Z",
        "event_type": "secret_access",
        "actor": {
          "type": "user",
          "id": "user-123",
          "name": "john.doe"
        },
        "resource": {
          "type": "secret",
          "id": "secret-456",
          "name": "api-key"
        },
        "action": "read",
        "result": "success",
        "ip_address": "192.168.1.100",
        "user_agent": "VaultAgent-SDK/1.0.0"
      }
    ],
    "total": 1,
    "has_more": false
  }
}
```

## Error Handling

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Access denied
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### Error Types

- `validation`: Input validation errors
- `authentication`: Authentication failures
- `authorization`: Access control violations
- `not_found`: Resource not found
- `conflict`: Resource conflicts
- `rate_limit`: Rate limiting
- `internal`: Internal server errors
- `unavailable`: Service unavailable

### Rate Limiting

API requests are rate-limited to prevent abuse:

- **Default Limit**: 1000 requests per minute per API key
- **Burst Limit**: 100 requests per second
- **Headers**: Rate limit information is included in response headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1694606400
```

## SDK Examples

### Python SDK
```python
from vault_agent_sdk import VaultAgentClient

client = VaultAgentClient(
    base_url="https://your-vault-agent:8200",
    api_key="your-api-key"
)

# Create a secret
secret = client.secrets.create(
    name="database-password",
    value="super-secure-password",
    metadata={"environment": "production"}
)

# Retrieve a secret
value = client.secrets.get_value("database-password")
print(f"Password: {value}")
```

### Node.js SDK
```javascript
const { VaultAgentClient } = require('@vault-agent/sdk');

const client = new VaultAgentClient({
  baseUrl: 'https://your-vault-agent:8200',
  apiKey: 'your-api-key'
});

// Create a secret
const secret = await client.secrets.create({
  name: 'api-key',
  value: 'sk-1234567890',
  metadata: { service: 'payment-api' }
});

// Retrieve a secret
const value = await client.secrets.getValue('api-key');
console.log(`API Key: ${value}`);
```

### Go SDK
```go
package main

import (
    "context"
    "fmt"
    "github.com/vault-agent/go-sdk"
)

func main() {
    client := vaultagent.NewClient(&vaultagent.Config{
        BaseURL: "https://your-vault-agent:8200",
        APIKey:  "your-api-key",
    })

    // Create a secret
    secret, err := client.Secrets.Create(context.Background(), &vaultagent.CreateSecretRequest{
        Name:  "jwt-secret",
        Value: "super-secret-jwt-key",
        Metadata: map[string]string{
            "service": "auth-service",
        },
    })
    if err != nil {
        panic(err)
    }

    // Retrieve a secret
    value, err := client.Secrets.GetValue(context.Background(), "jwt-secret")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("JWT Secret: %s\n", value)
}
```

## Interactive API Explorer

For interactive API exploration, visit the OpenAPI documentation at:
```
https://your-vault-agent:8200/api/docs
```

This provides a web-based interface to test API endpoints with your authentication credentials.