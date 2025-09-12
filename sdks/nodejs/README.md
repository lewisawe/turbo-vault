# Vault Agent Node.js SDK

Official Node.js SDK for Vault Agent with TypeScript definitions, Promise-based API, and comprehensive error handling.

## Installation

```bash
npm install @vault-agent/sdk
# or
yarn add @vault-agent/sdk
```

## Quick Start

```javascript
const { VaultAgentClient, APIKeyAuth } = require('@vault-agent/sdk');

async function main() {
  const auth = new APIKeyAuth('your-api-key');
  const client = new VaultAgentClient('https://vault.example.com', auth);

  try {
    // Create a secret
    const secret = await client.createSecret({
      name: 'database-password',
      value: 'super-secret-password',
      metadata: { environment: 'production' }
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

## TypeScript Support

```typescript
import { VaultAgentClient, APIKeyAuth, Secret, SecretMetadata } from '@vault-agent/sdk';

const auth = new APIKeyAuth('your-api-key');
const client = new VaultAgentClient('https://vault.example.com', auth);

const secret: Secret = await client.createSecret({
  name: 'api-key',
  value: 'secret-value',
  metadata: { service: 'web-app' },
  tags: ['production']
});
```

## Features

- **TypeScript Support**: Full type definitions included
- **Promise-based API**: Modern async/await patterns
- **Multiple Authentication**: API keys, JWT, certificates, OAuth, Basic auth
- **Automatic Retries**: Configurable retry logic with exponential backoff
- **Connection Pooling**: Efficient HTTP connection management
- **Caching**: Built-in response caching with TTL
- **Error Handling**: Comprehensive error types with context
- **Cloud Integration**: Hybrid deployments with major cloud providers
- **Logging**: Configurable logging with multiple levels

## Authentication

### API Key Authentication
```javascript
const { APIKeyAuth } = require('@vault-agent/sdk');
const auth = new APIKeyAuth('your-api-key');
```

### JWT Authentication
```javascript
const { JWTAuth } = require('@vault-agent/sdk');

// From existing token
const auth = new JWTAuth('your-jwt-token');

// From credentials
const auth = JWTAuth.fromCredentials('username', 'password', 'secret-key');
```

### Certificate Authentication
```javascript
const { CertificateAuth } = require('@vault-agent/sdk');

const auth = new CertificateAuth(
  '/path/to/cert.pem',
  '/path/to/key.pem',
  'optional-password'
);
```

### OAuth Authentication
```javascript
const { OAuthAuth } = require('@vault-agent/sdk');

const auth = new OAuthAuth({
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  tokenUrl: 'https://auth.example.com/token',
  scope: 'vault:read vault:write'
});
```

## Configuration

```javascript
const client = new VaultAgentClient(baseUrl, auth, {
  timeout: 30000,
  maxConnections: 10,
  verifySsl: true,
  retry: {
    maxAttempts: 3,
    initialDelay: 1000,
    maxDelay: 30000,
    backoffFactor: 2
  },
  cacheEnabled: true,
  cacheTtl: 300000,
  logLevel: 'info'
});
```

## Secret Management

### Create Secret
```javascript
const secret = await client.createSecret({
  name: 'api-key',
  value: 'secret-value',
  metadata: { service: 'web-app' },
  tags: ['production', 'api']
});
```

### Retrieve Secret
```javascript
const secret = await client.getSecret('secret-id');
console.log(secret.value);
```

### Update Secret
```javascript
const updated = await client.updateSecret('secret-id', {
  value: 'new-value',
  metadata: { updated: true }
});
```

### List Secrets
```javascript
const secrets = await client.listSecrets({
  tags: ['production'],
  limit: 50,
  offset: 0
});
```

### Secret Rotation
```javascript
const rotated = await client.rotateSecret('secret-id');
```

### Secret Versions
```javascript
const versions = await client.getSecretVersions('secret-id');
const restored = await client.rollbackSecret('secret-id', 1);
```

## Policy Management

```javascript
const policy = await client.createPolicy({
  name: 'read-only-policy',
  rules: [{
    id: 'rule-1',
    resource: 'secrets/*',
    actions: ['read'],
    effect: 'allow',
    conditions: {}
  }],
  priority: 100,
  enabled: true
});
```

## Audit Logging

```javascript
const events = await client.getAuditEvents({
  start_time: '2024-01-01T00:00:00Z',
  event_type: 'secret_read',
  limit: 100
});

events.forEach(event => {
  console.log(`${event.timestamp}: ${event.action} by ${event.actor.id}`);
});
```

## Error Handling

```javascript
const {
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  RateLimitError
} = require('@vault-agent/sdk');

try {
  const secret = await client.getSecret('invalid-id');
} catch (error) {
  if (error instanceof NotFoundError) {
    console.log('Secret not found');
  } else if (error instanceof AuthenticationError) {
    console.log('Authentication failed');
  } else if (error instanceof RateLimitError) {
    console.log(`Rate limited, retry after ${error.retryAfter} seconds`);
  }
}
```

## Cloud Integration

```javascript
const hybridConfig = {
  enabled: true,
  primary_provider: 'local',
  fallback_providers: ['aws'],
  sync_interval: 300,
  conflict_resolution: 'primary_wins',
  cloud_providers: {
    aws: {
      provider: 'aws',
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'your-access-key',
        secretAccessKey: 'your-secret-key'
      },
      service_config: {}
    }
  }
};

client.enableCloudIntegration(hybridConfig);
```

## Caching

```javascript
// Enable caching
const client = new VaultAgentClient(baseUrl, auth, {
  cacheEnabled: true,
  cacheTtl: 300000, // 5 minutes
  cacheMaxSize: 1000
});

// Get cache statistics
const stats = client.getCacheStats();
console.log(`Cache hits: ${stats.hits}, misses: ${stats.misses}`);

// Clear cache
client.clearCache();
```

## Health Monitoring

```javascript
// Health check
const health = await client.healthCheck();
console.log(`Status: ${health.status}, Version: ${health.version}`);

// Metrics
const metrics = await client.getMetrics();
console.log(metrics);
```

## Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run integration tests
npm run test:integration
```

## Examples

See the `examples/` directory for complete usage examples:

- `basic-usage.js` - Basic secret operations
- `authentication.js` - Different authentication methods
- `error-handling.js` - Error handling patterns
- `cloud-integration.js` - Hybrid cloud deployments
- `typescript-example.ts` - TypeScript usage

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: https://docs.vault-agent.com/nodejs-sdk
- Issues: https://github.com/vault-agent/nodejs-sdk/issues
- Email: support@vault-agent.com