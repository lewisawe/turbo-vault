/**
 * Integration tests for Vault Agent Node.js SDK
 */

const { VaultAgentClient, APIKeyAuth, AuthenticationError, NotFoundError } = require('../src');
const nock = require('nock');

describe('VaultAgentClient Integration Tests', () => {
  let client;
  let auth;
  const baseUrl = 'http://localhost:8200';

  beforeEach(() => {
    auth = new APIKeyAuth('test-api-key');
    client = new VaultAgentClient(baseUrl, auth, {
      timeout: 10000,
      cacheEnabled: false,
      logLevel: 'silent'
    });
  });

  afterEach(() => {
    client.close();
    nock.cleanAll();
  });

  describe('Secret Lifecycle', () => {
    test('should create, read, update, and delete secret', async () => {
      const secretData = {
        id: 'test-secret-id',
        name: 'test-secret',
        value: 'test-value',
        metadata: { test: 'true' },
        tags: ['integration-test'],
        version: 1,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        created_by: 'test-user',
        access_count: 0,
        status: 'active'
      };

      // Mock create secret
      nock(baseUrl)
        .post('/api/v1/secrets')
        .reply(200, secretData);

      const secret = await client.createSecret({
        name: 'test-secret',
        value: 'test-value',
        metadata: { test: 'true' },
        tags: ['integration-test']
      });

      expect(secret.name).toBe('test-secret');
      expect(secret.value).toBe('test-value');

      // Mock get secret
      nock(baseUrl)
        .get(`/api/v1/secrets/${secret.id}`)
        .reply(200, secretData);

      const retrieved = await client.getSecret(secret.id);
      expect(retrieved.id).toBe(secret.id);
      expect(retrieved.value).toBe('test-value');

      // Mock update secret
      const updatedData = { ...secretData, value: 'updated-value', version: 2 };
      nock(baseUrl)
        .put(`/api/v1/secrets/${secret.id}`)
        .reply(200, updatedData);

      const updated = await client.updateSecret(secret.id, {
        value: 'updated-value'
      });
      expect(updated.value).toBe('updated-value');
      expect(updated.version).toBe(2);

      // Mock list secrets
      nock(baseUrl)
        .get('/api/v1/secrets')
        .query({ tags: 'integration-test' })
        .reply(200, { secrets: [secretData] });

      const secrets = await client.listSecrets({ tags: ['integration-test'] });
      expect(secrets.length).toBeGreaterThanOrEqual(1);
      expect(secrets.some(s => s.id === secret.id)).toBe(true);

      // Mock delete secret
      nock(baseUrl)
        .delete(`/api/v1/secrets/${secret.id}`)
        .reply(200);

      await client.deleteSecret(secret.id);

      // Mock get secret after deletion (should return 404)
      nock(baseUrl)
        .get(`/api/v1/secrets/${secret.id}`)
        .reply(404, { message: 'Secret not found' });

      await expect(client.getSecret(secret.id)).rejects.toThrow(NotFoundError);
    });
  });

  describe('Authentication', () => {
    test('should handle authentication errors', async () => {
      nock(baseUrl)
        .get('/api/v1/secrets')
        .reply(401, { message: 'Invalid API key' });

      await expect(client.listSecrets()).rejects.toThrow(AuthenticationError);
    });
  });

  describe('Health Check', () => {
    test('should perform health check', async () => {
      const healthData = {
        status: 'healthy',
        version: '1.0.0',
        uptime: 3600,
        secrets_count: 10,
        policies_count: 5
      };

      nock(baseUrl)
        .get('/api/v1/health')
        .reply(200, healthData);

      const health = await client.healthCheck();
      expect(health.status).toBe('healthy');
      expect(health.version).toBe('1.0.0');
    });
  });

  describe('Caching', () => {
    test('should cache responses when enabled', async () => {
      const clientWithCache = new VaultAgentClient(baseUrl, auth, {
        cacheEnabled: true,
        cacheTtl: 60000,
        logLevel: 'silent'
      });

      const secretData = {
        id: 'cached-secret',
        name: 'cached-secret',
        value: 'cached-value',
        version: 1,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        created_by: 'test-user',
        access_count: 0,
        status: 'active'
      };

      // Mock should only be called once due to caching
      nock(baseUrl)
        .get('/api/v1/secrets/cached-secret')
        .once()
        .reply(200, secretData);

      const secret1 = await clientWithCache.getSecret('cached-secret');
      const secret2 = await clientWithCache.getSecret('cached-secret');

      expect(secret1.id).toBe(secret2.id);
      expect(secret1.value).toBe(secret2.value);

      clientWithCache.close();
    });
  });
});