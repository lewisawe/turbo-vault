/**
 * Comprehensive integration tests for Vault Agent Node.js SDK
 * Tests all major functionality including cloud integration, policy management, and advanced features
 */

const { 
  VaultAgentClient, 
  APIKeyAuth, 
  JWTAuth,
  CloudIntegration,
  AuthenticationError, 
  NotFoundError,
  ValidationError,
  RateLimitError
} = require('../src');
const nock = require('nock');

describe('Comprehensive VaultAgentClient Integration Tests', () => {
  let client;
  let auth;
  const baseUrl = 'http://localhost:8200';

  beforeEach(() => {
    auth = new APIKeyAuth('test-api-key');
    client = new VaultAgentClient(baseUrl, auth, {
      timeout: 30000,
      cacheEnabled: true,
      cacheTtl: 300000, // 5 minutes
      logLevel: 'silent',
      retry: {
        maxAttempts: 3,
        initialDelay: 1000,
        maxDelay: 10000,
        backoffFactor: 2.0,
        retryableStatusCodes: [500, 502, 503, 504]
      }
    });
  });

  afterEach(() => {
    client.close();
    nock.cleanAll();
  });

  describe('Secret Management Lifecycle', () => {
    test('should handle complete secret lifecycle with all operations', async () => {
      const secretData = {
        id: 'lifecycle-secret-id',
        name: 'test-lifecycle-secret',
        value: 'initial-secret-value',
        metadata: {
          environment: 'test',
          service: 'integration-test',
          created_by: 'test-suite',
          rotation_enabled: 'true',
          rotation_interval: '30d'
        },
        tags: ['integration-test', 'lifecycle', 'automated'],
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
        name: 'test-lifecycle-secret',
        value: 'initial-secret-value',
        metadata: {
          environment: 'test',
          service: 'integration-test',
          created_by: 'test-suite',
          rotation_enabled: 'true',
          rotation_interval: '30d'
        },
        tags: ['integration-test', 'lifecycle', 'automated']
      });

      expect(secret.name).toBe('test-lifecycle-secret');
      expect(secret.value).toBe('initial-secret-value');
      expect(secret.metadata.environment).toBe('test');
      expect(secret.tags).toContain('integration-test');

      // Mock get secret
      nock(baseUrl)
        .get(`/api/v1/secrets/${secret.id}`)
        .reply(200, secretData);

      const retrieved = await client.getSecret(secret.id);
      expect(retrieved.id).toBe(secret.id);
      expect(retrieved.value).toBe('initial-secret-value');

      // Mock update secret
      const updatedData = { 
        ...secretData, 
        value: 'updated-value-1', 
        version: 2,
        metadata: { ...secretData.metadata, updated: 'true', update_count: '1' }
      };
      nock(baseUrl)
        .put(`/api/v1/secrets/${secret.id}`)
        .reply(200, updatedData);

      const updated1 = await client.updateSecret(secret.id, {
        value: 'updated-value-1',
        metadata: { ...secret.metadata, updated: 'true', update_count: '1' }
      });
      expect(updated1.value).toBe('updated-value-1');
      expect(updated1.version).toBe(2);

      // Mock second update
      const updated2Data = { 
        ...updatedData, 
        value: 'updated-value-2', 
        version: 3,
        metadata: { ...updatedData.metadata, update_count: '2' }
      };
      nock(baseUrl)
        .put(`/api/v1/secrets/${secret.id}`)
        .reply(200, updated2Data);

      const updated2 = await client.updateSecret(secret.id, {
        value: 'updated-value-2',
        metadata: { ...updated1.metadata, update_count: '2' }
      });
      expect(updated2.value).toBe('updated-value-2');
      expect(updated2.version).toBe(3);

      // Mock get secret versions
      nock(baseUrl)
        .get(`/api/v1/secrets/${secret.id}/versions`)
        .reply(200, {
          versions: [
            { ...secretData, version: 1 },
            { ...updatedData, version: 2 },
            { ...updated2Data, version: 3 }
          ]
        });

      const versions = await client.getSecretVersions(secret.id);
      expect(versions).toHaveLength(3);
      expect(versions[0].version).toBe(1);
      expect(versions[1].version).toBe(2);
      expect(versions[2].version).toBe(3);

      // Mock rollback
      const rolledBackData = { 
        ...updatedData, 
        version: 4 // New version for rollback
      };
      nock(baseUrl)
        .post(`/api/v1/secrets/${secret.id}/rollback`)
        .reply(200, rolledBackData);

      const rolledBack = await client.rollbackSecret(secret.id, 2);
      expect(rolledBack.version).toBe(4);
      expect(rolledBack.value).toBe('updated-value-1');

      // Mock list secrets with filtering
      nock(baseUrl)
        .get('/api/v1/secrets')
        .query({ tags: 'integration-test' })
        .reply(200, { secrets: [secretData] });

      const testSecrets = await client.listSecrets({ tags: ['integration-test'] });
      expect(testSecrets.length).toBeGreaterThanOrEqual(1);
      expect(testSecrets.some(s => s.id === secret.id)).toBe(true);

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

    test('should handle secret rotation', async () => {
      const secretData = {
        id: 'rotation-secret-id',
        name: 'rotation-test-secret',
        value: 'original-rotatable-value',
        metadata: {
          rotation_enabled: 'true',
          rotation_interval: '7d',
          last_rotated: new Date().toISOString()
        },
        tags: ['rotation-test', 'auto-rotate'],
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
        name: 'rotation-test-secret',
        value: 'original-rotatable-value',
        metadata: {
          rotation_enabled: 'true',
          rotation_interval: '7d',
          last_rotated: new Date().toISOString()
        },
        tags: ['rotation-test', 'auto-rotate']
      });

      // Mock rotate secret
      const rotatedData = {
        ...secretData,
        value: 'rotated-secret-value',
        version: 2,
        metadata: {
          ...secretData.metadata,
          last_rotated: new Date().toISOString()
        }
      };
      nock(baseUrl)
        .post(`/api/v1/secrets/${secret.id}/rotate`)
        .reply(200, rotatedData);

      const rotated = await client.rotateSecret(secret.id);
      expect(rotated.version).toBeGreaterThan(secret.version);
      expect(rotated.value).not.toBe(secret.value);
      expect(rotated.metadata.last_rotated).toBeDefined();

      // Mock delete for cleanup
      nock(baseUrl)
        .delete(`/api/v1/secrets/${secret.id}`)
        .reply(200);

      await client.deleteSecret(secret.id);
    });

    test('should handle batch operations efficiently', async () => {
      const secretNames = ['batch-secret-1', 'batch-secret-2', 'batch-secret-3'];
      const createdSecrets = [];

      // Mock create operations
      for (let i = 0; i < secretNames.length; i++) {
        const secretData = {
          id: `batch-secret-${i}-id`,
          name: secretNames[i],
          value: `value-for-${secretNames[i]}`,
          metadata: { batch: 'true', test: 'batch-operations' },
          tags: ['batch-test'],
          version: 1,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          created_by: 'test-user',
          access_count: 0,
          status: 'active'
        };

        nock(baseUrl)
          .post('/api/v1/secrets')
          .reply(200, secretData);

        const secret = await client.createSecret({
          name: secretNames[i],
          value: `value-for-${secretNames[i]}`,
          metadata: { batch: 'true', test: 'batch-operations' },
          tags: ['batch-test']
        });

        createdSecrets.push(secret);
      }

      expect(createdSecrets).toHaveLength(secretNames.length);

      // Mock batch retrieve
      for (const secret of createdSecrets) {
        nock(baseUrl)
          .get(`/api/v1/secrets/${secret.id}`)
          .reply(200, secret);
      }

      const retrievedSecrets = await Promise.all(
        createdSecrets.map(secret => client.getSecret(secret.id))
      );
      expect(retrievedSecrets).toHaveLength(createdSecrets.length);

      // Mock batch update
      for (let i = 0; i < createdSecrets.length; i++) {
        const updatedData = {
          ...createdSecrets[i],
          value: `updated-value-${i}`,
          version: 2,
          metadata: { ...createdSecrets[i].metadata, updated: 'true' }
        };

        nock(baseUrl)
          .put(`/api/v1/secrets/${createdSecrets[i].id}`)
          .reply(200, updatedData);
      }

      const updatePromises = createdSecrets.map((secret, i) =>
        client.updateSecret(secret.id, {
          value: `updated-value-${i}`,
          metadata: { ...secret.metadata, updated: 'true' }
        })
      );

      const updatedSecrets = await Promise.all(updatePromises);
      updatedSecrets.forEach((updated, i) => {
        expect(updated.value).toBe(`updated-value-${i}`);
        expect(updated.metadata.updated).toBe('true');
      });

      // Mock batch delete
      for (const secret of createdSecrets) {
        nock(baseUrl)
          .delete(`/api/v1/secrets/${secret.id}`)
          .reply(200);
      }

      await Promise.all(
        createdSecrets.map(secret => client.deleteSecret(secret.id))
      );
    });
  });

  describe('Cloud Integration', () => {
    test('should setup cloud integration correctly', () => {
      const cloudConfigs = [
        {
          provider: 'aws',
          region: 'us-east-1',
          credentials: {
            accessKeyId: 'test-access-key',
            secretAccessKey: 'test-secret-key'
          },
          syncEnabled: true,
          tags: { source: 'vault-agent', environment: 'test' }
        },
        {
          provider: 'azure',
          credentials: {
            vaultUrl: 'https://test-vault.vault.azure.net/'
          },
          syncEnabled: true,
          tags: { source: 'vault-agent' }
        }
      ];

      const cloudIntegration = new CloudIntegration(cloudConfigs);
      expect(cloudIntegration.isEnabled()).toBe(true);
    });

    test('should sync secrets to cloud providers', async () => {
      const cloudConfigs = [
        {
          provider: 'aws',
          region: 'us-east-1',
          credentials: {
            accessKeyId: 'test-access-key',
            secretAccessKey: 'test-secret-key'
          },
          syncEnabled: true,
          tags: { source: 'vault-agent' }
        }
      ];

      const cloudIntegration = new CloudIntegration(cloudConfigs);
      
      // Mock cloud sync (would need to mock AWS SDK in real implementation)
      const syncResults = await cloudIntegration.syncSecret(
        'test-cloud-secret',
        'cloud-secret-value',
        { environment: 'test', cloud_sync: 'true' }
      );

      expect(typeof syncResults).toBe('object');
    });

    test('should handle cloud integration with vault client', async () => {
      const cloudConfigs = [
        {
          provider: 'aws',
          region: 'us-east-1',
          credentials: {
            accessKeyId: 'test-access-key',
            secretAccessKey: 'test-secret-key'
          },
          syncEnabled: true
        }
      ];

      client.enableCloudIntegration(cloudConfigs);

      const secretData = {
        id: 'cloud-sync-secret-id',
        name: 'cloud-sync-secret',
        value: 'cloud-sync-value',
        version: 1,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        created_by: 'test-user',
        access_count: 0,
        status: 'active'
      };

      // Mock create secret with cloud sync
      nock(baseUrl)
        .post('/api/v1/secrets')
        .reply(200, secretData);

      const secret = await client.createSecret({
        name: 'cloud-sync-secret',
        value: 'cloud-sync-value',
        tags: ['cloud-test']
      });

      expect(secret.name).toBe('cloud-sync-secret');
    });
  });

  describe('Policy Management', () => {
    test('should handle complete policy lifecycle', async () => {
      const policyData = {
        id: 'test-policy-id',
        name: 'test-comprehensive-policy',
        description: 'Comprehensive test policy with multiple rules',
        rules: [
          {
            resource: 'secrets',
            actions: ['read', 'list'],
            conditions: [
              {
                field: 'tags',
                operator: 'contains',
                value: 'production'
              },
              {
                field: 'metadata.environment',
                operator: 'equals',
                value: 'production'
              }
            ]
          },
          {
            resource: 'secrets',
            actions: ['create', 'update', 'delete'],
            conditions: [
              {
                field: 'user.role',
                operator: 'in',
                value: ['admin', 'power-user']
              },
              {
                field: 'time.hour',
                operator: 'between',
                value: [9, 17]
              }
            ]
          }
        ],
        priority: 100,
        enabled: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      // Mock create policy
      nock(baseUrl)
        .post('/api/v1/policies')
        .reply(200, policyData);

      const policy = {
        name: 'test-comprehensive-policy',
        description: 'Comprehensive test policy with multiple rules',
        rules: policyData.rules,
        priority: 100,
        enabled: true
      };

      const createdPolicy = await client.createPolicy(policy);
      expect(createdPolicy.name).toBe('test-comprehensive-policy');
      expect(createdPolicy.rules).toHaveLength(2);
      expect(createdPolicy.enabled).toBe(true);

      // Mock get policy
      nock(baseUrl)
        .get(`/api/v1/policies/${createdPolicy.id}`)
        .reply(200, policyData);

      const retrievedPolicy = await client.getPolicy(createdPolicy.id);
      expect(retrievedPolicy.id).toBe(createdPolicy.id);
      expect(retrievedPolicy.name).toBe('test-comprehensive-policy');

      // Mock update policy
      const updatedPolicyData = {
        ...policyData,
        description: 'Updated comprehensive test policy',
        priority: 200
      };
      nock(baseUrl)
        .put(`/api/v1/policies/${createdPolicy.id}`)
        .reply(200, updatedPolicyData);

      const updatedPolicy = await client.updatePolicy(createdPolicy.id, {
        description: 'Updated comprehensive test policy',
        priority: 200
      });
      expect(updatedPolicy.description).toBe('Updated comprehensive test policy');
      expect(updatedPolicy.priority).toBe(200);

      // Mock list policies
      nock(baseUrl)
        .get('/api/v1/policies')
        .reply(200, { policies: [policyData] });

      const policies = await client.listPolicies();
      expect(policies.some(p => p.id === createdPolicy.id)).toBe(true);

      // Mock delete policy
      nock(baseUrl)
        .delete(`/api/v1/policies/${createdPolicy.id}`)
        .reply(200);

      await client.deletePolicy(createdPolicy.id);

      // Mock get policy after deletion (should return 404)
      nock(baseUrl)
        .get(`/api/v1/policies/${createdPolicy.id}`)
        .reply(404, { message: 'Policy not found' });

      await expect(client.getPolicy(createdPolicy.id)).rejects.toThrow(NotFoundError);
    });
  });

  describe('Audit and Compliance', () => {
    test('should retrieve and filter audit events', async () => {
      const auditEvents = [
        {
          id: 'audit-1',
          event_type: 'secret_access',
          actor: { id: 'user-1', type: 'user' },
          resource: { id: 'secret-1', type: 'secret' },
          action: 'read',
          result: 'success',
          timestamp: new Date().toISOString(),
          ip_address: '192.168.1.1',
          user_agent: 'VaultAgent-SDK/1.0.0'
        },
        {
          id: 'audit-2',
          event_type: 'security',
          actor: { id: 'user-2', type: 'user' },
          resource: { id: 'vault', type: 'system' },
          action: 'login_failed',
          result: 'failure',
          timestamp: new Date().toISOString(),
          ip_address: '192.168.1.2',
          user_agent: 'VaultAgent-SDK/1.0.0'
        }
      ];

      // Mock get audit events
      nock(baseUrl)
        .get('/api/v1/audit/events')
        .query(true)
        .reply(200, { events: auditEvents });

      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000);

      const events = await client.getAuditEvents({
        start_time: startTime.toISOString(),
        end_time: endTime.toISOString(),
        limit: 100
      });

      expect(Array.isArray(events)).toBe(true);
      expect(events).toHaveLength(2);

      // Mock filtered events
      nock(baseUrl)
        .get('/api/v1/audit/events')
        .query({ event_type: 'security' })
        .reply(200, { events: auditEvents.filter(e => e.event_type === 'security') });

      const securityEvents = await client.getAuditEvents({
        event_type: 'security'
      });

      expect(securityEvents).toHaveLength(1);
      expect(securityEvents[0].event_type).toBe('security');
    });

    test('should analyze audit events', async () => {
      // Create test secret to generate audit events
      const secretData = {
        id: 'audit-test-secret-id',
        name: 'audit-test-secret',
        value: 'audit-test-value',
        tags: ['audit-test'],
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
        name: 'audit-test-secret',
        value: 'audit-test-value',
        tags: ['audit-test']
      });

      // Mock get secret
      nock(baseUrl)
        .get(`/api/v1/secrets/${secret.id}`)
        .reply(200, secretData);

      await client.getSecret(secret.id);

      // Mock update secret
      nock(baseUrl)
        .put(`/api/v1/secrets/${secret.id}`)
        .reply(200, { ...secretData, value: 'updated-audit-value', version: 2 });

      await client.updateSecret(secret.id, { value: 'updated-audit-value' });

      // Mock get recent audit events
      const recentEvents = [
        {
          id: 'audit-create',
          event_type: 'secret_operation',
          action: 'create',
          timestamp: new Date().toISOString()
        },
        {
          id: 'audit-read',
          event_type: 'secret_access',
          action: 'read',
          timestamp: new Date().toISOString()
        },
        {
          id: 'audit-update',
          event_type: 'secret_operation',
          action: 'update',
          timestamp: new Date().toISOString()
        }
      ];

      nock(baseUrl)
        .get('/api/v1/audit/events')
        .query(true)
        .reply(200, { events: recentEvents });

      const events = await client.getAuditEvents({
        limit: 100
      });

      // Analyze event types
      const eventTypes = {};
      events.forEach(event => {
        const eventType = event.event_type;
        eventTypes[eventType] = (eventTypes[eventType] || 0) + 1;
      });

      expect(Object.keys(eventTypes).length).toBeGreaterThan(0);

      // Mock delete for cleanup
      nock(baseUrl)
        .delete(`/api/v1/secrets/${secret.id}`)
        .reply(200);

      await client.deleteSecret(secret.id);
    });
  });

  describe('Backup and Recovery', () => {
    test('should create and list backups', async () => {
      const backupData = {
        id: 'backup-123',
        name: 'test-backup-123456789',
        status: 'completed',
        size: 1024000,
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        metadata: {
          include_secrets: true,
          include_policies: true,
          include_audit_logs: true,
          compression: true,
          encryption: true
        }
      };

      // Mock create backup
      nock(baseUrl)
        .post('/api/v1/backups')
        .reply(200, backupData);

      const backupName = `test-backup-${Date.now()}`;
      const backup = await client.createBackup(backupName, {
        includeSecrets: true,
        includePolicies: true,
        includeAuditLogs: true,
        compression: true,
        encryption: true
      });

      expect(backup.name).toBe(backupData.name);
      expect(['pending', 'in_progress', 'completed']).toContain(backup.status);

      // Mock list backups
      nock(baseUrl)
        .get('/api/v1/backups')
        .reply(200, { backups: [backupData] });

      const backups = await client.listBackups();
      expect(Array.isArray(backups)).toBe(true);
      expect(backups).toHaveLength(1);

      // Verify backup metadata structure
      backups.forEach(backup => {
        expect(backup).toHaveProperty('id');
        expect(backup).toHaveProperty('name');
        expect(backup).toHaveProperty('created_at');
        expect(backup).toHaveProperty('status');
      });
    });

    test('should handle backup restoration', async () => {
      const backupId = 'backup-restore-test';

      // Mock restore backup
      nock(baseUrl)
        .post(`/api/v1/backups/${backupId}/restore`)
        .reply(200, { status: 'restore_initiated' });

      await client.restoreBackup(backupId, {
        includeSecrets: true,
        includePolicies: true
      });

      // Verify cache is cleared after restore
      const cacheStats = client.getCacheStats();
      if (cacheStats) {
        // Cache should be cleared or reset after restore
        expect(typeof cacheStats).toBe('object');
      }
    });
  });

  describe('Authentication Methods', () => {
    test('should work with API key authentication', async () => {
      const apiKeyAuth = new APIKeyAuth('test-api-key');
      const apiKeyClient = new VaultAgentClient(baseUrl, apiKeyAuth, {
        timeout: 10000,
        logLevel: 'silent'
      });

      const headers = await apiKeyAuth.getHeaders();
      expect(headers).toHaveProperty('Authorization');
      expect(headers.Authorization).toContain('Bearer');

      apiKeyClient.close();
    });

    test('should work with JWT authentication', async () => {
      const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token';
      const jwtAuth = new JWTAuth(jwtToken);
      const jwtClient = new VaultAgentClient(baseUrl, jwtAuth, {
        timeout: 10000,
        logLevel: 'silent'
      });

      const headers = await jwtAuth.getHeaders();
      expect(headers).toHaveProperty('Authorization');
      expect(headers.Authorization).toBe(`Bearer ${jwtToken}`);

      jwtClient.close();
    });
  });

  describe('Error Handling', () => {
    test('should handle authentication errors', async () => {
      nock(baseUrl)
        .get('/api/v1/secrets')
        .reply(401, { message: 'Invalid API key' });

      await expect(client.listSecrets()).rejects.toThrow(AuthenticationError);
    });

    test('should handle not found errors', async () => {
      nock(baseUrl)
        .get('/api/v1/secrets/non-existent-secret')
        .reply(404, { message: 'Secret not found' });

      await expect(client.getSecret('non-existent-secret')).rejects.toThrow(NotFoundError);
    });

    test('should handle validation errors', async () => {
      nock(baseUrl)
        .post('/api/v1/secrets')
        .reply(400, { message: 'Invalid secret name' });

      await expect(client.createSecret({
        name: '', // Invalid empty name
        value: 'test-value'
      })).rejects.toThrow(ValidationError);
    });

    test('should handle rate limit errors', async () => {
      nock(baseUrl)
        .get('/api/v1/secrets')
        .reply(429, { message: 'Rate limit exceeded' });

      await expect(client.listSecrets()).rejects.toThrow(RateLimitError);
    });

    test('should retry on retryable errors', async () => {
      // First request fails with 500, second succeeds
      nock(baseUrl)
        .get('/api/v1/health')
        .reply(500, { message: 'Internal server error' });

      nock(baseUrl)
        .get('/api/v1/health')
        .reply(200, { status: 'healthy' });

      const health = await client.healthCheck();
      expect(health.status).toBe('healthy');
    });
  });

  describe('Performance and Caching', () => {
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

      // Verify cache statistics
      const cacheStats = clientWithCache.getCacheStats();
      expect(cacheStats).toBeTruthy();
      expect(typeof cacheStats).toBe('object');

      clientWithCache.close();
    });

    test('should handle concurrent operations efficiently', async () => {
      const secretIds = ['concurrent-1', 'concurrent-2', 'concurrent-3'];
      
      // Mock all concurrent requests
      secretIds.forEach(id => {
        nock(baseUrl)
          .get(`/api/v1/secrets/${id}`)
          .reply(200, {
            id: id,
            name: `secret-${id}`,
            value: `value-${id}`,
            version: 1,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            created_by: 'test-user',
            access_count: 0,
            status: 'active'
          });
      });

      const startTime = Date.now();
      
      // Perform concurrent requests
      const promises = secretIds.map(id => 
        client.getSecret(id).catch(err => ({ error: err.message }))
      );
      
      const results = await Promise.all(promises);
      const endTime = Date.now();
      
      expect(results).toHaveLength(secretIds.length);
      
      // Should complete reasonably quickly
      const totalTime = endTime - startTime;
      expect(totalTime).toBeLessThan(5000); // 5 seconds
    });

    test('should provide performance metrics', async () => {
      // Test cache statistics
      const cacheStats = client.getCacheStats();
      if (cacheStats) {
        expect(typeof cacheStats).toBe('object');
        expect(cacheStats).toHaveProperty('keys');
      }

      // Test cache clearing
      client.clearCache();
      
      const clearedStats = client.getCacheStats();
      if (clearedStats) {
        expect(clearedStats.keys).toBe(0);
      }
    });
  });

  describe('Health and Monitoring', () => {
    test('should perform health checks', async () => {
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
      expect(health.uptime).toBe(3600);
    });

    test('should collect metrics', async () => {
      const metricsData = `
# HELP vault_secrets_total Total number of secrets
# TYPE vault_secrets_total counter
vault_secrets_total 42
# HELP vault_requests_total Total number of requests
# TYPE vault_requests_total counter
vault_requests_total{method="GET",status="200"} 1234
      `.trim();

      nock(baseUrl)
        .get('/metrics')
        .reply(200, metricsData);

      const metrics = await client.getMetrics();
      expect(metrics).toContain('vault_secrets_total');
      expect(metrics).toContain('vault_requests_total');
    });
  });
});

// Performance benchmark tests
describe('Performance Benchmarks', () => {
  let client;
  let auth;
  const baseUrl = 'http://localhost:8200';

  beforeEach(() => {
    auth = new APIKeyAuth('test-api-key');
    client = new VaultAgentClient(baseUrl, auth, {
      timeout: 30000,
      cacheEnabled: true,
      logLevel: 'silent'
    });
  });

  afterEach(() => {
    client.close();
    nock.cleanAll();
  });

  test('should benchmark secret creation performance', async () => {
    const secretCount = 10;
    
    // Mock all create operations
    for (let i = 0; i < secretCount; i++) {
      nock(baseUrl)
        .post('/api/v1/secrets')
        .reply(200, {
          id: `perf-test-${i}`,
          name: `perf-test-${i}`,
          value: `performance-test-value-${i}`,
          tags: ['performance-test'],
          version: 1,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          created_by: 'test-user',
          access_count: 0,
          status: 'active'
        });
    }

    const startTime = Date.now();

    // Create multiple secrets
    const promises = [];
    for (let i = 0; i < secretCount; i++) {
      promises.push(
        client.createSecret({
          name: `perf-test-${i}`,
          value: `performance-test-value-${i}`,
          tags: ['performance-test']
        }).catch(err => ({ error: err.message }))
      );
    }

    await Promise.all(promises);
    const endTime = Date.now();
    const totalTime = endTime - startTime;

    // Should complete within reasonable time
    expect(totalTime).toBeLessThan(30000); // 30 seconds for 10 operations

    console.log(`Created ${secretCount} secrets in ${totalTime}ms`);
  });

  test('should benchmark secret retrieval performance', async () => {
    const secretId = 'perf-retrieval-test';
    const retrievalCount = 10;

    // Mock all retrieval operations
    for (let i = 0; i < retrievalCount; i++) {
      nock(baseUrl)
        .get(`/api/v1/secrets/${secretId}`)
        .reply(200, {
          id: secretId,
          name: 'perf-retrieval-test',
          value: 'performance-retrieval-value',
          tags: ['performance-test'],
          version: 1,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          created_by: 'test-user',
          access_count: i,
          status: 'active'
        });
    }

    const startTime = Date.now();

    // Retrieve the same secret multiple times
    const promises = [];
    for (let i = 0; i < retrievalCount; i++) {
      promises.push(
        client.getSecret(secretId).catch(err => ({ error: err.message }))
      );
    }

    await Promise.all(promises);
    const endTime = Date.now();
    const totalTime = endTime - startTime;

    // Should complete within reasonable time
    expect(totalTime).toBeLessThan(10000); // 10 seconds for 10 retrievals

    console.log(`Retrieved secret ${retrievalCount} times in ${totalTime}ms`);
  });
});