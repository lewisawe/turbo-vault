/**
 * Advanced usage examples for Vault Agent Node.js SDK
 * Demonstrates cloud integration, policy management, and advanced features
 */

const { 
  VaultAgentClient, 
  APIKeyAuth, 
  JWTAuth,
  CloudIntegration 
} = require('@vault-agent/sdk');

// Configure logging
const logger = console;

async function cloudIntegrationExample() {
  logger.log('=== Cloud Integration Example ===');
  
  // Configure cloud providers
  const cloudConfigs = [
    {
      provider: 'aws',
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'your-access-key',
        secretAccessKey: 'your-secret-key'
      },
      syncEnabled: true,
      tags: { source: 'vault-agent', environment: 'production' }
    },
    {
      provider: 'azure',
      credentials: {
        vaultUrl: 'https://your-vault.vault.azure.net/'
      },
      syncEnabled: true,
      tags: { source: 'vault-agent' }
    }
  ];
  
  // Initialize cloud integration
  const cloudIntegration = new CloudIntegration(cloudConfigs);
  
  // Initialize client
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    cacheEnabled: true,
    cacheTtl: 300000, // 5 minutes
    logLevel: 'info'
  });

  try {
    // Enable cloud integration
    client.enableCloudIntegration(cloudConfigs);
    
    // Create a secret (will automatically sync to cloud providers)
    const secret = await client.createSecret({
      name: 'database-connection',
      value: 'postgresql://user:pass@localhost:5432/db',
      metadata: {
        environment: 'production',
        service: 'api-server',
        rotationInterval: '30d'
      },
      tags: ['database', 'production', 'critical']
    });
    logger.log(`Created secret ${secret.id} with cloud sync`);
    
    // Verify cloud sync status
    const syncResults = await cloudIntegration.syncSecret(
      secret.name, 
      secret.value, 
      secret.metadata
    );
    logger.log('Cloud sync results:', syncResults);
    
    // List secrets from cloud providers
    for (const provider of ['aws', 'azure']) {
      try {
        const cloudSecrets = await cloudIntegration.listSecretsFromProvider(provider);
        logger.log(`Secrets in ${provider}:`, cloudSecrets);
      } catch (error) {
        logger.warn(`Failed to list secrets from ${provider}:`, error.message);
      }
    }
  } catch (error) {
    logger.error('Cloud integration example failed:', error.message);
  } finally {
    client.close();
  }
}

async function policyManagementExample() {
  logger.log('=== Policy Management Example ===');
  
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    logLevel: 'info'
  });

  try {
    // Create a comprehensive access policy
    const policy = {
      name: 'production-database-policy',
      description: 'Access policy for production database secrets',
      rules: [
        {
          resource: 'secrets',
          actions: ['read', 'list'],
          conditions: [
            {
              field: 'tags',
              operator: 'contains',
              value: 'database'
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
              value: ['admin', 'database-admin']
            },
            {
              field: 'time.hour',
              operator: 'between',
              value: [9, 17] // Business hours only
            }
          ]
        }
      ],
      priority: 100,
      enabled: true
    };
    
    const createdPolicy = await client.createPolicy(policy);
    logger.log(`Created policy: ${createdPolicy.id}`);
    
    // List all policies
    const policies = await client.listPolicies();
    logger.log(`Total policies: ${policies.length}`);
  } catch (error) {
    logger.error('Policy management example failed:', error.message);
  } finally {
    client.close();
  }
}

async function secretRotationExample() {
  logger.log('=== Secret Rotation Example ===');
  
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    logLevel: 'info'
  });

  try {
    // Create a secret with rotation policy
    const secret = await client.createSecret({
      name: 'api-key-service-a',
      value: 'initial-api-key-value',
      metadata: {
        service: 'service-a',
        rotationEnabled: 'true',
        rotationInterval: '7d',
        lastRotated: new Date().toISOString()
      },
      tags: ['api-key', 'auto-rotate']
    });
    logger.log(`Created secret with rotation: ${secret.id}`);
    
    // Simulate rotation
    const rotatedSecret = await client.rotateSecret(secret.id);
    logger.log(`Rotated secret to version ${rotatedSecret.version}`);
    
    // Get version history
    const versions = await client.getSecretVersions(secret.id);
    logger.log(`Secret has ${versions.length} versions`);
    
    // Rollback to previous version if needed
    if (versions.length > 1) {
      const previousVersion = versions[versions.length - 2].version;
      const rolledBack = await client.rollbackSecret(secret.id, previousVersion);
      logger.log(`Rolled back to version ${rolledBack.version}`);
    }
  } catch (error) {
    logger.error('Secret rotation example failed:', error.message);
  } finally {
    client.close();
  }
}

async function backupAndRecoveryExample() {
  logger.log('=== Backup and Recovery Example ===');
  
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    logLevel: 'info'
  });

  try {
    // Create a backup
    const backupName = `backup-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    const backup = await client.createBackup(backupName, {
      includeSecrets: true,
      includePolicies: true,
      includeAuditLogs: true,
      compression: true,
      encryption: true
    });
    logger.log(`Created backup: ${backup.id}`);
    
    // List all backups
    const backups = await client.listBackups();
    logger.log(`Available backups: ${backups.length}`);
    
    // Backup metadata
    backups.slice(-3).forEach(backupInfo => {
      logger.log(`Backup ${backupInfo.name}: ${backupInfo.size} bytes, created ${backupInfo.createdAt}`);
    });
  } catch (error) {
    logger.error('Backup and recovery example failed:', error.message);
  } finally {
    client.close();
  }
}

async function monitoringAndMetricsExample() {
  logger.log('=== Monitoring and Metrics Example ===');
  
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    logLevel: 'info'
  });

  try {
    // Health check
    const health = await client.healthCheck();
    logger.log(`Vault status: ${health.status}`);
    logger.log(`Version: ${health.version || 'unknown'}`);
    logger.log(`Uptime: ${health.uptime || 0} seconds`);
    
    // Get Prometheus metrics
    const metrics = await client.getMetrics();
    logger.log(`Metrics data length: ${metrics.length} characters`);
    
    // Parse some key metrics (simplified)
    const metricsLines = metrics.split('\n');
    metricsLines.forEach(line => {
      if (line.includes('vault_secrets_total') && !line.startsWith('#')) {
        logger.log(`Secrets metric: ${line}`);
      } else if (line.includes('vault_requests_total') && !line.startsWith('#')) {
        logger.log(`Requests metric: ${line}`);
      }
    });
    
    // Get cache statistics
    const cacheStats = client.getCacheStats();
    if (cacheStats) {
      logger.log('Cache statistics:', cacheStats);
    }
  } catch (error) {
    logger.error('Monitoring and metrics example failed:', error.message);
  } finally {
    client.close();
  }
}

async function auditAndComplianceExample() {
  logger.log('=== Audit and Compliance Example ===');
  
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    logLevel: 'info'
  });

  try {
    // Get recent audit events
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago
    
    const auditEvents = await client.getAuditEvents({
      start_time: startTime.toISOString(),
      end_time: endTime.toISOString(),
      limit: 50
    });
    
    logger.log(`Found ${auditEvents.length} audit events in last 24 hours`);
    
    // Analyze events by type
    const eventTypes = {};
    auditEvents.forEach(event => {
      const eventType = event.event_type;
      eventTypes[eventType] = (eventTypes[eventType] || 0) + 1;
    });
    
    logger.log('Event types distribution:');
    Object.entries(eventTypes).forEach(([eventType, count]) => {
      logger.log(`  ${eventType}: ${count}`);
    });
    
    // Show recent security events
    const securityEvents = auditEvents.filter(e => e.event_type === 'security');
    if (securityEvents.length > 0) {
      logger.log(`Recent security events: ${securityEvents.length}`);
      securityEvents.slice(-5).forEach(event => {
        logger.log(`  ${event.timestamp}: ${event.action} by ${event.actor}`);
      });
    }
  } catch (error) {
    logger.error('Audit and compliance example failed:', error.message);
  } finally {
    client.close();
  }
}

async function jwtAuthenticationExample() {
  logger.log('=== JWT Authentication Example ===');
  
  // JWT token (in real usage, this would be obtained from your auth system)
  const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
  
  const auth = new JWTAuth(jwtToken);
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    logLevel: 'info'
  });

  try {
    // Test authentication
    const health = await client.healthCheck();
    logger.log(`JWT authentication successful: ${health.status}`);
  } catch (error) {
    logger.error(`JWT authentication failed: ${error.message}`);
  } finally {
    client.close();
  }
}

async function errorHandlingAndRetryExample() {
  logger.log('=== Error Handling and Retry Example ===');
  
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    retry: {
      maxAttempts: 3,
      initialDelay: 1000,
      maxDelay: 10000,
      backoffFactor: 2.0,
      retryableStatusCodes: [500, 502, 503, 504]
    },
    logLevel: 'info'
  });

  try {
    // Try to get a non-existent secret
    try {
      await client.getSecret('non-existent-secret');
    } catch (error) {
      logger.log(`Expected error for non-existent secret: ${error.constructor.name}: ${error.message}`);
    }
    
    // Try with invalid authentication
    try {
      const invalidAuth = new APIKeyAuth('invalid-key');
      const invalidClient = new VaultAgentClient('https://localhost:8200', invalidAuth, {
        timeout: 10000,
        logLevel: 'silent'
      });
      
      await invalidClient.listSecrets();
      invalidClient.close();
    } catch (error) {
      logger.log(`Expected authentication error: ${error.constructor.name}: ${error.message}`);
    }
  } catch (error) {
    logger.error('Error handling example failed:', error.message);
  } finally {
    client.close();
  }
}

async function performanceOptimizationExample() {
  logger.log('=== Performance Optimization Example ===');
  
  const auth = new APIKeyAuth('your-api-key-here');
  const client = new VaultAgentClient('https://localhost:8200', auth, {
    timeout: 30000,
    cacheEnabled: true,
    cacheTtl: 300000, // 5 minutes
    cacheMaxSize: 1000,
    logLevel: 'info'
  });

  try {
    // Demonstrate caching performance
    const secretId = 'performance-test-secret';
    
    // First request (cache miss)
    const start1 = Date.now();
    try {
      await client.getSecret(secretId);
    } catch (error) {
      // Secret might not exist, that's ok for this example
    }
    const time1 = Date.now() - start1;
    
    // Second request (cache hit)
    const start2 = Date.now();
    try {
      await client.getSecret(secretId);
    } catch (error) {
      // Secret might not exist, that's ok for this example
    }
    const time2 = Date.now() - start2;
    
    logger.log(`First request: ${time1}ms, Second request: ${time2}ms`);
    
    // Batch operations for better performance
    const secretNames = ['secret1', 'secret2', 'secret3', 'secret4', 'secret5'];
    const batchStart = Date.now();
    
    const promises = secretNames.map(async (name) => {
      try {
        return await client.getSecret(name);
      } catch (error) {
        return null; // Secret might not exist
      }
    });
    
    await Promise.all(promises);
    const batchTime = Date.now() - batchStart;
    
    logger.log(`Batch operation for ${secretNames.length} secrets: ${batchTime}ms`);
    
    // Cache statistics
    const cacheStats = client.getCacheStats();
    if (cacheStats) {
      logger.log('Final cache statistics:', cacheStats);
    }
  } catch (error) {
    logger.error('Performance optimization example failed:', error.message);
  } finally {
    client.close();
  }
}

async function main() {
  const examples = [
    cloudIntegrationExample,
    policyManagementExample,
    secretRotationExample,
    backupAndRecoveryExample,
    monitoringAndMetricsExample,
    auditAndComplianceExample,
    jwtAuthenticationExample,
    errorHandlingAndRetryExample,
    performanceOptimizationExample
  ];
  
  for (const example of examples) {
    try {
      await example();
      console.log(); // Add spacing between examples
    } catch (error) {
      logger.error(`Example ${example.name} failed:`, error.message);
      console.log();
    }
  }
}

// Run examples if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  cloudIntegrationExample,
  policyManagementExample,
  secretRotationExample,
  backupAndRecoveryExample,
  monitoringAndMetricsExample,
  auditAndComplianceExample,
  jwtAuthenticationExample,
  errorHandlingAndRetryExample,
  performanceOptimizationExample
};