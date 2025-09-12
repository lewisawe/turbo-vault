/**
 * Basic usage example for Vault Agent Node.js SDK
 */

const { VaultAgentClient, APIKeyAuth } = require('@vault-agent/sdk');

async function main() {
  // Initialize client with API key authentication
  const auth = new APIKeyAuth('your-api-key-here');
  
  const client = new VaultAgentClient('https://localhost:8200', auth, {
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
      tags: ['database', 'production']
    });
    console.log(`Created secret: ${secret.id}`);

    // Retrieve the secret
    const retrieved = await client.getSecret(secret.id);
    console.log(`Retrieved secret value: ${retrieved.value}`);

    // List secrets
    const secrets = await client.listSecrets({ tags: ['production'] });
    console.log(`Found ${secrets.length} production secrets`);

    // Update secret
    const updated = await client.updateSecret(secret.id, {
      value: 'new-password',
      metadata: { environment: 'production', updated: 'true' }
    });
    console.log(`Updated secret to version ${updated.version}`);

    // Health check
    const health = await client.healthCheck();
    console.log(`Vault status: ${health.status}`);

  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    client.close();
  }
}

main().catch(console.error);