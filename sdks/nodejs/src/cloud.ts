/**
 * Cloud provider integration for hybrid deployments
 */

import { Logger } from 'pino';
import pino from 'pino';

export interface CloudConfig {
  provider: 'aws' | 'azure' | 'gcp';
  region?: string;
  credentials?: Record<string, any>;
  syncEnabled?: boolean;
  backupEnabled?: boolean;
  encryptionEnabled?: boolean;
  tags?: Record<string, string>;
}

export abstract class CloudProvider {
  protected logger: Logger;
  
  constructor(protected config: CloudConfig) {
    this.logger = pino({ name: `cloud-${config.provider}` });
  }
  
  abstract syncSecret(name: string, value: string, metadata?: Record<string, any>): Promise<boolean>;
  abstract getSecret(name: string): Promise<string | null>;
  abstract deleteSecret(name: string): Promise<boolean>;
  abstract listSecrets(): Promise<string[]>;
}

export class AWSSecretsManager extends CloudProvider {
  private client: any;
  
  constructor(config: CloudConfig) {
    super(config);
  }
  
  private async getClient() {
    if (!this.client) {
      try {
        const AWS = require('aws-sdk');
        AWS.config.update({
          accessKeyId: this.config.credentials?.accessKeyId,
          secretAccessKey: this.config.credentials?.secretAccessKey,
          region: this.config.region || 'us-east-1'
        });
        this.client = new AWS.SecretsManager();
      } catch (error) {
        throw new Error('aws-sdk is required for AWS integration. Install with: npm install aws-sdk');
      }
    }
    return this.client;
  }
  
  async syncSecret(name: string, value: string, metadata?: Record<string, any>): Promise<boolean> {
    try {
      const client = await this.getClient();
      const secretName = `vault-agent/${name}`;
      
      const params: any = {
        Name: secretName,
        SecretString: value,
        Description: `Synced from Vault Agent: ${metadata?.description || ''}`,
      };
      
      if (this.config.tags) {
        params.Tags = Object.entries(this.config.tags).map(([Key, Value]) => ({ Key, Value }));
      }
      
      try {
        // Try to update existing secret
        await client.updateSecret(params).promise();
        this.logger.info(`Updated secret ${name} in AWS Secrets Manager`);
      } catch (error: any) {
        if (error.code === 'ResourceNotFoundException') {
          // Create new secret
          await client.createSecret(params).promise();
          this.logger.info(`Created secret ${name} in AWS Secrets Manager`);
        } else {
          throw error;
        }
      }
      
      return true;
    } catch (error) {
      this.logger.error(`Failed to sync secret ${name} to AWS:`, error);
      return false;
    }
  }
  
  async getSecret(name: string): Promise<string | null> {
    try {
      const client = await this.getClient();
      const result = await client.getSecretValue({
        SecretId: `vault-agent/${name}`
      }).promise();
      
      return result.SecretString;
    } catch (error) {
      this.logger.error(`Failed to get secret ${name} from AWS:`, error);
      return null;
    }
  }
  
  async deleteSecret(name: string): Promise<boolean> {
    try {
      const client = await this.getClient();
      await client.deleteSecret({
        SecretId: `vault-agent/${name}`,
        ForceDeleteWithoutRecovery: true
      }).promise();
      
      this.logger.info(`Deleted secret ${name} from AWS Secrets Manager`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to delete secret ${name} from AWS:`, error);
      return false;
    }
  }
  
  async listSecrets(): Promise<string[]> {
    try {
      const client = await this.getClient();
      const secrets: string[] = [];
      let nextToken: string | undefined;
      
      do {
        const result = await client.listSecrets({
          NextToken: nextToken
        }).promise();
        
        for (const secret of result.SecretList || []) {
          if (secret.Name?.startsWith('vault-agent/')) {
            secrets.push(secret.Name.replace('vault-agent/', ''));
          }
        }
        
        nextToken = result.NextToken;
      } while (nextToken);
      
      return secrets;
    } catch (error) {
      this.logger.error('Failed to list secrets from AWS:', error);
      return [];
    }
  }
}

export class AzureKeyVault extends CloudProvider {
  private client: any;
  
  constructor(config: CloudConfig) {
    super(config);
  }
  
  private async getClient() {
    if (!this.client) {
      try {
        const { SecretClient } = require('@azure/keyvault-secrets');
        const { DefaultAzureCredential } = require('@azure/identity');
        
        const credential = new DefaultAzureCredential();
        const vaultUrl = this.config.credentials?.vaultUrl;
        
        if (!vaultUrl) {
          throw new Error('vaultUrl is required for Azure Key Vault');
        }
        
        this.client = new SecretClient(vaultUrl, credential);
      } catch (error) {
        throw new Error('@azure/keyvault-secrets is required for Azure integration');
      }
    }
    return this.client;
  }
  
  async syncSecret(name: string, value: string, metadata?: Record<string, any>): Promise<boolean> {
    try {
      const client = await this.getClient();
      
      // Azure Key Vault has naming restrictions
      const azureName = name.replace(/_/g, '-').replace(/\./g, '-');
      
      await client.setSecret(azureName, value, {
        tags: this.config.tags
      });
      
      this.logger.info(`Synced secret ${name} to Azure Key Vault as ${azureName}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to sync secret ${name} to Azure:`, error);
      return false;
    }
  }
  
  async getSecret(name: string): Promise<string | null> {
    try {
      const client = await this.getClient();
      const azureName = name.replace(/_/g, '-').replace(/\./g, '-');
      const secret = await client.getSecret(azureName);
      return secret.value || null;
    } catch (error) {
      this.logger.error(`Failed to get secret ${name} from Azure:`, error);
      return null;
    }
  }
  
  async deleteSecret(name: string): Promise<boolean> {
    try {
      const client = await this.getClient();
      const azureName = name.replace(/_/g, '-').replace(/\./g, '-');
      await client.beginDeleteSecret(azureName);
      
      this.logger.info(`Deleted secret ${name} from Azure Key Vault`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to delete secret ${name} from Azure:`, error);
      return false;
    }
  }
  
  async listSecrets(): Promise<string[]> {
    try {
      const client = await this.getClient();
      const secrets: string[] = [];
      
      for await (const secretProperties of client.listPropertiesOfSecrets()) {
        // Convert back from Azure naming convention
        const name = secretProperties.name.replace(/-/g, '_');
        secrets.push(name);
      }
      
      return secrets;
    } catch (error) {
      this.logger.error('Failed to list secrets from Azure:', error);
      return [];
    }
  }
}

export class GCPSecretManager extends CloudProvider {
  private client: any;
  
  constructor(config: CloudConfig) {
    super(config);
  }
  
  private async getClient() {
    if (!this.client) {
      try {
        const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
        this.client = new SecretManagerServiceClient();
      } catch (error) {
        throw new Error('@google-cloud/secret-manager is required for GCP integration');
      }
    }
    return this.client;
  }
  
  async syncSecret(name: string, value: string, metadata?: Record<string, any>): Promise<boolean> {
    try {
      const client = await this.getClient();
      const projectId = this.config.credentials?.projectId;
      
      if (!projectId) {
        throw new Error('projectId is required for GCP Secret Manager');
      }
      
      const parent = `projects/${projectId}`;
      const secretId = `vault-agent-${name.replace(/_/g, '-').replace(/\./g, '-')}`;
      
      try {
        // Try to create secret
        const secret: any = {
          replication: { automatic: {} },
        };
        
        if (this.config.tags) {
          secret.labels = this.config.tags;
        }
        
        await client.createSecret({
          parent,
          secretId,
          secret
        });
      } catch (error) {
        // Secret might already exist
      }
      
      // Add secret version
      const secretName = `${parent}/secrets/${secretId}`;
      await client.addSecretVersion({
        parent: secretName,
        payload: {
          data: Buffer.from(value, 'utf8')
        }
      });
      
      this.logger.info(`Synced secret ${name} to GCP Secret Manager as ${secretId}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to sync secret ${name} to GCP:`, error);
      return false;
    }
  }
  
  async getSecret(name: string): Promise<string | null> {
    try {
      const client = await this.getClient();
      const projectId = this.config.credentials?.projectId;
      const secretId = `vault-agent-${name.replace(/_/g, '-').replace(/\./g, '-')}`;
      
      const secretName = `projects/${projectId}/secrets/${secretId}/versions/latest`;
      const [response] = await client.accessSecretVersion({ name: secretName });
      
      return response.payload?.data?.toString('utf8') || null;
    } catch (error) {
      this.logger.error(`Failed to get secret ${name} from GCP:`, error);
      return null;
    }
  }
  
  async deleteSecret(name: string): Promise<boolean> {
    try {
      const client = await this.getClient();
      const projectId = this.config.credentials?.projectId;
      const secretId = `vault-agent-${name.replace(/_/g, '-').replace(/\./g, '-')}`;
      
      const secretName = `projects/${projectId}/secrets/${secretId}`;
      await client.deleteSecret({ name: secretName });
      
      this.logger.info(`Deleted secret ${name} from GCP Secret Manager`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to delete secret ${name} from GCP:`, error);
      return false;
    }
  }
  
  async listSecrets(): Promise<string[]> {
    try {
      const client = await this.getClient();
      const projectId = this.config.credentials?.projectId;
      const parent = `projects/${projectId}`;
      
      const secrets: string[] = [];
      const [secretsList] = await client.listSecrets({ parent });
      
      for (const secret of secretsList) {
        const name = secret.name?.split('/').pop();
        if (name?.startsWith('vault-agent-')) {
          // Convert back from GCP naming convention
          const originalName = name.replace('vault-agent-', '').replace(/-/g, '_');
          secrets.push(originalName);
        }
      }
      
      return secrets;
    } catch (error) {
      this.logger.error('Failed to list secrets from GCP:', error);
      return [];
    }
  }
}

export class CloudIntegration {
  private providers: Map<string, CloudProvider> = new Map();
  private logger: Logger;
  
  constructor(configs: CloudConfig[]) {
    this.logger = pino({ name: 'cloud-integration' });
    
    for (const config of configs) {
      switch (config.provider) {
        case 'aws':
          this.providers.set('aws', new AWSSecretsManager(config));
          break;
        case 'azure':
          this.providers.set('azure', new AzureKeyVault(config));
          break;
        case 'gcp':
          this.providers.set('gcp', new GCPSecretManager(config));
          break;
        default:
          this.logger.warn(`Unknown cloud provider: ${config.provider}`);
      }
    }
  }
  
  isEnabled(): boolean {
    return this.providers.size > 0;
  }
  
  async syncSecret(name: string, value: string, metadata?: Record<string, any>): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};
    
    const promises = Array.from(this.providers.entries()).map(async ([providerName, provider]) => {
      try {
        const result = await provider.syncSecret(name, value, metadata);
        results[providerName] = result;
      } catch (error) {
        this.logger.error(`Failed to sync to ${providerName}:`, error);
        results[providerName] = false;
      }
    });
    
    await Promise.all(promises);
    return results;
  }
  
  async deleteSecret(name: string): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};
    
    const promises = Array.from(this.providers.entries()).map(async ([providerName, provider]) => {
      try {
        const result = await provider.deleteSecret(name);
        results[providerName] = result;
      } catch (error) {
        this.logger.error(`Failed to delete from ${providerName}:`, error);
        results[providerName] = false;
      }
    });
    
    await Promise.all(promises);
    return results;
  }
  
  async getSecretFromProvider(name: string, provider: string): Promise<string | null> {
    const providerInstance = this.providers.get(provider);
    if (!providerInstance) {
      throw new Error(`Provider ${provider} not configured`);
    }
    
    return providerInstance.getSecret(name);
  }
  
  async listSecretsFromProvider(provider: string): Promise<string[]> {
    const providerInstance = this.providers.get(provider);
    if (!providerInstance) {
      throw new Error(`Provider ${provider} not configured`);
    }
    
    return providerInstance.listSecrets();
  }
}