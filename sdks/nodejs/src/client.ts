/**
 * Vault Agent Client for Node.js SDK
 */

import axios, { AxiosInstance, AxiosResponse, AxiosError } from 'axios';
import axiosRetry from 'axios-retry';
import NodeCache from 'node-cache';
import pino from 'pino';

import { AuthMethod } from './auth';
import { ClientConfig, createClientConfig } from './config';
import { parseErrorResponse } from './exceptions';
import {
  Secret,
  SecretMetadata,
  Policy,
  AuditEvent,
  BackupInfo,
  VaultStatus,
  CreateSecretRequest,
  UpdateSecretRequest,
  ListSecretsOptions,
  AuditQueryOptions,
} from './types';
import { CloudIntegration } from './cloud';

export class VaultAgentClient {
  private client: AxiosInstance;
  private config: ClientConfig;
  private logger: pino.Logger;
  private cache?: NodeCache;
  private cloudIntegration?: CloudIntegration;

  constructor(
    private baseUrl: string,
    private auth: AuthMethod,
    config: Partial<ClientConfig> = {}
  ) {
    this.config = createClientConfig(config);
    this.logger = pino({ level: this.config.logLevel });
    
    // Initialize cache if enabled
    if (this.config.cacheEnabled) {
      this.cache = new NodeCache({
        stdTTL: this.config.cacheTtl / 1000,
        maxKeys: this.config.cacheMaxSize,
      });
    }

    // Initialize HTTP client
    this.client = axios.create({
      baseURL: this.baseUrl.replace(/\/$/, ''),
      timeout: this.config.timeout,
      maxRedirects: 5,
      headers: {
        'User-Agent': this.config.userAgent,
        ...this.config.defaultHeaders,
      },
    });

    // Configure retry logic
    axiosRetry(this.client, {
      retries: this.config.retry.maxAttempts,
      retryDelay: (retryCount) => {
        const delay = Math.min(
          this.config.retry.initialDelay * Math.pow(this.config.retry.backoffFactor, retryCount - 1),
          this.config.retry.maxDelay
        );
        // Add jitter
        return delay + Math.random() * 1000;
      },
      retryCondition: (error: AxiosError) => {
        return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
               (error.response?.status ? this.config.retry.retryableStatusCodes.includes(error.response.status) : false);
      },
    });

    // Add request interceptor for authentication
    this.client.interceptors.request.use(async (config) => {
      const authHeaders = await this.auth.getHeaders();
      config.headers = { ...config.headers, ...authHeaders };
      return config;
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        const requestId = error.response?.headers['x-request-id'];
        if (error.response) {
          parseErrorResponse(error.response.status, error.response.data, requestId);
        }
        throw error;
      }
    );
  }

  /**
   * Enable cloud integration for hybrid deployments
   */
  enableCloudIntegration(config: any): void {
    this.cloudIntegration = new CloudIntegration(config);
  }

  /**
   * Get cached value or execute function and cache result
   */
  private async withCache<T>(key: string, fn: () => Promise<T>, ttl?: number): Promise<T> {
    if (!this.cache) {
      return fn();
    }

    const cached = this.cache.get<T>(key);
    if (cached !== undefined) {
      this.logger.debug(`Cache hit for key: ${key}`);
      return cached;
    }

    const result = await fn();
    this.cache.set(key, result, ttl ? ttl / 1000 : undefined);
    this.logger.debug(`Cache set for key: ${key}`);
    return result;
  }

  /**
   * Invalidate cache entries matching pattern
   */
  private invalidateCache(pattern: string): void {
    if (!this.cache) return;

    const keys = this.cache.keys();
    const matchingKeys = keys.filter(key => key.includes(pattern));
    this.cache.del(matchingKeys);
    this.logger.debug(`Invalidated ${matchingKeys.length} cache entries matching: ${pattern}`);
  }

  // Secret Management Methods

  async createSecret(request: CreateSecretRequest): Promise<Secret> {
    this.logger.info(`Creating secret: ${request.name}`);
    
    const response = await this.client.post<Secret>('/api/v1/secrets', request);
    const secret = response.data;

    // Sync to cloud providers if enabled
    if (this.cloudIntegration?.isEnabled()) {
      try {
        await this.cloudIntegration.syncSecret(secret.name, secret.value);
      } catch (error) {
        this.logger.warn('Failed to sync secret to cloud providers:', error);
      }
    }

    this.invalidateCache('secrets');
    return secret;
  }

  async getSecret(secretId: string): Promise<Secret> {
    return this.withCache(`secret:${secretId}`, async () => {
      this.logger.info(`Getting secret: ${secretId}`);
      const response = await this.client.get<Secret>(`/api/v1/secrets/${secretId}`);
      return response.data;
    });
  }

  async updateSecret(secretId: string, request: UpdateSecretRequest): Promise<Secret> {
    this.logger.info(`Updating secret: ${secretId}`);
    
    const response = await this.client.put<Secret>(`/api/v1/secrets/${secretId}`, request);
    const secret = response.data;

    // Sync to cloud providers if enabled
    if (this.cloudIntegration?.isEnabled() && request.value) {
      try {
        await this.cloudIntegration.syncSecret(secret.name, request.value);
      } catch (error) {
        this.logger.warn('Failed to sync updated secret to cloud providers:', error);
      }
    }

    this.invalidateCache(`secret:${secretId}`);
    this.invalidateCache('secrets');
    return secret;
  }

  async deleteSecret(secretId: string): Promise<void> {
    this.logger.info(`Deleting secret: ${secretId}`);
    
    // Get secret name for cloud sync
    let secretName: string | undefined;
    if (this.cloudIntegration?.isEnabled()) {
      try {
        const secret = await this.getSecret(secretId);
        secretName = secret.name;
      } catch (error) {
        this.logger.warn('Failed to get secret name for cloud deletion:', error);
      }
    }

    await this.client.delete(`/api/v1/secrets/${secretId}`);

    // Delete from cloud providers if enabled
    if (this.cloudIntegration?.isEnabled() && secretName) {
      try {
        await this.cloudIntegration.deleteSecret(secretName);
      } catch (error) {
        this.logger.warn('Failed to delete secret from cloud providers:', error);
      }
    }

    this.invalidateCache(`secret:${secretId}`);
    this.invalidateCache('secrets');
  }

  async listSecrets(options: ListSecretsOptions = {}): Promise<SecretMetadata[]> {
    const cacheKey = `secrets:${JSON.stringify(options)}`;
    return this.withCache(cacheKey, async () => {
      this.logger.info('Listing secrets');
      const params = new URLSearchParams();
      
      if (options.tags?.length) {
        params.append('tags', options.tags.join(','));
      }
      if (options.limit) {
        params.append('limit', options.limit.toString());
      }
      if (options.offset) {
        params.append('offset', options.offset.toString());
      }

      const response = await this.client.get<{ secrets: SecretMetadata[] }>('/api/v1/secrets', { params });
      return response.data.secrets;
    });
  }

  async rotateSecret(secretId: string): Promise<Secret> {
    this.logger.info(`Rotating secret: ${secretId}`);
    const response = await this.client.post<Secret>(`/api/v1/secrets/${secretId}/rotate`);
    
    this.invalidateCache(`secret:${secretId}`);
    this.invalidateCache('secrets');
    return response.data;
  }

  async getSecretVersions(secretId: string): Promise<SecretMetadata[]> {
    return this.withCache(`secret-versions:${secretId}`, async () => {
      this.logger.info(`Getting secret versions: ${secretId}`);
      const response = await this.client.get<{ versions: SecretMetadata[] }>(`/api/v1/secrets/${secretId}/versions`);
      return response.data.versions;
    });
  }

  async rollbackSecret(secretId: string, version: number): Promise<Secret> {
    this.logger.info(`Rolling back secret ${secretId} to version ${version}`);
    const response = await this.client.post<Secret>(`/api/v1/secrets/${secretId}/rollback`, { version });
    
    this.invalidateCache(`secret:${secretId}`);
    this.invalidateCache('secrets');
    return response.data;
  }

  // Policy Management Methods

  async createPolicy(policy: Policy): Promise<Policy> {
    this.logger.info(`Creating policy: ${policy.name}`);
    const response = await this.client.post<Policy>('/api/v1/policies', policy);
    
    this.invalidateCache('policies');
    return response.data;
  }

  async getPolicy(policyId: string): Promise<Policy> {
    return this.withCache(`policy:${policyId}`, async () => {
      this.logger.info(`Getting policy: ${policyId}`);
      const response = await this.client.get<Policy>(`/api/v1/policies/${policyId}`);
      return response.data;
    });
  }

  async updatePolicy(policyId: string, policy: Partial<Policy>): Promise<Policy> {
    this.logger.info(`Updating policy: ${policyId}`);
    const response = await this.client.put<Policy>(`/api/v1/policies/${policyId}`, policy);
    
    this.invalidateCache(`policy:${policyId}`);
    this.invalidateCache('policies');
    return response.data;
  }

  async deletePolicy(policyId: string): Promise<void> {
    this.logger.info(`Deleting policy: ${policyId}`);
    await this.client.delete(`/api/v1/policies/${policyId}`);
    
    this.invalidateCache(`policy:${policyId}`);
    this.invalidateCache('policies');
  }

  async listPolicies(): Promise<Policy[]> {
    return this.withCache('policies', async () => {
      this.logger.info('Listing policies');
      const response = await this.client.get<{ policies: Policy[] }>('/api/v1/policies');
      return response.data.policies;
    });
  }

  // Audit Methods

  async getAuditEvents(options: AuditQueryOptions = {}): Promise<AuditEvent[]> {
    const cacheKey = `audit:${JSON.stringify(options)}`;
    return this.withCache(cacheKey, async () => {
      this.logger.info('Getting audit events');
      const params = new URLSearchParams();
      
      if (options.start_time) {
        params.append('start_time', options.start_time);
      }
      if (options.end_time) {
        params.append('end_time', options.end_time);
      }
      if (options.event_type) {
        params.append('event_type', options.event_type);
      }
      if (options.limit) {
        params.append('limit', options.limit.toString());
      }

      const response = await this.client.get<{ events: AuditEvent[] }>('/api/v1/audit/events', { params });
      return response.data.events;
    }, 60000); // Cache for 1 minute only
  }

  // Backup Methods

  async createBackup(name: string, options: Record<string, any> = {}): Promise<BackupInfo> {
    this.logger.info(`Creating backup: ${name}`);
    const response = await this.client.post<BackupInfo>('/api/v1/backups', { name, ...options });
    return response.data;
  }

  async listBackups(): Promise<BackupInfo[]> {
    return this.withCache('backups', async () => {
      this.logger.info('Listing backups');
      const response = await this.client.get<{ backups: BackupInfo[] }>('/api/v1/backups');
      return response.data.backups;
    });
  }

  async restoreBackup(backupId: string, options: Record<string, any> = {}): Promise<void> {
    this.logger.info(`Restoring backup: ${backupId}`);
    await this.client.post(`/api/v1/backups/${backupId}/restore`, options);
    
    // Clear all caches after restore
    this.cache?.flushAll();
  }

  // Health and Status Methods

  async healthCheck(): Promise<VaultStatus> {
    // Don't cache health checks
    this.logger.debug('Performing health check');
    const response = await this.client.get<VaultStatus>('/api/v1/health');
    return response.data;
  }

  async getMetrics(): Promise<string> {
    this.logger.debug('Getting metrics');
    const response = await this.client.get<string>('/metrics', {
      headers: { Accept: 'text/plain' },
    });
    return response.data;
  }

  // Utility Methods

  /**
   * Clear all cached data
   */
  clearCache(): void {
    if (this.cache) {
      this.cache.flushAll();
      this.logger.info('Cache cleared');
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): Record<string, any> | null {
    if (!this.cache) return null;
    
    return {
      keys: this.cache.keys().length,
      hits: this.cache.getStats().hits,
      misses: this.cache.getStats().misses,
      ksize: this.cache.getStats().ksize,
      vsize: this.cache.getStats().vsize,
    };
  }

  /**
   * Close the client and cleanup resources
   */
  close(): void {
    if (this.cache) {
      this.cache.close();
    }
    this.logger.info('Client closed');
  }
}