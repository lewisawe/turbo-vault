/**
 * Configuration for Vault Agent Node.js SDK
 */

import { z } from 'zod';

export interface RetryConfig {
  maxAttempts: number;
  initialDelay: number;
  maxDelay: number;
  backoffFactor: number;
  retryableStatusCodes: number[];
}

export interface ClientConfig {
  timeout: number;
  maxConnections: number;
  verifySsl: boolean;
  retry: RetryConfig;
  userAgent: string;
  defaultHeaders: Record<string, string>;
  logLevel: 'debug' | 'info' | 'warn' | 'error' | 'silent';
  cacheEnabled: boolean;
  cacheTtl: number;
  cacheMaxSize: number;
}

const RetryConfigSchema = z.object({
  maxAttempts: z.number().min(1).max(10).default(3),
  initialDelay: z.number().min(100).default(1000),
  maxDelay: z.number().min(1000).default(30000),
  backoffFactor: z.number().min(1).default(2),
  retryableStatusCodes: z.array(z.number()).default([408, 429, 500, 502, 503, 504]),
});

const ClientConfigSchema = z.object({
  timeout: z.number().min(1000).default(30000),
  maxConnections: z.number().min(1).default(10),
  verifySsl: z.boolean().default(true),
  retry: RetryConfigSchema.default({}),
  userAgent: z.string().default('vault-agent-nodejs-sdk/1.0.0'),
  defaultHeaders: z.record(z.string()).default({}),
  logLevel: z.enum(['debug', 'info', 'warn', 'error', 'silent']).default('info'),
  cacheEnabled: z.boolean().default(true),
  cacheTtl: z.number().min(1000).default(300000), // 5 minutes
  cacheMaxSize: z.number().min(1).default(1000),
});

export function createClientConfig(config: Partial<ClientConfig> = {}): ClientConfig {
  return ClientConfigSchema.parse(config);
}

export function validateConfig(config: any): ClientConfig {
  try {
    return ClientConfigSchema.parse(config);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issues = error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`);
      throw new Error(`Configuration validation failed: ${issues.join(', ')}`);
    }
    throw error;
  }
}

export const DEFAULT_CONFIG: ClientConfig = createClientConfig();