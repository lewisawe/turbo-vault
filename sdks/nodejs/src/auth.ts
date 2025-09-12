/**
 * Authentication methods for Vault Agent Node.js SDK
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import axios from 'axios';

export interface AuthHeaders {
  [key: string]: string;
}

export abstract class AuthMethod {
  abstract getHeaders(): Promise<AuthHeaders> | AuthHeaders;
}

export class APIKeyAuth extends AuthMethod {
  constructor(private apiKey: string) {
    super();
  }

  getHeaders(): AuthHeaders {
    return {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
    };
  }
}

export class JWTAuth extends AuthMethod {
  constructor(private token: string) {
    super();
  }

  getHeaders(): AuthHeaders {
    return {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json',
    };
  }

  static fromCredentials(
    username: string,
    password: string,
    secretKey: string,
    options: {
      algorithm?: string;
      expiresIn?: number;
    } = {}
  ): JWTAuth {
    const { algorithm = 'HS256', expiresIn = 3600 } = options;
    
    const payload = {
      sub: username,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresIn,
    };

    const token = jwt.sign(payload, secretKey, { algorithm: algorithm as jwt.Algorithm });
    return new JWTAuth(token);
  }
}

export class CertificateAuth extends AuthMethod {
  private certificate?: Buffer;
  private privateKey?: Buffer;

  constructor(
    private certPath: string,
    private keyPath: string,
    private keyPassword?: string
  ) {
    super();
    this.loadCertificate();
  }

  private loadCertificate(): void {
    try {
      this.certificate = fs.readFileSync(this.certPath);
      this.privateKey = fs.readFileSync(this.keyPath);
    } catch (error) {
      throw new Error(`Failed to load certificate: ${error}`);
    }
  }

  getHeaders(): AuthHeaders {
    if (!this.certificate) {
      throw new Error('Certificate not loaded');
    }

    // Calculate certificate fingerprint for identification
    const fingerprint = crypto
      .createHash('sha256')
      .update(this.certificate)
      .digest('hex');

    return {
      'X-Client-Cert-Fingerprint': fingerprint,
      'Content-Type': 'application/json',
    };
  }

  getCertTuple(): { cert: Buffer; key: Buffer } {
    if (!this.certificate || !this.privateKey) {
      throw new Error('Certificate or private key not loaded');
    }
    return { cert: this.certificate, key: this.privateKey };
  }
}

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  tokenUrl: string;
  scope?: string;
}

export class OAuthAuth extends AuthMethod {
  private accessToken?: string;
  private tokenExpiry?: Date;

  constructor(private config: OAuthConfig) {
    super();
  }

  async getHeaders(): Promise<AuthHeaders> {
    const token = await this.getAccessToken();
    return {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    };
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return this.accessToken;
    }

    const data = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });

    if (this.config.scope) {
      data.append('scope', this.config.scope);
    }

    try {
      const response = await axios.post(this.config.tokenUrl, data, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      const tokenData = response.data;
      this.accessToken = tokenData.access_token;
      
      // Set expiry time (subtract 60 seconds for safety)
      const expiresIn = tokenData.expires_in || 3600;
      this.tokenExpiry = new Date(Date.now() + (expiresIn - 60) * 1000);

      return this.accessToken;
    } catch (error) {
      throw new Error(`Failed to obtain OAuth token: ${error}`);
    }
  }
}

export class BasicAuth extends AuthMethod {
  constructor(
    private username: string,
    private password: string
  ) {
    super();
  }

  getHeaders(): AuthHeaders {
    const credentials = Buffer.from(`${this.username}:${this.password}`).toString('base64');
    return {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/json',
    };
  }
}