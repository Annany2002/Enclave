import crypto from 'node:crypto';
import { KeyCache } from './cache.js';
import { EnclaveTransport, TransportConfig } from './transport.js';

export interface EnclaveClientConfig extends TransportConfig {
  enableLocalCaching?: boolean;
  cacheTtlMs?: number;
  cacheCapacity?: number;
}

export interface EncryptedPayloadResult {
  ciphertextHex: string;
  ivHex: string;
  authTagHex: string;
  keyVersion: number;
}

export class EnclaveClient {
  private transport: EnclaveTransport;
  private cache: KeyCache | null = null;
  private enableLocalCaching: boolean;

  constructor(config: EnclaveClientConfig) {
    this.transport = new EnclaveTransport(config);
    this.enableLocalCaching = config.enableLocalCaching ?? true;

    if (this.enableLocalCaching) {
      this.cache = new KeyCache(config.cacheCapacity, config.cacheTtlMs);
    }
  }

  public async generateKey(alias: string): Promise<{ id: string; alias: string; version: number }> {
    return this.transport.request<{ id: string; alias: string; version: number }>(
      '/api/v1/keys/generate',
      { alias }
    );
  }

  public async encrypt(keyAlias: string, plaintext: string): Promise<EncryptedPayloadResult> {
    if (this.enableLocalCaching && this.cache) {
      return this.encryptLocal(keyAlias, plaintext);
    }
    return this.encryptRemote(keyAlias, plaintext);
  }

  public async decrypt(
    keyAlias: string,
    ciphertextHex: string,
    ivHex: string,
    authTagHex: string
  ): Promise<string> {
    if (this.enableLocalCaching && this.cache) {
      return this.decryptLocal(keyAlias, ciphertextHex, ivHex, authTagHex);
    }
    return this.decryptRemote(keyAlias, ciphertextHex, ivHex, authTagHex);
  }

  public async encryptRemote(keyAlias: string, plaintext: string): Promise<EncryptedPayloadResult> {
    return this.transport.request<EncryptedPayloadResult>('/api/v1/crypto/encrypt', {
      keyAlias,
      plaintext,
    });
  }

  public async decryptRemote(
    keyAlias: string,
    ciphertextHex: string,
    ivHex: string,
    authTagHex: string
  ): Promise<string> {
    const res = await this.transport.request<{ plaintext: string }>('/api/v1/crypto/decrypt', {
      keyAlias,
      ciphertextHex,
      ivHex,
      authTagHex,
    });
    return res.plaintext;
  }

  private async fetchDek(keyAlias: string): Promise<{ dek: Buffer; version: number }> {
    if (this.cache) {
      const cached = this.cache.get(keyAlias);
      if (cached) {
        return { dek: cached.dek, version: cached.version };
      }
    }

    const res = await this.transport.request<{ keyAlias: string; dekHex: string; version: number }>(
      '/api/v1/keys/fetch',
      { keyAlias }
    );

    const dek = Buffer.from(res.dekHex, 'hex');

    if (this.cache) {
      this.cache.set(keyAlias, dek, res.version);
    }

    return { dek, version: res.version };
  }

  public async encryptLocal(keyAlias: string, plaintext: string): Promise<EncryptedPayloadResult> {
    const { dek, version } = await this.fetchDek(keyAlias);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv, {
      authTagLength: 16,
    } as crypto.CipherGCMOptions) as crypto.CipherGCM;

    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertextHex: ciphertext.toString('hex'),
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      keyVersion: version,
    };
  }

  public async decryptLocal(
    keyAlias: string,
    ciphertextHex: string,
    ivHex: string,
    authTagHex: string
  ): Promise<string> {
    const { dek } = await this.fetchDek(keyAlias);

    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, Buffer.from(ivHex, 'hex'), {
      authTagLength: 16,
    } as crypto.CipherGCMOptions) as crypto.DecipherGCM;
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertextHex, 'hex')),
      decipher.final(),
    ]);

    return decrypted.toString('utf-8');
  }

  public clearCache(): void {
    if (this.cache) {
      this.cache.clear();
    }
  }
}
