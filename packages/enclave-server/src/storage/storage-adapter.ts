import { EncryptedDEK } from '../crypto/crypto-engine.js';

export interface StoredKeyRecord {
  id: string;
  alias: string;
  serviceOwner: string;
  encryptedKeyMaterial: Buffer;
  iv: Buffer;
  authTag: Buffer;
  version: number;
  state: 'ENABLED' | 'DISABLED' | 'REVOKED';
  createdAt: Date;
  updatedAt: Date;
}

export interface AuditRecord {
  id: string;
  timestamp: Date;
  serviceId: string;
  action: string;
  keyId?: string;
  status: string;
  ipAddress?: string;
}

export interface IStorageAdapter {
  saveKey(
    id: string,
    alias: string,
    serviceOwner: string,
    encryptedDek: EncryptedDEK
  ): Promise<StoredKeyRecord>;
  
  getKeyById(id: string): Promise<StoredKeyRecord | null>;
  getKeyByAlias(alias: string): Promise<StoredKeyRecord | null>;
  
  updateKey(
    id: string,
    encryptedDek: EncryptedDEK,
    newVersion: number
  ): Promise<StoredKeyRecord>;

  logAudit(record: Omit<AuditRecord, 'id' | 'timestamp'>): Promise<void>;
}

export class InMemoryStorageAdapter implements IStorageAdapter {
  private keys: Map<string, StoredKeyRecord> = new Map();
  private aliasIndex: Map<string, string> = new Map();
  private auditLogs: AuditRecord[] = [];

  public async saveKey(
    id: string,
    alias: string,
    serviceOwner: string,
    encryptedDek: EncryptedDEK
  ): Promise<StoredKeyRecord> {
    const record: StoredKeyRecord = {
      id,
      alias,
      serviceOwner,
      encryptedKeyMaterial: encryptedDek.encryptedDek,
      iv: encryptedDek.iv,
      authTag: encryptedDek.authTag,
      version: 1,
      state: 'ENABLED',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.keys.set(id, record);
    this.aliasIndex.set(alias, id);
    return record;
  }

  public async getKeyById(id: string): Promise<StoredKeyRecord | null> {
    return this.keys.get(id) || null;
  }

  public async getKeyByAlias(alias: string): Promise<StoredKeyRecord | null> {
    const id = this.aliasIndex.get(alias);
    if (!id) return null;
    return this.getKeyById(id);
  }

  public async updateKey(
    id: string,
    encryptedDek: EncryptedDEK,
    newVersion: number
  ): Promise<StoredKeyRecord> {
    const existing = this.keys.get(id);
    if (!existing) {
      throw new Error(`Key record not found for ID: ${id}`);
    }

    existing.encryptedKeyMaterial = encryptedDek.encryptedDek;
    existing.iv = encryptedDek.iv;
    existing.authTag = encryptedDek.authTag;
    existing.version = newVersion;
    existing.updatedAt = new Date();

    return existing;
  }

  public async logAudit(record: Omit<AuditRecord, 'id' | 'timestamp'>): Promise<void> {
    this.auditLogs.push({
      id: crypto.randomUUID(),
      timestamp: new Date(),
      ...record,
    });
  }

  public getAuditLogs(): AuditRecord[] {
    return [...this.auditLogs];
  }
}
