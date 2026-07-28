import { PrismaClient } from '@prisma/client';
import { IStorageAdapter, StoredKeyRecord, AuditRecord } from './storage-adapter.js';
import { EncryptedDEK } from '../crypto/crypto-engine.js';

/**
 * PostgreSQL persistent storage adapter using Prisma ORM.
 */
export class PrismaStorageAdapter implements IStorageAdapter {
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient();
  }

  public async saveKey(
    id: string,
    alias: string,
    serviceOwner: string,
    encryptedDek: EncryptedDEK
  ): Promise<StoredKeyRecord> {
    const record = await this.prisma.keyMeta.create({
      data: {
        id,
        alias,
        serviceOwner,
        encryptedKeyMaterial: encryptedDek.encryptedDek,
        iv: encryptedDek.iv,
        authTag: encryptedDek.authTag,
        version: 1,
        state: 'ENABLED',
      },
    });

    return {
      id: record.id,
      alias: record.alias,
      serviceOwner: record.serviceOwner,
      encryptedKeyMaterial: Buffer.from(record.encryptedKeyMaterial),
      iv: Buffer.from(record.iv),
      authTag: Buffer.from(record.authTag),
      version: record.version,
      state: record.state as 'ENABLED' | 'DISABLED' | 'REVOKED',
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  public async getKeyById(id: string): Promise<StoredKeyRecord | null> {
    const record = await this.prisma.keyMeta.findUnique({
      where: { id },
    });
    if (!record) return null;

    return {
      id: record.id,
      alias: record.alias,
      serviceOwner: record.serviceOwner,
      encryptedKeyMaterial: Buffer.from(record.encryptedKeyMaterial),
      iv: Buffer.from(record.iv),
      authTag: Buffer.from(record.authTag),
      version: record.version,
      state: record.state as 'ENABLED' | 'DISABLED' | 'REVOKED',
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  public async getKeyByAlias(alias: string): Promise<StoredKeyRecord | null> {
    const record = await this.prisma.keyMeta.findUnique({
      where: { alias },
    });
    if (!record) return null;

    return {
      id: record.id,
      alias: record.alias,
      serviceOwner: record.serviceOwner,
      encryptedKeyMaterial: Buffer.from(record.encryptedKeyMaterial),
      iv: Buffer.from(record.iv),
      authTag: Buffer.from(record.authTag),
      version: record.version,
      state: record.state as 'ENABLED' | 'DISABLED' | 'REVOKED',
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  public async listKeys(): Promise<StoredKeyRecord[]> {
    const records = await this.prisma.keyMeta.findMany();
    return records.map((record) => ({
      id: record.id,
      alias: record.alias,
      serviceOwner: record.serviceOwner,
      encryptedKeyMaterial: Buffer.from(record.encryptedKeyMaterial),
      iv: Buffer.from(record.iv),
      authTag: Buffer.from(record.authTag),
      version: record.version,
      state: record.state as 'ENABLED' | 'DISABLED' | 'REVOKED',
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    }));
  }

  public async updateKey(
    id: string,
    encryptedDek: EncryptedDEK,
    newVersion: number
  ): Promise<StoredKeyRecord> {
    const record = await this.prisma.keyMeta.update({
      where: { id },
      data: {
        encryptedKeyMaterial: encryptedDek.encryptedDek,
        iv: encryptedDek.iv,
        authTag: encryptedDek.authTag,
        version: newVersion,
      },
    });

    return {
      id: record.id,
      alias: record.alias,
      serviceOwner: record.serviceOwner,
      encryptedKeyMaterial: Buffer.from(record.encryptedKeyMaterial),
      iv: Buffer.from(record.iv),
      authTag: Buffer.from(record.authTag),
      version: record.version,
      state: record.state as 'ENABLED' | 'DISABLED' | 'REVOKED',
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  public async revokeKey(id: string): Promise<StoredKeyRecord> {
    const record = await this.prisma.keyMeta.update({
      where: { id },
      data: {
        state: 'REVOKED',
      },
    });

    return {
      id: record.id,
      alias: record.alias,
      serviceOwner: record.serviceOwner,
      encryptedKeyMaterial: Buffer.from(record.encryptedKeyMaterial),
      iv: Buffer.from(record.iv),
      authTag: Buffer.from(record.authTag),
      version: record.version,
      state: record.state as 'ENABLED' | 'DISABLED' | 'REVOKED',
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  public async logAudit(record: Omit<AuditRecord, 'id' | 'timestamp'>): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        serviceId: record.serviceId,
        action: record.action,
        keyId: record.keyId,
        status: record.status,
        ipAddress: record.ipAddress,
      },
    });
  }

  public async exportAuditLogs(): Promise<AuditRecord[]> {
    const logs = await this.prisma.auditLog.findMany({
      orderBy: { timestamp: 'desc' },
      take: 100,
    });

    return logs.map((log) => ({
      id: log.id,
      timestamp: log.timestamp,
      serviceId: log.serviceId,
      action: log.action,
      keyId: log.keyId || undefined,
      status: log.status,
      ipAddress: log.ipAddress || undefined,
    }));
  }
}
