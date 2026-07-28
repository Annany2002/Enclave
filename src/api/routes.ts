import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { MasterKeyManager } from '../crypto/master-key.js';
import { CryptoEngine } from '../crypto/crypto-engine.js';
import { IStorageAdapter } from '../storage/storage-adapter.js';
import { IAMManager } from '../auth/iam.js';

interface MetricsState {
  totalRequests: number;
  encryptOps: number;
  decryptOps: number;
  rotateOps: number;
  generateOps: number;
  revokeOps: number;
}

const metrics: MetricsState = {
  totalRequests: 0,
  encryptOps: 0,
  decryptOps: 0,
  rotateOps: 0,
  generateOps: 0,
  revokeOps: 0,
};

/**
 * Registers all HTTP API endpoints, authentication hooks, and metrics probes on Fastify instance.
 */
export function registerEnclaveRoutes(
  fastify: FastifyInstance,
  keyManager: MasterKeyManager,
  storage: IStorageAdapter,
  iam: IAMManager
): void {
  /**
   * Request authentication middleware hook for Bearer tokens and mTLS client certificates.
   */
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    metrics.totalRequests++;

    if (request.url === '/healthz' || request.url === '/readyz' || request.url === '/metrics') {
      return;
    }

    let identity = null;

    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      identity = iam.authenticateToken(token);
    }

    if (!identity) {
      const certCnHeader = (request.headers['x-client-cert-cn'] || request.headers['x-forwarded-client-cert']) as string;
      if (certCnHeader) {
        identity = iam.authenticateMtlsCert(certCnHeader);
      }
    }

    if (!identity) {
      reply.code(403).send({ error: 'Forbidden', message: 'Invalid or missing authentication credentials' });
      return;
    }

    (request as any).identity = identity;
  });

  /**
   * GET /healthz - Liveness probe checking Master Key unseal status.
   */
  fastify.get('/healthz', async () => {
    return { status: 'ok', unsealed: keyManager.isUnsealed() };
  });

  /**
   * GET /readyz - Kubernetes readiness probe.
   */
  fastify.get('/readyz', async (_request, reply) => {
    if (!keyManager.isUnsealed()) {
      reply.code(503).send({ status: 'unhealthy', reason: 'Master key not unsealed' });
      return;
    }
    return { status: 'ready' };
  });

  /**
   * GET /metrics - Prometheus metrics scrape endpoint.
   */
  fastify.get('/metrics', async (_request, reply) => {
    reply.header('Content-Type', 'text/plain; version=0.0.4');
    return [
      '# HELP enclave_requests_total Total HTTP requests handled by Enclave',
      '# TYPE enclave_requests_total counter',
      `enclave_requests_total ${metrics.totalRequests}`,
      '# HELP enclave_crypto_operations_total Cryptographic operations count',
      '# TYPE enclave_crypto_operations_total counter',
      `enclave_crypto_operations_total{operation="encrypt"} ${metrics.encryptOps}`,
      `enclave_crypto_operations_total{operation="decrypt"} ${metrics.decryptOps}`,
      `enclave_crypto_operations_total{operation="rotate"} ${metrics.rotateOps}`,
      `enclave_crypto_operations_total{operation="generate"} ${metrics.generateOps}`,
      `enclave_crypto_operations_total{operation="revoke"} ${metrics.revokeOps}`,
      '# HELP enclave_unsealed_status Unseal status of master key',
      '# TYPE enclave_unsealed_status gauge',
      `enclave_unsealed_status ${keyManager.isUnsealed() ? 1 : 0}`,
    ].join('\n');
  });

  /**
   * GET /api/v1/audit/export - Exports structured JSON audit log trail.
   */
  fastify.get('/api/v1/audit/export', async (request, reply) => {
    const identity = (request as any).identity;
    if (!iam.authorize(identity, '*', 'ExportAudit')) {
      reply.code(403).send({ error: 'Forbidden', message: 'Unauthorized to export audit logs' });
      return;
    }

    const logs = await storage.exportAuditLogs();
    return { logs };
  });

  /**
   * POST /api/v1/keys/generate - Generates a new 256-bit DEK wrapped via Master KEK.
   */
  fastify.post<{ Body: { alias: string } }>(
    '/api/v1/keys/generate',
    {
      schema: {
        body: {
          type: 'object',
          required: ['alias'],
          properties: {
            alias: { type: 'string', minLength: 3, maxLength: 64 },
          },
        },
      },
    },
    async (request, reply) => {
      metrics.generateOps++;
      const identity = (request as any).identity;
      const { alias } = request.body;

      if (!iam.authorize(identity, alias, 'GenerateKey')) {
        await storage.logAudit({
          serviceId: identity.serviceId,
          action: 'GenerateKey',
          status: 'DENIED',
          ipAddress: request.ip,
        });
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized to generate key for alias ${alias}` });
        return;
      }

      const existing = await storage.getKeyByAlias(alias);
      if (existing) {
        reply.code(409).send({ error: 'Conflict', message: `Key alias ${alias} already exists` });
        return;
      }

      const rawDek = CryptoEngine.generateDEK();
      const masterKey = keyManager.getMasterKey();
      const encryptedDek = CryptoEngine.encryptWithMasterKey(rawDek, masterKey);

      const id = crypto.randomUUID();
      const record = await storage.saveKey(id, alias, identity.serviceId, encryptedDek);

      CryptoEngine.zeroBuffer(rawDek);

      await storage.logAudit({
        serviceId: identity.serviceId,
        action: 'GenerateKey',
        keyId: id,
        status: 'SUCCESS',
        ipAddress: request.ip,
      });

      return {
        id: record.id,
        alias: record.alias,
        version: record.version,
        createdAt: record.createdAt,
      };
    }
  );

  /**
   * POST /api/v1/keys/rotate - Generates a new DEK version for an existing key alias.
   */
  fastify.post<{ Body: { keyAlias: string } }>(
    '/api/v1/keys/rotate',
    {
      schema: {
        body: {
          type: 'object',
          required: ['keyAlias'],
          properties: {
            keyAlias: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      metrics.rotateOps++;
      const identity = (request as any).identity;
      const { keyAlias } = request.body;

      if (!iam.authorize(identity, keyAlias, 'RotateKey')) {
        await storage.logAudit({
          serviceId: identity.serviceId,
          action: 'RotateKey',
          status: 'DENIED',
          ipAddress: request.ip,
        });
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized to rotate key ${keyAlias}` });
        return;
      }

      const existing = await storage.getKeyByAlias(keyAlias);
      if (!existing || existing.state !== 'ENABLED') {
        reply.code(404).send({ error: 'Not Found', message: `Active key not found for alias ${keyAlias}` });
        return;
      }

      const newRawDek = CryptoEngine.generateDEK();
      const masterKey = keyManager.getMasterKey();
      const newEncryptedDek = CryptoEngine.encryptWithMasterKey(newRawDek, masterKey);

      const updatedRecord = await storage.updateKey(
        existing.id,
        newEncryptedDek,
        existing.version + 1
      );

      CryptoEngine.zeroBuffer(newRawDek);

      await storage.logAudit({
        serviceId: identity.serviceId,
        action: 'RotateKey',
        keyId: existing.id,
        status: 'SUCCESS',
        ipAddress: request.ip,
      });

      return {
        id: updatedRecord.id,
        alias: updatedRecord.alias,
        version: updatedRecord.version,
        updatedAt: updatedRecord.updatedAt,
      };
    }
  );

  /**
   * POST /api/v1/keys/revoke - Revokes a key alias and blocks subsequent access.
   */
  fastify.post<{ Body: { keyAlias: string } }>(
    '/api/v1/keys/revoke',
    {
      schema: {
        body: {
          type: 'object',
          required: ['keyAlias'],
          properties: {
            keyAlias: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      metrics.revokeOps++;
      const identity = (request as any).identity;
      const { keyAlias } = request.body;

      if (!iam.authorize(identity, keyAlias, 'RevokeKey')) {
        await storage.logAudit({
          serviceId: identity.serviceId,
          action: 'RevokeKey',
          status: 'DENIED',
          ipAddress: request.ip,
        });
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized to revoke key ${keyAlias}` });
        return;
      }

      const existing = await storage.getKeyByAlias(keyAlias);
      if (!existing || existing.state === 'REVOKED') {
        reply.code(404).send({ error: 'Not Found', message: `Active key not found for alias ${keyAlias}` });
        return;
      }

      const revokedRecord = await storage.revokeKey(existing.id);

      await storage.logAudit({
        serviceId: identity.serviceId,
        action: 'RevokeKey',
        keyId: existing.id,
        status: 'SUCCESS',
        ipAddress: request.ip,
      });

      return {
        id: revokedRecord.id,
        alias: revokedRecord.alias,
        state: revokedRecord.state,
        updatedAt: revokedRecord.updatedAt,
      };
    }
  );

  /**
   * POST /api/v1/crypto/encrypt - Encrypts plaintext payload via AES-256-GCM.
   */
  fastify.post<{ Body: { keyAlias: string; plaintext: string } }>(
    '/api/v1/crypto/encrypt',
    {
      schema: {
        body: {
          type: 'object',
          required: ['keyAlias', 'plaintext'],
          properties: {
            keyAlias: { type: 'string' },
            plaintext: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      metrics.encryptOps++;
      const identity = (request as any).identity;
      const { keyAlias, plaintext } = request.body;

      if (!iam.authorize(identity, keyAlias, 'Encrypt')) {
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized for operation Encrypt on key ${keyAlias}` });
        return;
      }

      const keyRecord = await storage.getKeyByAlias(keyAlias);
      if (!keyRecord || keyRecord.state !== 'ENABLED') {
        reply.code(410).send({ error: 'Gone', message: `Key ${keyAlias} is disabled or revoked` });
        return;
      }

      const masterKey = keyManager.getMasterKey();
      const rawDek = CryptoEngine.decryptWithMasterKey(
        keyRecord.encryptedKeyMaterial,
        keyRecord.iv,
        keyRecord.authTag,
        masterKey
      );

      const plaintextBuf = Buffer.from(plaintext, 'utf-8');
      const encryptedPayload = CryptoEngine.encryptPayload(plaintextBuf, rawDek);

      CryptoEngine.zeroBuffer(rawDek);

      return {
        ciphertextHex: encryptedPayload.ciphertext.toString('hex'),
        ivHex: encryptedPayload.iv.toString('hex'),
        authTagHex: encryptedPayload.authTag.toString('hex'),
        keyVersion: keyRecord.version,
      };
    }
  );

  /**
   * POST /api/v1/crypto/decrypt - Decrypts ciphertext payload via AES-256-GCM.
   */
  fastify.post<{ Body: { keyAlias: string; ciphertextHex: string; ivHex: string; authTagHex: string } }>(
    '/api/v1/crypto/decrypt',
    {
      schema: {
        body: {
          type: 'object',
          required: ['keyAlias', 'ciphertextHex', 'ivHex', 'authTagHex'],
          properties: {
            keyAlias: { type: 'string' },
            ciphertextHex: { type: 'string' },
            ivHex: { type: 'string' },
            authTagHex: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      metrics.decryptOps++;
      const identity = (request as any).identity;
      const { keyAlias, ciphertextHex, ivHex, authTagHex } = request.body;

      if (!iam.authorize(identity, keyAlias, 'Decrypt')) {
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized for operation Decrypt on key ${keyAlias}` });
        return;
      }

      const keyRecord = await storage.getKeyByAlias(keyAlias);
      if (!keyRecord || keyRecord.state !== 'ENABLED') {
        reply.code(410).send({ error: 'Gone', message: `Key ${keyAlias} is disabled or revoked` });
        return;
      }

      const masterKey = keyManager.getMasterKey();
      const rawDek = CryptoEngine.decryptWithMasterKey(
        keyRecord.encryptedKeyMaterial,
        keyRecord.iv,
        keyRecord.authTag,
        masterKey
      );

      const decryptedBuf = CryptoEngine.decryptPayload(
        Buffer.from(ciphertextHex, 'hex'),
        Buffer.from(ivHex, 'hex'),
        Buffer.from(authTagHex, 'hex'),
        rawDek
      );

      CryptoEngine.zeroBuffer(rawDek);

      return {
        plaintext: decryptedBuf.toString('utf-8'),
      };
    }
  );

  /**
   * POST /api/v1/keys/fetch - Returns unwrapped DEK for client SDK caching.
   */
  fastify.post<{ Body: { keyAlias: string } }>(
    '/api/v1/keys/fetch',
    {
      schema: {
        body: {
          type: 'object',
          required: ['keyAlias'],
          properties: {
            keyAlias: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      const identity = (request as any).identity;
      const { keyAlias } = request.body;

      if (!iam.authorize(identity, keyAlias, 'GetKey')) {
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized for operation GetKey on key ${keyAlias}` });
        return;
      }

      const keyRecord = await storage.getKeyByAlias(keyAlias);
      if (!keyRecord || keyRecord.state !== 'ENABLED') {
        reply.code(410).send({ error: 'Gone', message: `Key ${keyAlias} is disabled or revoked` });
        return;
      }

      const masterKey = keyManager.getMasterKey();
      const rawDek = CryptoEngine.decryptWithMasterKey(
        keyRecord.encryptedKeyMaterial,
        keyRecord.iv,
        keyRecord.authTag,
        masterKey
      );

      const dekHex = rawDek.toString('hex');
      CryptoEngine.zeroBuffer(rawDek);

      return {
        keyAlias: keyRecord.alias,
        dekHex,
        version: keyRecord.version,
      };
    }
  );
}
