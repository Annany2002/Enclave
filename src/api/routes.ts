import crypto from 'node:crypto';

import { FastifyInstance, FastifyReply,FastifyRequest } from 'fastify';

import { IAMManager } from '../auth/iam.js';
import { CryptoEngine } from '../crypto/crypto-engine.js';
import { MasterKeyManager } from '../crypto/master-key.js';
import { IStorageAdapter } from '../storage/storage-adapter.js';
import { WebhookDispatcher } from '../webhooks/webhook-dispatcher.js';

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
 * Registers all HTTP API endpoints, OpenAPI schemas, authentication hooks, and metrics probes on Fastify instance.
 */
export function registerEnclaveRoutes(
  fastify: FastifyInstance,
  keyManager: MasterKeyManager,
  storage: IStorageAdapter,
  iam: IAMManager,
  webhooks?: WebhookDispatcher
): void {
  /**
   * Request authentication middleware hook for Bearer tokens and mTLS client certificates.
   */
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    metrics.totalRequests++;

    if (
      request.url === '/healthz' ||
      request.url === '/readyz' ||
      request.url === '/metrics' ||
      request.url.startsWith('/docs')
    ) {
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
      if (webhooks) {
        webhooks.dispatch({
          event: 'AccessDenied',
          timestamp: new Date().toISOString(),
          status: 'DENIED',
          ipAddress: request.ip,
        });
      }
      reply.code(403).send({ error: 'Forbidden', message: 'Invalid or missing authentication credentials' });
      return;
    }

    (request as any).identity = identity;
  });

  /**
   * GET /healthz - Liveness probe checking Master Key unseal status.
   */
  fastify.get(
    '/healthz',
    {
      schema: {
        summary: 'Liveness Probe',
        tags: ['System Probes'],
        response: {
          200: {
            type: 'object',
            properties: {
              status: { type: 'string' },
              unsealed: { type: 'boolean' },
            },
          },
        },
      },
    },
    async () => {
      return { status: 'ok', unsealed: keyManager.isUnsealed() };
    }
  );

  /**
   * GET /readyz - Kubernetes readiness probe.
   */
  fastify.get(
    '/readyz',
    {
      schema: {
        summary: 'Readiness Probe',
        tags: ['System Probes'],
        response: {
          200: {
            type: 'object',
            properties: {
              status: { type: 'string' },
            },
          },
          503: {
            type: 'object',
            properties: {
              status: { type: 'string' },
              reason: { type: 'string' },
            },
          },
        },
      },
    },
    async (_request, reply) => {
      if (!keyManager.isUnsealed()) {
        reply.code(503).send({ status: 'unhealthy', reason: 'Master key not unsealed' });
        return;
      }
      return { status: 'ready' };
    }
  );

  /**
   * GET /metrics - Prometheus metrics scrape endpoint.
   */
  fastify.get(
    '/metrics',
    {
      schema: {
        summary: 'Prometheus Metrics',
        tags: ['System Probes'],
      },
    },
    async (_request, reply) => {
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
    }
  );

  /**
   * GET /api/v1/audit/export - Exports structured JSON audit log trail.
   */
  fastify.get(
    '/api/v1/audit/export',
    {
      schema: {
        summary: 'Export Security Audit Logs',
        tags: ['Audit & Compliance'],
        response: {
          200: {
            type: 'object',
            properties: {
              logs: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    timestamp: { type: 'string' },
                    serviceId: { type: 'string' },
                    action: { type: 'string' },
                    keyId: { type: 'string' },
                    status: { type: 'string' },
                    ipAddress: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const identity = (request as any).identity;
      if (!iam.authorize(identity, '*', 'ExportAudit')) {
        if (webhooks) {
          webhooks.dispatch({
            event: 'ExportAudit',
            timestamp: new Date().toISOString(),
            serviceId: identity.serviceId,
            status: 'DENIED',
            ipAddress: request.ip,
          });
        }
        reply.code(403).send({ error: 'Forbidden', message: 'Unauthorized to export audit logs' });
        return;
      }

      const logs = await storage.exportAuditLogs();
      return { logs };
    }
  );

  /**
   * POST /api/v1/keys/generate - Generates a new 256-bit DEK wrapped via Master KEK.
   * 
   * @remark **Generated Key Record ID Prefix**: `enc_key_` (e.g. `enc_key_5a791bcf-02b7-4ea1-9caf-e5c48acf63f0`)
   */
  fastify.post<{ Body: { alias: string } }>(
    '/api/v1/keys/generate',
    {
      schema: {
        summary: 'Generate New DEK',
        tags: ['Key Lifecycle Management'],
        body: {
          type: 'object',
          required: ['alias'],
          properties: {
            alias: { type: 'string', minLength: 3, maxLength: 64 },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              alias: { type: 'string' },
              version: { type: 'number' },
              createdAt: { type: 'string' },
            },
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

        if (webhooks) {
          webhooks.dispatch({
            event: 'GenerateKey',
            timestamp: new Date().toISOString(),
            serviceId: identity.serviceId,
            keyAlias: alias,
            status: 'DENIED',
            ipAddress: request.ip,
          });
        }

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

      const id = `enc_key_${crypto.randomUUID()}`;
      const record = await storage.saveKey(id, alias, identity.serviceId, encryptedDek);

      CryptoEngine.zeroBuffer(rawDek);

      await storage.logAudit({
        serviceId: identity.serviceId,
        action: 'GenerateKey',
        keyId: id,
        status: 'SUCCESS',
        ipAddress: request.ip,
      });

      if (webhooks) {
        webhooks.dispatch({
          event: 'GenerateKey',
          timestamp: new Date().toISOString(),
          serviceId: identity.serviceId,
          keyAlias: alias,
          status: 'SUCCESS',
          ipAddress: request.ip,
        });
      }

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
        summary: 'Rotate Key Version',
        tags: ['Key Lifecycle Management'],
        body: {
          type: 'object',
          required: ['keyAlias'],
          properties: {
            keyAlias: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              alias: { type: 'string' },
              version: { type: 'number' },
              updatedAt: { type: 'string' },
            },
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

        if (webhooks) {
          webhooks.dispatch({
            event: 'RotateKey',
            timestamp: new Date().toISOString(),
            serviceId: identity.serviceId,
            keyAlias,
            status: 'DENIED',
            ipAddress: request.ip,
          });
        }

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

      if (webhooks) {
        webhooks.dispatch({
          event: 'RotateKey',
          timestamp: new Date().toISOString(),
          serviceId: identity.serviceId,
          keyAlias,
          status: 'SUCCESS',
          ipAddress: request.ip,
        });
      }

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
        summary: 'Revoke Key Alias',
        tags: ['Key Lifecycle Management'],
        body: {
          type: 'object',
          required: ['keyAlias'],
          properties: {
            keyAlias: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              alias: { type: 'string' },
              state: { type: 'string' },
              updatedAt: { type: 'string' },
            },
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

        if (webhooks) {
          webhooks.dispatch({
            event: 'RevokeKey',
            timestamp: new Date().toISOString(),
            serviceId: identity.serviceId,
            keyAlias,
            status: 'DENIED',
            ipAddress: request.ip,
          });
        }

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

      if (webhooks) {
        webhooks.dispatch({
          event: 'RevokeKey',
          timestamp: new Date().toISOString(),
          serviceId: identity.serviceId,
          keyAlias,
          status: 'SUCCESS',
          ipAddress: request.ip,
        });
      }

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
        summary: 'Encrypt Payload',
        tags: ['Cryptographic Operations'],
        body: {
          type: 'object',
          required: ['keyAlias', 'plaintext'],
          properties: {
            keyAlias: { type: 'string' },
            plaintext: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              ciphertextHex: { type: 'string' },
              ivHex: { type: 'string' },
              authTagHex: { type: 'string' },
              keyVersion: { type: 'number' },
            },
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
        summary: 'Decrypt Payload',
        tags: ['Cryptographic Operations'],
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
        response: {
          200: {
            type: 'object',
            properties: {
              plaintext: { type: 'string' },
            },
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
}
