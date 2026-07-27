import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { MasterKeyManager } from '../crypto/master-key.js';
import { CryptoEngine } from '../crypto/crypto-engine.js';
import { IStorageAdapter } from '../storage/storage-adapter.js';
import { IAMManager, EnclaveOperation } from '../auth/iam.js';

export function registerEnclaveRoutes(
  fastify: FastifyInstance,
  keyManager: MasterKeyManager,
  storage: IStorageAdapter,
  iam: IAMManager
): void {
  // Authentication middleware
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    if (request.url === '/healthz' || request.url === '/readyz') {
      return;
    }

    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      reply.code(401).send({ error: 'Unauthorized', message: 'Missing or invalid Authorization header' });
      return;
    }

    const token = authHeader.substring(7);
    const identity = iam.authenticate(token);

    if (!identity) {
      reply.code(403).send({ error: 'Forbidden', message: 'Invalid authentication credentials' });
      return;
    }

    (request as any).identity = identity;
  });

  // Health probe
  fastify.get('/healthz', async () => {
    return { status: 'ok', unsealed: keyManager.isUnsealed() };
  });

  // Readiness probe
  fastify.get('/readyz', async (request, reply) => {
    if (!keyManager.isUnsealed()) {
      reply.code(503).send({ status: 'unhealthy', reason: 'Master key not unsealed' });
      return;
    }
    return { status: 'ready' };
  });

  // Generate a new DEK
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

      // Scrub raw DEK from server memory immediately
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

  // Encrypt payload via Enclave server
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
      const identity = (request as any).identity;
      const { keyAlias, plaintext } = request.body;

      if (!iam.authorize(identity, keyAlias, 'Encrypt')) {
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized for operation Encrypt on key ${keyAlias}` });
        return;
      }

      const keyRecord = await storage.getKeyByAlias(keyAlias);
      if (!keyRecord || keyRecord.state !== 'ENABLED') {
        reply.code(404).send({ error: 'Not Found', message: `Active key not found for alias ${keyAlias}` });
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

      // Scrub raw DEK
      CryptoEngine.zeroBuffer(rawDek);

      return {
        ciphertextHex: encryptedPayload.ciphertext.toString('hex'),
        ivHex: encryptedPayload.iv.toString('hex'),
        authTagHex: encryptedPayload.authTag.toString('hex'),
        keyVersion: keyRecord.version,
      };
    }
  );

  // Decrypt payload via Enclave server
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
      const identity = (request as any).identity;
      const { keyAlias, ciphertextHex, ivHex, authTagHex } = request.body;

      if (!iam.authorize(identity, keyAlias, 'Decrypt')) {
        reply.code(403).send({ error: 'Forbidden', message: `Unauthorized for operation Decrypt on key ${keyAlias}` });
        return;
      }

      const keyRecord = await storage.getKeyByAlias(keyAlias);
      if (!keyRecord || keyRecord.state !== 'ENABLED') {
        reply.code(404).send({ error: 'Not Found', message: `Active key not found for alias ${keyAlias}` });
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

      // Scrub raw DEK
      CryptoEngine.zeroBuffer(rawDek);

      return {
        plaintext: decryptedBuf.toString('utf-8'),
      };
    }
  );

  // Fetch raw DEK (for client SDK local envelope caching)
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
        reply.code(404).send({ error: 'Not Found', message: `Active key not found for alias ${keyAlias}` });
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
