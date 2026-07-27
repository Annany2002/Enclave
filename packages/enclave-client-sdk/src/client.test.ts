import assert from 'node:assert';
import { test, describe, before, after } from 'node:test';
import crypto from 'node:crypto';

process.env.ENCLAVE_MASTER_KEY = crypto.randomBytes(32).toString('hex');
process.env.NODE_ENV = 'test';

import { createEnclaveServer } from '../../enclave-server/dist/server.js';
import { EnclaveClient } from './client.js';

describe('Enclave End-to-End Integration Tests', () => {
  let fastifyInstance: any;
  let serverUrl: string;
  const serviceToken = 'test-microservice-token-123';
  const serviceId = 'payment-service';

  before(async () => {
    const { fastify, iamManager } = await createEnclaveServer();
    iamManager.registerService({
      serviceId,
      token: serviceToken,
      allowedKeyAliases: ['payment-card-key'],
      allowedOperations: ['*'],
    });

    fastifyInstance = fastify;
    const address = await fastify.listen({ port: 0, host: '127.0.0.1' });
    serverUrl = address;
  });

  after(async () => {
    if (fastifyInstance) {
      await fastifyInstance.close();
    }
  });

  test('SDK generates key and performs remote encryption/decryption', async () => {
    const client = new EnclaveClient({
      baseUrl: serverUrl,
      authToken: serviceToken,
      enableLocalCaching: false,
    });

    const keyAlias = 'payment-card-key';
    const keyInfo = await client.generateKey(keyAlias);
    assert.strictEqual(keyInfo.alias, keyAlias);

    const plaintext = '4111-2222-3333-4444';
    const encrypted = await client.encryptRemote(keyAlias, plaintext);
    assert.strictEqual(typeof encrypted.ciphertextHex, 'string');

    const decrypted = await client.decryptRemote(
      keyAlias,
      encrypted.ciphertextHex,
      encrypted.ivHex,
      encrypted.authTagHex
    );

    assert.strictEqual(decrypted, plaintext);
  });

  test('SDK performs high-speed local envelope encryption with DEK caching', async () => {
    const client = new EnclaveClient({
      baseUrl: serverUrl,
      authToken: serviceToken,
      enableLocalCaching: true,
    });

    const keyAlias = 'payment-card-key';
    const secretMessage = 'Top Secret Vault Payload';

    const encrypted = await client.encrypt(keyAlias, secretMessage);
    const decrypted = await client.decrypt(
      keyAlias,
      encrypted.ciphertextHex,
      encrypted.ivHex,
      encrypted.authTagHex
    );

    assert.strictEqual(decrypted, secretMessage);
  });

  test('SDK rejects unauthorized operations with 403 Forbidden', async () => {
    const unauthorizedClient = new EnclaveClient({
      baseUrl: serverUrl,
      authToken: 'invalid-unregistered-token',
      enableLocalCaching: false,
    });

    await assert.rejects(async () => {
      await unauthorizedClient.generateKey('unauthorized-alias');
    }, /403/);
  });
});
