import assert from 'node:assert';
import { test, describe, before, after } from 'node:test';
import crypto from 'node:crypto';

const masterKeyHex = crypto.randomBytes(32).toString('hex');
process.env.ENCLAVE_MASTER_KEY = masterKeyHex;
process.env.NODE_ENV = 'test';

import { createEnclaveServer } from './server.js';
import { ShamirUnsealEngine } from './crypto/shamir-unseal.js';
import { WebhookDispatcher } from './webhooks/webhook-dispatcher.js';

describe('Enclave Server Integration Tests', () => {
  let fastifyInstance: any;
  let serverUrl: string;
  const serviceToken = 'test-microservice-token-123';
  const serviceId = 'payment-service';

  before(async () => {
    const { fastify, iamManager } = await createEnclaveServer();
    iamManager.registerService({
      serviceId,
      token: serviceToken,
      clientCertCn: 'payment-service.internal',
      allowedKeyAliases: ['payment-card-key', 'revocable-key'],
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

  test('Swagger UI documentation endpoint is accessible at /docs', async () => {
    const res = await fetch(`${serverUrl}/docs/static/index.html`);
    assert.strictEqual(res.status, 200);
  });

  test('WebhookDispatcher signs payload with HMAC-SHA256 signature', () => {
    const dispatcher = new WebhookDispatcher();
    const secret = 'webhook-hmac-secret-key';
    const jsonPayload = JSON.stringify({ event: 'KeyRevoked', keyAlias: 'test-key' });
    
    const signature = dispatcher.computeSignature(jsonPayload, secret);
    assert.strictEqual(signature.startsWith('sha256='), true);
    assert.strictEqual(signature.length, 7 + 64);
  });

  test('Shamir Secret Sharing splits and reconstructs Master Key correctly', () => {
    const shares = ShamirUnsealEngine.splitMasterKey(masterKeyHex, 3);
    assert.strictEqual(shares.length, 3);

    const reconstructed = ShamirUnsealEngine.combineShares(shares);
    assert.strictEqual(reconstructed, masterKeyHex);
  });

  test('Generates key and performs remote encryption/decryption', async () => {
    const keyAlias = 'payment-card-key';
    const genRes = await fetch(`${serverUrl}/api/v1/keys/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({ alias: keyAlias }),
    });

    assert.strictEqual(genRes.status, 200);
    const keyInfo: any = await genRes.json();
    assert.strictEqual(keyInfo.alias, keyAlias);

    const plaintext = '4111-2222-3333-4444';
    const encRes = await fetch(`${serverUrl}/api/v1/crypto/encrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({ keyAlias, plaintext }),
    });

    assert.strictEqual(encRes.status, 200);
    const encrypted: any = await encRes.json();
    assert.strictEqual(typeof encrypted.ciphertextHex, 'string');

    const decRes = await fetch(`${serverUrl}/api/v1/crypto/decrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({
        keyAlias,
        ciphertextHex: encrypted.ciphertextHex,
        ivHex: encrypted.ivHex,
        authTagHex: encrypted.authTagHex,
      }),
    });

    assert.strictEqual(decRes.status, 200);
    const decrypted: any = await decRes.json();
    assert.strictEqual(decrypted.plaintext, plaintext);
  });

  test('Rejects unauthorized operations with 403 Forbidden', async () => {
    const res = await fetch(`${serverUrl}/api/v1/keys/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid-token',
      },
      body: JSON.stringify({ alias: 'unauthorized-alias' }),
    });

    assert.strictEqual(res.status, 403);
  });

  test('Supports key rotation and exposes prometheus metrics', async () => {
    const resMetrics = await fetch(`${serverUrl}/metrics`);
    assert.strictEqual(resMetrics.status, 200);
    const metricsText = await resMetrics.text();
    assert.strictEqual(metricsText.includes('enclave_requests_total'), true);

    const resRotate = await fetch(`${serverUrl}/api/v1/keys/rotate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({ keyAlias: 'payment-card-key' }),
    });

    assert.strictEqual(resRotate.status, 200);
    const rotateData: any = await resRotate.json();
    assert.strictEqual(rotateData.version, 2);
  });

  test('Revokes key and blocks subsequent cryptographic access', async () => {
    await fetch(`${serverUrl}/api/v1/keys/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({ alias: 'revocable-key' }),
    });

    const resRevoke = await fetch(`${serverUrl}/api/v1/keys/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({ keyAlias: 'revocable-key' }),
    });

    assert.strictEqual(resRevoke.status, 200);

    const resEnc = await fetch(`${serverUrl}/api/v1/crypto/encrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({ keyAlias: 'revocable-key', plaintext: 'fail payload' }),
    });

    assert.strictEqual(resEnc.status, 410);
  });

  test('Exports structured audit log history', async () => {
    const resAudit = await fetch(`${serverUrl}/api/v1/audit/export`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${serviceToken}`,
      },
    });

    assert.strictEqual(resAudit.status, 200);
    const auditData: any = await resAudit.json();
    assert.strictEqual(Array.isArray(auditData.logs), true);
    assert.strictEqual(auditData.logs.length > 0, true);
  });
});
