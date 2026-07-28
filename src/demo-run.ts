import crypto from 'node:crypto';
import { createEnclaveServer } from './server.js';

const MASTER_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const SERVICE_TOKEN = 'billing-secret-token';
const SERVICE_ID = 'billing-service';
const KEY_ALIAS = 'billing-card-key';

process.env.ENCLAVE_MASTER_KEY = MASTER_KEY;

async function runLiveServerDemo() {
  console.log('=== 1. Starting Enclave Server ===');
  const { fastify, iamManager } = await createEnclaveServer();

  iamManager.registerService({
    serviceId: SERVICE_ID,
    token: SERVICE_TOKEN,
    allowedKeyAliases: [KEY_ALIAS],
    allowedOperations: ['*'],
  });

  const address = await fastify.listen({ port: 3000, host: '127.0.0.1' });
  console.log(`Enclave Server running at: ${address}`);

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${SERVICE_TOKEN}`,
  };

  try {
    // 2. Health check
    console.log('\n=== 2. Testing GET /healthz ===');
    const healthRes = await fetch(`${address}/healthz`);
    console.log('Status:', healthRes.status, await healthRes.json());

    // 3. Generate Key
    console.log('\n=== 3. Testing POST /api/v1/keys/generate ===');
    const genRes = await fetch(`${address}/api/v1/keys/generate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ alias: KEY_ALIAS }),
    });
    console.log('Status:', genRes.status, await genRes.json());

    // 4. Encrypt Payload
    console.log('\n=== 4. Testing POST /api/v1/crypto/encrypt ===');
    const plaintextPayload = '4111-2222-3333-4444';
    const encRes = await fetch(`${address}/api/v1/crypto/encrypt`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ keyAlias: KEY_ALIAS, plaintext: plaintextPayload }),
    });
    const encData: any = await encRes.json();
    console.log('Status:', encRes.status, encData);

    // 5. Decrypt Payload
    console.log('\n=== 5. Testing POST /api/v1/crypto/decrypt ===');
    const decRes = await fetch(`${address}/api/v1/crypto/decrypt`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        keyAlias: KEY_ALIAS,
        ciphertextHex: encData.ciphertextHex,
        ivHex: encData.ivHex,
        authTagHex: encData.authTagHex,
      }),
    });
    console.log('Status:', decRes.status, await decRes.json());

    // 6. Rotate Key
    console.log('\n=== 6. Testing POST /api/v1/keys/rotate ===');
    const rotRes = await fetch(`${address}/api/v1/keys/rotate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ keyAlias: KEY_ALIAS }),
    });
    console.log('Status:', rotRes.status, await rotRes.json());

    // 7. Prometheus Metrics
    console.log('\n=== 7. Testing GET /metrics ===');
    const metricsRes = await fetch(`${address}/metrics`);
    const metricsText = await metricsRes.text();
    console.log(metricsText);

    // 8. Export Audit Logs
    console.log('=== 8. Testing GET /api/v1/audit/export ===');
    const auditRes = await fetch(`${address}/api/v1/audit/export`, {
      method: 'GET',
      headers,
    });
    console.log('Status:', auditRes.status, await auditRes.json());

  } finally {
    console.log('\n=== 9. Shutting down Enclave Server ===');
    await fastify.close();
    console.log('Server stopped.');
  }
}

runLiveServerDemo().catch(console.error);
