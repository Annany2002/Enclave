# @enclave/client-sdk Library

Client SDK for microservices to interface with `@enclave/server` with automatic retries and local envelope encryption caching.

## Installation

```bash
npm install @enclave/client-sdk
```

## Quick Code Example

```typescript
import { EnclaveClient } from '@enclave/client-sdk';

const enclave = new EnclaveClient({
  baseUrl: 'http://localhost:3000',
  authToken: 'my-service-auth-token',
  enableLocalCaching: true, // Sub-millisecond local AES-256-GCM encryption
});

// 1. Generate Key Alias
await enclave.generateKey('user-card-key');

// 2. Encrypt Data
const encrypted = await enclave.encrypt('user-card-key', '4111-2222-3333-4444');
console.log(encrypted.ciphertextHex);

// 3. Decrypt Data
const plaintext = await enclave.decrypt(
  'user-card-key',
  encrypted.ciphertextHex,
  encrypted.ivHex,
  encrypted.authTagHex
);
console.log(plaintext); // "4111-2222-3333-4444"
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | `string` | **Required** | Enclave Server HTTP endpoint |
| `authToken` | `string` | **Required** | Service Bearer token |
| `enableLocalCaching` | `boolean` | `true` | Caches DEKs in memory for local crypto operations |
| `cacheTtlMs` | `number` | `300000` (5m) | LRU key cache TTL in milliseconds |
| `cacheCapacity` | `number` | `100` | Max DEKs stored in LRU memory cache |
| `maxRetries` | `number` | `3` | Network retry attempts for 5xx errors |
| `timeoutMs` | `number` | `5000` | HTTP request timeout in milliseconds |
