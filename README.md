# Enclave Server

High-performance, production-grade Key Management System (KMS) & Secret Enclave microservice built with Fastify, TypeScript, PostgreSQL, and Node.js native `crypto`.

## Architecture & Security

- **Envelope Encryption**: Data Encryption Keys (DEKs) are generated with `crypto.randomBytes(32)` and encrypted using a 256-bit Master Key (KEK) via `aes-256-gcm`.
- **Memory Scrubbing**: Plaintext DEK buffers are explicitly zeroed out (`buffer.fill(0)`) post-operation to mitigate heap inspection risks.
- **Timing-Safe Auth**: Token comparisons use `crypto.timingSafeEqual` to eliminate side-channel timing vectors.
- **Zero-Trust IAM & RBAC**: Microservices authenticate via Bearer tokens or mTLS headers, enforced by fine-grained key alias and operation permissions (`Encrypt`, `Decrypt`, `GenerateKey`, `RotateKey`, `GetKey`).
- **Audit Logging**: Every access attempt and cryptographic operation is logged with caller identity, timestamp, IP, and status.

---

## Quickstart

### Prerequisites
- Node.js >= 20.x
- Docker & Docker Compose (for containerized deployment)

### 1. Build
```bash
npm run build
```

### 2. Run Tests
```bash
npm run test
```

### 3. Run via Docker Compose
```bash
docker-compose up --build -d
```

Check health status:
```bash
curl http://localhost:3000/healthz
```

---

## API Endpoints

### `POST /api/v1/keys/generate`
Generates a new AES-256 Data Encryption Key (DEK).
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "alias": "user-pii-key" }`
- **Response**: `{ "id": "uuid", "alias": "user-pii-key", "version": 1, "createdAt": "ISO-date" }`

### `POST /api/v1/crypto/encrypt`
Encrypts plaintext payload on the server using a DEK.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-pii-key", "plaintext": "secret payload" }`
- **Response**: `{ "ciphertextHex": "...", "ivHex": "...", "authTagHex": "...", "keyVersion": 1 }`

### `POST /api/v1/crypto/decrypt`
Decrypts ciphertext payload on the server.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-pii-key", "ciphertextHex": "...", "ivHex": "...", "authTagHex": "..." }`
- **Response**: `{ "plaintext": "secret payload" }`
