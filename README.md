# Enclave Server

High-performance, production-grade Key Management System (KMS) & Secret Enclave microservice built with Fastify, TypeScript, PostgreSQL, and Node.js native `crypto`.

Detailed architectural specification: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Architecture & Security Highlights

- **Envelope Encryption**: Data Encryption Keys (DEKs) generated with `crypto.randomBytes(32)` and encrypted using 256-bit Master KEK via `aes-256-gcm`.
- **Memory Scrubbing**: Plaintext DEK buffers explicitly zeroed out (`buffer.fill(0)`) post-operation to prevent heap inspection.
- **Timing-Safe Auth**: Token and certificate comparisons use `crypto.timingSafeEqual`.
- **Zero-Trust IAM & RBAC**: Dual Bearer token and mTLS X.509 client certificate SAN authentication with fine-grained operation permissions.
- **Shamir Secret Sharing**: Multi-operator threshold key splitting and unsealing.
- **Key Revocation & Audit**: Dynamic key revocation with real-time audit logging and JSON trail export.

---

## Quickstart

### Prerequisites
- Node.js >= 20.x
- Docker & Docker Compose (for production container deployment)

### 1. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 2. Build
```bash
npm run build
```

### 3. Run Test Suite
```bash
npm run test
```

### 4. Run via Docker Compose
```bash
docker-compose up --build -d
```

Check health status:
```bash
curl http://localhost:3000/healthz
```

---

## API Reference Summary

### `POST /api/v1/keys/generate`
Generates a new AES-256 Data Encryption Key (DEK).
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "alias": "user-card-key" }`
- **Response**: `{ "id": "uuid", "alias": "user-card-key", "version": 1 }`

### `POST /api/v1/crypto/encrypt`
Encrypts plaintext payload on the server using a DEK.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-card-key", "plaintext": "secret payload" }`
- **Response**: `{ "ciphertextHex": "...", "ivHex": "...", "authTagHex": "...", "keyVersion": 1 }`

### `POST /api/v1/crypto/decrypt`
Decrypts ciphertext payload on the server.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-card-key", "ciphertextHex": "...", "ivHex": "...", "authTagHex": "..." }`
- **Response**: `{ "plaintext": "secret payload" }`

### `POST /api/v1/keys/rotate`
Rotates key version and re-encrypts DEK.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-card-key" }`
- **Response**: `{ "id": "...", "alias": "user-card-key", "version": 2 }`

### `POST /api/v1/keys/revoke`
Revokes a key alias (blocks cryptographic access).
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-card-key" }`
- **Response**: `{ "id": "...", "state": "REVOKED" }`

### `GET /api/v1/audit/export`
Exports audit log trail.
- **Header**: `Authorization: Bearer <service_token>`
- **Response**: `{ "logs": [...] }`
