# Enclave Server

High-performance, production-grade Key Management System (KMS) & Secret Enclave microservice built with Fastify, TypeScript, PostgreSQL, and Node.js native `crypto`.

Detailed architectural specification: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Architecture & Security Highlights

- **Envelope Encryption**: Data Encryption Keys (DEKs) generated with `crypto.randomBytes(32)` and encrypted using a 256-bit Master KEK via `aes-256-gcm`.
- **Memory Scrubbing**: Plaintext DEK buffers explicitly zeroed out (`buffer.fill(0)`) post-operation to prevent heap inspection.
- **Timing-Safe Auth**: Token and certificate comparisons use `crypto.timingSafeEqual`.
- **Zero-Trust IAM & RBAC**: Dual Bearer token and mTLS X.509 client certificate SAN authentication with fine-grained operation permissions.
- **Shamir Secret Sharing**: Multi-operator threshold key splitting and unsealing.
- **Key Revocation & Audit**: Dynamic key revocation with real-time audit logging and JSON trail export.
- **PostgreSQL Persistence**: Prisma ORM persistence layer storing wrapped key metadata and structured audit logs.

---

## Quickstart

### Prerequisites
- Node.js >= 20.x
- PostgreSQL database (or Docker Compose)

### 1. Configure Environment
Copy `.env.example` to `.env` and set `ENCLAVE_MASTER_KEY` and `DATABASE_URL`:
```bash
cp .env.example .env
```

### 2. Sync Database Schema
Apply Prisma schema migrations to your live PostgreSQL database:
```bash
npx prisma db push
```

### 3. Development Workflow Commands

```bash
# Start hot-reloading dev server (Port 8200)
npm run dev

# Zero-build typechecking & unused imports check
npm run check

# Zero-build test suite execution
npm run test

# Production build (compile TypeScript to dist/)
npm run build
```

---

## API Reference & Quick Verification

Server listens on **Port 8200**.

### 1. Liveness & Health Probe
```bash
curl http://localhost:8200/healthz
# Response: { "status": "ok", "unsealed": true }
```

### 2. Generate Data Encryption Key (DEK)
```bash
curl -X POST http://localhost:8200/api/v1/keys/generate \
  -H "Authorization: Bearer billing-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"alias": "production-payment-key"}'
```

### 3. Encrypt Plaintext Payload
```bash
curl -X POST http://localhost:8200/api/v1/crypto/encrypt \
  -H "Authorization: Bearer billing-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"keyAlias": "production-payment-key", "plaintext": "my-secret-payload"}'
```

### 4. Decrypt Ciphertext Payload
```bash
curl -X POST http://localhost:8200/api/v1/crypto/decrypt \
  -H "Authorization: Bearer billing-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "keyAlias": "production-payment-key",
    "ciphertextHex": "<CIPHERTEXT>",
    "ivHex": "<IV>",
    "authTagHex": "<AUTH_TAG>"
  }'
```

### 5. Key Rotation
```bash
curl -X POST http://localhost:8200/api/v1/keys/rotate \
  -H "Authorization: Bearer billing-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"keyAlias": "production-payment-key"}'
```

### 6. Key Revocation
```bash
curl -X POST http://localhost:8200/api/v1/keys/revoke \
  -H "Authorization: Bearer billing-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"keyAlias": "production-payment-key"}'
```

### 7. Export Audit Log History
```bash
curl -H "Authorization: Bearer billing-secret-token" \
  http://localhost:8200/api/v1/audit/export
```
