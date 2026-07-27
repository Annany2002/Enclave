# @enclave/server Microservice

Centralized Enclave Service built with Fastify, TypeScript, and Node.js native `crypto`.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENCLAVE_MASTER_KEY` | Yes | - | 64-char hex string (256-bit Key Encryption Key) |
| `DATABASE_URL` | Yes (for SQL) | - | PostgreSQL connection string |
| `ENCLAVE_RBAC_POLICIES` | No | `[]` | JSON array defining service permissions |
| `PORT` | No | `3000` | HTTP listen port |
| `HOST` | No | `0.0.0.0` | Bind host address |

---

## API Reference

### `POST /api/v1/keys/generate`
Generates a new AES-256 Data Encryption Key (DEK) for a service.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "alias": "user-pii-key" }`
- **Response**: `{ "id": "uuid", "alias": "user-pii-key", "version": 1, "createdAt": "ISO-date" }`

### `POST /api/v1/crypto/encrypt`
Encrypts plaintext payload on the server.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-pii-key", "plaintext": "secret payload" }`
- **Response**: `{ "ciphertextHex": "...", "ivHex": "...", "authTagHex": "...", "keyVersion": 1 }`

### `POST /api/v1/crypto/decrypt`
Decrypts ciphertext payload on the server.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-pii-key", "ciphertextHex": "...", "ivHex": "...", "authTagHex": "..." }`
- **Response**: `{ "plaintext": "secret payload" }`

### `POST /api/v1/keys/fetch`
Retrieves raw DEK for authenticated services.
- **Header**: `Authorization: Bearer <service_token>`
- **Body**: `{ "keyAlias": "user-pii-key" }`
- **Response**: `{ "keyAlias": "user-pii-key", "dekHex": "...", "version": 1 }`
