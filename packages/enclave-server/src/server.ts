import Fastify from 'fastify';
import { fileURLToPath } from 'node:url';
import { MasterKeyManager } from './crypto/master-key.js';
import { InMemoryStorageAdapter } from './storage/storage-adapter.js';
import { IAMManager } from './auth/iam.js';
import { registerEnclaveRoutes } from './api/routes.js';

export async function createEnclaveServer() {
  const fastify = Fastify({
    logger: {
      level: process.env.LOG_LEVEL || 'info',
    },
  });

  const masterKeyManager = new MasterKeyManager();
  const storageAdapter = new InMemoryStorageAdapter();
  const iamManager = new IAMManager();

  registerEnclaveRoutes(fastify, masterKeyManager, storageAdapter, iamManager);

  return { fastify, masterKeyManager, storageAdapter, iamManager };
}

const currentFile = fileURLToPath(import.meta.url);
const mainFile = process.argv[1];
const isMain = mainFile && (mainFile === currentFile || mainFile.endsWith('/server.js') || mainFile.endsWith('\\server.js'));

if (isMain && process.env.NODE_ENV !== 'test') {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '0.0.0.0';

  createEnclaveServer()
    .then(({ fastify }) => {
      fastify.listen({ port, host }, (err, address) => {
        if (err) {
          fastify.log.error(err);
          process.exit(1);
        }
        fastify.log.info(`Enclave Server running at ${address}`);
      });
    })
    .catch((err) => {
      console.error('Fatal initialization failure:', err);
      process.exit(1);
    });
}
