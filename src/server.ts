import Fastify from 'fastify';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import { MasterKeyManager } from './crypto/master-key.js';
import { InMemoryStorageAdapter, IStorageAdapter } from './storage/storage-adapter.js';
import { PrismaStorageAdapter } from './storage/prisma-adapter.js';
import { IAMManager } from './auth/iam.js';
import { WebhookDispatcher } from './webhooks/webhook-dispatcher.js';
import { registerEnclaveRoutes } from './api/routes.js';

/**
 * Bootstraps the Enclave Fastify server instance with MasterKeyManager, StorageAdapter, IAMManager, and WebhookDispatcher.
 */
export async function createEnclaveServer() {
  const isProduction = process.env.NODE_ENV === 'production';
  const isTest = process.env.NODE_ENV === 'test';

  const fastify = Fastify({
    genReqId: (req) => {
      const headerId = req.headers['x-request-id'];
      if (typeof headerId === 'string' && headerId.trim().length > 0) {
        return headerId.trim();
      }
      return crypto.randomUUID();
    },
    logger: isTest
      ? false
      : isProduction
      ? { level: process.env.LOG_LEVEL || 'info' }
      : {
          level: process.env.LOG_LEVEL || 'info',
          transport: {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'HH:MM:ss',
              ignore: 'pid,hostname',
              singleLine: true,
            },
          },
        },
  });

  await fastify.register(fastifySwagger, {
    openapi: {
      info: {
        title: 'Enclave KMS & Security Enclave API',
        description: 'Zero-Trust Key Management System & Cryptographic Engine Specification',
        version: '1.0.0',
      },
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'API Key',
            description: 'Microservice Bearer Authorization Token',
          },
        },
      },
      security: [{ bearerAuth: [] }],
    },
  });

  await fastify.register(fastifySwaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: false,
    },
  });

  const masterKeyManager = new MasterKeyManager();

  let storageAdapter: IStorageAdapter;
  if (process.env.DATABASE_URL && !isTest) {
    storageAdapter = new PrismaStorageAdapter();
  } else {
    storageAdapter = new InMemoryStorageAdapter();
  }

  const iamManager = new IAMManager();
  const webhookDispatcher = new WebhookDispatcher();

  registerEnclaveRoutes(fastify, masterKeyManager, storageAdapter, iamManager, webhookDispatcher);

  return { fastify, masterKeyManager, storageAdapter, iamManager, webhookDispatcher };
}

const currentFile = fileURLToPath(import.meta.url);
const mainFile = process.argv[1];
const isMain = mainFile && (mainFile === currentFile || mainFile.endsWith('/server.js') || mainFile.endsWith('\\server.js'));

if (isMain && process.env.NODE_ENV !== 'test') {
  const port = Number(process.env.PORT) || 8200;
  const host = process.env.HOST || '0.0.0.0';

  createEnclaveServer()
    .then(({ fastify }) => {
      fastify.listen({ port, host }, (err) => {
        if (err) {
          fastify.log.error(err);
          process.exit(1);
        }
        const displayHost = host === '0.0.0.0' ? '127.0.0.1' : host;
        fastify.log.info(`Interactive OpenAPI Swagger UI available at http://${displayHost}:${port}/docs`);
      });
    })
    .catch((err) => {
      console.error('Fatal initialization failure:', err);
      process.exit(1);
    });
}
