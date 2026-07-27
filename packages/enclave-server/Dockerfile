# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

RUN npm install -g pnpm

COPY package.json pnpm-workspace.yaml tsconfig.json ./
COPY packages/enclave-server ./packages/enclave-server

RUN pnpm install --frozen-lockfile || pnpm install
RUN pnpm --filter @enclave/server run build

# Production stage
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

COPY --from=builder /app/packages/enclave-server/package.json ./package.json
COPY --from=builder /app/packages/enclave-server/dist ./dist
COPY --from=builder /app/packages/enclave-server/node_modules ./node_modules

USER node

EXPOSE 3000

CMD ["node", "dist/server.js"]
