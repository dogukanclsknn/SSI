FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json .npmrc ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:22-alpine AS production-dependencies

WORKDIR /app

COPY package*.json .npmrc ./
RUN npm ci --omit=dev

FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=5021

COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder --chown=node:node /app/src/data ./src/data
COPY --from=builder --chown=node:node /app/src/lib ./src/lib
COPY --from=builder --chown=node:node /app/src/server ./src/server
COPY --from=production-dependencies --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node db ./db
COPY --chown=node:node scripts ./scripts
COPY --chown=node:node package*.json ./
COPY --chown=node:node server.js ./server.js

USER node

EXPOSE 5021

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:5021/api/v1/health').then((response) => { if (!response.ok) process.exit(1); }).catch(() => process.exit(1))"

CMD ["node", "server.js"]
