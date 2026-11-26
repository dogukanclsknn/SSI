import { readFile } from 'node:fs/promises';
import pg from 'pg';

const { Pool } = pg;
const sslModes = new Set(['disable', 'require', 'verify-full']);

function positiveInteger(value, fallback, name) {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

async function sslConfiguration() {
  const mode = String(process.env.DATABASE_SSL_MODE || 'verify-full').trim().toLowerCase();
  if (!sslModes.has(mode)) {
    throw new Error('DATABASE_SSL_MODE must be disable, require, or verify-full');
  }

  if (mode === 'disable') return false;
  if (mode === 'require') return { rejectUnauthorized: false };

  const caPath = String(process.env.DATABASE_CA_CERT_PATH || '').trim();
  if (!caPath) {
    throw new Error('DATABASE_CA_CERT_PATH is required when DATABASE_SSL_MODE=verify-full');
  }

  return {
    ca: await readFile(caPath, 'utf8'),
    rejectUnauthorized: true,
  };
}

export async function createPostgresPool({ databaseUrl = process.env.DATABASE_URL } = {}) {
  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required when PostgreSQL persistence is enabled');
  }

  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: await sslConfiguration(),
    max: positiveInteger(process.env.DATABASE_POOL_MAX, 10, 'DATABASE_POOL_MAX'),
    connectionTimeoutMillis: positiveInteger(
      process.env.DATABASE_CONNECT_TIMEOUT_MS,
      5000,
      'DATABASE_CONNECT_TIMEOUT_MS',
    ),
    idleTimeoutMillis: positiveInteger(process.env.DATABASE_IDLE_TIMEOUT_MS, 30000, 'DATABASE_IDLE_TIMEOUT_MS'),
    application_name: process.env.DATABASE_APPLICATION_NAME || 'ssi-api',
  });

  pool.on('error', (error) => {
    console.error('Unexpected PostgreSQL pool error:', error.message);
  });

  return pool;
}

