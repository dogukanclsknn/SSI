import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPostgresPool } from '../src/server/database.js';

const migrationsDirectory = fileURLToPath(new URL('../db/migrations/', import.meta.url));
const migrationLockId = 7212026;

async function migrate() {
  const pool = await createPostgresPool({
    databaseUrl: process.env.DATABASE_MIGRATION_URL || process.env.DATABASE_URL,
  });
  const client = await pool.connect();

  try {
    await client.query('SELECT pg_advisory_lock($1)', [migrationLockId]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const files = (await readdir(migrationsDirectory)).filter((name) => name.endsWith('.sql')).sort();
    for (const file of files) {
      const sql = await readFile(join(migrationsDirectory, file), 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const existing = await client.query('SELECT checksum FROM schema_migrations WHERE version = $1', [file]);

      if (existing.rowCount > 0) {
        if (existing.rows[0].checksum !== checksum) {
          throw new Error(`Applied migration ${file} has a different checksum`);
        }
        console.log(`Already applied: ${file}`);
        continue;
      }

      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)', [file, checksum]);
        await client.query('COMMIT');
        console.log(`Applied: ${file}`);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [migrationLockId]).catch(() => {});
    client.release();
    await pool.end();
  }
}

migrate().catch((error) => {
  console.error(`Database migration failed: ${error.message}`);
  process.exitCode = 1;
});

