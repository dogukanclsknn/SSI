// SSI — revoked session ids (server-side sign-out).
//
// Signed session cookies are stateless, so signing out records the token's `jti` here
// until the token would have expired anyway. Identity resolution checks `isRevoked`
// on every request, so lookups are synchronous.
//
// Two drivers, one interface (Liskov), following userStore.js:
//  - memory:   process-local (PoC / tests).
//  - postgres: write-through cache — non-expired ids are loaded at start-up and every
//              revocation is written to both the in-memory mirror and the database, so
//              a sign-out survives a restart. SSI runs single-instance, so the mirror is
//              always consistent.

const MAX_JTI_LENGTH = 128;

function validJti(jti) {
  return typeof jti === 'string' && jti.length >= 16 && jti.length <= MAX_JTI_LENGTH;
}

class MemorySessionRevocations {
  constructor({ now = Date.now } = {}) {
    this.driver = 'memory';
    this.now = now;
    this.revoked = new Map(); // jti → expiresAtMs
  }

  async initialize() {}

  prune() {
    const at = this.now();
    for (const [jti, expiresAtMs] of this.revoked) {
      if (expiresAtMs <= at) this.revoked.delete(jti);
    }
  }

  isRevoked(jti) {
    const expiresAtMs = this.revoked.get(jti);
    return expiresAtMs !== undefined && expiresAtMs > this.now();
  }

  async revoke({ jti, expiresAtSeconds }) {
    if (!validJti(jti)) return;
    this.prune();
    this.revoked.set(jti, expiresAtSeconds * 1000);
  }
}

class PostgresSessionRevocations extends MemorySessionRevocations {
  constructor(pool, options) {
    super(options);
    this.driver = 'postgres';
    this.pool = pool;
  }

  async initialize() {
    let result;
    try {
      await this.pool.query('DELETE FROM session_revocations WHERE expires_at <= now()');
      result = await this.pool.query('SELECT jti, expires_at FROM session_revocations');
    } catch (error) {
      throw new Error(`PostgreSQL persistence is not initialized. Run npm run db:migrate first. ${error.message}`, {
        cause: error,
      });
    }
    this.revoked.clear();
    for (const row of result.rows) this.revoked.set(row.jti, new Date(row.expires_at).getTime());
  }

  // The mirror is updated FIRST: if the database write fails, this process still
  // rejects the token (fail-safe for sign-out) and the error is surfaced to the caller.
  async revoke({ jti, subject = '', expiresAtSeconds }) {
    if (!validJti(jti)) return;
    this.prune();
    this.revoked.set(jti, expiresAtSeconds * 1000);
    const revokedAt = new Date(this.now()).toISOString();
    const expiresAt = new Date(expiresAtSeconds * 1000).toISOString();
    await this.pool.query(
      `INSERT INTO session_revocations (jti, subject, revoked_at, expires_at)
       VALUES ($1, $2, $3::timestamptz, $4::timestamptz)
       ON CONFLICT (jti) DO NOTHING`,
      [jti, String(subject).slice(0, 200), revokedAt, expiresAt],
    );
    await this.pool.query('DELETE FROM session_revocations WHERE expires_at <= now()');
  }
}

export function createSessionRevocations({ driver = 'memory', pool = null, now } = {}) {
  if (driver === 'postgres') {
    if (!pool) throw new Error('A PostgreSQL pool is required for session revocations.');
    return new PostgresSessionRevocations(pool, { now });
  }
  return new MemorySessionRevocations({ now });
}
