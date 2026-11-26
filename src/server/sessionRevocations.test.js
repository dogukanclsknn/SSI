import { describe, expect, it } from 'vitest';
import { createSessionRevocations } from './sessionRevocations.js';

const JTI = 'AAAAAAAAAAAAAAAAAAAAAA';

function clock(start = 1_700_000_000_000) {
  let value = start;
  return { now: () => value, advance: (ms) => (value += ms) };
}

describe('session revocations (memory)', () => {
  it('reports a revoked jti until the token would have expired', async () => {
    const time = clock();
    const store = createSessionRevocations({ now: time.now });
    const expiresAtSeconds = Math.floor(time.now() / 1000) + 60;
    expect(store.isRevoked(JTI)).toBe(false);
    await store.revoke({ jti: JTI, subject: 'alex', expiresAtSeconds });
    expect(store.isRevoked(JTI)).toBe(true);
    time.advance(61_000);
    expect(store.isRevoked(JTI)).toBe(false);
  });

  it('ignores malformed ids', async () => {
    const store = createSessionRevocations();
    await store.revoke({ jti: 'short', expiresAtSeconds: 9_999_999_999 });
    await store.revoke({ jti: undefined, expiresAtSeconds: 9_999_999_999 });
    expect(store.isRevoked('short')).toBe(false);
  });
});

describe('session revocations (postgres driver)', () => {
  function fakePool(rows = []) {
    const calls = [];
    return {
      calls,
      async query(sql, params) {
        calls.push({ sql: sql.replace(/\s+/g, ' ').trim(), params });
        if (sql.startsWith('SELECT')) return { rows };
        return { rows: [] };
      },
    };
  }

  it('loads non-expired ids at start-up so sign-outs survive a restart', async () => {
    const future = new Date(Date.now() + 3_600_000).toISOString();
    const pool = fakePool([{ jti: JTI, expires_at: future }]);
    const store = createSessionRevocations({ driver: 'postgres', pool });
    await store.initialize();
    expect(store.isRevoked(JTI)).toBe(true);
    expect(pool.calls[0].sql).toMatch(/^DELETE FROM session_revocations WHERE expires_at <= now\(\)/);
  });

  it('writes the revocation to the database and the mirror', async () => {
    const pool = fakePool();
    const store = createSessionRevocations({ driver: 'postgres', pool });
    await store.revoke({ jti: JTI, subject: 'alex', expiresAtSeconds: Math.floor(Date.now() / 1000) + 60 });
    expect(pool.calls[0].sql).toMatch(/^INSERT INTO session_revocations/);
    expect(pool.calls[0].params.slice(0, 2)).toEqual([JTI, 'alex']);
    expect(store.isRevoked(JTI)).toBe(true);
  });

  it('keeps the id revoked in this process even when the database write fails', async () => {
    const pool = {
      async query() {
        throw new Error('connection lost');
      },
    };
    const store = createSessionRevocations({ driver: 'postgres', pool });
    await expect(
      store.revoke({ jti: JTI, expiresAtSeconds: Math.floor(Date.now() / 1000) + 60 }),
    ).rejects.toThrow('connection lost');
    expect(store.isRevoked(JTI)).toBe(true);
  });

  it('requires a pool', () => {
    expect(() => createSessionRevocations({ driver: 'postgres' })).toThrow(/pool is required/);
  });
});
