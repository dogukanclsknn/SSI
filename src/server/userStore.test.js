import { describe, expect, it } from 'vitest';
import { assertNotSelfLockout, createUserStore, DEFAULT_ROLE, UserStoreError } from './userStore.js';

// ---------------------------------------------------------------------------
// Bellek sürücüsü (yazmalar async).
// ---------------------------------------------------------------------------
describe('userStore (memory)', () => {
  it('ilk LDAP girişinde varsayılan rolle (viewer) oluşturur', async () => {
    const store = createUserStore();
    const user = await store.upsertOnLogin({ username: 'Alex', displayName: 'Alex M', email: 'd@x' });
    expect(user).toMatchObject({ username: 'alex', role: DEFAULT_ROLE, status: 'active', loginType: 'ldap' });
    expect(user.lastLoginAt).toBeTruthy();
  });

  it('ikinci girişte rolü korur, son giriş zamanını günceller', async () => {
    const store = createUserStore();
    await store.upsertOnLogin({ username: 'alex' });
    await store.update('alex', { role: 'approver' });
    const again = await store.upsertOnLogin({ username: 'alex', displayName: 'Yeni Ad' });
    expect(again.role).toBe('approver'); // giriş rolü sıfırlamaz
    expect(again.displayName).toBe('Yeni Ad');
  });

  it('update rolü ve durumu değiştirir, geçersizleri reddeder', async () => {
    const store = createUserStore();
    await store.upsertOnLogin({ username: 'ali' });
    expect((await store.update('ali', { role: 'operator' })).role).toBe('operator');
    expect((await store.update('ali', { status: 'disabled' })).status).toBe('disabled');
    await expect(store.update('ali', { role: 'superuser' })).rejects.toThrow(UserStoreError);
    await expect(store.update('ali', { status: 'frozen' })).rejects.toThrow(UserStoreError);
  });

  it('create önceden rol atar; çift kayıt 409', async () => {
    const store = createUserStore();
    const u = await store.create({ username: 'sam', role: 'approver', email: 'i@x' });
    expect(u).toMatchObject({ username: 'sam', role: 'approver', lastLoginAt: null });
    await expect(store.create({ username: 'sam' })).rejects.toThrow(/already exists/);
  });

  it('remove siler; olmayan kullanıcı 404', async () => {
    const store = createUserStore();
    await store.upsertOnLogin({ username: 'gecici' });
    await store.remove('gecici');
    expect(store.get('gecici')).toBeNull();
    await expect(store.remove('gecici')).rejects.toThrow(UserStoreError);
  });

  it('list kullanıcıları ada göre sıralı döner', async () => {
    const store = createUserStore();
    await store.upsertOnLogin({ username: 'zeynep' });
    await store.upsertOnLogin({ username: 'ahmet' });
    expect(store.list().map((u) => u.username)).toEqual(['ahmet', 'zeynep']);
  });
});

// ---------------------------------------------------------------------------
// Postgres sürücüsü (write-through cache). Sahte havuz sorguları kaydeder.
// ---------------------------------------------------------------------------
function fakePool({ initialRows = [], failInsertWith = null } = {}) {
  const calls = [];
  return {
    calls,
    async query(text, params) {
      calls.push({ text: text.replace(/\s+/g, ' ').trim(), params });
      if (/^SELECT/i.test(text.trim()) && /FROM users/i.test(text)) {
        return { rows: initialRows, rowCount: initialRows.length };
      }
      if (/^INSERT/i.test(text.trim()) && failInsertWith) {
        const error = new Error('insert failed');
        error.code = failInsertWith;
        throw error;
      }
      return { rows: [], rowCount: 1 };
    },
  };
}

const wrote = (pool, verb) => pool.calls.some((c) => c.text.toUpperCase().startsWith(verb));

describe('userStore (postgres, write-through)', () => {
  it('initialize aynayı veritabanından yükler', async () => {
    const pool = fakePool({
      initialRows: [
        {
          username: 'ali',
          display_name: 'Jordan R',
          email: 'a@x',
          role: 'operator',
          status: 'active',
          login_type: 'ldap',
          last_login_at: '2026-09-01T00:00:00.000Z',
          created_at: '2026-08-01T00:00:00.000Z',
          updated_at: '2026-09-01T00:00:00.000Z',
        },
      ],
    });
    const store = createUserStore({ driver: 'postgres', pool });
    await store.initialize();
    expect(store.get('ali')).toMatchObject({ username: 'ali', role: 'operator', loginType: 'ldap' });
    expect(store.list().map((u) => u.username)).toEqual(['ali']);
  });

  it('upsertOnLogin: yeni kullanıcıyı DB\'ye yazar (INSERT), sonra günceller (UPDATE)', async () => {
    const pool = fakePool();
    const store = createUserStore({ driver: 'postgres', pool });
    await store.initialize();

    const created = await store.upsertOnLogin({ username: 'Alex', displayName: 'Alex' });
    expect(created).toMatchObject({ username: 'alex', role: DEFAULT_ROLE, status: 'active' });
    expect(wrote(pool, 'INSERT')).toBe(true);
    expect(store.get('alex').role).toBe(DEFAULT_ROLE);

    const again = await store.upsertOnLogin({ username: 'alex', displayName: 'Yeni Ad' });
    expect(again.displayName).toBe('Yeni Ad');
    expect(wrote(pool, 'UPDATE')).toBe(true);
  });

  it('create + update + remove aynayı ve DB\'yi tutarlı tutar', async () => {
    const pool = fakePool();
    const store = createUserStore({ driver: 'postgres', pool });
    await store.initialize();

    await store.create({ username: 'sam', role: 'approver' });
    expect(store.get('sam').role).toBe('approver');
    await expect(store.create({ username: 'sam' })).rejects.toThrow(/already exists/);

    const updated = await store.update('sam', { role: 'admin', status: 'disabled' });
    expect(updated).toMatchObject({ role: 'admin', status: 'disabled' });

    await store.remove('sam');
    expect(store.get('sam')).toBeNull();
    expect(wrote(pool, 'DELETE')).toBe(true);
    await expect(store.remove('sam')).rejects.toThrow(UserStoreError);
  });

  it('update: olmayan kullanıcı 404, geçersiz rol reddedilir', async () => {
    const pool = fakePool();
    const store = createUserStore({ driver: 'postgres', pool });
    await store.initialize();
    await expect(store.update('yok', { role: 'viewer' })).rejects.toThrow(UserStoreError);
    await store.create({ username: 'x' });
    await expect(store.update('x', { role: 'superuser' })).rejects.toThrow(UserStoreError);
  });

  it('create: DB unique ihlali (23505) 409\'a çevrilir', async () => {
    const pool = fakePool({ failInsertWith: '23505' });
    const store = createUserStore({ driver: 'postgres', pool });
    await store.initialize();
    await expect(store.create({ username: 'race' })).rejects.toThrow(/already exists/);
  });

  it('postgres sürücüsü havuzsuz çağrılırsa hata verir', () => {
    expect(() => createUserStore({ driver: 'postgres' })).toThrow(/pool/);
  });
});

describe('assertNotSelfLockout', () => {
  const self = { actorId: 'Alex.Morgan', targetUsername: 'alex.morgan' };

  it('yönetici kendini silemez, pasife alamaz, rolünü düşüremez (403)', () => {
    for (const call of [
      { ...self, method: 'DELETE' },
      { ...self, method: 'PATCH', changes: { status: 'disabled' } },
      { ...self, method: 'PATCH', changes: { role: 'viewer' } },
    ]) {
      expect(() => assertNotSelfLockout(call)).toThrow(UserStoreError);
      try {
        assertNotSelfLockout(call);
      } catch (error) {
        expect(error.statusCode).toBe(403);
      }
    }
  });

  it('kendi hesabında zararsız değişikliklere izin verir', () => {
    expect(() => assertNotSelfLockout({ ...self, method: 'PATCH', changes: { role: 'admin', status: 'active' } })).not.toThrow();
    expect(() => assertNotSelfLockout({ ...self, method: 'PATCH', changes: {} })).not.toThrow();
  });

  it('başka kullanıcılar ve kimliksiz istekler etkilenmez', () => {
    expect(() =>
      assertNotSelfLockout({ actorId: 'alex.morgan', targetUsername: 'casey.kim', method: 'DELETE' }),
    ).not.toThrow();
    expect(() => assertNotSelfLockout({ actorId: '', targetUsername: 'casey.kim', method: 'DELETE' })).not.toThrow();
  });
});

describe('userStore field validation', () => {
  it('rejects usernames with spaces, slashes or unsupported characters', async () => {
    const store = createUserStore();
    for (const username of ['ali veli', 'ali/veli', '<script>', '.leading-dot', 'a'.repeat(129)]) {
      await expect(store.create({ username })).rejects.toMatchObject({ statusCode: 400 });
    }
  });

  it('accepts directory-style usernames and normalises them to lower case', async () => {
    const store = createUserStore();
    const user = await store.create({ username: 'Alex.Morgan@Example.com', role: 'operator' });
    expect(user.username).toBe('alex.morgan@example.com');
  });

  it('validates display name and email on create and update', async () => {
    const store = createUserStore();
    await expect(store.create({ username: 'a1', email: 'not-an-email' })).rejects.toThrow(/valid email/);
    await expect(store.create({ username: 'a2', displayName: 'x'.repeat(129) })).rejects.toThrow(/up to 128/);
    await expect(store.create({ username: 'a3', displayName: 'bad\u0007name' })).rejects.toThrow(/control/);
    await store.create({ username: 'a4', email: 'a4@example.com' });
    await expect(store.update('a4', { email: 'nope' })).rejects.toMatchObject({ statusCode: 400 });
    await expect(store.update('a4', { email: '' })).resolves.toMatchObject({ email: '' });
  });

  it('keeps directory sign-in tolerant but bounded and free of control characters', async () => {
    const store = createUserStore();
    const user = await store.upsertOnLogin({ username: 'ldap.user', displayName: 'Name\u0000 ' + 'y'.repeat(200) });
    expect(user.displayName).not.toMatch(/\p{Cc}/u);
    expect(user.displayName.length).toBeLessThanOrEqual(128);
  });
});
