import { describe, expect, it } from 'vitest';
import { createTenantStore, MemoryTenantStore, PostgresTenantStore } from './tenantStore.js';

const clock = () => {
  let tick = 0;
  return () => new Date(Date.UTC(2026, 10, 10, 10, 0, tick++)).toISOString();
};

async function rejection(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected a rejection');
}

describe('tenant store — memory driver', () => {
  it('starts with the active default team', () => {
    const store = new MemoryTenantStore({ now: clock() });
    expect(store.listTenants()).toEqual([
      expect.objectContaining({ id: 'default', displayName: 'Default', status: 'active', harbor: {}, rowVersion: 1 }),
    ]);
  });

  it('creates a team once and returns copies the caller cannot change', async () => {
    const store = new MemoryTenantStore({ now: clock() });
    const created = await store.createTenant({ id: 'payments', displayName: 'Payments', harbor: { project: 'payments' } });
    created.harbor.project = 'tampered';
    expect(store.getTenant('PAYMENTS').harbor).toEqual({ project: 'payments' });
    expect(await rejection(store.createTenant({ id: 'payments', displayName: 'Again' }))).toMatchObject({ statusCode: 409 });
  });

  it('updates a team with optimistic concurrency and never disables the default team', async () => {
    const store = new MemoryTenantStore({ now: clock() });
    await store.createTenant({ id: 'payments', displayName: 'Payments' });
    const updated = await store.updateTenant('payments', { status: 'disabled' }, { expectedRowVersion: 1 });
    expect(updated).toMatchObject({ status: 'disabled', rowVersion: 2 });
    expect(await rejection(store.updateTenant('payments', { displayName: 'Old' }, { expectedRowVersion: 1 }))).toMatchObject({
      statusCode: 409,
    });
    expect(await rejection(store.updateTenant('default', { status: 'disabled' }))).toMatchObject({ statusCode: 409 });
    expect(await rejection(store.updateTenant('missing', { status: 'active' }))).toMatchObject({ statusCode: 404 });
  });

  it('adds, changes and removes memberships', async () => {
    const store = new MemoryTenantStore({ now: clock() });
    await store.createTenant({ id: 'payments', displayName: 'Payments' });
    const added = await store.setMembership({ tenantId: 'payments', username: 'Ayse.Yilmaz', role: 'operator', actorId: 'admin' });
    expect(added).toMatchObject({ created: true, membership: { username: 'ayse.yilmaz', role: 'operator', createdBy: 'admin' } });
    const changed = await store.setMembership({ tenantId: 'payments', username: 'ayse.yilmaz', role: 'approver', actorId: 'other' });
    expect(changed).toMatchObject({ created: false, membership: { role: 'approver', createdBy: 'admin' } });
    expect(store.membershipsForUser('AYSE.YILMAZ')).toEqual([expect.objectContaining({ tenantId: 'payments', role: 'approver' })]);
    expect(store.listMembers('payments')).toHaveLength(1);

    await store.removeMembership('payments', 'ayse.yilmaz');
    expect(store.membershipsForUser('ayse.yilmaz')).toEqual([]);
    expect(await rejection(store.removeMembership('payments', 'ayse.yilmaz'))).toMatchObject({ statusCode: 404 });
  });

  it('refuses invalid memberships', async () => {
    const store = new MemoryTenantStore({ now: clock() });
    expect(await rejection(store.setMembership({ tenantId: 'missing', username: 'ayse', role: 'viewer' }))).toMatchObject({
      statusCode: 404,
    });
    expect(await rejection(store.setMembership({ tenantId: 'default', username: 'ayse', role: 'admin' }))).toMatchObject({
      statusCode: 400,
    });
    expect(await rejection(store.setMembership({ tenantId: 'default', username: ' ', role: 'viewer' }))).toMatchObject({
      statusCode: 400,
    });
    expect(
      await rejection(store.setMembership({ tenantId: 'default', username: 'ayse', role: 'viewer', source: 'ldap' })),
    ).toMatchObject({ statusCode: 400 });
  });

  it('forgets every membership of a removed user', async () => {
    const store = new MemoryTenantStore({ now: clock() });
    await store.createTenant({ id: 'payments', displayName: 'Payments' });
    await store.setMembership({ tenantId: 'payments', username: 'ayse', role: 'viewer' });
    await store.setMembership({ tenantId: 'default', username: 'ayse', role: 'operator' });
    store.forgetUser('AYSE');
    expect(store.membershipsForUser('ayse')).toEqual([]);
  });

  it('chooses the driver from the persistence setting', () => {
    expect(createTenantStore({ driver: 'memory' })).toBeInstanceOf(MemoryTenantStore);
    expect(() => createTenantStore({ driver: 'postgres' })).toThrow(/requires a pool/);
    expect(() => createTenantStore({ driver: 'sqlite' })).toThrow(/memory or postgres/);
  });
});

describe('tenant store — postgres driver', () => {
  const tenantRow = (id, overrides = {}) => ({
    id,
    display_name: id,
    status: 'active',
    tenant_data: { harbor: {} },
    created_at: '2026-11-10T10:00:00.000Z',
    updated_at: '2026-11-10T10:00:00.000Z',
    row_version: 1,
    ...overrides,
  });
  const membershipRow = (tenant_id, username, role) => ({
    tenant_id,
    username,
    role,
    source: 'manual',
    created_by: 'migration-009',
    created_at: '2026-11-10T10:00:00.000Z',
    updated_at: '2026-11-10T10:00:00.000Z',
  });

  function fakePool(handlers) {
    const queries = [];
    return {
      queries,
      async query(sql, params) {
        const text = String(sql).replace(/\s+/g, ' ').trim();
        queries.push({ text, params });
        for (const [pattern, answer] of handlers) {
          if (pattern.test(text)) return typeof answer === 'function' ? answer(params) : answer;
        }
        throw new Error(`unexpected SQL: ${text}`);
      },
    };
  }

  const loaded = (extra = []) =>
    fakePool([
      [/^SELECT id, display_name/, { rows: [tenantRow('default'), tenantRow('payments')] }],
      [/^SELECT tenant_id, username/, { rows: [membershipRow('default', 'ayse', 'operator')] }],
      ...extra,
    ]);

  it('loads teams and memberships into the mirror at start-up', async () => {
    const store = new PostgresTenantStore(loaded(), { now: clock() });
    await store.initialize();
    expect(store.listTenants().map((item) => item.id)).toEqual(['default', 'payments']);
    expect(store.membershipsForUser('ayse')).toEqual([expect.objectContaining({ tenantId: 'default', role: 'operator' })]);
  });

  it('asks for the migration when the tables are missing', async () => {
    const store = new PostgresTenantStore(fakePool([]), { now: clock() });
    await expect(store.initialize()).rejects.toThrow(/Run npm run db:migrate/);
  });

  it('upserts a membership and reports whether it was created', async () => {
    const pool = loaded([
      [
        /^INSERT INTO tenant_memberships .* ON CONFLICT \(tenant_id, username\) DO UPDATE/,
        (params) => ({ rows: [{ ...membershipRow(params[0], params[1], params[2]), inserted: true }], rowCount: 1 }),
      ],
    ]);
    const store = new PostgresTenantStore(pool, { now: clock() });
    await store.initialize();
    const result = await store.setMembership({ tenantId: 'payments', username: 'Mehmet', role: 'approver', actorId: 'admin' });
    expect(result).toMatchObject({ created: true, membership: { tenantId: 'payments', username: 'mehmet', role: 'approver' } });
    expect(store.membershipsForUser('mehmet')).toHaveLength(1);
  });

  it('turns a missing user (foreign key) into a 404', async () => {
    const pool = loaded([
      [
        /^INSERT INTO tenant_memberships/,
        () => {
          const error = new Error('violates foreign key constraint');
          error.code = '23503';
          throw error;
        },
      ],
    ]);
    const store = new PostgresTenantStore(pool, { now: clock() });
    await store.initialize();
    expect(await rejection(store.setMembership({ tenantId: 'payments', username: 'ghost', role: 'viewer' }))).toMatchObject({
      statusCode: 404,
    });
    expect(store.membershipsForUser('ghost')).toEqual([]);
  });

  it('updates a team only at the version it read and reloads after a lost race', async () => {
    let version = 1;
    const pool = loaded([
      [/^UPDATE tenants .* WHERE id = \$1 AND row_version = \$6 RETURNING row_version$/, (params) => (params[5] === version ? { rows: [{ row_version: ++version }], rowCount: 1 } : { rows: [], rowCount: 0 })],
    ]);
    const store = new PostgresTenantStore(pool, { now: clock() });
    await store.initialize();
    expect(await store.updateTenant('payments', { displayName: 'Payments' })).toMatchObject({ rowVersion: 2 });
    version = 5; // changed outside this instance
    expect(await rejection(store.updateTenant('payments', { displayName: 'Again' }))).toMatchObject({ statusCode: 409 });
  });
});
