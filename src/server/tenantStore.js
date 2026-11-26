// SSI — team ("tenant") and team membership store. Rules and validation: src/lib/tenancy.js.
//
// Same shape as userStore: two drivers behind one interface (`memory` for PoC/tests,
// `postgres` for persistence) and, in Postgres, a write-through mirror. Every tenant and
// membership is loaded at start-up (initialize) and every write updates the database first,
// then the mirror, so the reads on the request hot path (tenant context resolution) stay
// synchronous. SSI runs as a single instance, so the mirror is always current.
//
// The 'default' team is created by migration 009 (and by the memory driver itself); it
// holds every record that predates multi-tenancy and cannot be disabled.

import {
  assertTenantChangeAllowed,
  assertTenantId,
  assertTenantRole,
  DEFAULT_TENANT_ID,
  MEMBERSHIP_SOURCES,
  normalizeTenantId,
  TenancyError,
  validateNewTenant,
  validateTenantChanges,
} from '../lib/tenancy.js';

function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

function assertUsername(username) {
  const key = normalizeUsername(username);
  if (!key) throw new TenancyError(400, 'A username is required.');
  return key;
}

function assertSource(source) {
  if (!MEMBERSHIP_SOURCES.includes(source)) throw new TenancyError(400, 'Invalid membership source.');
  return source;
}

function iso(value) {
  return new Date(value).toISOString();
}

function tenantView(record) {
  return { ...record, harbor: { ...record.harbor } };
}

function membershipView(record) {
  return { ...record };
}

function rowToTenant(row) {
  return {
    id: row.id,
    displayName: row.display_name,
    status: row.status,
    harbor: { ...(row.tenant_data?.harbor || {}) },
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    rowVersion: Number(row.row_version),
  };
}

function rowToMembership(row) {
  return {
    tenantId: row.tenant_id,
    username: row.username,
    role: row.role,
    source: row.source,
    createdBy: row.created_by,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

// Optimistic concurrency for tenant changes: a caller that sends the version it read gets
// a 409 when someone else changed the team in the meantime.
function assertExpectedVersion(current, expectedRowVersion) {
  if (expectedRowVersion === undefined || expectedRowVersion === null) return;
  if (Number(expectedRowVersion) !== Number(current.rowVersion)) {
    throw new TenancyError(409, 'The team was changed by someone else. Reload it and try again.');
  }
}

// Mirror shared by both drivers: tenants by id, memberships by tenant then username.
class TenantMirror {
  constructor() {
    this.tenants = new Map();
    this.memberships = new Map();
  }

  clear() {
    this.tenants.clear();
    this.memberships.clear();
  }

  setTenant(record) {
    this.tenants.set(record.id, record);
    if (!this.memberships.has(record.id)) this.memberships.set(record.id, new Map());
  }

  setMembership(record) {
    if (!this.memberships.has(record.tenantId)) this.memberships.set(record.tenantId, new Map());
    this.memberships.get(record.tenantId).set(record.username, record);
  }

  deleteMembership(tenantId, username) {
    return this.memberships.get(tenantId)?.delete(username) || false;
  }

  listTenants() {
    return [...this.tenants.values()].map(tenantView).sort((a, b) => a.id.localeCompare(b.id));
  }

  getTenant(id) {
    const record = this.tenants.get(normalizeTenantId(id));
    return record ? tenantView(record) : null;
  }

  requireTenant(id) {
    const record = this.tenants.get(normalizeTenantId(id));
    if (!record) throw new TenancyError(404, 'Team not found.');
    return record;
  }

  getMembership(tenantId, username) {
    return this.memberships.get(normalizeTenantId(tenantId))?.get(normalizeUsername(username)) || null;
  }

  listMembers(tenantId) {
    this.requireTenant(tenantId);
    return [...(this.memberships.get(normalizeTenantId(tenantId))?.values() || [])]
      .map(membershipView)
      .sort((a, b) => a.username.localeCompare(b.username));
  }

  membershipsForUser(username) {
    const key = normalizeUsername(username);
    if (!key) return [];
    const result = [];
    for (const members of this.memberships.values()) {
      const record = members.get(key);
      if (record) result.push(membershipView(record));
    }
    return result.sort((a, b) => a.tenantId.localeCompare(b.tenantId));
  }

  forgetUser(username) {
    const key = normalizeUsername(username);
    for (const members of this.memberships.values()) members.delete(key);
  }
}

function newTenantRecord(input, timestamp) {
  return { ...input, createdAt: timestamp, updatedAt: timestamp, rowVersion: 1 };
}

function membershipInput({ tenantId, username, role, source = 'manual', actorId }) {
  return {
    tenantId: assertTenantId(tenantId),
    username: assertUsername(username),
    role: assertTenantRole(role),
    source: assertSource(source),
    actorId: String(actorId || 'ssi-api').slice(0, 200),
  };
}

// ---------------------------------------------------------------------------
// Memory driver (PoC/tests). Writes are async so both drivers share one interface.
// ---------------------------------------------------------------------------
class MemoryTenantStore {
  constructor({ now = () => new Date().toISOString() } = {}) {
    this.driver = 'memory';
    this.now = now;
    this.mirror = new TenantMirror();
    const timestamp = now();
    this.mirror.setTenant(
      newTenantRecord({ id: DEFAULT_TENANT_ID, displayName: 'Default', status: 'active', harbor: {} }, timestamp),
    );
  }

  async initialize() {}
  async close() {}

  listTenants() {
    return this.mirror.listTenants();
  }

  getTenant(id) {
    return this.mirror.getTenant(id);
  }

  listMembers(tenantId) {
    return this.mirror.listMembers(tenantId);
  }

  membershipsForUser(username) {
    return this.mirror.membershipsForUser(username);
  }

  forgetUser(username) {
    this.mirror.forgetUser(username);
  }

  async createTenant(input) {
    const tenant = validateNewTenant(input);
    if (this.mirror.tenants.has(tenant.id)) throw new TenancyError(409, 'A team with this id already exists.');
    const record = newTenantRecord(tenant, this.now());
    this.mirror.setTenant(record);
    return tenantView(record);
  }

  async updateTenant(id, changes = {}, { expectedRowVersion } = {}) {
    const current = this.mirror.requireTenant(id);
    const next = validateTenantChanges(changes);
    assertTenantChangeAllowed(current.id, next);
    assertExpectedVersion(current, expectedRowVersion);
    const record = { ...current, ...next, updatedAt: this.now(), rowVersion: current.rowVersion + 1 };
    this.mirror.setTenant(record);
    return tenantView(record);
  }

  // Adds a member or changes the member's role; returns { membership, created }.
  async setMembership(values) {
    const input = membershipInput(values);
    this.mirror.requireTenant(input.tenantId);
    const existing = this.mirror.getMembership(input.tenantId, input.username);
    const timestamp = this.now();
    const record = {
      tenantId: input.tenantId,
      username: input.username,
      role: input.role,
      source: input.source,
      createdBy: existing?.createdBy || input.actorId,
      createdAt: existing?.createdAt || timestamp,
      updatedAt: timestamp,
    };
    this.mirror.setMembership(record);
    return { membership: membershipView(record), created: !existing };
  }

  async removeMembership(tenantId, username) {
    const id = assertTenantId(tenantId);
    this.mirror.requireTenant(id);
    const existing = this.mirror.getMembership(id, username);
    if (!existing) throw new TenancyError(404, 'This user is not a member of the team.');
    this.mirror.deleteMembership(id, existing.username);
    return membershipView(existing);
  }
}

// ---------------------------------------------------------------------------
// Postgres driver (persistent). Write-through mirror: reads from the mirror (synchronous),
// writes to the database first and then to the mirror.
// ---------------------------------------------------------------------------
class PostgresTenantStore {
  constructor(pool, { now = () => new Date().toISOString() } = {}) {
    this.driver = 'postgres';
    this.pool = pool;
    this.now = now;
    this.mirror = new TenantMirror();
  }

  async initialize() {
    let tenants;
    let memberships;
    try {
      tenants = await this.pool.query(
        'SELECT id, display_name, status, tenant_data, created_at, updated_at, row_version FROM tenants',
      );
      memberships = await this.pool.query(
        'SELECT tenant_id, username, role, source, created_by, created_at, updated_at FROM tenant_memberships',
      );
    } catch (error) {
      throw new Error(`PostgreSQL persistence is not initialized. Run npm run db:migrate first. ${error.message}`, {
        cause: error,
      });
    }
    this.mirror.clear();
    for (const row of tenants.rows) this.mirror.setTenant(rowToTenant(row));
    for (const row of memberships.rows) this.mirror.setMembership(rowToMembership(row));
  }

  // The shared pool is closed by remediationStore.close().
  async close() {}

  listTenants() {
    return this.mirror.listTenants();
  }

  getTenant(id) {
    return this.mirror.getTenant(id);
  }

  listMembers(tenantId) {
    return this.mirror.listMembers(tenantId);
  }

  membershipsForUser(username) {
    return this.mirror.membershipsForUser(username);
  }

  // The rows go with the user (ON DELETE CASCADE); only the mirror needs updating.
  forgetUser(username) {
    this.mirror.forgetUser(username);
  }

  async createTenant(input) {
    const tenant = validateNewTenant(input);
    if (this.mirror.tenants.has(tenant.id)) throw new TenancyError(409, 'A team with this id already exists.');
    const record = newTenantRecord(tenant, this.now());
    try {
      await this.pool.query(
        `INSERT INTO tenants (id, display_name, status, tenant_data, created_at, updated_at, row_version)
         VALUES ($1, $2, $3, $4::jsonb, $5::timestamptz, $6::timestamptz, 1)`,
        [record.id, record.displayName, record.status, { harbor: record.harbor }, record.createdAt, record.updatedAt],
      );
    } catch (error) {
      if (error.code === '23505') throw new TenancyError(409, 'A team with this id already exists.');
      throw error;
    }
    this.mirror.setTenant(record);
    return tenantView(record);
  }

  async updateTenant(id, changes = {}, { expectedRowVersion } = {}) {
    const current = this.mirror.requireTenant(id);
    const next = validateTenantChanges(changes);
    assertTenantChangeAllowed(current.id, next);
    assertExpectedVersion(current, expectedRowVersion);
    const record = { ...current, ...next, updatedAt: this.now() };
    const result = await this.pool.query(
      `UPDATE tenants
          SET display_name = $2, status = $3, tenant_data = $4::jsonb, updated_at = $5::timestamptz,
              row_version = row_version + 1
        WHERE id = $1 AND row_version = $6
        RETURNING row_version`,
      [record.id, record.displayName, record.status, { harbor: record.harbor }, record.updatedAt, current.rowVersion],
    );
    if (result.rowCount === 0) {
      // The database moved on without this instance (outside change): reload the mirror.
      await this.initialize();
      throw new TenancyError(409, 'The team was changed by someone else. Reload it and try again.');
    }
    record.rowVersion = Number(result.rows[0].row_version);
    this.mirror.setTenant(record);
    return tenantView(record);
  }

  async setMembership(values) {
    const input = membershipInput(values);
    this.mirror.requireTenant(input.tenantId);
    const timestamp = this.now();
    let result;
    try {
      result = await this.pool.query(
        `INSERT INTO tenant_memberships (tenant_id, username, role, source, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $6::timestamptz)
         ON CONFLICT (tenant_id, username)
         DO UPDATE SET role = EXCLUDED.role, source = EXCLUDED.source, updated_at = EXCLUDED.updated_at
         RETURNING tenant_id, username, role, source, created_by, created_at, updated_at, (xmax = 0) AS inserted`,
        [input.tenantId, input.username, input.role, input.source, input.actorId, timestamp],
      );
    } catch (error) {
      // 23503: the user (or the team) does not exist any more.
      if (error.code === '23503') throw new TenancyError(404, 'User or team not found.');
      throw error;
    }
    const row = result.rows[0];
    const record = rowToMembership(row);
    this.mirror.setMembership(record);
    return { membership: membershipView(record), created: Boolean(row.inserted) };
  }

  async removeMembership(tenantId, username) {
    const id = assertTenantId(tenantId);
    this.mirror.requireTenant(id);
    const key = assertUsername(username);
    const result = await this.pool.query(
      `DELETE FROM tenant_memberships WHERE tenant_id = $1 AND username = $2
       RETURNING tenant_id, username, role, source, created_by, created_at, updated_at`,
      [id, key],
    );
    this.mirror.deleteMembership(id, key);
    if (result.rowCount === 0) throw new TenancyError(404, 'This user is not a member of the team.');
    return rowToMembership(result.rows[0]);
  }
}

// Factory. The Postgres driver uses the pool server.js shares with the other stores.
export function createTenantStore({ driver = process.env.PERSISTENCE_DRIVER, pool = null, now } = {}) {
  const selected = String(driver || 'memory').trim().toLowerCase();
  if (selected === 'memory') return new MemoryTenantStore({ now });
  if (selected !== 'postgres') {
    throw new Error('PERSISTENCE_DRIVER must be memory or postgres');
  }
  if (!pool) throw new Error('createTenantStore requires a pool when PERSISTENCE_DRIVER=postgres');
  return new PostgresTenantStore(pool, { now });
}

export { MemoryTenantStore, PostgresTenantStore };
