// Paging, filtering and counting the audit log (src/lib/auditQuery.js) in both stores.
import { describe, expect, it } from 'vitest';
import {
  buildAuditEvent,
  MemoryRemediationStore,
  PostgresRemediationStore,
} from './remediationStore.js';
import { ALL_TENANTS, tenantScope } from '../lib/tenancy.js';
import { decodeAuditCursor, parseAuditFilters } from '../lib/auditQuery.js';

const CORRELATION = '22222222-2222-4222-8222-222222222222';
const filters = (query) => parseAuditFilters(new URLSearchParams(query));

// 25 events: several share a millisecond (ties are broken by id), two teams, a few failures.
async function seeded() {
  const store = new MemoryRemediationStore();
  for (let index = 0; index < 25; index += 1) {
    await store.appendAuditEvent(
      buildAuditEvent({
        tenantId: index % 5 === 0 ? 'mobile' : 'payments',
        eventType: index % 3 === 0 ? 'publish.receipt.accepted' : 'onboarding.request.created',
        action: 'test',
        actorId: index % 2 ? 'alice' : 'bob',
        resourceType: 'test',
        resourceId: `R-${index}`,
        correlationId: index === 7 ? CORRELATION : '11111111-1111-4111-8111-111111111111',
        outcome: index % 4 === 0 ? 'failure' : 'success',
        summary: `event ${index}`,
        occurredAt: new Date(Date.UTC(2026, 10, 17, 10, 0, 0, Math.floor(index / 3))).toISOString(),
      }),
    );
  }
  return store;
}

async function readAll(store, scope, query = {}) {
  const seen = [];
  let before = null;
  let pages = 0;
  do {
    const page = await store.queryAuditEvents({ limit: 4, before, ...query }, scope);
    seen.push(...page.events);
    before = page.nextCursor ? decodeAuditCursor(page.nextCursor) : null;
    pages += 1;
  } while (before && pages < 50);
  return seen;
}

describe('audit log paging (memory store)', () => {
  it('reads every event exactly once, newest first, across pages', async () => {
    const store = await seeded();
    const all = await readAll(store, ALL_TENANTS);
    expect(all).toHaveLength(25);
    expect(new Set(all.map((item) => item.id)).size).toBe(25);
    for (let index = 1; index < all.length; index += 1) {
      const [previous, current] = [all[index - 1], all[index]];
      expect(previous.occurredAt >= current.occurredAt).toBe(true);
      if (previous.occurredAt === current.occurredAt) expect(previous.id > current.id).toBe(true);
    }
  });

  it('does not shift a page when new events are recorded meanwhile', async () => {
    const store = await seeded();
    const first = await store.queryAuditEvents({ limit: 10 }, ALL_TENANTS);
    await store.appendAuditEvent(
      buildAuditEvent({
        eventType: 'auth.login.success',
        action: 'login',
        actorId: 'carol',
        resourceType: 'session',
        correlationId: CORRELATION,
        summary: 'new',
      }),
    );
    const second = await store.queryAuditEvents(
      { limit: 10, before: decodeAuditCursor(first.nextCursor) },
      ALL_TENANTS,
    );
    const ids = [...first.events, ...second.events].map((item) => item.id);
    expect(new Set(ids).size).toBe(20);
    expect(second.events.map((item) => item.summary)).not.toContain('new');
  });

  it("keeps a team's pages to its own events", async () => {
    const store = await seeded();
    const payments = await readAll(store, tenantScope(['payments']));
    expect(payments).toHaveLength(20);
    expect(payments.every((item) => item.tenantId === 'payments')).toBe(true);
  });

  it('filters, counts and summarises with the same rules', async () => {
    const store = await seeded();
    const failures = filters('failures=true&actor=bob');
    const matching = await readAll(store, ALL_TENANTS, { filters: failures });
    expect(matching.every((item) => item.outcome !== 'success' && item.actorId === 'bob')).toBe(
      true,
    );
    expect(await store.countAuditEvents({ filters: failures }, ALL_TENANTS)).toBe(matching.length);
    expect(
      (await readAll(store, ALL_TENANTS, { filters: filters(`correlationId=${CORRELATION}`) })).map(
        (item) => item.resourceId,
      ),
    ).toEqual(['R-7']);

    const summary = await store.summarizeAuditEvents(
      { filters: filters('category=publish') },
      ALL_TENANTS,
    );
    expect(summary.total).toBe(25);
    expect(summary.categories).toMatchObject({
      all: 25,
      publish: 9,
      onboarding: 16,
      other: 0,
      signin: 0,
    });
  });
});

describe('audit log paging (postgres store SQL)', () => {
  function recordingPool(rows = []) {
    const queries = [];
    const query = async (sql, params) => {
      queries.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params });
      return { rows, rowCount: rows.length };
    };
    return { queries, pool: { query, connect: async () => ({ query, release() {} }) } };
  }

  const row = (index) => ({
    id: `0000000${index}-0000-4000-8000-000000000000`,
    event_type: 'publish.x',
    action: 'x',
    actor_id: 'a',
    resource_type: 't',
    resource_id: null,
    correlation_id: CORRELATION,
    outcome: 'success',
    severity: 'info',
    summary: 's',
    metadata: {},
    occurred_at: new Date('2026-11-17T10:00:00.000Z'),
    occurred_micros: `179491680000000${index}`,
    tenant_id: 'payments',
  });

  it('binds filters, cursor, scope and limit, and returns the cursor of the last row shown', async () => {
    const { pool, queries } = recordingPool([row(3), row(2), row(1)]);
    const store = new PostgresRemediationStore(pool);
    const page = await store.queryAuditEvents(
      {
        limit: 2,
        before: { occurredMicros: '1794916800000009', id: '00000009-0000-4000-8000-000000000000' },
        filters: filters('category=publish&q=x'),
      },
      tenantScope(['payments']),
    );
    expect(queries[0].sql).toContain("WHERE event_type LIKE $1 AND (summary ILIKE $2 ESCAPE '\\'");
    expect(queries[0].sql).toContain(
      "AND (occurred_at, id) < ((timestamptz 'epoch' + $3::bigint * interval '1 microsecond'), $4::uuid) AND tenant_id = ANY($5::text[]) ORDER BY occurred_at DESC, id DESC LIMIT $6",
    );
    expect(queries[0].params).toEqual([
      'publish.%',
      '%x%',
      '1794916800000009',
      '00000009-0000-4000-8000-000000000000',
      ['payments'],
      3,
    ]);
    expect(page.events).toHaveLength(2);
    expect(page.events[0]).not.toHaveProperty('occurred_micros');
    expect(decodeAuditCursor(page.nextCursor)).toEqual({
      occurredMicros: '1794916800000002',
      id: '00000002-0000-4000-8000-000000000000',
    });
  });

  it('has no next page when the database returned the page and nothing more', async () => {
    const { pool } = recordingPool([row(1)]);
    const page = await new PostgresRemediationStore(pool).queryAuditEvents(
      { limit: 2 },
      ALL_TENANTS,
    );
    expect(page.nextCursor).toBeNull();
  });

  it('counts per category in one query and derives "other"', async () => {
    const { pool, queries } = recordingPool([
      { all: 10, signin: 1, access: 0, remediation: 2, publish: 3, onboarding: 1, users: 0 },
    ]);
    const summary = await new PostgresRemediationStore(pool).summarizeAuditEvents(
      { filters: filters('category=publish&failures=true') },
      ALL_TENANTS,
    );
    expect(queries[0].sql).not.toContain('event_type LIKE $1 AND');
    expect(queries[0].sql).toContain(`WHERE outcome <> 'success'`);
    expect(summary).toEqual({
      total: 10,
      categories: {
        all: 10,
        signin: 1,
        access: 0,
        remediation: 2,
        publish: 3,
        onboarding: 1,
        users: 0,
        other: 3,
      },
    });
  });
});
