import { describe, expect, it } from 'vitest';
import {
  createRemediationStore,
  MemoryRemediationStore,
  PostgresRemediationStore,
  RemediationStoreConflictError,
} from './remediationStore.js';
import { ALL_TENANTS } from '../lib/tenancy.js';

// Basit bir onboarding isteği (store yalnızca id/source/target/status/tarihleri okur).
function onboardingRequest(id, overrides = {}) {
  const now = '2026-09-08T10:00:00.000Z';
  return {
    id,
    tenantId: 'default',
    type: 'onboarding',
    status: 'Requested',
    source: { reference: 'docker.io/library/nginx:1.27' },
    target: { tagReference: 'harbor.local/proj/onboarded/nginx:1.27' },
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

const audit = (id) => ({
  id: '00000000-0000-0000-0000-000000000001',
  eventType: 'onboarding.request.created',
  action: 'create-onboarding-request',
  actorId: 'tester',
  resourceType: 'onboarding-request',
  resourceId: id,
  correlationId: '00000000-0000-0000-0000-0000000000aa',
  outcome: 'success',
  severity: 'info',
  summary: 'x',
  metadata: {},
  occurredAt: '2026-09-08T10:00:00.000Z',
});

describe('onboarding persistence — memory', () => {
  it('createRemediationStore memory döner (varsayılan)', async () => {
    const store = await createRemediationStore();
    expect(store).toBeInstanceOf(MemoryRemediationStore);
    expect(store.driver).toBe('memory');
  });

  it('nextOnboardingId ONB-#### üretir ve artar', async () => {
    const store = new MemoryRemediationStore();
    expect(await store.nextOnboardingId()).toBe('ONB-0001');
    expect(await store.nextOnboardingId()).toBe('ONB-0002');
  });

  it('create + list (yeni en üstte) + get', async () => {
    const store = new MemoryRemediationStore();
    await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
    await store.createOnboardingRequest(
      onboardingRequest('ONB-0002', { target: { tagReference: 'harbor.local/proj/onboarded/redis:7.2' } }),
      audit('ONB-0002'),
      ALL_TENANTS,
    );
    expect((await store.listOnboardingRequests(ALL_TENANTS)).map((r) => r.id)).toEqual(['ONB-0002', 'ONB-0001']);
    expect((await store.getOnboardingRequest('ONB-0001', ALL_TENANTS)).id).toBe('ONB-0001');
    expect(await store.getOnboardingRequest('YOK', ALL_TENANTS)).toBeNull();
    // audit da yazıldı
    expect((await store.listAuditEvents({}, ALL_TENANTS)).length).toBe(2);
  });

  it('aynı id ile create çakışması 409', async () => {
    const store = new MemoryRemediationStore();
    await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
    await expect(store.createOnboardingRequest(onboardingRequest('ONB-0001'), undefined, ALL_TENANTS)).rejects.toBeInstanceOf(
      RemediationStoreConflictError,
    );
  });

  it('update durum geçişini kalıcılaştırır; olmayan istek null', async () => {
    const store = new MemoryRemediationStore();
    await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
    const updated = await store.updateOnboardingRequest(
      onboardingRequest('ONB-0001', { status: 'Imported', importedDigest: 'sha256:' + 'a'.repeat(64) }),
      audit('ONB-0001'), ALL_TENANTS,
    );
    expect(updated.status).toBe('Imported');
    expect((await store.getOnboardingRequest('ONB-0001', ALL_TENANTS)).status).toBe('Imported');
    expect(await store.updateOnboardingRequest(onboardingRequest('ONB-9999'), undefined, ALL_TENANTS)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Postgres sürücüsü — transaction-farkında sahte havuz (in-memory tablo).
// ---------------------------------------------------------------------------
function fakePool() {
  const rows = new Map(); // id -> { request_data, tenant_id }
  let seq = 0;
  let audits = 0;

  function run(text, params) {
    const sql = text.replace(/\s+/g, ' ').trim();
    if (/nextval\('onboarding_request_seq'\)/.test(sql)) {
      seq += 1;
      return { rows: [{ value: seq }], rowCount: 1 };
    }
    if (/^SELECT pg_advisory_xact_lock\(hashtext\(\$1\)\)$/.test(sql)) return { rows: [{}], rowCount: 1 };
    if (/^SELECT id FROM onboarding_requests WHERE tenant_id = \$1 AND target_reference = \$2 AND status = ANY/.test(sql)) {
      const open = [...rows.values()].filter(
        (r) => r.tenant_id === params[0] && r.request_data.target.tagReference === params[1] && params[2].includes(r.request_data.status),
      );
      return { rows: open.map((r) => ({ id: r.request_data.id })).slice(0, 1), rowCount: Math.min(open.length, 1) };
    }
    if (/^SELECT request_data, tenant_id FROM onboarding_requests WHERE id = \$1( FOR UPDATE)?$/.test(sql)) {
      const r = rows.get(params[0]);
      return { rows: r ? [r] : [], rowCount: r ? 1 : 0 };
    }
    if (/^SELECT request_data, tenant_id FROM onboarding_requests ORDER BY/.test(sql)) {
      const list = [...rows.values()].sort((a, b) => (a.request_data.createdAt < b.request_data.createdAt ? 1 : -1));
      return { rows: list, rowCount: list.length };
    }
    if (/^INSERT INTO onboarding_requests/.test(sql)) {
      const req = params[4];
      if (rows.has(req.id)) {
        const err = new Error('duplicate key');
        err.code = '23505';
        throw err;
      }
      rows.set(req.id, { request_data: req, tenant_id: params[7] });
      return { rows: [], rowCount: 1 };
    }
    if (/^UPDATE onboarding_requests .* WHERE id = \$1 AND tenant_id = \$6$/.test(sql)) {
      const id = params[0];
      if (rows.get(id)?.tenant_id !== params[5]) return { rows: [], rowCount: 0 };
      rows.set(id, { request_data: params[3], tenant_id: params[5] });
      return { rows: [], rowCount: 1 };
    }
    if (/^INSERT INTO audit_events/.test(sql)) {
      audits += 1;
      return { rows: [], rowCount: 1 };
    }
    if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)) return { rows: [], rowCount: 0 };
    throw new Error(`unexpected SQL in fake pool: ${sql}`);
  }

  return {
    _stats: () => ({ size: rows.size, audits }),
    async query(text, params) {
      return run(text, params);
    },
    async connect() {
      return {
        async query(text, params) {
          return run(text, params);
        },
        release() {},
      };
    },
  };
}

describe('onboarding persistence — postgres (fake pool)', () => {
  it('create INSERT + audit yazar, get/list DB\'den okur', async () => {
    const pool = fakePool();
    const store = new PostgresRemediationStore(pool);
    expect(await store.nextOnboardingId()).toBe('ONB-0001');

    await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
    expect((await store.getOnboardingRequest('ONB-0001', ALL_TENANTS)).id).toBe('ONB-0001');
    expect((await store.listOnboardingRequests(ALL_TENANTS)).map((r) => r.id)).toEqual(['ONB-0001']);
    expect(pool._stats()).toMatchObject({ size: 1, audits: 1 });
  });

  it('aynı id INSERT çakışması (23505) 409\'a çevrilir', async () => {
    const pool = fakePool();
    const store = new PostgresRemediationStore(pool);
    await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
    await expect(
      store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS),
    ).rejects.toBeInstanceOf(RemediationStoreConflictError);
  });

  it('update durum geçişini yazar; olmayan istek null döner', async () => {
    const pool = fakePool();
    const store = new PostgresRemediationStore(pool);
    await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);

    const updated = await store.updateOnboardingRequest(
      onboardingRequest('ONB-0001', { status: 'Importing' }),
      undefined, ALL_TENANTS, // handoff geçişi: audit yok
    );
    expect(updated.status).toBe('Importing');
    expect((await store.getOnboardingRequest('ONB-0001', ALL_TENANTS)).status).toBe('Importing');

    expect(await store.updateOnboardingRequest(onboardingRequest('ONB-9999'), audit('ONB-9999'), ALL_TENANTS)).toBeNull();
  });
});

describe('one open onboarding request per quarantine target, and atomic updates', () => {
  const cancel = (current) => ({
    request: { ...current, status: 'Cancelled', updatedAt: '2026-11-11T14:00:00.000Z' },
    auditEvent: audit(current.id),
  });

  for (const [driver, make] of [
    ['memory', () => new MemoryRemediationStore()],
    ['postgres (fake pool)', () => new PostgresRemediationStore(fakePool())],
  ]) {
    it(`${driver}: refuses a second open request for the same target and names the open one`, async () => {
      const store = make();
      await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
      const refused = store.createOnboardingRequest(onboardingRequest('ONB-0002'), audit('ONB-0002'), ALL_TENANTS);
      await expect(refused).rejects.toBeInstanceOf(RemediationStoreConflictError);
      await expect(
        store.createOnboardingRequest(onboardingRequest('ONB-0002'), audit('ONB-0002'), ALL_TENANTS),
      ).rejects.toThrow(/open onboarding request \(ONB-0001\) already exists/);
      expect(await store.getOnboardingRequest('ONB-0002', ALL_TENANTS)).toBeNull();
    });

    it(`${driver}: allows the target again once the open request is finished or cancelled`, async () => {
      const store = make();
      await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
      const result = await store.updateOnboardingRequestWith('ONB-0001', cancel, ALL_TENANTS);
      expect(result).toMatchObject({ changed: true, request: { status: 'Cancelled' } });
      await store.createOnboardingRequest(onboardingRequest('ONB-0002'), audit('ONB-0002'), ALL_TENANTS);
      expect((await store.getOnboardingRequest('ONB-0002', ALL_TENANTS)).status).toBe('Requested');
    });

    it(`${driver}: an atomic update decides on the stored state; no change and missing requests are reported`, async () => {
      const store = make();
      await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
      expect(await store.updateOnboardingRequestWith('ONB-0001', () => null, ALL_TENANTS)).toMatchObject({ changed: false });
      expect(await store.updateOnboardingRequestWith('ONB-9999', cancel, ALL_TENANTS)).toBeNull();
      await expect(
        store.updateOnboardingRequestWith('ONB-0001', () => { throw new Error('refused'); }, ALL_TENANTS),
      ).rejects.toThrow('refused');
      expect((await store.getOnboardingRequest('ONB-0001', ALL_TENANTS)).status).toBe('Requested');
    });
  }

  it('memory: concurrent updates of one request run one after the other', async () => {
    const store = new MemoryRemediationStore();
    await store.createOnboardingRequest(onboardingRequest('ONB-0001'), audit('ONB-0001'), ALL_TENANTS);
    const seen = [];
    const step = (label) => async (current) => {
      seen.push(`${label}:${current.status}`);
      await new Promise((resolve) => setTimeout(resolve, 5));
      return current.status === 'Requested' ? cancel(current) : null;
    };
    await Promise.all([
      store.updateOnboardingRequestWith('ONB-0001', step('first'), ALL_TENANTS),
      store.updateOnboardingRequestWith('ONB-0001', step('second'), ALL_TENANTS),
    ]);
    expect(seen).toEqual(['first:Requested', 'second:Cancelled']);
  });
});
