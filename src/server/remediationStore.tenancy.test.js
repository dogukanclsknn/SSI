// Team isolation of the remediation store: every read returns only the scope's records,
// every write stays in the record's own team, and nothing runs without a scope.
import { describe, expect, it } from 'vitest';
import { buildAuditEvent, MemoryRemediationStore, PostgresRemediationStore } from './remediationStore.js';
import { ALL_TENANTS, tenantScope } from '../lib/tenancy.js';

const A = tenantScope(['payments']);
const B = tenantScope(['mobile']);
const digestOf = (letter) => `sha256:${letter.repeat(64)}`;

const audit = (resourceId, overrides = {}) =>
  buildAuditEvent({
    eventType: 'test.event',
    action: 'test',
    actorId: 'tester',
    resourceType: 'test',
    resourceId,
    correlationId: '11111111-1111-4111-8111-111111111111',
    summary: 'test',
    ...overrides,
  });

const job = (id, tenantId, overrides = {}) => ({
  id,
  tenantId,
  mode: 'execution',
  status: 'Verified',
  lifecycleState: 'verified',
  sourceDigest: digestOf('a'),
  patchedImageDigest: digestOf(tenantId === 'payments' ? 'b' : 'c'),
  createdAt: '2026-11-10T10:00:00.000Z',
  ...overrides,
});

const publishRequest = (id, jobId, tenantId, status = 'Published') => ({
  id,
  tenantId,
  jobId,
  status,
  source: { digest: digestOf(tenantId === 'payments' ? 'b' : 'c') },
  target: { tagReference: `harbor.example/approved/${id}:r1` },
  policyVersion: 'ssi.publish-policy/v1.4',
  createdAt: '2026-11-10T10:00:00.000Z',
  updatedAt: '2026-11-10T10:00:00.000Z',
});

const onboarding = (id, tenantId) => ({
  id,
  tenantId,
  status: 'Requested',
  source: { reference: 'docker.io/library/nginx:1.27' },
  target: { tagReference: `harbor.example/onboarded/${id}:1.27` },
  createdAt: '2026-11-10T10:00:00.000Z',
  updatedAt: '2026-11-10T10:00:00.000Z',
});

const exception = (id, tenantId) => ({
  id,
  tenantId,
  cve: 'CVE-2023-45853',
  repository: 'ssi-images/onboarded/nginx',
  package: 'zlib1g',
  digest: '',
  reasonCode: 'no-fix-available',
  justification: 'No upstream fix; not reachable in this image.',
  status: 'Requested',
  expiresAt: '2099-01-01T00:00:00.000Z',
  requestedBy: 'tester',
  decidedBy: null,
  createdAt: '2026-11-10T10:00:00.000Z',
  updatedAt: '2026-11-10T10:00:00.000Z',
});

// Two teams with one record of each kind, written through their own scopes.
async function twoTeams() {
  const store = new MemoryRemediationStore();
  for (const [tenantId, scope, suffix] of [
    ['payments', A, 'A'],
    ['mobile', B, 'B'],
  ]) {
    await store.createJob(job(`RM-EXEC-${suffix}`, tenantId), audit(`RM-EXEC-${suffix}`), scope);
    await store.createPublishRequest(publishRequest(`PUB-${suffix}`, `RM-EXEC-${suffix}`, tenantId), audit(`PUB-${suffix}`), scope);
    await store.createOnboardingRequest(onboarding(`ONB-${suffix}`, tenantId), audit(`ONB-${suffix}`), scope);
    // The same CVE and repository in both teams: risk acceptances do not cross teams.
    await store.createException(exception(`EXC-${suffix}`, tenantId), audit(`EXC-${suffix}`), scope);
  }
  await store.appendAuditEvent(audit('platform', { eventType: 'auth.login' }));
  return store;
}

const ids = (records) => records.map((item) => item.id).sort();

describe('remediation store — team isolation (memory driver)', () => {
  it('lists only the records of the scope; ALL_TENANTS sees every team', async () => {
    const store = await twoTeams();
    expect(ids(await store.listJobs(A))).toEqual(['RM-EXEC-A']);
    expect(ids(await store.listPublishRequests(A))).toEqual(['PUB-A']);
    expect(ids(await store.listOnboardingRequests(A))).toEqual(['ONB-A']);
    expect(ids(await store.listExceptions(A))).toEqual(['EXC-A']);
    expect(ids(await store.listJobs(B))).toEqual(['RM-EXEC-B']);
    expect(ids(await store.listJobs(ALL_TENANTS))).toEqual(['RM-EXEC-A', 'RM-EXEC-B']);
    expect(ids(await store.listJobs(tenantScope(['payments', 'mobile'])))).toEqual(['RM-EXEC-A', 'RM-EXEC-B']);
  });

  it("returns null for another team's record, as for a record that does not exist", async () => {
    const store = await twoTeams();
    expect(await store.getJob('RM-EXEC-B', A)).toBeNull();
    expect(await store.getPublishRequest('PUB-B', A)).toBeNull();
    expect(await store.getOnboardingRequest('ONB-B', A)).toBeNull();
    expect(await store.getException('EXC-B', A)).toBeNull();
    expect((await store.getJob('RM-EXEC-B', B)).tenantId).toBe('mobile');
  });

  it("does not update another team's record", async () => {
    const store = await twoTeams();
    const foreign = await store.getJob('RM-EXEC-B', B);
    let called = false;
    expect(
      await store.updateJobWith(
        'RM-EXEC-B',
        () => {
          called = true;
          return { job: foreign };
        },
        A,
      ),
    ).toBeNull();
    expect(called).toBe(false);
    await expect(store.updateJob({ ...foreign, status: 'Hijacked' }, null, A)).rejects.toThrow(/outside the request's tenant scope/);
    const request = await store.getPublishRequest('PUB-B', B);
    await expect(store.updatePublishRequest({ ...request, status: 'Withdrawn' }, null, A)).rejects.toThrow(/outside/);
    expect((await store.getJob('RM-EXEC-B', B)).status).toBe('Verified');
  });

  it('never moves a record to another team', async () => {
    const store = await twoTeams();
    await expect(
      store.updateJobWith('RM-EXEC-A', (current) => ({ job: { ...current, tenantId: 'mobile' } }), ALL_TENANTS),
    ).rejects.toThrow(/must not change the record's team/);
    const request = await store.getPublishRequest('PUB-A', A);
    // A record claiming another team is not found in that team.
    expect(await store.updatePublishRequest({ ...request, tenantId: 'mobile' }, null, ALL_TENANTS)).toBeNull();
    expect((await store.getPublishRequest('PUB-A', A)).tenantId).toBe('payments');
  });

  it('refuses to create a record outside the scope or without a team', async () => {
    const store = new MemoryRemediationStore();
    await expect(store.createJob(job('RM-EXEC-X', 'mobile'), null, A)).rejects.toThrow(/outside/);
    await expect(store.createJob({ ...job('RM-EXEC-X', 'payments'), tenantId: undefined }, null, A)).rejects.toThrow(
      /valid tenantId/,
    );
    expect(await store.listJobs(ALL_TENANTS)).toEqual([]);
  });

  it.each([
    ['listJobs', []],
    ['getJob', ['RM-EXEC-A']],
    ['listPublishRequests', []],
    ['getPublishRequest', ['PUB-A']],
    ['listOnboardingRequests', []],
    ['getOnboardingRequest', ['ONB-A']],
    ['listExceptions', []],
    ['getException', ['EXC-A']],
    ['listAuditEvents', [{}]],
    ['updateJobWith', ['RM-EXEC-A', () => ({ job: null })]],
    ['updateJobAndPublishRequests', ['RM-EXEC-A', async () => ({ requests: [] })]],
    ['createJob', [job('RM-EXEC-Z', 'payments'), null]],
  ])('%s refuses to run without a scope (fail-closed)', async (method, args) => {
    const store = await twoTeams();
    await expect(store[method](...args)).rejects.toThrow(/tenant scope is required/);
  });

  it("does not let one team's risk acceptance block or apply to another team", async () => {
    const store = await twoTeams();
    // Already open in both teams, independently.
    expect((await store.listExceptions(ALL_TENANTS)).filter((item) => item.cve === 'CVE-2023-45853')).toHaveLength(2);
    await expect(store.createException(exception('EXC-A2', 'payments'), null, A)).rejects.toThrow(/already covers/);
  });

  it('loads and withdraws only the publish requests of the scope inside the job transaction', async () => {
    const store = await twoTeams();
    // A request of the other team with the same digest must not be loaded.
    await store.createPublishRequest({ ...publishRequest('PUB-B2', 'RM-EXEC-B', 'mobile'), source: { digest: digestOf('b') } }, null, B);
    const result = await store.updateJobAndPublishRequests(
      'RM-EXEC-A',
      async (current, load) => {
        const published = await load({ digest: digestOf('b'), statuses: ['Published'] });
        expect(ids(published)).toEqual(['PUB-A']);
        return { requests: published.map((item) => ({ request: { ...item, status: 'Withdrawn' }, auditEvent: audit(item.id) })) };
      },
      A,
    );
    expect(ids(result.requests)).toEqual(['PUB-A']);
    expect((await store.getPublishRequest('PUB-B2', B)).status).toBe('Published');
    // The other team's job is invisible to the transaction.
    const seen = await store.updateJobAndPublishRequests('RM-EXEC-B', async (current) => ({ requests: [], current }), A);
    expect(seen.job).toBeNull();
  });

  it('labels audit events with the team of their record and shows platform events to ALL_TENANTS only', async () => {
    const store = await twoTeams();
    const eventsOf = async (scope) => (await store.listAuditEvents({ limit: 100 }, scope)).map((item) => [item.resourceId, item.tenantId]);
    expect((await eventsOf(A)).sort()).toEqual([
      ['EXC-A', 'payments'],
      ['ONB-A', 'payments'],
      ['PUB-A', 'payments'],
      ['RM-EXEC-A', 'payments'],
    ]);
    expect(await eventsOf(ALL_TENANTS)).toContainEqual(['platform', null]);
    expect(await eventsOf(ALL_TENANTS)).toHaveLength(9);
  });

  it('stores verified evidence in the team of its dry run only', async () => {
    const store = new MemoryRemediationStore();
    const dryRun = { ...job('RM-DRY-A', 'payments'), mode: 'dry-run' };
    await store.createJob(dryRun, null, A);
    const evidence = { contractVersion: 'ssi.copa-remediation-poc/v1alpha1', output: { digest: digestOf('d') } };
    await expect(
      store.acceptVerifiedEvidence(
        { dryRunJob: dryRun, verifiedJob: job('RM-EXEC-D', 'mobile'), evidence, evidenceDigest: digestOf('e') },
        ALL_TENANTS,
      ),
    ).rejects.toThrow(/unknown dry-run job/);
    const accepted = await store.acceptVerifiedEvidence(
      { dryRunJob: dryRun, verifiedJob: job('RM-EXEC-D', 'payments'), evidence, evidenceDigest: digestOf('e') },
      A,
    );
    expect(accepted).toMatchObject({ created: true, job: { tenantId: 'payments' } });
    // An identical replay is idempotent; another team's scope cannot write it.
    await expect(
      store.acceptVerifiedEvidence(
        { dryRunJob: dryRun, verifiedJob: job('RM-EXEC-D', 'payments'), evidence, evidenceDigest: digestOf('e') },
        A,
      ),
    ).resolves.toMatchObject({ created: false, job: { id: 'RM-EXEC-D' } });
    await expect(
      store.acceptVerifiedEvidence(
        { dryRunJob: dryRun, verifiedJob: job('RM-EXEC-D', 'payments'), evidence, evidenceDigest: digestOf('e') },
        B,
      ),
    ).rejects.toThrow(/outside the request's tenant scope/);
  });
});

describe('remediation store — tenant scope in SQL (postgres driver)', () => {
  function recordingPool(rows = []) {
    const queries = [];
    const run = async (sql, params) => {
      queries.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params });
      return { rows, rowCount: rows.length };
    };
    return { queries, pool: { query: run, connect: async () => ({ query: run, release() {} }) } };
  }

  it('filters every read by the scope and leaves the filter out for ALL_TENANTS', async () => {
    const { pool, queries } = recordingPool();
    const store = new PostgresRemediationStore(pool);
    await store.listJobs(A);
    await store.getPublishRequest('PUB-A', tenantScope(['payments', 'mobile']));
    await store.listAuditEvents({ limit: 10 }, A);
    await store.listJobs(ALL_TENANTS);
    expect(queries[0]).toEqual({
      sql: 'SELECT job_data, tenant_id FROM remediation_jobs WHERE tenant_id = ANY($1::text[]) ORDER BY created_at DESC, id DESC',
      params: [['payments']],
    });
    expect(queries[1]).toEqual({
      sql: 'SELECT request_data, row_version, tenant_id FROM publish_requests WHERE id = $1 AND tenant_id = ANY($2::text[])',
      params: ['PUB-A', ['payments', 'mobile']],
    });
    // One row more than the page: it tells whether another page exists.
    expect(queries[2].sql).toMatch(/FROM audit_events WHERE tenant_id = ANY\(\$1::text\[\]\) ORDER BY occurred_at DESC, id DESC LIMIT \$2$/);
    expect(queries[2].params).toEqual([['payments'], 11]);
    expect(queries[3].sql).toBe('SELECT job_data, tenant_id FROM remediation_jobs ORDER BY created_at DESC, id DESC');
  });

  it('maps the tenant column onto the record and keeps it out of the stored document', async () => {
    const { pool, queries } = recordingPool([{ job_data: { id: 'RM-EXEC-A', tenantId: 'forged' }, tenant_id: 'payments' }]);
    const store = new PostgresRemediationStore(pool);
    expect((await store.getJob('RM-EXEC-A', A)).tenantId).toBe('payments');
    await store.createJob(job('RM-EXEC-N', 'payments'), audit('RM-EXEC-N'), A);
    const insert = queries.find((item) => item.sql.startsWith('INSERT INTO remediation_jobs'));
    expect(insert.params[7]).not.toHaveProperty('tenantId');
    expect(insert.params[10]).toBe('payments');
    const auditInsert = queries.find((item) => item.sql.startsWith('INSERT INTO audit_events'));
    expect(auditInsert.params.at(-1)).toBe('payments');
  });

  it('runs no SQL without a scope', async () => {
    const { pool, queries } = recordingPool();
    const store = new PostgresRemediationStore(pool);
    await expect(store.listJobs()).rejects.toThrow(/tenant scope is required/);
    await expect(store.updateJobWith('RM-EXEC-A', () => ({ job: null }))).rejects.toThrow(/tenant scope is required/);
    expect(queries).toEqual([]);
  });
});
