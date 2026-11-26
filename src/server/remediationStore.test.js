import { describe, expect, it } from 'vitest';
import {
  buildAuditEvent,
  MemoryRemediationStore,
  PostgresRemediationStore,
  redactAuditMetadata,
  RemediationStoreConflictError,
} from './remediationStore.js';
import { ALL_TENANTS } from '../lib/tenancy.js';

const sourceDigest = `sha256:${'a'.repeat(64)}`;
const outputDigest = `sha256:${'b'.repeat(64)}`;
const evidenceDigest = `sha256:${'c'.repeat(64)}`;

function auditEvent(overrides = {}) {
  return buildAuditEvent({
    eventType: 'remediation.job.created',
    action: 'create',
    actorId: 'test-user',
    resourceType: 'remediation-job',
    resourceId: 'RM-DRY-0001',
    correlationId: '11111111-1111-4111-8111-111111111111',
    summary: 'Test remediation job created',
    ...overrides,
  });
}

function dryRunJob() {
  return {
    id: 'RM-DRY-0001',
    tenantId: 'default',
    mode: 'dry-run',
    status: 'Planned',
    lifecycleState: 'planned',
    image: 'harbor.example.com/team/app:source',
    sourceDigest,
    createdAt: '2026-07-21T10:00:00.000Z',
  };
}

function verifiedJob() {
  return {
    id: 'RM-EXEC-0001',
    tenantId: 'default',
    parentJobId: 'RM-DRY-0001',
    mode: 'execution',
    status: 'Verified',
    lifecycleState: 'verified',
    image: 'harbor.example.com/team/app:source',
    sourceDigest,
    patchedImageDigest: outputDigest,
    fixed: [{ cve: 'CVE-2026-0001' }],
    before: { critical: 1, high: 0, medium: 0, low: 0 },
    after: { critical: 0, high: 0, medium: 0, low: 0 },
    publishGate: { allowed: false, status: 'Blocked' },
    createdAt: '2026-07-21T10:05:00.000Z',
    verifiedAt: '2026-07-21T10:06:00.000Z',
  };
}

function evidence() {
  return {
    contractVersion: 'ssi.copa-remediation-poc/v1alpha1',
    output: { digest: outputDigest },
  };
}

describe('redactAuditMetadata', () => {
  it('redacts nested credentials without mutating the input', () => {
    const input = {
      registry: 'harbor.example.com',
      authorization: 'Bearer value',
      nested: { robotSecret: 'secret-value', result: 'verified' },
    };

    expect(redactAuditMetadata(input)).toEqual({
      registry: 'harbor.example.com',
      authorization: '[REDACTED]',
      nested: { robotSecret: '[REDACTED]', result: 'verified' },
    });
    expect(input.nested.robotSecret).toBe('secret-value');
  });
});

describe('MemoryRemediationStore', () => {
  it('stores cloned jobs and their append-only audit event', async () => {
    const store = new MemoryRemediationStore();
    const job = dryRunJob();

    await store.createJob(job, auditEvent(), ALL_TENANTS);
    job.status = 'Mutated outside the store';

    expect(await store.getJob('RM-DRY-0001', ALL_TENANTS)).toMatchObject({ status: 'Planned' });
    expect(await store.listAuditEvents({}, ALL_TENANTS)).toEqual([
      expect.objectContaining({
        action: 'create',
        actorId: 'test-user',
        resourceId: 'RM-DRY-0001',
      }),
    ]);
  });

  it('accepts identical evidence idempotently and rejects conflicting evidence', async () => {
    const store = new MemoryRemediationStore();
    const dryRun = dryRunJob();
    const execution = verifiedJob();
    const acceptedAudit = auditEvent({
      eventType: 'remediation.evidence.accepted',
      action: 'accept-evidence',
      resourceId: execution.id,
    });

    await store.createJob(dryRun, auditEvent(), ALL_TENANTS);
    const first = await store.acceptVerifiedEvidence({
      dryRunJob: dryRun,
      verifiedJob: execution,
      evidence: evidence(),
      evidenceDigest,
      auditEvent: acceptedAudit,
    }, ALL_TENANTS);
    const duplicate = await store.acceptVerifiedEvidence({
      dryRunJob: dryRun,
      verifiedJob: { ...execution, id: 'RM-EXEC-9999' },
      evidence: evidence(),
      evidenceDigest,
      auditEvent: acceptedAudit,
    }, ALL_TENANTS);

    expect(first).toMatchObject({ created: true, job: { id: 'RM-EXEC-0001' } });
    expect(duplicate).toMatchObject({ created: false, job: { id: 'RM-EXEC-0001' } });
    expect(await store.listJobs(ALL_TENANTS)).toHaveLength(2);

    await expect(
      store.acceptVerifiedEvidence({
        dryRunJob: dryRun,
        verifiedJob: { ...execution, id: 'RM-EXEC-0002' },
        evidence: evidence(),
        evidenceDigest: `sha256:${'d'.repeat(64)}`,
        auditEvent: acceptedAudit,
      }, ALL_TENANTS),
    ).rejects.toBeInstanceOf(RemediationStoreConflictError);
  });

  it('rejects evidence with an invalid output digest or unknown dry-run job', async () => {
    const store = new MemoryRemediationStore();
    const dryRun = dryRunJob();
    await store.createJob(dryRun, undefined, ALL_TENANTS);

    await expect(
      store.acceptVerifiedEvidence({
        dryRunJob: dryRun,
        verifiedJob: verifiedJob(),
        evidence: { output: { digest: 'sha256:invalid' } },
        evidenceDigest,
      }, ALL_TENANTS),
    ).rejects.toThrow(/output digest is invalid/i);

    await expect(
      store.acceptVerifiedEvidence({
        dryRunJob: { ...dryRun, id: 'RM-DRY-9999' },
        verifiedJob: verifiedJob(),
        evidence: evidence(),
        evidenceDigest,
      }, ALL_TENANTS),
    ).rejects.toThrow(/unknown dry-run job/i);
  });

  it('stores publish transitions with optimistic concurrency and audit events', async () => {
    const store = new MemoryRemediationStore();
    const request = {
      id: 'PUB-0001',
      tenantId: 'default',
      jobId: 'RM-EXEC-0001',
      source: { digest: outputDigest },
      target: { tagReference: 'harbor.example.com/approved/app:verified-r1' },
      status: 'ApprovalRequired',
      policyVersion: 'ssi.publish-policy/v1',
      createdAt: '2026-07-21T15:00:00.000Z',
      updatedAt: '2026-07-21T15:00:00.000Z',
    };

    const created = await store.createPublishRequest(
      request,
      auditEvent({
        eventType: 'publish.policy.evaluated',
        action: 'evaluate-publish-policy',
        resourceType: 'publish-request',
        resourceId: request.id,
      }), ALL_TENANTS,
    );
    expect(created.rowVersion).toBe(1);

    const approved = await store.updatePublishRequest(
      { ...created, status: 'Approved', updatedAt: '2026-07-21T15:05:00.000Z' },
      auditEvent({
        eventType: 'publish.approval.granted',
        action: 'approve-publish-request',
        resourceType: 'publish-request',
        resourceId: request.id,
      }), ALL_TENANTS,
    );
    expect(approved).toMatchObject({ status: 'Approved', rowVersion: 2 });

    await expect(
      store.updatePublishRequest({ ...created, status: 'Published' }, undefined, ALL_TENANTS),
    ).rejects.toBeInstanceOf(RemediationStoreConflictError);
    expect(await store.listAuditEvents({}, ALL_TENANTS)).toHaveLength(2);
  });
});

describe('atomic job updates (updateJobWith)', () => {
  it('applies the mutation and its audit event, or leaves the job untouched', async () => {
    const store = new MemoryRemediationStore();
    await store.createJob(verifiedJob(), undefined, ALL_TENANTS);

    const updated = await store.updateJobWith('RM-EXEC-0001', (job) => ({
      job: { ...job, candidateTest: { passed: true } },
      auditEvent: auditEvent({ eventType: 'remediation.candidate-test.accepted', resourceId: job.id }),
    }), ALL_TENANTS);
    expect(updated.candidateTest).toEqual({ passed: true });
    expect((await store.getJob('RM-EXEC-0001', ALL_TENANTS)).candidateTest).toEqual({ passed: true });

    const unchanged = await store.updateJobWith('RM-EXEC-0001', () => ({ job: null }), ALL_TENANTS);
    expect(unchanged.candidateTest).toEqual({ passed: true });

    await expect(store.updateJobWith('RM-EXEC-0001', () => {
      throw new Error('validation failed');
    }, ALL_TENANTS)).rejects.toThrow('validation failed');
    expect((await store.getJob('RM-EXEC-0001', ALL_TENANTS)).candidateTest).toEqual({ passed: true });
    expect(await store.updateJobWith('RM-EXEC-9999', () => ({ job: {} }), ALL_TENANTS)).toBeNull();
    await expect(store.updateJobWith('RM-EXEC-0001', (job) => ({ job: { ...job, id: 'RM-EXEC-0002' } }), ALL_TENANTS)).rejects.toThrow(/job ID/);
    expect(await store.listAuditEvents({}, ALL_TENANTS)).toHaveLength(1);
  });

  function fakePool(row, { failOnUpdate = false } = {}) {
    const queries = [];
    const client = {
      async query(sql, params) {
        queries.push(String(sql).replace(/\s+/g, ' ').trim());
        if (String(sql).startsWith('SELECT job_data')) return { rows: row ? [{ job_data: row, tenant_id: 'default' }] : [] };
        if (failOnUpdate && String(sql).includes('UPDATE remediation_jobs')) throw new Error('database unavailable');
        return { rows: [], rowCount: 1, params };
      },
      release() {},
    };
    return { queries, pool: { connect: async () => client } };
  }

  it('locks the row in Postgres while the mutation runs and commits job and audit together', async () => {
    const { pool, queries } = fakePool(verifiedJob());
    const store = new PostgresRemediationStore(pool);
    await store.updateJobWith('RM-EXEC-0001', (job) => ({
      job: { ...job, consumerAcceptance: { decision: 'accepted' } },
      auditEvent: auditEvent({ resourceId: job.id }),
    }), ALL_TENANTS);

    expect(queries[0]).toBe('BEGIN');
    expect(queries[1]).toBe('SELECT job_data, tenant_id FROM remediation_jobs WHERE id = $1 FOR UPDATE');
    expect(queries[2]).toMatch(/^UPDATE remediation_jobs SET status = \$2.* WHERE id = \$1 AND tenant_id = \$6$/);
    expect(queries[3]).toMatch(/^INSERT INTO audit_events/);
    expect(queries.at(-1)).toBe('COMMIT');
  });

  it('rolls back in Postgres when the mutation or the write fails', async () => {
    const rejected = fakePool(verifiedJob());
    await expect(
      new PostgresRemediationStore(rejected.pool).updateJobWith('RM-EXEC-0001', () => {
        throw new Error('A newer candidate test result is already recorded for this job.');
      }, ALL_TENANTS),
    ).rejects.toThrow(/newer candidate test/);
    expect(rejected.queries.at(-1)).toBe('ROLLBACK');
    expect(rejected.queries.some((query) => query.startsWith('UPDATE'))).toBe(false);

    const broken = fakePool(verifiedJob(), { failOnUpdate: true });
    await expect(
      new PostgresRemediationStore(broken.pool).updateJobWith('RM-EXEC-0001', (job) => ({ job, auditEvent: null }), ALL_TENANTS),
    ).rejects.toThrow('database unavailable');
    expect(broken.queries.at(-1)).toBe('ROLLBACK');

    const missing = fakePool(null);
    expect(await new PostgresRemediationStore(missing.pool).updateJobWith('RM-EXEC-0001', () => ({ job: {} }), ALL_TENANTS)).toBeNull();
    expect(missing.queries.at(-1)).toBe('COMMIT');
  });
});

describe('memory store serializes concurrent updates of one job', () => {
  it('applies every one of several interleaving updates (no lost update)', async () => {
    const store = new MemoryRemediationStore();
    await store.createJob({ ...verifiedJob(), counter: 0 }, undefined, ALL_TENANTS);
    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        store.updateJobWith('RM-EXEC-0001', async (job) => {
          await new Promise((resolve) => setTimeout(resolve, (index % 3) * 2));
          return { job: { ...job, counter: job.counter + 1 } };
        }, ALL_TENANTS),
      ),
    );
    expect((await store.getJob('RM-EXEC-0001', ALL_TENANTS)).counter).toBe(20);
    expect(store.jobLocks.size).toBe(0);
  });

  it('keeps working for the next update after a failed one', async () => {
    const store = new MemoryRemediationStore();
    await store.createJob({ ...verifiedJob(), counter: 0 }, undefined, ALL_TENANTS);
    await expect(store.updateJobWith('RM-EXEC-0001', () => Promise.reject(new Error('boom')), ALL_TENANTS)).rejects.toThrow('boom');
    await store.updateJobWith('RM-EXEC-0001', (job) => ({ job: { ...job, counter: 1 } }), ALL_TENANTS);
    expect((await store.getJob('RM-EXEC-0001', ALL_TENANTS)).counter).toBe(1);
  });
});

describe('job and publish requests in one transaction (updateJobAndPublishRequests)', () => {
  const publishedRequest = (id, tag, status = 'Published') => ({
    id,
    tenantId: 'default',
    jobId: 'RM-EXEC-0001',
    source: { digest: outputDigest },
    target: { tagReference: `harbor.example.com/approved/app:${tag}` },
    status,
    policyVersion: 'ssi.publish-policy/v1.4',
    createdAt: '2026-11-05T14:00:00.000Z',
    updatedAt: '2026-11-05T14:00:00.000Z',
  });
  const withdrawnOf = (request) => ({ ...request, status: 'Withdrawn', withdrawal: { digest: outputDigest } });
  const markJob = (job) => ({ ...job, publishWithdrawal: { digest: outputDigest, withdrawnBy: 'sam.lee' } });

  async function storeWithRequests() {
    const store = new MemoryRemediationStore();
    await store.createJob(verifiedJob(), undefined, ALL_TENANTS);
    await store.createPublishRequest(publishedRequest('PUB-0012', 'r3'), undefined, ALL_TENANTS);
    await store.createPublishRequest(publishedRequest('PUB-0013', 'r3-alias'), undefined, ALL_TENANTS);
    await store.createPublishRequest(publishedRequest('PUB-0014', 'pending', 'Approved'), undefined, ALL_TENANTS);
    return store;
  }

  it('loads the requests of a digest under the job lock and writes job, requests and audit together', async () => {
    const store = await storeWithRequests();
    const result = await store.updateJobAndPublishRequests('RM-EXEC-0001', async (job, load) => {
      const published = await load({ digest: outputDigest, statuses: ['Published'] });
      expect(published.map((item) => item.id)).toEqual(['PUB-0012', 'PUB-0013']);
      return {
        job: markJob(job),
        jobAuditEvent: auditEvent({ eventType: 'remediation.output.withdrawn', resourceId: job.id }),
        requests: published.map((item) => ({
          request: withdrawnOf(item),
          auditEvent: auditEvent({ eventType: 'publish.withdrawn', resourceType: 'publish-request', resourceId: item.id }),
        })),
        auditEvents: [auditEvent({ eventType: 'extra.event' })],
      };
    }, ALL_TENANTS);

    expect(result.job.publishWithdrawal.withdrawnBy).toBe('sam.lee');
    expect(result.requests.map((item) => [item.id, item.status, item.rowVersion])).toEqual([
      ['PUB-0012', 'Withdrawn', 2],
      ['PUB-0013', 'Withdrawn', 2],
    ]);
    expect((await store.getPublishRequest('PUB-0014', ALL_TENANTS)).status).toBe('Approved');
    expect((await store.listAuditEvents({}, ALL_TENANTS)).map((item) => item.eventType).sort()).toEqual([
      'extra.event',
      'publish.withdrawn',
      'publish.withdrawn',
      'remediation.output.withdrawn',
    ]);
  });

  it('leaves nothing behind when a request changed during the decision (no partial write)', async () => {
    const store = await storeWithRequests();
    await expect(
      store.updateJobAndPublishRequests('RM-EXEC-0001', async (job, load) => {
        const published = await load({ digest: outputDigest, statuses: ['Published'] });
        // Another writer (not under the job lock, e.g. an approval) changes a row meanwhile.
        await store.updatePublishRequest({ ...published[1], updatedAt: '2026-11-09T00:00:00.000Z' }, undefined, ALL_TENANTS);
        return { job: markJob(job), requests: published.map((item) => ({ request: withdrawnOf(item), auditEvent: null })) };
      }, ALL_TENANTS),
    ).rejects.toBeInstanceOf(RemediationStoreConflictError);

    expect((await store.getJob('RM-EXEC-0001', ALL_TENANTS)).publishWithdrawal).toBeUndefined();
    expect((await store.getPublishRequest('PUB-0012', ALL_TENANTS)).status).toBe('Published');
  });

  it('serializes two decisions on the same job (the second sees the first)', async () => {
    const store = await storeWithRequests();
    const withdraw = () =>
      store.updateJobAndPublishRequests('RM-EXEC-0001', async (job, load) => {
        const published = await load({ digest: outputDigest, statuses: ['Published'] });
        if (published.length === 0) throw new RemediationStoreConflictError('Only a published image can be withdrawn.');
        return { job: markJob(job), requests: published.map((item) => ({ request: withdrawnOf(item), auditEvent: null })) };
      }, ALL_TENANTS);
    const results = await Promise.allSettled([withdraw(), withdraw()]);
    expect(results.map((item) => item.status).sort()).toEqual(['fulfilled', 'rejected']);
  });

  it('loads requests by ID and passes a missing job as null', async () => {
    const store = await storeWithRequests();
    const seen = await store.updateJobAndPublishRequests('RM-EXEC-9999', async (job, load) => {
      expect(job).toBeNull();
      return { requests: [], ids: (await load({ ids: ['PUB-0014'] })).map((item) => item.id) };
    }, ALL_TENANTS);
    expect(seen).toEqual({ job: null, requests: [] });
  });

  function fakeClient({ conflict = false } = {}) {
    const queries = [];
    const client = {
      async query(sql) {
        const text = String(sql).replace(/\s+/g, ' ').trim();
        queries.push(text);
        if (text.startsWith('SELECT job_data')) return { rows: [{ job_data: verifiedJob(), tenant_id: 'default' }] };
        if (text.startsWith('SELECT request_data')) {
          return { rows: [{ request_data: publishedRequest('PUB-0012', 'r3'), row_version: 3, tenant_id: 'default' }] };
        }
        if (text.startsWith('UPDATE publish_requests')) {
          return conflict ? { rows: [], rowCount: 0 } : { rows: [{ row_version: 4 }], rowCount: 1 };
        }
        return { rows: [], rowCount: 1 };
      },
      release() {},
    };
    return { queries, pool: { connect: async () => client } };
  }

  it('locks the job, then the requests, and commits everything in one Postgres transaction', async () => {
    const { pool, queries } = fakeClient();
    const result = await new PostgresRemediationStore(pool).updateJobAndPublishRequests('RM-EXEC-0001', async (job, load) => {
      const [current] = await load({ digest: outputDigest, statuses: ['Published'] });
      expect(current.rowVersion).toBe(3);
      return {
        job: markJob(job),
        jobAuditEvent: auditEvent(),
        requests: [{ request: withdrawnOf(current), auditEvent: auditEvent() }],
      };
    }, ALL_TENANTS);

    expect(queries[0]).toBe('BEGIN');
    expect(queries[1]).toBe('SELECT job_data, tenant_id FROM remediation_jobs WHERE id = $1 FOR UPDATE');
    expect(queries[2]).toMatch(/^SELECT request_data, row_version, tenant_id FROM publish_requests WHERE source_digest = \$1 AND status = ANY\(\$2::text\[\]\) ORDER BY id FOR UPDATE$/);
    expect(queries[3]).toMatch(/^UPDATE remediation_jobs/);
    expect(queries[4]).toMatch(/^INSERT INTO audit_events/);
    expect(queries[5]).toMatch(/^UPDATE publish_requests .* WHERE id = \$1 AND row_version = \$5 AND tenant_id = \$6/);
    expect(queries.at(-1)).toBe('COMMIT');
    expect(result.requests[0].rowVersion).toBe(4);
  });

  it('rolls the Postgres transaction back on a request conflict', async () => {
    const { pool, queries } = fakeClient({ conflict: true });
    await expect(
      new PostgresRemediationStore(pool).updateJobAndPublishRequests('RM-EXEC-0001', async (job, load) => {
        const [current] = await load({ ids: ['PUB-0012'] });
        return { job: markJob(job), requests: [{ request: withdrawnOf(current), auditEvent: null }] };
      }, ALL_TENANTS),
    ).rejects.toBeInstanceOf(RemediationStoreConflictError);
    expect(queries).toContain('SELECT request_data, row_version, tenant_id FROM publish_requests WHERE id = ANY($1::text[]) ORDER BY id FOR UPDATE');
    expect(queries.at(-1)).toBe('ROLLBACK');
  });
});
