import { describe, expect, it } from 'vitest';
import { acceptPublishReceipt, buildPublishPolicyConfig, isPublishReceiptReplay } from './publishPolicy.js';
import { MemoryRemediationStore } from '../server/remediationStore.js';
import { ALL_TENANTS } from './tenancy.js';
import {
  applyJobWithdrawal,
  buildWithdrawalDecision,
  cancelForWithdrawnImage,
  decideDigestWithdrawal,
  decidePublishReceipt,
  isWithdrawnDigest,
  OPEN_PUBLISH_STATUSES,
  receiptBaseline,
  rejectPublishRequest,
  WITHDRAWAL_CATEGORIES,
  withdrawLatePublication,
  withdrawPublishedRequest,
} from './publishLifecycle.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const OTHER = `sha256:${'b'.repeat(64)}`;
const REFERENCE = 'harbor.example/ssi-images/approved/nginx:verified-r3';
const config = buildPublishPolicyConfig({ SSI_RBAC_ENFORCED: 'true', SSI_SESSION_SECRET: 'test-secret' });
const approver = { actorId: 'sam.lee', actorRoles: ['approver'], config };

function request(status, overrides = {}) {
  return {
    id: 'PUB-0012',
    tenantId: 'default',
    jobId: 'RM-EXEC-0004',
    status,
    requestedBy: 'alex.morgan',
    rowVersion: 3,
    source: { digest: DIGEST },
    target: { tagReference: REFERENCE },
    publish:
      status === 'Published'
        ? { status: 'Published', receipt: { targetReference: REFERENCE } }
        : { status: 'NotStarted', receipt: null },
    ...overrides,
  };
}

const decision = (overrides = {}) =>
  buildWithdrawalDecision({
    ...approver,
    reason: 'TLS handshake fails in html-hello-world.',
    category: 'Functional',
    withdrawnAt: '2026-11-09T10:00:00.000Z',
    ...overrides,
  });

describe('rejectPublishRequest', () => {
  it('rejects a request that waits for approval and keeps who, why and when', () => {
    const result = rejectPublishRequest(request('ApprovalRequired'), {
      ...approver,
      reason: 'Stale request from the r1 image, not needed.',
      rejectedAt: '2026-11-09T09:00:00.000Z',
    });
    expect(result).toMatchObject({
      status: 'Rejected',
      updatedAt: '2026-11-09T09:00:00.000Z',
      rowVersion: 3,
      rejection: {
        rejectedBy: 'sam.lee',
        reason: 'Stale request from the r1 image, not needed.',
        rejectedAt: '2026-11-09T09:00:00.000Z',
      },
    });
  });

  it('only rejects requests that wait for approval (approved ones may be publishing)', () => {
    for (const status of ['Blocked', 'Approved', 'Published', 'Rejected', 'Withdrawn']) {
      expect(() => rejectPublishRequest(request(status), { ...approver, reason: 'not going to happen' })).toThrow(
        /waiting for approval/,
      );
    }
  });

  it('requires publish authority and a valid reason', () => {
    const pending = request('ApprovalRequired');
    expect(() => rejectPublishRequest(pending, { ...approver, actorRoles: ['operator'], reason: 'long enough reason' })).toThrow(
      /not an authorized publish approver/,
    );
    expect(() => rejectPublishRequest(pending, { ...approver, reason: 'short' })).toThrow(/at least 10 characters/);
    expect(() => rejectPublishRequest(pending, { ...approver, reason: 'x'.repeat(1001) })).toThrow(/must not exceed 1000/);
  });

  it('accepts only one line of visible text as a reason', () => {
    const pending = request('ApprovalRequired');
    const reject = (reason) => rejectPublishRequest(pending, { ...approver, reason });
    for (const reason of [
      'line one\nline two',
      'right-to-left \u202e override',
      'line \u2028 separator',
      'next \u0085 line',
      'zero \u200b width space',
    ]) {
      expect(() => reject(reason)).toThrow(/single line of printable text/);
    }
    expect(() => reject({ toString: () => 'object reason long' })).toThrow(/must be text/);
    expect(() => reject(['an array reason here'])).toThrow(/must be text/);
    expect(reject('Türkçe gerekçe: imaj eski, gerek yok.').rejection.reason).toBe('Türkçe gerekçe: imaj eski, gerek yok.');
  });
});

describe('buildWithdrawalDecision', () => {
  it('validates the decider, reason and category once for the whole digest', () => {
    expect(decision()).toEqual({
      withdrawnBy: 'sam.lee',
      reason: 'TLS handshake fails in html-hello-world.',
      category: 'functional',
      withdrawnAt: '2026-11-09T10:00:00.000Z',
    });
    expect(WITHDRAWAL_CATEGORIES).toEqual(['functional', 'security', 'compliance', 'other']);
  });

  it('refuses an unknown or non-text category, missing authority and an invalid reason', () => {
    expect(() => decision({ category: 'oops' })).toThrow(/category must be one of/);
    expect(() => decision({ category: ['security'] })).toThrow(/category must be one of/);
    expect(() => decision({ actorId: '' })).toThrow(/authenticated approver/);
    expect(() => decision({ actorRoles: ['operator'] })).toThrow(/not an authorized publish approver/);
    expect(() => decision({ reason: { a: 1 } })).toThrow(/must be text/);
  });

  it('does not need a second person: the requester may withdraw when they hold publish authority', () => {
    expect(decision({ actorId: 'alex.morgan', actorRoles: ['admin'] }).withdrawnBy).toBe('alex.morgan');
  });
});

describe('withdrawPublishedRequest', () => {
  it('withdraws a published image and keeps the publish receipt', () => {
    const result = withdrawPublishedRequest(request('Published'), decision());
    expect(result.status).toBe('Withdrawn');
    expect(result.updatedAt).toBe('2026-11-09T10:00:00.000Z');
    expect(result.withdrawal).toEqual({
      withdrawnBy: 'sam.lee',
      reason: 'TLS handshake fails in html-hello-world.',
      category: 'functional',
      withdrawnAt: '2026-11-09T10:00:00.000Z',
      digest: DIGEST,
      targetReference: REFERENCE,
    });
    expect(result.publish.receipt).toBeTruthy();
  });

  it('only withdraws published images with an immutable digest', () => {
    for (const status of ['Blocked', 'ApprovalRequired', 'Approved', 'Rejected', 'Withdrawn']) {
      expect(() => withdrawPublishedRequest(request(status), decision())).toThrow(/Only a published image/);
    }
    expect(() => withdrawPublishedRequest(request('Published', { source: { digest: 'latest' } }), decision())).toThrow(
      /no immutable digest/,
    );
  });
});

describe('withdrawLatePublication', () => {
  const jobWithdrawal = { ...decision(), digest: DIGEST, targetReference: 'other:tag', requestIds: ['PUB-0001'] };

  it('records a registry write that finished after the withdrawal as withdrawn', () => {
    const result = withdrawLatePublication(request('Published', { id: 'PUB-0013' }), jobWithdrawal, '2026-11-09T11:00:00.000Z');
    expect(result.status).toBe('Withdrawn');
    expect(result.publish.status).toBe('Published');
    expect(result.withdrawal).toEqual({
      withdrawnBy: 'sam.lee',
      reason: 'TLS handshake fails in html-hello-world.',
      category: 'functional',
      withdrawnAt: '2026-11-09T10:00:00.000Z',
      digest: DIGEST,
      targetReference: REFERENCE,
      publishedAfterWithdrawal: true,
      recordedAt: '2026-11-09T11:00:00.000Z',
    });
  });

  it('applies only to a request that has just been published', () => {
    expect(() => withdrawLatePublication(request('Approved'), jobWithdrawal)).toThrow(/Only a published request/);
  });
});

describe('isWithdrawnDigest', () => {
  it('matches only a valid withdrawal record of the same digest', () => {
    expect(isWithdrawnDigest({ publishWithdrawal: { digest: DIGEST } }, DIGEST.toUpperCase().replace('SHA256', 'sha256'))).toBe(true);
    expect(isWithdrawnDigest({ publishWithdrawal: { digest: DIGEST } }, OTHER)).toBe(false);
    expect(isWithdrawnDigest({ publishWithdrawal: { digest: 'latest' } }, 'latest')).toBe(false);
    expect(isWithdrawnDigest({}, DIGEST)).toBe(false);
    expect(isWithdrawnDigest(null, DIGEST)).toBe(false);
  });
});

describe('applyJobWithdrawal', () => {
  const withdrawal = withdrawPublishedRequest(request('Published'), decision({ category: 'security' })).withdrawal;
  const job = { id: 'RM-EXEC-0004', status: 'Verified', patchedImageDigest: DIGEST };

  it('records the withdrawal on the job that produced the digest', () => {
    expect(applyJobWithdrawal(job, withdrawal, ['PUB-0012', 'PUB-0013', 'PUB-0012']).publishWithdrawal).toEqual({
      digest: DIGEST,
      withdrawnBy: 'sam.lee',
      reason: 'TLS handshake fails in html-hello-world.',
      category: 'security',
      withdrawnAt: '2026-11-09T10:00:00.000Z',
      targetReference: REFERENCE,
      requestIds: ['PUB-0012', 'PUB-0013'],
    });
  });

  it('keeps the first record and only adds new request IDs later', () => {
    const first = applyJobWithdrawal(job, withdrawal, ['PUB-0012']);
    expect(applyJobWithdrawal(first, { ...withdrawal, withdrawnBy: 'someone.else' }, ['PUB-0012'])).toBeNull();
    const later = applyJobWithdrawal(first, { ...withdrawal, withdrawnBy: 'someone.else' }, ['PUB-0013', 'PUB-0013']);
    expect(later.publishWithdrawal.withdrawnBy).toBe('sam.lee');
    expect(later.publishWithdrawal.requestIds).toEqual(['PUB-0012', 'PUB-0013']);
  });

  it('fails closed for a missing job or another digest', () => {
    expect(() => applyJobWithdrawal(null, withdrawal)).toThrow(/was not found/);
    expect(() => applyJobWithdrawal({ ...job, patchedImageDigest: OTHER }, withdrawal)).toThrow(/not the output digest/);
  });
});

describe('decideDigestWithdrawal and decidePublishReceipt (in the store transaction)', () => {
  const job = { id: 'RM-EXEC-0004', tenantId: 'default', mode: 'execution', status: 'Verified', patchedImageDigest: DIGEST };
  const receiptFor = (item) => ({
    contractVersion: 'ssi.publish-receipt/v1',
    requestId: item.id,
    sourceDigest: DIGEST,
    targetDigest: DIGEST,
    targetReference: item.target.tagReference,
    status: 'published',
    verified: true,
    workerId: 'LinuxAgent1@build-agent-01',
  });

  async function store() {
    const memory = new MemoryRemediationStore();
    await memory.createJob(job, undefined, ALL_TENANTS);
    for (const [id, status, tag] of [
      ['PUB-0012', 'Published', 'r3'],
      ['PUB-0013', 'Published', 'r3-alias'],
      ['PUB-0014', 'Approved', 'pending'],
      ['PUB-0015', 'ApprovalRequired', 'waiting'],
      ['PUB-0016', 'Blocked', 'blocked'],
    ]) {
      await memory.createPublishRequest(
        request(status, { id, target: { tagReference: `${REFERENCE}-${tag}` }, publish: status === 'Published' ? request('Published').publish : { status: 'NotStarted', receipt: null } }), undefined, ALL_TENANTS,
      );
    }
    return memory;
  }

  const withdraw = (memory, requestId) =>
    memory.updateJobAndPublishRequests('RM-EXEC-0004', async (current, load) => {
      // As in server.js: the published requests are withdrawn, the open ones cancelled.
      const published = await load({ digest: DIGEST, statuses: ['Published'] });
      const open = await load({ digest: DIGEST, statuses: OPEN_PUBLISH_STATUSES });
      const decided = decideDigestWithdrawal({ job: current, published, open, requestId, decision: decision() });
      return {
        job: decided.job,
        requests: [...decided.requests, ...decided.cancelled].map((item) => ({ request: item, auditEvent: null })),
      };
    }, ALL_TENANTS);
  const receive = (memory, requestId) =>
    memory.updateJobAndPublishRequests('RM-EXEC-0004', async (current, load) => {
      const [item] = await load({ ids: [requestId] });
      const decided = decidePublishReceipt({ job: current, request: item, receipt: receiptFor(item), recordedAt: '2026-11-09T11:00:00.000Z' });
      return { job: decided.job, requests: [{ request: decided.request, auditEvent: null }], withdrawnLate: decided.withdrawnLate };
    }, ALL_TENANTS);

  it('withdraws every published request of the digest, the selected one first', async () => {
    const memory = await store();
    const result = await withdraw(memory, 'PUB-0013');
    expect(result.requests.map((item) => [item.id, item.status])).toEqual([
      ['PUB-0013', 'Withdrawn'],
      ['PUB-0012', 'Withdrawn'],
      ['PUB-0014', 'Cancelled'],
      ['PUB-0015', 'Cancelled'],
      ['PUB-0016', 'Cancelled'],
    ]);
    // Only published requests belong to the withdrawal record of the job.
    expect(result.job.publishWithdrawal.requestIds).toEqual(['PUB-0013', 'PUB-0012']);
  });

  it('cancels every request of the digest that was not published yet, with the cause', async () => {
    const memory = await store();
    await withdraw(memory, 'PUB-0012');
    for (const [id, previousStatus] of [['PUB-0014', 'Approved'], ['PUB-0015', 'ApprovalRequired'], ['PUB-0016', 'Blocked']]) {
      expect(await memory.getPublishRequest(id, ALL_TENANTS)).toMatchObject({
        status: 'Cancelled',
        updatedAt: '2026-11-09T10:00:00.000Z',
        cancellation: {
          cause: 'image-withdrawn',
          previousStatus,
          cancelledBy: 'sam.lee',
          reason: 'TLS handshake fails in html-hello-world.',
          category: 'functional',
          digest: DIGEST,
        },
      });
    }
  });

  it('still records a receipt of a request that was approved before its image was withdrawn', async () => {
    const memory = await store();
    await withdraw(memory, 'PUB-0012');
    const result = await receive(memory, 'PUB-0014');
    expect(result.requests[0]).toMatchObject({
      status: 'Withdrawn',
      publish: { status: 'Published' },
      withdrawal: { publishedAfterWithdrawal: true, withdrawnBy: 'sam.lee' },
      cancellation: { cause: 'image-withdrawn', previousStatus: 'Approved' },
    });
    expect((await memory.getJob('RM-EXEC-0004', ALL_TENANTS)).publishWithdrawal.requestIds).toContain('PUB-0014');
  });

  it('refuses a receipt for a cancelled request that was never approved (no worker had it)', async () => {
    const memory = await store();
    await withdraw(memory, 'PUB-0012');
    await expect(receive(memory, 'PUB-0015')).rejects.toThrow(/approved request/);
    await expect(receive(memory, 'PUB-0016')).rejects.toThrow(/approved request/);
  });

  it('refuses a request that another withdrawal already took', async () => {
    const memory = await store();
    await withdraw(memory, 'PUB-0012');
    await expect(withdraw(memory, 'PUB-0013')).rejects.toThrow(/Only a published image/);
  });

  it('records a normal receipt as Published', async () => {
    const memory = await store();
    const result = await receive(memory, 'PUB-0014');
    expect(result.requests[0]).toMatchObject({ status: 'Published', publish: { status: 'Published' } });
    expect(result.job.publishWithdrawal).toBeUndefined();
  });

  it('records a receipt that arrives after the withdrawal as Withdrawn and adds it to the job', async () => {
    const memory = await store();
    await withdraw(memory, 'PUB-0012');
    const result = await receive(memory, 'PUB-0014');
    expect(result.requests[0]).toMatchObject({
      status: 'Withdrawn',
      publish: { status: 'Published' },
      withdrawal: { publishedAfterWithdrawal: true, withdrawnBy: 'sam.lee', recordedAt: '2026-11-09T11:00:00.000Z' },
    });
    expect((await memory.getJob('RM-EXEC-0004', ALL_TENANTS)).publishWithdrawal.requestIds).toEqual(['PUB-0012', 'PUB-0013', 'PUB-0014']);
  });

  it('a receipt for an image withdrawn while its request was still approved is recorded once', async () => {
    const memory = await store();
    await withdraw(memory, 'PUB-0012');
    await receive(memory, 'PUB-0014');
    await expect(receive(memory, 'PUB-0014')).rejects.toThrow(/approved request/);
  });

  it('refuses a second receipt for the same request', async () => {
    const memory = await store();
    await receive(memory, 'PUB-0014');
    await expect(receive(memory, 'PUB-0014')).rejects.toThrow(/approved request/);
  });
});

describe('isPublishReceiptReplay (a worker retries a receipt that is already recorded)', () => {
  const receipt = (overrides = {}) => ({
    contractVersion: 'ssi.publish-receipt/v1',
    requestId: 'PUB-0012',
    sourceDigest: DIGEST,
    targetDigest: DIGEST,
    targetReference: REFERENCE,
    status: 'published',
    verified: true,
    workerId: 'LinuxAgent1@build-agent-01',
    ...overrides,
  });
  const published = acceptPublishReceipt(request('Approved'), receipt(), '2026-11-10T10:00:00.000Z');

  it('recognises the same registry write, also after the image was withdrawn', () => {
    expect(isPublishReceiptReplay(published, receipt())).toBe(true);
    expect(isPublishReceiptReplay(published, receipt({ targetReference: REFERENCE.toUpperCase(), workerId: 'retry' }))).toBe(true);
    expect(isPublishReceiptReplay({ ...published, status: 'Withdrawn' }, receipt())).toBe(true);
  });

  it('records a verified latest alias and binds retries to its digest', () => {
    const target = { registry: 'harbor.example', project: 'ssi-images', repository: 'approved/nginx', tagReference: REFERENCE };
    const latestReference = 'harbor.example/ssi-images/approved/nginx:latest';
    const withAlias = receipt({ latestReference, latestDigest: DIGEST });
    const saved = acceptPublishReceipt(request('Approved', { target }), withAlias);
    expect(saved.publish.receipt).toMatchObject({ latestReference, latestDigest: DIGEST });
    expect(isPublishReceiptReplay(saved, withAlias)).toBe(true);
    expect(isPublishReceiptReplay(saved, { ...withAlias, latestDigest: OTHER })).toBe(false);
    expect(isPublishReceiptReplay(saved, receipt())).toBe(false);
    for (const invalid of [
      { latestReference, latestDigest: OTHER },
      { latestReference: 'harbor.example/other/nginx:latest', latestDigest: DIGEST },
      { latestReference },
      { latestDigest: DIGEST },
    ]) {
      expect(() => acceptPublishReceipt(request('Approved', { target }), receipt(invalid))).toThrow(/Latest alias/);
    }
  });

  it('is not a replay when anything about the write differs or nothing was published', () => {
    expect(isPublishReceiptReplay(published, receipt({ targetDigest: OTHER }))).toBe(false);
    expect(isPublishReceiptReplay(published, receipt({ targetReference: `${REFERENCE}-other` }))).toBe(false);
    expect(isPublishReceiptReplay(published, receipt({ requestId: 'PUB-0013' }))).toBe(false);
    expect(isPublishReceiptReplay(published, receipt({ verified: false }))).toBe(false);
    expect(isPublishReceiptReplay(published, receipt({ contractVersion: 'ssi.publish-receipt/v0' }))).toBe(false);
    expect(isPublishReceiptReplay(request('Approved'), receipt())).toBe(false);
    expect(isPublishReceiptReplay({ ...published, status: 'Rejected' }, receipt())).toBe(false);
  });
});

describe('cancelForWithdrawnImage and receiptBaseline', () => {
  it('cancels only open requests', () => {
    for (const status of ['Published', 'Rejected', 'Withdrawn', 'Cancelled']) {
      expect(() => cancelForWithdrawnImage(request(status), decision())).toThrow(/Only an open publish request/);
    }
  });

  it('checks a late receipt only for a request that was approved when it was cancelled', () => {
    const approved = cancelForWithdrawnImage(request('Approved'), decision());
    const waiting = cancelForWithdrawnImage(request('ApprovalRequired'), decision());
    expect(receiptBaseline(approved).status).toBe('Approved');
    expect(receiptBaseline(waiting).status).toBe('Cancelled');
    expect(receiptBaseline(request('Published')).status).toBe('Published');
  });
});
