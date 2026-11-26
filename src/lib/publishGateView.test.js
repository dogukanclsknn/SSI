import { describe, expect, it } from 'vitest';
import { derivePublishGateView } from './publishGateView.js';

const outputDigest = `sha256:${'0c70cf19'.repeat(8)}`;

const verifiedJob = {
  id: 'RM-EXEC-0002',
  mode: 'execution',
  status: 'Verified',
  patchedImageDigest: outputDigest,
  publishGate: {
    allowed: false,
    status: 'Blocked',
    reason: 'Verified PoC output is not approved for central publish.',
    approvedPublishAttempted: false,
  },
};

function publishRequest(overrides = {}) {
  return {
    id: 'PUB-0003',
    jobId: 'RM-EXEC-0002',
    status: 'ApprovalRequired',
    source: { digest: outputDigest },
    target: { tagReference: 'harbor.example.com/approved/app:1.0.0' },
    publish: { status: 'NotStarted', receipt: null },
    ...overrides,
  };
}

describe('derivePublishGateView', () => {
  it('falls back to the immutable evidence gate when no publish request exists', () => {
    const view = derivePublishGateView({ job: verifiedJob, publishRequests: [] });

    expect(view.status).toBe('Blocked');
    expect(view.label).toBe('Publish blocked');
    expect(view.reason).toBe('Verified PoC output is not approved for central publish.');
    expect(view.request).toBeNull();
  });

  it('falls back safely when the job is missing', () => {
    const view = derivePublishGateView();

    expect(view.status).toBe('Blocked');
    expect(view.reason).toBe('Patched image is not approved for central publish yet.');
  });

  // Faz 4 regresyonu: PUB-0003 Published olduğu hâlde kart "Publish blocked" gösteriyordu.
  it('reports a completed central publish even though the evidence gate stays blocked', () => {
    const view = derivePublishGateView({
      job: verifiedJob,
      publishRequests: [
        publishRequest({
          status: 'Published',
          publish: {
            status: 'Published',
            receipt: { targetReference: 'harbor.example.com/approved/app:1.0.0' },
          },
        }),
      ],
    });

    expect(view.status).toBe('Published');
    expect(view.label).toBe('Published');
    expect(view.tone).toBe('published');
    expect(view.reason).toContain('harbor.example.com/approved/app:1.0.0');
    expect(view.reason).toContain('PUB-0003');
  });

  it('matches a publish request by output digest when the job id differs', () => {
    const view = derivePublishGateView({
      job: verifiedJob,
      publishRequests: [publishRequest({ jobId: 'RM-EXEC-0001' })],
    });

    expect(view.status).toBe('ApprovalRequired');
    expect(view.label).toBe('Approval required');
  });

  it('ignores publish requests belonging to another job and digest', () => {
    const view = derivePublishGateView({
      job: verifiedJob,
      publishRequests: [
        publishRequest({ id: 'PUB-0001', jobId: 'RM-EXEC-0001', source: { digest: `sha256:${'ab'.repeat(32)}` } }),
      ],
    });

    expect(view.status).toBe('Blocked');
    expect(view.request).toBeNull();
  });

  it('prefers the most advanced status when several requests target the same output', () => {
    const view = derivePublishGateView({
      job: verifiedJob,
      publishRequests: [
        publishRequest({ id: 'PUB-0002', status: 'Blocked' }),
        publishRequest({ id: 'PUB-0003', status: 'Approved' }),
      ],
    });

    expect(view.status).toBe('Approved');
    expect(view.request.id).toBe('PUB-0003');
  });
});

describe('derivePublishGateView — rejected and withdrawn', () => {
  const withdrawal = {
    digest: outputDigest,
    withdrawnBy: 'sam.lee',
    withdrawnAt: '2026-11-09T10:00:00.000Z',
    reason: 'Consumer saw broken TLS after publish.',
    category: 'functional',
    targetReference: 'harbor.example.com/approved/app:1.0.0',
  };

  it('shows a withdrawal above every other request and tells people not to use the image', () => {
    const view = derivePublishGateView({
      job: verifiedJob,
      publishRequests: [
        publishRequest({ id: 'PUB-0004', status: 'Published' }),
        publishRequest({ id: 'PUB-0003', status: 'Withdrawn', withdrawal }),
      ],
    });
    expect(view).toMatchObject({ status: 'Withdrawn', label: 'Withdrawn', tone: 'withdrawn', withdrawal });
    expect(view.request.id).toBe('PUB-0003');
    expect(view.reason).toBe(
      'Withdrawn by sam.lee on 2026-11-09 10:00 UTC (harbor.example.com/approved/app:1.0.0): ' +
        'Consumer saw broken TLS after publish. Do not use this image; it can no longer be published.',
    );
  });

  it('trusts the job record even when no request is loaded', () => {
    const view = derivePublishGateView({ job: { ...verifiedJob, publishWithdrawal: withdrawal }, publishRequests: [] });
    expect(view.status).toBe('Withdrawn');
    expect(view.request).toBeNull();
  });

  it('shows a rejection with the approver and reason, below any other request', () => {
    const rejected = publishRequest({
      status: 'Rejected',
      rejection: { rejectedBy: 'sam.lee', reason: 'Stale request, not needed.' },
    });
    expect(derivePublishGateView({ job: verifiedJob, publishRequests: [rejected] })).toMatchObject({
      status: 'Rejected',
      label: 'Publish rejected',
      tone: 'blocked',
      reason: 'Publish request PUB-0003 was rejected by sam.lee: Stale request, not needed.',
    });
    const blocked = publishRequest({ id: 'PUB-0004', status: 'Blocked' });
    expect(derivePublishGateView({ job: verifiedJob, publishRequests: [rejected, blocked] }).request.id).toBe('PUB-0004');
  });
});
