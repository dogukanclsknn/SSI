import { describe, expect, it } from 'vitest';
import { candidateStageView, candidateTestParameters } from './candidateTestView.js';

const SOURCE = `sha256:${'a'.repeat(64)}`;
const OUTPUT = `sha256:${'b'.repeat(64)}`;

function job(overrides = {}) {
  return {
    id: 'RM-EXEC-0004',
    image: 'ssi-images/onboarded/nginx:alpine',
    sourceDigest: SOURCE,
    patchedImageDigest: OUTPUT,
    patchedImageTag: 'registry.example.com/ssi-images/onboarded/nginx:copa-poc-20261102-alpine-r2',
    ...overrides,
  };
}

describe('candidateTestParameters', () => {
  it('derives digest-pinned references for a job verified before the source reference was stored', () => {
    expect(candidateTestParameters(job())).toEqual({
      remediationJobId: 'RM-EXEC-0004',
      sourceReference: `registry.example.com/ssi-images/onboarded/nginx@${SOURCE}`,
      candidateReference: `registry.example.com/ssi-images/onboarded/nginx@${OUTPUT}`,
    });
  });

  it('prefers the exact source reference from the Copa evidence', () => {
    const exact = `registry.example.com/ssi-images/onboarded/nginx@${SOURCE}`;
    expect(candidateTestParameters(job({ image: 'other', verificationEvidence: { sourceReference: exact } })).sourceReference).toBe(exact);
  });

  it('keeps a registry host that is already in the image name and returns null without digests', () => {
    expect(candidateTestParameters(job({ image: 'registry.local:5000/team/app:1.0' })).sourceReference).toBe(
      `registry.local:5000/team/app@${SOURCE}`,
    );
    expect(candidateTestParameters(job({ patchedImageDigest: '' }))).toBeNull();
  });
});

describe('candidateStageView', () => {
  it('starts with no test and no decision', () => {
    expect(candidateStageView(job())).toMatchObject({ testStatus: 'not-run', acceptanceStatus: 'pending', canAccept: false, ready: false });
  });

  it('is ready only when the test passed and a consumer accepted this digest', () => {
    const tested = job({
      candidateTest: { passed: true, candidateDigest: OUTPUT },
      consumerAcceptance: { decision: 'accepted', candidateDigest: OUTPUT, history: [{ decision: 'accepted', candidateDigest: OUTPUT }] },
    });
    expect(candidateStageView(tested)).toMatchObject({ testStatus: 'passed', acceptanceStatus: 'accepted', canAccept: true, ready: true });
    expect(candidateStageView(tested).history).toHaveLength(1);

    const issue = job({ ...tested, consumerAcceptance: { decision: 'issue-found', candidateDigest: OUTPUT } });
    expect(candidateStageView(issue)).toMatchObject({ acceptanceStatus: 'issue-found', ready: false });
  });

  it("keeps another person's open issue visible after a later acceptance", () => {
    const alice = { decision: 'issue-found', decidedBy: 'alice', decidedAt: '2026-11-04T10:00:00Z', candidateDigest: OUTPUT };
    const bob = { decision: 'accepted', decidedBy: 'bob', decidedAt: '2026-11-04T11:00:00Z', candidateDigest: OUTPUT };
    const view = candidateStageView(
      job({
        candidateTest: { passed: true, candidateDigest: OUTPUT, intake: { channel: 'manual', actor: 'ops.user' } },
        consumerAcceptance: { ...bob, decisionsByActor: { alice, bob } },
      }),
    );
    expect(view).toMatchObject({ acceptanceStatus: 'issue-found', ready: false, manualUploader: 'ops.user' });
    expect(view.acceptance.decidedBy).toBe('alice');
    expect(view.openIssues).toHaveLength(1);
    expect(view.acceptances).toHaveLength(1);
  });

  it('ignores results bound to another digest', () => {
    const stale = job({ candidateTest: { passed: true, candidateDigest: SOURCE } });
    expect(candidateStageView(stale)).toMatchObject({ testStatus: 'not-run', canAccept: false });
  });
});

describe('candidateStageView — withdrawn image', () => {
  it('is never ready again and takes no further decisions', () => {
    const withdrawn = job({
      candidateTest: { passed: true, candidateDigest: OUTPUT },
      consumerAcceptance: { decision: 'accepted', candidateDigest: OUTPUT },
      publishWithdrawal: { digest: OUTPUT, withdrawnBy: 'sam.lee' },
    });
    expect(candidateStageView(withdrawn)).toMatchObject({ withdrawn: true, canAccept: false, ready: false });
  });
});
