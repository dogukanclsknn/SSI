import { describe, expect, it } from 'vitest';
import {
  EVIDENCE_PURPOSE,
  createWorkerEvidenceHeaders,
  verifyWorkerEvidenceRequest,
  WorkerEvidenceAuthenticationError,
} from './workerEvidenceAuth.js';

const secret = 'worker-evidence-test-secret-with-at-least-32-bytes';
const jobId = 'RM-DRY-0001';
const workerId = 'LinuxAgent1:build-agent-01';
const now = Date.UTC(2026, 6, 22, 9, 30, 0);
const timestamp = Math.floor(now / 1000);
const rawBody = Buffer.from(JSON.stringify({ contractVersion: 'ssi.copa-remediation-poc/v1alpha1' }));

function signedRequest(overrides = {}) {
  const values = {
    jobId,
    rawBody,
    secret,
    workerId,
    timestamp,
    ...overrides,
  };
  return {
    ...values,
    headers: createWorkerEvidenceHeaders(values),
  };
}

describe('worker evidence authentication', () => {
  it('accepts a fresh request bound to the job, worker, and exact body', () => {
    const request = signedRequest();

    expect(verifyWorkerEvidenceRequest({ ...request, now })).toEqual({
      contentDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      timestamp,
      version: 'v1',
      workerId,
    });
  });

  it('rejects body tampering and a signature replayed for another job', () => {
    const request = signedRequest();

    expect(() =>
      verifyWorkerEvidenceRequest({ ...request, rawBody: Buffer.from('{"tampered":true}'), now }),
    ).toThrow(WorkerEvidenceAuthenticationError);
    expect(() => verifyWorkerEvidenceRequest({ ...request, jobId: 'RM-DRY-9999', now })).toThrow(
      WorkerEvidenceAuthenticationError,
    );
  });

  it('rejects expired and materially future-dated requests', () => {
    const stale = signedRequest({ timestamp: timestamp - 301 });
    const future = signedRequest({ timestamp: timestamp + 31 });

    expect(() => verifyWorkerEvidenceRequest({ ...stale, now })).toThrow(
      WorkerEvidenceAuthenticationError,
    );
    expect(() => verifyWorkerEvidenceRequest({ ...future, now })).toThrow(
      WorkerEvidenceAuthenticationError,
    );
  });

  it('fails closed when the server signing secret is not securely configured', () => {
    const request = signedRequest();

    expect(() => verifyWorkerEvidenceRequest({ ...request, secret: 'too-short', now })).toThrowError(
      expect.objectContaining({ statusCode: 503 }),
    );
  });
});

describe('evidence purpose (domain separation)', () => {
  it('accepts a supply-chain signature only for the supply-chain purpose', () => {
    const request = signedRequest({ purpose: EVIDENCE_PURPOSE.SUPPLY_CHAIN });
    expect(
      verifyWorkerEvidenceRequest({ ...request, now, purpose: EVIDENCE_PURPOSE.SUPPLY_CHAIN }).workerId,
    ).toBe(workerId);
    expect(() =>
      verifyWorkerEvidenceRequest({ ...request, now, purpose: EVIDENCE_PURPOSE.REMEDIATION }),
    ).toThrow(WorkerEvidenceAuthenticationError);
  });

  it('never accepts a remediation-evidence signature as supply-chain evidence', () => {
    const request = signedRequest();
    expect(() =>
      verifyWorkerEvidenceRequest({ ...request, now, purpose: EVIDENCE_PURPOSE.SUPPLY_CHAIN }),
    ).toThrow(WorkerEvidenceAuthenticationError);
  });
});

describe('candidate test evidence purpose', () => {
  it('accepts a candidate-test signature only for the candidate-test purpose', () => {
    const request = signedRequest({ purpose: EVIDENCE_PURPOSE.CANDIDATE_TEST });
    expect(verifyWorkerEvidenceRequest({ ...request, now, purpose: EVIDENCE_PURPOSE.CANDIDATE_TEST }).workerId).toBe(workerId);
    for (const purpose of [EVIDENCE_PURPOSE.REMEDIATION, EVIDENCE_PURPOSE.SUPPLY_CHAIN]) {
      expect(() => verifyWorkerEvidenceRequest({ ...request, now, purpose })).toThrow(WorkerEvidenceAuthenticationError);
    }
  });
});
