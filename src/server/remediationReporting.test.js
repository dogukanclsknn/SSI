import { describe, expect, it } from 'vitest';
import { buildRemediationReport } from './remediationReporting.js';

describe('buildRemediationReport', () => {
  it('aggregates lifecycle counts, fixed findings, and residual weekly severity', () => {
    const report = buildRemediationReport([
      {
        id: 'RM-EXEC-0001',
        mode: 'execution',
        status: 'Verified',
        image: 'harbor.example.com/team/app:patched',
        engine: 'Copacetic',
        engineVersion: 'v0.14.2',
        fixed: [{ cve: 'CVE-1' }, { cve: 'CVE-2' }],
        before: { critical: 1, high: 1, medium: 2, low: 1, unknown: 0 },
        after: { critical: 0, high: 0, medium: 1, low: 1, unknown: 0 },
        publishGate: { status: 'Blocked' },
        verifiedAt: '2026-07-21T14:30:00.000Z',
      },
      {
        id: 'RM-DRY-0002',
        mode: 'dry-run',
        status: 'Planned',
        image: 'harbor.example.com/team/other:source',
        before: { critical: 1, high: 0, medium: 0, low: 0 },
        createdAt: '2026-07-21T15:00:00.000Z',
      },
      {
        id: 'RM-DRY-0003',
        mode: 'dry-run',
        status: 'Blocked',
        image: 'harbor.example.com/team/blocked:source',
        before: { critical: 0, high: 1, medium: 0, low: 0 },
        createdAt: '2026-07-21T16:00:00.000Z',
      },
    ]);

    expect(report.summary).toEqual({
      totalJobs: 3,
      verifiedJobs: 1,
      plannedJobs: 1,
      blockedJobs: 1,
      cvesRemediated: 2,
      publishBlocked: 1,
      publishRequests: 0,
      policyBlocked: 0,
      approvalRequired: 0,
      approvedForPublish: 0,
      published: 0,
      rejected: 0,
      withdrawn: 0,
    });
    expect(report.history[0]).toMatchObject({
      id: 'RM-EXEC-0001',
      engine: 'Copacetic v0.14.2',
      cvesFixed: 2,
      before: 5,
      after: 2,
      status: 'Verified',
    });
    expect(report.trend).toEqual([{ week: '2026-W30', critical: 0, high: 0, medium: 1 }]);
  });

  it('returns an explicit empty report', () => {
    const report = buildRemediationReport([]);

    expect(report.summary.totalJobs).toBe(0);
    expect(report.history).toEqual([]);
    expect(report.trend).toEqual([]);
    expect(Number.isNaN(Date.parse(report.generatedAt))).toBe(false);
  });

  it('keeps planned jobs reportable before severity snapshots exist', () => {
    const report = buildRemediationReport([
      {
        id: 'RM-DRY-0001',
        mode: 'dry-run',
        status: 'Planned',
        image: 'harbor.example.com/team/app:source',
        before: null,
        after: null,
        createdAt: '2026-07-21T15:00:00.000Z',
      },
    ]);

    expect(report.summary).toMatchObject({ totalJobs: 1, plannedJobs: 1, verifiedJobs: 0 });
    expect(report.history[0]).toMatchObject({
      id: 'RM-DRY-0001',
      before: 0,
      after: 0,
      cvesFixed: 0,
      status: 'Planned',
    });
  });
});

describe('buildRemediationReport publish status', () => {
  const job = {
    id: 'RM-EXEC-0001',
    mode: 'execution',
    status: 'Verified',
    patchedImageDigest: `sha256:${'a'.repeat(64)}`,
    fixed: [{ cve: 'CVE-1' }],
    before: { critical: 1 },
    after: {},
    verifiedAt: '2026-09-08T12:16:00.000Z',
  };

  it('keeps a published job Published when a newer request is still pending', () => {
    const report = buildRemediationReport(
      [job],
      [
        { id: 'PUB-0007', jobId: 'RM-EXEC-0001', status: 'ApprovalRequired' },
        {
          id: 'PUB-0006',
          jobId: 'RM-EXEC-0001',
          status: 'Published',
          target: { tagReference: 'r/a:v1' },
        },
      ],
    );
    expect(report.history[0]).toMatchObject({
      publishStatus: 'Published',
      publishRequestId: 'PUB-0006',
      publishTarget: 'r/a:v1',
    });
  });

  it('shows the pending state when nothing has been published yet', () => {
    const report = buildRemediationReport(
      [job],
      [
        { id: 'PUB-0002', jobId: 'RM-EXEC-0001', status: 'Blocked' },
        { id: 'PUB-0003', jobId: 'RM-EXEC-0001', status: 'ApprovalRequired' },
      ],
    );
    expect(report.history[0]).toMatchObject({
      publishStatus: 'ApprovalRequired',
      publishRequestId: 'PUB-0003',
    });
  });

  it('falls back to the job gate when there is no publish request', () => {
    const report = buildRemediationReport([{ ...job, publishGate: { status: 'Blocked' } }], []);
    expect(report.history[0]).toMatchObject({ publishStatus: 'Blocked', publishRequestId: '' });
  });
});
