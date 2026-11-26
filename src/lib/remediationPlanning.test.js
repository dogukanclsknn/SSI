import { describe, expect, it } from 'vitest';
import {
  latestRemediationJobForReport,
  planFreshness,
  remediationJobsForReport,
  scanTime,
  summarizeScanReport,
} from './remediationPlanning.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const OTHER = `sha256:${'b'.repeat(64)}`;
const report = { id: 'ssi-images/onboarded/nginx:1.26.3', digest: DIGEST };

describe('remediationJobsForReport', () => {
  const jobs = [
    { id: 'RM-DRY-0001', scanReportId: report.id, createdAt: '2026-10-10T10:00:00Z' },
    {
      id: 'RM-DRY-0002',
      scanReportId: 'other',
      sourceDigest: DIGEST.toUpperCase().replace('SHA256', 'sha256'),
      createdAt: '2026-10-12T10:00:00Z',
    },
    {
      id: 'RM-EXEC-0001',
      scanReportId: 'other',
      sourceDigest: OTHER,
      verifiedAt: '2026-10-13T10:00:00Z',
    },
  ];

  it('matches by scan report id or by the immutable source digest, newest first', () => {
    expect(remediationJobsForReport(jobs, report).map((job) => job.id)).toEqual([
      'RM-DRY-0002',
      'RM-DRY-0001',
    ]);
    expect(latestRemediationJobForReport(jobs, report).id).toBe('RM-DRY-0002');
  });

  it('never matches on a short or missing digest', () => {
    const shortDigest = { id: 'x', digest: 'sha256:aaaaaaaaaaaa' };
    expect(
      remediationJobsForReport([{ id: 'J', sourceDigest: 'sha256:aaaaaaaaaaaa' }], shortDigest),
    ).toEqual([]);
    expect(remediationJobsForReport([{ id: 'J' }], { id: '' })).toEqual([]);
  });

  it('returns nothing for an unknown report or job list', () => {
    expect(remediationJobsForReport(jobs, null)).toEqual([]);
    expect(latestRemediationJobForReport(undefined, report)).toBeNull();
  });
});

describe('summarizeScanReport', () => {
  it('counts findings by severity and how many have a fixed version', () => {
    expect(
      summarizeScanReport({
        findings: [
          { severity: 'Critical', status: 'Fix available' },
          { severity: 'high', status: 'Fix available' },
          { severity: 'Medium', status: 'No fix' },
          { severity: 'Negligible' },
        ],
      }),
    ).toEqual({
      total: 4,
      withFix: 2,
      severity: { critical: 1, high: 1, medium: 1, low: 0, unknown: 1 },
    });
  });

  it('handles a report without findings', () => {
    expect(summarizeScanReport(undefined)).toEqual({
      total: 0,
      withFix: 0,
      severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    });
  });
});

describe('planFreshness', () => {
  const scanned = { scannedAt: '2026-10-15 12:00' }; // Harbor format, UTC

  it('is current when the job was created from the latest scan', () => {
    expect(planFreshness({ createdAt: '2026-10-15T12:00:30.000Z' }, scanned)).toBe('current');
    expect(planFreshness({ createdAt: '2026-10-15T13:10:00.000Z' }, scanned)).toBe('current');
  });

  it('is stale when the image was re-scanned after the job was created', () => {
    expect(planFreshness({ createdAt: '2026-09-16T10:05:00.000Z' }, scanned)).toBe('stale');
  });

  it('accepts ISO scan times and reports unknown without both timestamps', () => {
    expect(
      planFreshness({ createdAt: '2026-10-15T11:00:00Z' }, { scannedAt: '2026-10-15T12:00:00Z' }),
    ).toBe('stale');
    expect(planFreshness({ createdAt: '' }, scanned)).toBe('unknown');
    expect(planFreshness({ createdAt: '2026-10-15T12:00:00Z' }, { scannedAt: '' })).toBe('unknown');
  });
});

describe('scanTime', () => {
  it('reads Harbor minute timestamps as UTC', () => {
    expect(scanTime('2026-10-15 12:00')).toBe(Date.parse('2026-10-15T12:00:00Z'));
    expect(Number.isNaN(scanTime(''))).toBe(true);
  });
});
