import { describe, expect, it } from 'vitest';
import {
  CVE_REMEDIATION_STATUS,
  cveRemediationStatus,
  indexVerifiedRemediations,
  isVerifiedRemediationJob,
  summarizeCveRemediation,
} from './cveRemediationStatus.js';

const SOURCE = `sha256:${'a'.repeat(64)}`;
const OTHER = `sha256:${'b'.repeat(64)}`;

const verifiedJob = (overrides = {}) => ({
  id: 'RM-EXEC-0001',
  mode: 'execution',
  status: 'Verified',
  verificationStatus: 'Passed',
  sourceDigest: SOURCE,
  scanReportId: 'ssi-images/app:1.0@' + SOURCE,
  verifiedAt: '2026-09-08T10:00:00.000Z',
  patchedImageTag: 'harbor.example/ssi-images/test/app:1.0-patched',
  patchedImageDigest: OTHER,
  fixed: [{ cve: 'CVE-2024-0001', package: 'openssl' }],
  remaining: [{ cve: 'CVE-2024-0002', package: 'libc6' }],
  ...overrides,
});

const image = (overrides = {}) => ({ reportId: 'report-1', digest: SOURCE, ...overrides });

describe('isVerifiedRemediationJob', () => {
  it('accepts only executions that passed verification (same rule as the publish gate)', () => {
    expect(isVerifiedRemediationJob(verifiedJob())).toBe(true);
    expect(isVerifiedRemediationJob(verifiedJob({ mode: 'dry-run' }))).toBe(false);
    expect(isVerifiedRemediationJob(verifiedJob({ status: 'Patched' }))).toBe(false);
    expect(isVerifiedRemediationJob(verifiedJob({ verificationStatus: 'Pending' }))).toBe(false);
    expect(isVerifiedRemediationJob(null)).toBe(false);
  });
});

describe('cveRemediationStatus', () => {
  const index = indexVerifiedRemediations([verifiedJob()]);

  it('marks a finding the verified job removed as remediated, with its evidence', () => {
    expect(cveRemediationStatus(index, image(), 'CVE-2024-0001', ['openssl'])).toEqual({
      status: CVE_REMEDIATION_STATUS.REMEDIATED,
      jobId: 'RM-EXEC-0001',
      verifiedAt: '2026-09-08T10:00:00.000Z',
      patchedImageTag: 'harbor.example/ssi-images/test/app:1.0-patched',
    });
  });

  it('marks a finding that survived the verification re-scan as remaining', () => {
    expect(cveRemediationStatus(index, image(), 'CVE-2024-0002', ['libc6']).status).toBe(
      CVE_REMEDIATION_STATUS.REMAINING,
    );
  });

  it('matches CVE and package case-insensitively and the digest in any case', () => {
    const upper = image({ digest: SOURCE.toUpperCase().replace('SHA256', 'sha256') });
    expect(cveRemediationStatus(index, upper, 'cve-2024-0001', ['OpenSSL']).status).toBe(
      CVE_REMEDIATION_STATUS.REMEDIATED,
    );
  });

  it('treats a CVE as remaining when any affected package survived', () => {
    const job = verifiedJob({
      fixed: [{ cve: 'CVE-2024-0003', package: 'libssl3' }],
      remaining: [{ cve: 'CVE-2024-0003', package: 'openssl' }],
    });
    const result = cveRemediationStatus(
      indexVerifiedRemediations([job]),
      image(),
      'CVE-2024-0003',
      ['libssl3', 'openssl'],
    );
    expect(result.status).toBe(CVE_REMEDIATION_STATUS.REMAINING);
  });

  it('leaves findings the job did not plan, other images and unverified jobs open', () => {
    expect(cveRemediationStatus(index, image(), 'CVE-2024-9999', ['zlib'])).toEqual({
      status: 'open',
    });
    expect(
      cveRemediationStatus(index, image({ reportId: 'x', digest: OTHER }), 'CVE-2024-0001', [
        'openssl',
      ]),
    ).toEqual({
      status: 'open',
    });
    const dryRunOnly = indexVerifiedRemediations([verifiedJob({ mode: 'dry-run' })]);
    expect(cveRemediationStatus(dryRunOnly, image(), 'CVE-2024-0001', ['openssl'])).toEqual({
      status: 'open',
    });
    expect(cveRemediationStatus(undefined, image(), 'CVE-2024-0001', ['openssl'])).toEqual({
      status: 'open',
    });
  });

  it('falls back to the scan report id when the image has no full digest', () => {
    const byReport = image({
      reportId: 'ssi-images/app:1.0@' + SOURCE,
      digest: 'sha256:aaaaaaaaaaaa',
    });
    expect(cveRemediationStatus(index, byReport, 'CVE-2024-0001', ['openssl']).status).toBe(
      CVE_REMEDIATION_STATUS.REMEDIATED,
    );
  });

  it('uses the newest verification of the same source image', () => {
    const older = verifiedJob({ id: 'RM-EXEC-0001', verifiedAt: '2026-09-01T00:00:00.000Z' });
    const newer = verifiedJob({
      id: 'RM-EXEC-0002',
      verifiedAt: '2026-10-01T00:00:00.000Z',
      fixed: [{ cve: 'CVE-2024-0002', package: 'libc6' }],
      remaining: [],
    });
    for (const jobs of [
      [older, newer],
      [newer, older],
    ]) {
      const result = cveRemediationStatus(
        indexVerifiedRemediations(jobs),
        image(),
        'CVE-2024-0002',
        ['libc6'],
      );
      expect(result).toMatchObject({
        status: CVE_REMEDIATION_STATUS.REMEDIATED,
        jobId: 'RM-EXEC-0002',
      });
    }
  });
});

describe('summarizeCveRemediation', () => {
  const withStatus = (...statuses) => statuses.map((status) => ({ remediation: { status } }));

  it('is remediated only when every affected image is remediated', () => {
    expect(summarizeCveRemediation(withStatus('remediated', 'remediated'))).toEqual({
      status: 'remediated',
      remediated: 2,
      remaining: 0,
      open: 0,
      total: 2,
    });
  });

  it('is remaining when any image still has the finding after verification', () => {
    expect(summarizeCveRemediation(withStatus('remediated', 'remaining', 'open')).status).toBe(
      'remaining',
    );
  });

  it('is open (with a partial count) when some images were never remediated', () => {
    expect(summarizeCveRemediation(withStatus('remediated', 'open'))).toMatchObject({
      status: 'open',
      remediated: 1,
      total: 2,
    });
  });

  it('handles no images', () => {
    expect(summarizeCveRemediation([])).toEqual({
      status: 'open',
      remediated: 0,
      remaining: 0,
      open: 0,
      total: 0,
    });
    expect(summarizeCveRemediation(undefined).total).toBe(0);
  });
});
