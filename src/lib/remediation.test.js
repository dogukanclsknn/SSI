import { describe, expect, it } from 'vitest';
import {
  createDryRunRemediationJob,
  planOsPackageRemediation,
  proposePatchedReference,
  replanDryRunFromCanonicalReport,
} from './remediation.js';

const ubuntuReport = {
  id: 'registry.example.com/payment-api:1.2.3',
  image: 'registry.example.com/payment-api:1.2.3',
  digest: 'sha256:abc123',
  os: 'ubuntu 22.04',
  scanner: 'Trivy',
  findings: [
    {
      cve: 'CVE-2024-3094',
      package: 'xz-utils',
      installed: '5.2.5-2ubuntu1',
      fixed: '5.2.5-2ubuntu1.1',
      severity: 'Critical',
      cvss: 10,
      class: 'os-pkgs',
      type: 'ubuntu',
    },
    {
      cve: 'CVE-2022-37434',
      package: 'zlib1g',
      installed: '1.2.11.dfsg-2ubuntu9',
      fixed: '-',
      severity: 'Medium',
      cvss: 6.5,
      class: 'os-pkgs',
      type: 'ubuntu',
    },
    {
      cve: 'CVE-2026-0001',
      package: 'axios',
      installed: '1.0.0',
      fixed: '1.1.0',
      severity: 'High',
      cvss: 7.5,
      class: 'lang-pkgs',
      type: 'npm',
    },
  ],
};

describe('planOsPackageRemediation', () => {
  it('plans only fixed OS package findings', () => {
    const plan = planOsPackageRemediation(ubuntuReport);

    expect(plan.before).toEqual({ critical: 1, high: 0, medium: 1, low: 0 });
    expect(plan.plannedFixes).toHaveLength(1);
    expect(plan.plannedFixes[0]).toMatchObject({ cve: 'CVE-2024-3094', package: 'xz-utils' });
    expect(plan.remaining).toEqual([
      expect.objectContaining({ cve: 'CVE-2022-37434', reason: 'No fixed package version is available.' }),
    ]);
    expect(plan.excluded).toEqual([
      expect.objectContaining({ cve: 'CVE-2026-0001', reason: expect.stringContaining('outside') }),
    ]);
  });

  it('blocks Wolfi targets rather than producing a Copa plan', () => {
    const plan = planOsPackageRemediation({
      ...ubuntuReport,
      os: 'Wolfi',
      findings: [ubuntuReport.findings[0]],
    });

    expect(plan.plannedFixes).toHaveLength(0);
    expect(plan.remaining[0].reason).toContain('Wolfi');
  });
});

describe('createDryRunRemediationJob', () => {
  it('creates an auditable plan without claiming that an image was patched', () => {
    const job = createDryRunRemediationJob({
      id: 'RM-DRY-0001',
      report: ubuntuReport,
      createdAt: '2026-07-17T10:00:00.000Z',
    });

    expect(job).toMatchObject({
      id: 'RM-DRY-0001',
      mode: 'dry-run',
      status: 'Planned',
      lifecycleState: 'planned',
      proposedPatchedTag: 'registry.example.com/payment-api:1.2.3-copa-r1',
      patchedImageDigest: '',
      verificationStatus: 'Pending',
    });
    expect(job.fixed).toEqual([]);
    expect(job.after).toBeNull();
    expect(job.executionReadiness).toMatchObject({ dispatchAllowed: false, workerConfigured: false });
    expect(job.logs.at(-1)).toContain('No image pull');
  });

  it('re-evaluates a blocked dry run only after a validated canonical OS-only report is attached', () => {
    const harborOnlyJob = createDryRunRemediationJob({
      id: 'RM-DRY-0002',
      report: {
        ...ubuntuReport,
        findings: [{ ...ubuntuReport.findings[0], class: 'unknown' }],
      },
      createdAt: '2026-07-20T10:00:00.000Z',
    });

    const replanned = replanDryRunFromCanonicalReport({
      job: harborOnlyJob,
      acceptedAt: '2026-07-20T10:05:00.000Z',
      canonicalReport: {
        normalizedReport: ubuntuReport,
        receipt: {
          reportId: 'CTR-4c2d1a8f7b30',
          contentDigest: 'sha256:4c2d1a8f7b30d467e87eab1250e77bf9e5d5945d0c4869ec3f0c6d341f07f6b4',
          sourceDigest: ubuntuReport.digest,
          artifactName: ubuntuReport.image,
          scope: 'os-packages-only',
          schemaVersion: 2,
          findingCount: 2,
        },
      },
    });

    expect(harborOnlyJob.status).toBe('Blocked');
    expect(replanned).toMatchObject({
      id: 'RM-DRY-0002',
      status: 'Planned',
      sourceDigest: ubuntuReport.digest,
      canonicalReport: expect.objectContaining({
        sourceDigest: ubuntuReport.digest,
        acceptedAt: '2026-07-20T10:05:00.000Z',
      }),
    });
    expect(replanned.plannedFixes).toHaveLength(1);
    expect(replanned.executionReadiness.requirements.find((item) => item.id === 'canonical-trivy-report')).toMatchObject({
      met: true,
    });
  });
});

describe('proposePatchedReference', () => {
  it('uses an immutable-looking patched tag without modifying the source reference', () => {
    expect(proposePatchedReference('harbor.example.com/team/app@sha256:abc')).toBe(
      'harbor.example.com/team/app:latest-copa-r1',
    );
  });
});
