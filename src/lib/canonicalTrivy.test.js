import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CanonicalTrivyValidationError, validateCanonicalTrivyReport } from './canonicalTrivy.js';

const sourceDigest = 'sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9';

function canonicalReport(overrides = {}) {
  return {
    SchemaVersion: 2,
    Trivy: { Version: '0.70.0' },
    ReportID: 'trivy-report-001',
    CreatedAt: '2026-07-20T10:50:20Z',
    ArtifactName: `harbor.example.com/ssi-images/ssi-remediation-test@${sourceDigest}`,
    ArtifactType: 'container_image',
    Metadata: {
      RepoDigests: [`harbor.example.com/ssi-images/ssi-remediation-test@${sourceDigest}`],
      OS: { Family: 'alpine', Name: '3.7.1', EOSL: true },
    },
    Results: [
      {
        Target: `harbor.example.com/ssi-images/ssi-remediation-test@${sourceDigest} (alpine 3.7.1)`,
        Class: 'os-pkgs',
        Type: 'alpine',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2026-0001',
            PkgName: 'curl',
            InstalledVersion: '7.61.0-r0',
            FixedVersion: '7.61.1-r1',
            Severity: 'CRITICAL',
            CVSS: { nvd: { V3Score: 9.8 } },
          },
        ],
      },
    ],
    ...overrides,
  };
}

describe('validateCanonicalTrivyReport', () => {
  it('accepts an OS-only report bound to the expected immutable source digest', () => {
    const result = validateCanonicalTrivyReport(canonicalReport(), { expectedSourceDigest: sourceDigest });

    expect(result.normalizedReport).toMatchObject({
      digest: sourceDigest,
      os: 'alpine 3.7.1',
      findings: [expect.objectContaining({ cve: 'CVE-2026-0001', class: 'os-pkgs' })],
    });
    expect(result.receipt).toMatchObject({
      sourceDigest,
      scope: 'os-packages-only',
      resultClasses: ['os-pkgs'],
      findingCount: 1,
    });
    expect(result.receipt.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('derives a deterministic receipt id when Trivy does not provide ReportID', () => {
    const report = canonicalReport({ ReportID: '' });
    const first = validateCanonicalTrivyReport(report, { expectedSourceDigest: sourceDigest });
    const second = validateCanonicalTrivyReport(report, { expectedSourceDigest: sourceDigest });

    expect(first.receipt.reportId).toMatch(/^CTR-[a-f0-9]{12}$/);
    expect(second.receipt.reportId).toBe(first.receipt.reportId);
  });

  it('binds the receipt digest to the exact uploaded report bytes', () => {
    const report = canonicalReport();
    const rawContent = `${JSON.stringify(report, null, 2)}\n`;
    const expectedDigest = `sha256:${createHash('sha256').update(rawContent, 'utf8').digest('hex')}`;
    const result = validateCanonicalTrivyReport(report, {
      expectedSourceDigest: sourceDigest,
      rawContent,
    });

    expect(result.receipt.contentDigest).toBe(expectedDigest);
  });

  it('rejects a report for a different immutable artifact', () => {
    const differentDigest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const report = canonicalReport({
      ArtifactName: `harbor.example.com/ssi-images/ssi-remediation-test@${differentDigest}`,
      Metadata: { RepoDigests: [`harbor.example.com/ssi-images/ssi-remediation-test@${differentDigest}`] },
    });

    expect(() => validateCanonicalTrivyReport(report, { expectedSourceDigest: sourceDigest })).toThrow(
      CanonicalTrivyValidationError,
    );
  });

  it('rejects mixed OS and application dependency results', () => {
    const report = canonicalReport({
      Results: [
        ...canonicalReport().Results,
        { Target: 'package-lock.json', Class: 'lang-pkgs', Type: 'npm', Vulnerabilities: [] },
      ],
    });

    expect(() => validateCanonicalTrivyReport(report, { expectedSourceDigest: sourceDigest })).toThrow(
      'only os-pkgs',
    );
  });
});
