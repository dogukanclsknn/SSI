import { describe, expect, it } from 'vitest';
import { normalizeTrivyScan } from './trivy.js';

const trivyScan = {
  SchemaVersion: 2,
  ArtifactName: 'registry.example.com/payment-api:1.2.3',
  ArtifactType: 'container_image',
  Metadata: {
    ImageID: 'sha256:image-id',
    RepoTags: ['registry.example.com/payment-api:1.2.3'],
    RepoDigests: ['registry.example.com/payment-api@sha256:digest-id'],
    OS: {
      Family: 'ubuntu',
      Name: '22.04',
    },
  },
  Results: [
    {
      Target: 'ubuntu:22.04',
      Class: 'os-pkgs',
      Type: 'ubuntu',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2024-3094',
          PkgName: 'xz-utils',
          InstalledVersion: '5.2.5-2ubuntu1',
          FixedVersion: '5.2.5-2ubuntu1.1',
          Status: 'fixed',
          Severity: 'CRITICAL',
          Title: 'Backdoor in XZ Utils',
          CVSS: {
            nvd: {
              V3Score: 10,
              V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            },
          },
        },
        {
          VulnerabilityID: 'CVE-2022-37434',
          PkgName: 'zlib1g',
          InstalledVersion: '1.2.11.dfsg-2ubuntu9',
          FixedVersion: '',
          Status: 'affected',
          Severity: 'MEDIUM',
          Title: 'Heap-based Buffer Over-read',
          CVSS: {
            nvd: {
              V3Score: 6.5,
            },
          },
        },
      ],
    },
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-IGNORED',
          PkgName: 'demo',
          Severity: 'HIGH',
        },
      ],
    },
  ],
};

describe('normalizeTrivyScan', () => {
  it('Trivy OS package findings modelini Scan Results formatına çevirir', () => {
    const report = normalizeTrivyScan(trivyScan);

    expect(report.id).toBe('registry.example.com/payment-api:1.2.3');
    expect(report.digest).toBe('sha256:digest-id');
    expect(report.os).toBe('ubuntu 22.04');
    expect(report.scanner).toBe('Trivy');
    expect(report.findings).toHaveLength(2);
  });

  it('fixable ve no-fix bulguları ayırır', () => {
    const report = normalizeTrivyScan(trivyScan);

    expect(report.findings[0]).toMatchObject({
      cve: 'CVE-2024-3094',
      package: 'xz-utils',
      fixed: '5.2.5-2ubuntu1.1',
      severity: 'Critical',
      cvss: 10,
      epss: null,
      status: 'Fix available',
    });
    expect(report.findings[1]).toMatchObject({
      cve: 'CVE-2022-37434',
      package: 'zlib1g',
      fixed: '-',
      severity: 'Medium',
      cvss: 6.5,
      status: 'No fix',
    });
  });
});
