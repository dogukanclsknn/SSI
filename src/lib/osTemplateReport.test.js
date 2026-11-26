import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildManifest,
  buildScanReport,
  comparePackages,
  countBySeverity,
  countUniqueCves,
  osOf,
  parseMinimized,
  parsePackages,
  renderMarkdown,
  vulnerabilitiesOf,
} from '../../poc/os-template/host/template-report.mjs';

// Trivy JSON as `trivy rootfs --format json` writes it (SchemaVersion 2).
const trivy = (vulnerabilities) => ({
  SchemaVersion: 2,
  ArtifactName: '/',
  ArtifactType: 'filesystem',
  Results: [
    {
      Target: '/ (ubuntu 24.04)',
      Class: 'os-pkgs',
      Type: 'ubuntu',
      Vulnerabilities: vulnerabilities,
    },
  ],
});
const vuln = (VulnerabilityID, PkgName, Severity, FixedVersion = '', InstalledVersion = '1.0') => ({
  VulnerabilityID,
  PkgName,
  InstalledVersion,
  FixedVersion,
  Severity,
});

const BEFORE = trivy([
  vuln('CVE-2026-0001', 'openssl', 'CRITICAL', '3.0.13-0ubuntu3.6'),
  vuln('CVE-2026-0002', 'libc6', 'HIGH', '2.39-0ubuntu8.5'),
  vuln('CVE-2026-0003', 'curl', 'MEDIUM'),
  vuln('CVE-2026-0003', 'curl', 'MEDIUM'), // the same finding twice (two targets) counts once
]);

describe('reading Trivy results', () => {
  it('keeps one entry per CVE and package, most severe first', () => {
    const items = vulnerabilitiesOf(BEFORE);
    expect(items.map((item) => `${item.severity}:${item.id}:${item.pkg}`)).toEqual([
      'CRITICAL:CVE-2026-0001:openssl',
      'HIGH:CVE-2026-0002:libc6',
      'MEDIUM:CVE-2026-0003:curl',
    ]);
    expect(countBySeverity(items)).toMatchObject({
      total: 3,
      critical: 1,
      high: 1,
      medium: 1,
      fixable: 2,
    });
  });

  it('accepts a clean scan and refuses something that is not a Trivy report', () => {
    expect(
      vulnerabilitiesOf({ SchemaVersion: 2, Results: [{ Target: '/', Class: 'os-pkgs' }] }),
    ).toEqual([]);
    expect(vulnerabilitiesOf({ SchemaVersion: 2 })).toEqual([]);
    expect(() => vulnerabilitiesOf(null)).toThrow(/Not a Trivy/);
    expect(() => vulnerabilitiesOf({ Results: 'x' })).toThrow(/Not a Trivy/);
  });

  it('maps an unknown severity to UNKNOWN', () => {
    expect(vulnerabilitiesOf(trivy([vuln('CVE-2026-9', 'zlib1g', 'weird')]))[0].severity).toBe(
      'UNKNOWN',
    );
  });
});

describe('the before/after report and the gate', () => {
  const before = vulnerabilitiesOf(BEFORE);

  it('passes when the upgrade closed every vulnerability that had a fix', () => {
    const after = vulnerabilitiesOf(trivy([vuln('CVE-2026-0003', 'curl', 'MEDIUM')]));
    const report = buildScanReport({ before, after });
    expect(report.gate).toMatchObject({ passed: true, enforced: true });
    expect(report.resolved).toMatchObject({ total: 2, critical: 1, high: 1 });
    expect(report.remainingUnfixed.map((item) => item.id)).toEqual(['CVE-2026-0003']);
    expect(report.introduced.total).toBe(0);
  });

  it('fails when a vulnerability with a fix is still there, unless the gate is off', () => {
    const after = vulnerabilitiesOf(
      trivy([vuln('CVE-2026-0002', 'libc6', 'HIGH', '2.39-0ubuntu8.5')]),
    );
    const report = buildScanReport({ before, after });
    expect(report.gate.passed).toBe(false);
    expect(report.gate.reason).toMatch(/1 vulnerability has a fix/);
    expect(buildScanReport({ before, after, failOnFixable: false }).gate).toMatchObject({
      passed: true,
      enforced: false,
    });
  });

  it('reports vulnerabilities the upgrade brought in', () => {
    const after = vulnerabilitiesOf(
      trivy([vuln('CVE-2026-0100', 'linux-image-6.8.0-90-generic', 'LOW')]),
    );
    expect(buildScanReport({ before, after }).introducedItems.map((item) => item.id)).toEqual([
      'CVE-2026-0100',
    ]);
  });

  it('lists upgraded, added and removed packages', () => {
    const changes = comparePackages(
      parsePackages('openssl\t3.0.13-0ubuntu3.5\nlibc6\t2.39-0ubuntu8.4\nold-tool\t1\n'),
      parsePackages('openssl\t3.0.13-0ubuntu3.6\nlibc6\t2.39-0ubuntu8.4\nopen-vm-tools\t2:12.4\n'),
    );
    expect(changes).toEqual({
      upgraded: [{ name: 'openssl', from: '3.0.13-0ubuntu3.5', to: '3.0.13-0ubuntu3.6' }],
      added: [{ name: 'open-vm-tools', version: '2:12.4' }],
      removed: [{ name: 'old-tool', version: '1' }],
    });
  });

  it('renders a readable summary with the blocking items first', () => {
    const after = vulnerabilitiesOf(
      trivy([
        vuln('CVE-2026-0002', 'libc6', 'HIGH', '2.39-0ubuntu8.5'),
        vuln('CVE-2026-0003', 'curl', 'MEDIUM'),
      ]),
    );
    const markdown = renderMarkdown(
      buildScanReport({
        before,
        after,
        kernelBefore: '6.8.0-85-generic',
        kernelAfter: '6.8.0-90-generic',
      }),
      {
        templateName: 'ssi-ubuntu-2404',
        templateVersion: '20261119.1',
      },
    );
    expect(markdown).toContain('**Gate:** FAILED');
    expect(markdown).toContain('| Before the upgrade | 3 | 1 | 1 | 1 | 0 | 0 | 2 |');
    expect(markdown).toContain('Kernel: 6.8.0-85-generic → 6.8.0-90-generic.');
    expect(markdown.indexOf('Still present with a fix')).toBeLessThan(
      markdown.indexOf('no fix released yet'),
    );
  });
});

describe('the template manifest', () => {
  let directory;
  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  it('records each delivery format with its size, SHA-256 and signature', async () => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-template-'));
    writeFileSync(join(directory, 't-1.qcow2'), 'qcow2 bytes');
    writeFileSync(join(directory, 't-1.ova'), 'ova bytes');
    writeFileSync(join(directory, 't-1.vhdx'), 'vhdx bytes');
    writeFileSync(join(directory, 'SHA256SUMS'), 'not an artifact');
    const report = buildScanReport({ before: vulnerabilitiesOf(BEFORE), after: [] });
    const manifest = await buildManifest({
      artifactsDir: directory,
      report,
      templateName: 't',
      templateVersion: '1',
      buildId: '42',
      baseImageUrl:
        'https://cloud-images.ubuntu.com/releases/noble/release-20261101/ubuntu-24.04-server-cloudimg-amd64.img',
      baseImageSha256: 'a'.repeat(64),
      signed: true,
      keyId: 'cosign (sha256:abc)',
      tools: { cosign: 'v2.4.1' },
      createdAt: '2026-11-19T10:00:00.000Z',
    });
    expect(manifest.manifestVersion).toBe('ssi.os-template-manifest/v1');
    expect(manifest.artifacts).toEqual([
      {
        file: 't-1.ova',
        format: 'ova',
        platforms: ['vmware-vsphere'],
        sizeBytes: 9,
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        signature: 't-1.ova.sig',
      },
      {
        file: 't-1.qcow2',
        format: 'qcow2',
        platforms: ['proxmox', 'kvm'],
        sizeBytes: 11,
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        signature: 't-1.qcow2.sig',
      },
      {
        file: 't-1.vhdx',
        format: 'vhdx',
        platforms: ['hyper-v'],
        sizeBytes: 10,
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        signature: 't-1.vhdx.sig',
      },
    ]);
    expect(manifest.scan.gate.passed).toBe(true);
    expect(manifest.signing).toEqual({
      signed: true,
      tool: 'cosign v2.4.1',
      keyId: 'cosign (sha256:abc)',
      publicKey: 'cosign.pub',
    });
  });

  it('refuses a directory without a template file', async () => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-template-'));
    await expect(
      buildManifest({
        artifactsDir: directory,
        report: buildScanReport({ before: [], after: [] }),
      }),
    ).rejects.toThrow(/No \.qcow2, \.ova or \.vhdx/);
  });
});

describe('the template profile in the report', () => {
  it('records what the profile removed and why, and what was listed but absent', () => {
    const minimized = parseMinimized({
      plan: 'telnet\t0.17\trequested\nlibfoo\t1.0\tdependency\n',
      removed: 'telnet\t0.17\nlibfoo\t1.0\n',
      skipped: 'ghost\n',
      profile: 'web-minimal',
    });
    expect(minimized).toEqual({
      profile: 'web-minimal',
      removed: [
        { name: 'telnet', version: '0.17', reason: 'requested' },
        { name: 'libfoo', version: '1.0', reason: 'dependency' },
      ],
      skipped: ['ghost'],
    });
    const markdown = renderMarkdown(buildScanReport({ before: [], after: [], minimized }));
    expect(markdown).toContain(
      'Template profile web-minimal: 2 package(s) removed; listed but not installed: ghost.',
    );
    expect(markdown).toContain('| libfoo | 1.0 | dependency |');
  });

  it('is absent when no profile was applied', () => {
    expect(parseMinimized({})).toBeNull();
    expect(buildScanReport({ before: [], after: [] }).minimized).toBeNull();
  });
});

// The first real Ubuntu run (ADO 20261124.2) reported 25,352 findings before and "3,802 new"
// after: a kernel CVE counts once per kernel package, and the upgrade renamed every package
// (…-147 → …-151). Counted per CVE, a renamed package brings nothing new.
describe('counting per CVE', () => {
  const kernel = (version, id, fixed = '') =>
    ['linux-image', 'linux-modules', 'linux-headers'].map((name) =>
      vuln(id, `${name}-${version}-generic`, 'HIGH', fixed),
    );

  it('counts each CVE once, at its highest severity, fixable when any package has a fix', () => {
    const items = vulnerabilitiesOf(
      trivy([
        ...kernel('6.8.0-147', 'CVE-2026-1000', '6.8.0-151.151'),
        vuln('CVE-2026-1000', 'linux-libc-dev', 'CRITICAL'),
        vuln('CVE-2026-2000', 'curl', 'LOW'),
      ]),
    );
    expect(countBySeverity(items)).toMatchObject({ total: 5, fixable: 3 });
    expect(countUniqueCves(items)).toEqual({
      total: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      unknown: 0,
      fixable: 1,
    });
  });

  it('does not call a CVE new because the package carrying it was renamed', () => {
    const report = buildScanReport({
      before: vulnerabilitiesOf(
        trivy([
          ...kernel('6.8.0-147', 'CVE-2026-1000', '6.8.0-151.151'),
          ...kernel('6.8.0-147', 'CVE-2026-3000'),
        ]),
      ),
      after: vulnerabilitiesOf(trivy(kernel('6.8.0-151', 'CVE-2026-3000'))),
      os: { family: 'ubuntu', name: '24.04' },
    });
    expect(report.introduced.total).toBe(3); // per package: the renamed packages look new
    expect(report.cves).toMatchObject({
      before: { total: 2, fixable: 1 },
      after: { total: 1, fixable: 0 },
      resolved: { total: 1 },
      introduced: { total: 0 },
    });
    const markdown = renderMarkdown(report);
    expect(markdown).toContain('Scanned as: ubuntu 24.04');
    expect(markdown).toContain('| Before the upgrade | 2 | 0 | 2 | 0 | 0 | 0 | 1 |');
    expect(markdown.indexOf('### CVEs')).toBeLessThan(markdown.indexOf('### Findings'));
  });

  it('reads the operating system Trivy recognised, and none when it saw none', () => {
    expect(osOf({ Metadata: { OS: { Family: 'ubuntu', Name: '24.04' } } })).toEqual({
      family: 'ubuntu',
      name: '24.04',
    });
    expect(osOf({ Metadata: { OS: { Family: 'none', Name: '' } } })).toBeNull();
    expect(osOf({})).toBeNull();
  });
});
