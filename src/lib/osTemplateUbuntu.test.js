import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  buildManifest,
  buildScanReport,
  vulnerabilitiesOf,
} from '../../poc/os-template/host/template-report.mjs';
import { assembleResult } from '../../scripts/os-template-evidence.mjs';
import {
  applyOsTemplateResult,
  createOsTemplateBuild,
  decideOsTemplate,
  describeBuildRequest,
  OS_TEMPLATE_BUILD_CONTRACT,
  osTemplateArtifacts,
  osTemplateResultAudit,
  osTemplateRetentionTarget,
  osTemplateSummary,
  validateBuildRequest,
  validateOsTemplateEvidence,
} from './osTemplate.js';
import { findOsTemplateDownload, osTemplateDownloads } from './osTemplateDownloads.js';
import { PipelineRunError } from './pipelineRuns.js';
import { planOsTemplateRun, workerActionsView } from './workerPipelineActions.js';

// Ubuntu 24.04 templates (docs/os-template-poc.md, "Ubuntu"): the request, the result SSI
// accepts from azure-pipelines-os-template-ubuntu.yml and the worker run.
const URL_20261017 =
  'https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img';
// The cloud image of the second ADO run (20261124.2), from its SHA256SUMS.
const IMAGE_SHA = '04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94';
const NOW = Date.parse('2026-11-24T21:00:00.000Z');
const INPUT = {
  os: 'ubuntu-24.04',
  baseImageUrl: URL_20261017,
  baseImageSha256: IMAGE_SHA.toUpperCase(),
  templateName: 'ssi-ubuntu-2404',
  diskSizeGb: 20,
  aptMirror: '',
};
const VERSION = '24.04-20261124-ado-883942';
const requested = (input = INPUT) =>
  createOsTemplateBuild({
    id: 'OST-0002',
    input,
    requestedBy: 'def.op',
    now: new Date(NOW - 3600_000),
  });

const trivy = (vulnerabilities, os = { Family: 'ubuntu', Name: '24.04' }) => ({
  SchemaVersion: 2,
  Metadata: { OS: os },
  Results: [
    {
      Target: 'x (ubuntu 24.04)',
      Class: 'os-pkgs',
      Type: 'ubuntu',
      Vulnerabilities: vulnerabilities,
    },
  ],
});
const vuln = (VulnerabilityID, PkgName, Severity, FixedVersion = '') => ({
  VulnerabilityID,
  PkgName,
  InstalledVersion: '1',
  FixedVersion,
  Severity,
});

// The template manifest exactly as poc/os-template/host/template-report.mjs writes it from a
// worker's reports and files: the contract between the worker and SSI, kept in one place.
let directory;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'ssi-ubuntu-template-'));
});
afterEach(() => rmSync(directory, { recursive: true, force: true }));

async function workerManifest({
  after = [vuln('CVE-2026-3000', 'linux-headers-6.8.0-151-generic', 'HIGH')],
  scannedOs,
  version = VERSION,
  formats = ['qcow2', 'ova', 'vhdx'],
  baseImageSha256 = IMAGE_SHA,
  trivyDbUpdatedAt = '2026-11-24T18:10:00Z',
} = {}) {
  for (const format of formats) {
    writeFileSync(join(directory, `ssi-ubuntu-2404-${version}.${format}`), `${format} bytes`);
  }
  writeFileSync(join(directory, 'SHA256SUMS'), 'not an artifact');
  const before = trivy([
    vuln('CVE-2026-1000', 'linux-image-6.8.0-147-generic', 'CRITICAL', '6.8.0-151.151'),
    vuln('CVE-2026-1000', 'linux-modules-6.8.0-147-generic', 'CRITICAL', '6.8.0-151.151'),
    vuln('CVE-2026-2000', 'openssl', 'HIGH', '3.0.13-0ubuntu3.7'),
    vuln('CVE-2026-3000', 'linux-headers-6.8.0-147-generic', 'HIGH'),
  ]);
  const afterReport = trivy(after);
  const report = buildScanReport({
    before: vulnerabilitiesOf(before),
    after: vulnerabilitiesOf(afterReport),
    kernelBefore: '6.8.0-147-generic',
    kernelAfter: '6.8.0-151-generic',
    os: scannedOs === undefined ? { family: 'ubuntu', name: '24.04' } : scannedOs,
  });
  return buildManifest({
    artifactsDir: directory,
    report,
    templateName: 'ssi-ubuntu-2404',
    templateVersion: version,
    buildId: 'ado-883942',
    baseImageUrl: URL_20261017,
    baseImageSha256,
    signed: false,
    tools: {
      libguestfs: 'virt-customize 1.52.0',
      'qemu-img': 'qemu-img version 8.2.2',
      trivy: '0.70.0',
      trivyDbUpdatedAt,
    },
    createdAt: '2026-11-24T18:31:00.000Z',
  });
}

// What the pipeline's delivery step sends: scripts/os-template-evidence.mjs assemble.
async function evidence(manifestOptions = {}, options = {}) {
  const manifest = await workerManifest(manifestOptions);
  const path = join(directory, 'template-manifest.json');
  writeFileSync(path, JSON.stringify(manifest));
  const qcow2 = manifest.artifacts.find((item) => item.format === 'qcow2')?.file || 'x.qcow2';
  return assembleResult(
    {
      manifest: path,
      'build-id': 'OST-0002',
      'location-host': 'azure-devops',
      'location-path': `os-template-ubuntu-qcow2/${qcow2}`,
      pipeline: 'SSI - OS Template (Ubuntu)',
      'ado-build-id': '883942',
      agent: 'LinuxAgent2',
      ...options,
    },
    { generatedAt: '2026-11-24T18:32:00.000Z' },
  );
}

const validate = (value, build = requested()) =>
  validateOsTemplateEvidence(value, {
    build,
    evidenceDigest: `sha256:${'e'.repeat(64)}`,
    intake: { channel: 'worker', receivedAt: '2026-11-24T18:33:00.000Z' },
    now: NOW,
  });

describe('Ubuntu template requests', () => {
  it('pin the official cloud image by URL and SHA-256', () => {
    expect(validateBuildRequest(INPUT)).toEqual({ ...INPUT, baseImageSha256: IMAGE_SHA });
    expect(requested().request.os).toBe('ubuntu-24.04');
    expect(describeBuildRequest(requested().request)).toBe(
      'OS template ssi-ubuntu-2404 (Ubuntu 24.04) requested from release-20261017/ubuntu-24.04-server-cloudimg-amd64.img',
    );
  });

  it.each([
    [{ baseImageSha256: '' }, /baseImageSha256/],
    [{ baseImageUrl: 'https://example.com/ubuntu.img' }, /official/],
    [{ baseImageUrl: 'http://cloud-images.ubuntu.com/a/b.img' }, /official/],
    [{ baseImageUrl: 'https://cloud-images.ubuntu.com/../evil/x.img' }, /"\.\."/],
    [{ diskSizeGb: 4 }, /diskSizeGb/],
    [{ diskSizeGb: '20; rm' }, /diskSizeGb/],
    [{ aptMirror: 'http://user:pw@mirror/ubuntu' }, /aptMirror/],
    [{ templateName: 'Bad Name' }, /templateName/],
    [{ os: 'ubuntu-22.04' }, /os must be/],
  ])('refuses %o', (change, message) => {
    expect(() => validateBuildRequest({ ...INPUT, ...change })).toThrow(message);
  });

  it('leave Windows requests exactly as they were', () => {
    const windows = {
      isoFile: 'WS2025_EVAL_en-us.iso',
      isoSha256: 'a'.repeat(64),
      imageIndex: 2,
      product: 'Windows Server 2025',
      templateName: 'ssi-ws2025-std-de',
    };
    expect(validateBuildRequest(windows)).toEqual(windows);
    expect(validateBuildRequest({ ...windows, os: 'windows' })).toEqual(windows);
  });
});

describe('the Ubuntu worker result', () => {
  it('is accepted as template-report.mjs writes it and summarised per CVE', async () => {
    const result = validate(await evidence());
    expect(result.location).toEqual({
      host: 'azure-devops',
      path: `os-template-ubuntu-qcow2/ssi-ubuntu-2404-${VERSION}.qcow2`,
      artifact: 'os-template-ubuntu-qcow2',
      adoBuildId: '883942',
      layout: 'per-format',
    });
    const { build, changed } = applyOsTemplateResult(requested(), result);
    expect(changed).toBe(true);
    const summary = osTemplateSummary(build);
    expect(summary).toMatchObject({ os: 'ubuntu-24.04', status: 'Built' });
    expect(summary.template).toMatchObject({
      os: 'ubuntu-24.04',
      version: VERSION,
      scannedAs: 'ubuntu 24.04',
      kernelBefore: '6.8.0-147-generic',
      kernelAfter: '6.8.0-151-generic',
      cvesBefore: { total: 3, critical: 1, fixable: 2 },
      cvesAfter: { total: 1, fixable: 0 },
      findingsBefore: 4,
      base: { url: URL_20261017, sha256: IMAGE_SHA },
      location: { adoBuildId: '883942' },
    });
    expect(summary.template.artifacts.map((item) => [item.format, item.platforms])).toEqual([
      ['qcow2', ['proxmox', 'kvm']],
      ['ova', ['vmware-vsphere']],
      ['vhdx', ['hyper-v']],
    ]);
    expect(osTemplateArtifacts(build).map((item) => item.format)).toEqual(['qcow2', 'ova', 'vhdx']);
    expect(osTemplateResultAudit('OST-0002', result)).toMatchObject({
      summary:
        'OS template ssi-ubuntu-2404 24.04-20261124-ado-883942 built for OST-0002: 2 -> 0 CVEs with a fix (Trivy, 1 without a released fix)',
      metadata: { os: 'ubuntu-24.04', kernel: '6.8.0-147-generic -> 6.8.0-151-generic' },
    });
    const approved = decideOsTemplate(build, { decision: 'approve', actorId: 'def.ap' });
    expect(approved.status).toBe('Approved');
  });

  it.each([
    [
      'a scan that did not recognise Ubuntu (the first ADO run)',
      { scannedOs: null },
      {},
      /did not recognise the image as Ubuntu 24\.04/,
    ],
    [
      'another cloud image',
      { baseImageSha256: 'f'.repeat(64) },
      {},
      /cloud image this request pinned/,
    ],
    [
      'a CVE with a released fix left',
      { after: [vuln('CVE-2026-2000', 'openssl', 'HIGH', '3.0.13-0ubuntu3.7')] },
      {},
      /gate did not pass/,
    ],
    ['a missing format', { formats: ['qcow2', 'ova'] }, {}, /exactly the qcow2, ova, vhdx files/],
    [
      'a stale vulnerability database',
      { trivyDbUpdatedAt: '2026-11-01T00:00:00Z' },
      {},
      /more than 7 days old/,
    ],
    [
      'a location outside the run artifact',
      {},
      { 'location-path': 'os-template-ubuntu-qcow2/other.qcow2' },
      /location must name/,
    ],
    ['a run that cannot be found', {}, { 'ado-build-id': 'local' }, /runner\.buildId/],
  ])('is refused for %s', async (_, manifestOptions, options, message) => {
    const value = await evidence(manifestOptions, options);
    expect(() => validate(value)).toThrow(message);
  });

  it('is refused when it names another template or request', async () => {
    const value = await evidence();
    expect(() =>
      validate(value, requested({ ...INPUT, templateName: 'ssi-ubuntu-other' })),
    ).toThrow(/template name differs/);
    expect(() => validate({ ...value, buildId: 'OST-0003' })).toThrow(/not for the build request/);
    expect(() => validate({ ...value, contractVersion: 'v0' })).toThrow(
      /Unsupported OS template contract/,
    );
    expect(value.contractVersion).toBe(OS_TEMPLATE_BUILD_CONTRACT);
  });

  it('is never read with the Windows rules, nor a Windows result with the Ubuntu rules', async () => {
    const windowsRequest = createOsTemplateBuild({
      id: 'OST-0002',
      input: {
        isoFile: 'WS2025_EVAL_en-us.iso',
        isoSha256: IMAGE_SHA,
        imageIndex: 2,
        product: 'Windows Server 2025',
        templateName: 'ssi-ubuntu-2404',
      },
      requestedBy: 'def.op',
    });
    const ubuntuResult = await evidence();
    expect(() => validate(ubuntuResult, windowsRequest)).toThrow();
  });
});

describe('the Ubuntu worker run', () => {
  const worker = { workerApiBaseUrl: 'http://10.0.0.10:5021/api/v1' };

  it('takes every parameter from the request, as the pipeline declares them', () => {
    const plan = planOsTemplateRun(requested(), 'os-template-build-ubuntu', worker);
    expect(plan).toEqual({
      action: 'os-template-build-ubuntu',
      role: 'osTemplateUbuntu',
      templateParameters: {
        osTemplateBuildId: 'OST-0002',
        baseImageUrl: URL_20261017,
        baseImageSha256: IMAGE_SHA,
        templateName: 'ssi-ubuntu-2404',
        diskSizeGb: '20',
        aptMirror: 'none',
        deliverToSsi: true,
        ssiApiBaseUrl: 'http://10.0.0.10:5021/api/v1',
        allowInsecurePocApi: true,
      },
    });
    // azure-pipelines-os-template-ubuntu.yml declares exactly these parameters.
    const pipeline = readFileSync(
      new URL('../../azure-pipelines-os-template-ubuntu.yml', import.meta.url),
      'utf8',
    );
    const declared = [...pipeline.matchAll(/^ {2}- name: (\w+)$/gm)].map((match) => match[1]);
    expect(declared.sort()).toEqual(Object.keys(plan.templateParameters).sort());
  });

  it('offers each request only the pipeline of its own operating system', () => {
    const windows = createOsTemplateBuild({
      id: 'OST-0001',
      input: {
        isoFile: 'WS2025_EVAL_en-us.iso',
        isoSha256: IMAGE_SHA,
        imageIndex: 2,
        product: 'Windows Server 2025',
        templateName: 'ssi-ws2025-std-de',
      },
      requestedBy: 'def.op',
    });
    expect(() => planOsTemplateRun(windows, 'os-template-build-ubuntu', worker)).toThrow(
      PipelineRunError,
    );
    expect(() => planOsTemplateRun(requested(), 'os-template-build', worker)).toThrow(
      /is for ubuntu-24\.04/,
    );
    const view = workerActionsView('os-template-ubuntu', requested(), {
      enabled: true,
      pipelines: { osTemplateUbuntu: 4700 },
      plan: (action) => planOsTemplateRun(requested(), action, worker),
    });
    expect(view.actions).toEqual([
      expect.objectContaining({
        action: 'os-template-build-ubuntu',
        role: 'osTemplateUbuntu',
        confirm: true,
        available: true,
      }),
    ]);
  });
});

// What SSI offers for download, and how an approved template's files are kept.
describe('Ubuntu template downloads and retention', () => {
  const built = async (options) =>
    applyOsTemplateResult(requested(), validate(await evidence({}, options))).build;

  it('offers one download per format and the evidence once the template is built', async () => {
    expect(osTemplateDownloads(requested())).toEqual([]);
    const build = await built();
    const downloads = osTemplateDownloads(build);
    expect(downloads.map((item) => [item.id, item.artifact, item.fileName])).toEqual([
      ['qcow2', 'os-template-ubuntu-qcow2', `ssi-ubuntu-2404-${VERSION}.qcow2.zip`],
      ['ova', 'os-template-ubuntu-ova', `ssi-ubuntu-2404-${VERSION}.ova.zip`],
      ['vhdx', 'os-template-ubuntu-vhdx', `ssi-ubuntu-2404-${VERSION}.vhdx.zip`],
      ['evidence', 'os-template-ubuntu-evidence', `ssi-ubuntu-2404-${VERSION}-evidence.zip`],
    ]);
    expect(downloads.every((item) => item.runId === '883942')).toBe(true);
    expect(downloads[1].files).toEqual([
      expect.objectContaining({ format: 'ova', sha256: expect.stringMatching(/^[a-f0-9]{64}$/) }),
    ]);
    expect(osTemplateSummary(build).downloads).toHaveLength(4);
  });

  it('offers the one archive of the first runs (all formats in os-template-ubuntu-images)', async () => {
    const build = await built({
      'location-path': `os-template-ubuntu-images/ssi-ubuntu-2404-${VERSION}.qcow2`,
    });
    expect(osTemplateDownloads(build).map((item) => [item.id, item.artifact])).toEqual([
      ['images', 'os-template-ubuntu-images'],
      ['evidence', 'os-template-ubuntu-evidence'],
    ]);
    expect(findOsTemplateDownload(build, 'images').files).toHaveLength(3);
  });

  // OST-0002 in production: recorded before `layout` was stored, so its location has none.
  it('reads a result recorded before the layout was stored as the one combined archive', async () => {
    const build = await built({
      'location-path': `os-template-ubuntu-images/ssi-ubuntu-2404-${VERSION}.qcow2`,
    });
    const { layout, ...stored } = build.result.location;
    expect(layout).toBe('combined');
    const old = { ...build, result: { ...build.result, location: stored } };
    expect(osTemplateDownloads(old).map((item) => item.artifact)).toEqual([
      'os-template-ubuntu-images',
      'os-template-ubuntu-evidence',
    ]);
    expect(osTemplateSummary(old).template.location.layout).toBe('combined');
  });

  it('offers nothing for a rejected template, an unknown download or a Windows ISO', async () => {
    const build = await built();
    const rejected = decideOsTemplate(build, {
      decision: 'reject',
      actorId: 'def.ap',
      reason: 'x',
    });
    expect(osTemplateDownloads(rejected)).toEqual([]);
    expect(() => findOsTemplateDownload(rejected, 'ova')).toThrow(
      /rejected template is not offered/,
    );
    expect(() => findOsTemplateDownload(build, 'iso')).toThrow(/Unknown download/);
    expect(() => findOsTemplateDownload(build, '../x')).toThrow(/Unknown download/);
    const windows = { status: 'Approved', request: { isoFile: 'x.iso' }, result: { manifest: {} } };
    expect(osTemplateDownloads(windows)).toEqual([]);
    expect(() => findOsTemplateDownload(windows, 'iso')).toThrow(
      /stays on the Windows build machine/,
    );
  });

  it('retains the run of an approved Ubuntu template, recorded with the approval', async () => {
    const build = await built();
    expect(osTemplateRetentionTarget(build)).toEqual({
      role: 'osTemplateUbuntu',
      runId: 883942,
      ownerId: 'SSI:OST-0002',
    });
    const retention = {
      secured: true,
      runId: 883942,
      leaseId: 51,
      validUntil: '2126-11-25T00:00:00Z',
    };
    const approved = decideOsTemplate(build, { decision: 'approve', actorId: 'def.ap', retention });
    expect(osTemplateSummary(approved)).toMatchObject({ status: 'Approved', retention });
    const rejected = decideOsTemplate(build, {
      decision: 'reject',
      actorId: 'def.ap',
      reason: 'no',
      retention,
    });
    expect(rejected.retention).toBeUndefined();
  });
});
