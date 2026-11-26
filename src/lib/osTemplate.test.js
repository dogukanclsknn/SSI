import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  applyOsTemplateResult,
  compareBuilds,
  createOsTemplateBuild,
  decideOsTemplate,
  OS_TEMPLATE_BUILD_CONTRACT,
  osTemplateSummary,
  validateBuildRequest,
  validateOsTemplateEvidence,
} from './osTemplate.js';

const ISO_SHA = '7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51';
const NOW = Date.parse('2026-11-24T12:00:00.000Z');
const INPUT = {
  isoFile: 'WS2025_EVAL_en-us.iso',
  isoSha256: ISO_SHA.toUpperCase(),
  imageIndex: 2,
  product: 'Windows Server 2025',
  templateName: 'ssi-ws2025-std-de',
};
const requested = () =>
  createOsTemplateBuild({
    id: 'OST-0001',
    input: INPUT,
    requestedBy: 'def.op',
    now: new Date(NOW - 3600_000),
  });

// Shaped like the template-manifest.json Build-WindowsTemplate.ps1 wrote on 2026-11-24.
const manifest = (overrides = {}) => ({
  manifestVersion: 'ssi.os-template-manifest/v1',
  template: {
    name: 'ssi-ws2025-std-de',
    version: '26100.33822',
    os: 'windows-server-2025',
    edition: 'Windows Server 2025 Standard Evaluation (Desktop Experience)',
    architecture: 'amd64',
  },
  build: {
    id: 'ado-4711',
    createdAt: '2026-11-24T11:30:00Z',
    tools: { dism: '10.0.26100.9457', oscdimg: '2.56', powershell: '5.1.20348.5773' },
  },
  base: {
    file: 'WS2025_EVAL_en-us.iso',
    sha256: ISO_SHA,
    imageIndex: 2,
    build: '10.0.26100.32230',
  },
  updates: [
    {
      kb: 'KB5043080',
      file: `windows11.0-kb5043080-x64_${'9'.repeat(40)}.msu`,
      sha256: 'a'.repeat(64),
      applied: false,
    },
    {
      kb: 'KB5131080',
      file: `windows11.0-kb5131080-x64_${'3'.repeat(40)}.msu`,
      sha256: 'b'.repeat(64),
      applied: true,
    },
  ],
  scan: {
    source: 'Microsoft Security Update Guide (MSRC CVRF API v3.0)',
    before: { build: '10.0.26100.32230', open: 3388, critical: 210, important: 3173 },
    after: { build: '10.0.26100.33822', open: 0, critical: 0, important: 0 },
    gate: { maxOpenAfter: 0, passed: true },
  },
  artifacts: [
    {
      file: 'ssi-ws2025-std-de-26100.33822.iso',
      format: 'iso',
      sizeBytes: 8_101_986_304,
      sha256: 'c'.repeat(64),
      signature: null,
    },
  ],
  signing: { signed: false },
  ...overrides,
});
const evidence = (overrides = {}, manifestOverrides = {}) => ({
  contractVersion: OS_TEMPLATE_BUILD_CONTRACT,
  buildId: 'OST-0001',
  generatedAt: '2026-11-24T11:31:00Z',
  runner: { pipeline: 'SSI - OS Template (Windows)', buildId: '4711', agent: 'WINBUILD01' },
  location: {
    host: 'WINBUILD01',
    path: 'E:\\SSI-Image\\runs\\ado-4711\\out\\ssi-ws2025-std-de-26100.33822.iso',
  },
  manifest: manifest(manifestOverrides),
  ...overrides,
});
const validate = (value, build = requested()) =>
  validateOsTemplateEvidence(value, {
    build,
    evidenceDigest: `sha256:${'e'.repeat(64)}`,
    intake: { channel: 'worker', receivedAt: '2026-11-24T11:32:00.000Z' },
    now: NOW,
  });

describe('OS template build requests', () => {
  it('normalise the operator input with the worker pipeline rules', () => {
    expect(validateBuildRequest(INPUT)).toEqual({ ...INPUT, isoSha256: ISO_SHA });
    expect(requested()).toMatchObject({
      id: 'OST-0001',
      status: 'Requested',
      requestedBy: 'def.op',
      pipelineRuns: [],
    });
  });

  it.each([
    [{ isoFile: '..\\Windows\\x.iso' }, /isoFile/],
    [{ isoSha256: '' }, /isoSha256/],
    [{ imageIndex: 17 }, /imageIndex/],
    [{ imageIndex: '2; rm' }, /imageIndex/],
    [{ product: "Windows Server 2025'; x" }, /product/],
    [{ templateName: 'Bad Name' }, /templateName/],
  ])('refuses %o', (change, message) => {
    expect(() => validateBuildRequest({ ...INPUT, ...change })).toThrow(message);
  });
});

describe('the worker result', () => {
  it('is accepted when it is bound to the request and leaves no CVE open', () => {
    const result = validate(evidence());
    expect(result.manifest.scan).toMatchObject({
      before: { open: 3388 },
      after: { open: 0 },
      gate: { passed: true },
    });
    expect(result.location.host).toBe('WINBUILD01');
    const { build, changed } = applyOsTemplateResult(requested(), result);
    expect(changed).toBe(true);
    expect(osTemplateSummary(build)).toMatchObject({
      status: 'Built',
      template: {
        version: '26100.33822',
        baseBuild: '10.0.26100.32230',
        build: '10.0.26100.33822',
        openBefore: 3388,
        openAfter: 0,
        update: 'KB5131080',
      },
    });
  });

  it.each([
    ['another request', evidence({ buildId: 'OST-0002' }), /not for the build request/],
    [
      'another ISO',
      evidence({}, { base: { ...manifest().base, sha256: 'f'.repeat(64) } }),
      /ISO this request pinned/,
    ],
    [
      'another edition',
      evidence({}, { base: { ...manifest().base, imageIndex: 4 } }),
      /requested edition/,
    ],
    [
      'another name',
      evidence({}, { template: { ...manifest().template, name: 'other' } }),
      /template name differs/,
    ],
    [
      'open CVEs',
      evidence({}, { scan: { ...manifest().scan, after: { ...manifest().scan.after, open: 3 } } }),
      /still open/,
    ],
    [
      'a failed gate',
      evidence({}, { scan: { ...manifest().scan, gate: { maxOpenAfter: 0, passed: false } } }),
      /gate did not pass/,
    ],
    [
      'an older build',
      evidence(
        {},
        {
          scan: { ...manifest().scan, after: { ...manifest().scan.after, build: '10.0.26100.1' } },
        },
      ),
      /older than the source/,
    ],
    [
      'two applied updates',
      evidence({}, { updates: manifest().updates.map((item) => ({ ...item, applied: true })) }),
      /exactly the one update/,
    ],
    [
      'a path to another file',
      evidence({ location: { host: 'H', path: 'E:\\x\\other.iso' } }),
      /does not name the template ISO/,
    ],
    ['a future timestamp', evidence({ generatedAt: '2027-01-01T00:00:00Z' }), /in the future/],
    ['another contract', evidence({ contractVersion: 'v0' }), /Unsupported OS template contract/],
  ])('is refused for %s', (_, value, message) => {
    expect(() => validate(value)).toThrow(message);
  });

  it('is idempotent on replay and refused once the request has moved on', () => {
    const result = validate(evidence());
    const { build } = applyOsTemplateResult(requested(), result);
    expect(applyOsTemplateResult(build, result).changed).toBe(false);
    expect(() =>
      applyOsTemplateResult(build, { ...result, evidenceDigest: `sha256:${'d'.repeat(64)}` }),
    ).toThrow(/Built; it takes no new result/);
  });
});

describe('the decision', () => {
  const built = () => applyOsTemplateResult(requested(), validate(evidence())).build;

  it('approves a built template, by someone other than the requester', () => {
    const approved = decideOsTemplate(built(), {
      decision: 'approve',
      actorId: 'def.ap',
      now: new Date(NOW),
    });
    expect(approved).toMatchObject({
      status: 'Approved',
      decision: { decision: 'approve', by: 'def.ap', reason: '' },
    });
    expect(() => decideOsTemplate(built(), { decision: 'approve', actorId: 'DEF.OP' })).toThrow(
      /four eyes/,
    );
    expect(
      decideOsTemplate(built(), {
        decision: 'approve',
        actorId: 'def.op',
        requireSeparateApprover: false,
      }).status,
    ).toBe('Approved');
  });

  it('approves nothing that is not built and rejects only with a reason', () => {
    expect(() => decideOsTemplate(requested(), { decision: 'approve', actorId: 'def.ap' })).toThrow(
      /Only a built template/,
    );
    expect(() => decideOsTemplate(requested(), { decision: 'reject', actorId: 'def.ap' })).toThrow(
      /reason is required/,
    );
    const rejected = decideOsTemplate(requested(), {
      decision: 'reject',
      actorId: 'def.ap',
      reason: 'wrong edition',
    });
    expect(rejected.status).toBe('Rejected');
    expect(() =>
      decideOsTemplate(rejected, { decision: 'reject', actorId: 'def.ap', reason: 'again' }),
    ).toThrow(/already Rejected/);
  });
});

it('compares Windows builds part by part', () => {
  expect(compareBuilds('10.0.26100.33822', '10.0.26100.32230')).toBeGreaterThan(0);
  expect(compareBuilds('10.0.26100.9', '10.0.26100.10')).toBeLessThan(0);
  expect(compareBuilds('10.0.26100.1', '10.0.26100.1')).toBe(0);
});

// The manifest Build-WindowsTemplate.ps1 wrote on WINBUILD01 on 2026-11-24 (every value as
// Windows PowerShell 5.1 wrote it; only whitespace condensed): a format change in the script that SSI would refuse fails here.
it('accepts the manifest of the first real build on the Windows build machine', () => {
  const real = JSON.parse(
    readFileSync(
      new URL(
        '../../poc/os-template/windows/samples/template-manifest-20261124.json',
        import.meta.url,
      ),
      'utf8',
    ),
  );
  const result = validate(
    evidence({
      location: {
        host: 'WINBUILD01',
        path: 'E:\\SSI-Image\\runs\\20261124-095815\\out\\ssi-ws2025-std-de-26100.33822.iso',
      },
      manifest: real,
    }),
  );
  expect(
    osTemplateSummary(applyOsTemplateResult(requested(), result).build).template,
  ).toMatchObject({
    build: '10.0.26100.33822',
    openBefore: 3388,
    openAfter: 0,
    update: 'KB5131080',
    iso: {
      sha256: '45594952f01aed6fe7b85368f49787e6243b0b62bc4d23771d6787cbecd43606',
      sizeBytes: 8_092_522_496,
    },
  });
});
