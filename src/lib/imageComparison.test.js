import { describe, expect, it } from 'vitest';
import {
  buildImageComparison,
  buildImageDiff,
  configFieldRows,
  DIMENSION_STATUS,
  describeDimension,
  dimensionCsv,
  findScanReport,
  IMAGE_COMPARISON_CONTRACT,
  ImageComparisonError,
  scanReportReference,
} from './imageComparison.js';

const SOURCE = `sha256:${'a'.repeat(64)}`;
const OUTPUT = `sha256:${'b'.repeat(64)}`;

function job(overrides = {}) {
  return {
    id: 'RM-EXEC-0004',
    tenantId: 'default',
    mode: 'execution',
    status: 'Verified',
    image: 'ssi-images/onboarded/nginx:alpine',
    patchedImageTag: 'harbor.example/ssi-images/onboarded/nginx:copa-r2',
    sourceDigest: SOURCE,
    patchedImageDigest: OUTPUT,
    before: { critical: 0, high: 1, medium: 1, low: 0 },
    after: { critical: 0, high: 0, medium: 1, low: 0 },
    fixed: [
      {
        cve: 'CVE-2026-0001',
        package: 'curl',
        from: '8.22.0-r0',
        to: '8.23.0-r0',
        severity: 'HIGH',
      },
    ],
    remaining: [
      { cve: 'CVE-2026-0002', package: 'busybox', from: '1.37.0-r1', to: '-', severity: 'Medium' },
    ],
    fullImageComparison: { status: 'available', source: { findings: 3 }, output: { findings: 1 } },
    verificationEvidence: {
      configIntegrity: {
        status: 'restored',
        platform: 'linux/amd64',
        restoredFields: ['Cmd', 'Entrypoint'],
      },
    },
    candidateTest: {
      passed: true,
      platform: 'linux/amd64',
      generatedAt: '2026-11-05T10:00:00.000Z',
      startup: { source: { state: 'running' }, candidate: { state: 'running' } },
      checks: [
        { id: 'image-config', status: 'pass', detail: 'identical' },
        { id: 'startup', status: 'pass', detail: 'both running' },
        { id: 'healthcheck', status: 'not-applicable', detail: '' },
        { id: 'package-inventory', status: 'pass', detail: '1 changed' },
      ],
      packageChanges: {
        summary: {
          unchanged: 69,
          changed: 1,
          added: 0,
          removed: 0,
          majorVersionChanges: 0,
          unplanned: 0,
        },
        changes: [
          {
            name: 'curl',
            arch: 'x86_64',
            from: '8.22.0-r0',
            to: '8.23.0-r0',
            change: 'changed',
            majorVersionChange: false,
            planned: true,
          },
        ],
      },
    },
    supplyChain: { signature: true, sbom: true, provenance: false },
    ...overrides,
  };
}

const report = (digest, findings) => ({
  digest,
  scanner: 'Trivy',
  scannedAt: '2026-11-10 09:00',
  findings,
});
const sourceReport = report(SOURCE, [
  {
    cve: 'CVE-2026-0001',
    package: 'curl',
    installed: '8.22.0-r0',
    fixed: '8.23.0-r0',
    severity: 'High',
  },
  { cve: 'CVE-2026-0002', package: 'busybox', installed: '1.37.0-r1', severity: 'Medium' },
  {
    cve: 'CVE-2026-0003',
    package: 'zlib',
    installed: '1.3.1-r0',
    fixed: '1.3.1-r1',
    severity: 'Low',
  },
]);
const outputReport = report(OUTPUT, [
  { cve: 'CVE-2026-0002', package: 'busybox', installed: '1.37.0-r1', severity: 'Medium' },
]);
const dimensionOf = (comparison, id) => comparison.dimensions.find((item) => item.id === id);

describe('buildImageComparison', () => {
  it('describes the two images and lists every dimension in reading order', () => {
    const comparison = buildImageComparison({
      job: job(),
      sourceReport,
      outputReport,
      generatedAt: '2026-11-10T10:00:00.000Z',
    });
    expect(comparison).toMatchObject({
      contractVersion: IMAGE_COMPARISON_CONTRACT,
      jobId: 'RM-EXEC-0004',
      tenantId: 'default',
      base: { role: 'source', digest: SOURCE },
      head: { role: 'patched', digest: OUTPUT },
    });
    expect(comparison.dimensions.map((item) => item.id)).toEqual([
      'vulnerabilities-verified',
      'vulnerabilities-current',
      'packages',
      'configuration',
      'runtime',
      'layers',
      'supply-chain',
    ]);
    expect(comparison.headline).toEqual({
      vulnerabilitiesFixed: 1,
      vulnerabilitiesRemaining: 1,
      vulnerabilitiesNew: 0,
      // The fixture's candidate test is not bound to a digest: no package evidence.
      vulnerabilitiesNewUnchangedPackages: null,
      findingsBase: 3,
      findingsHead: 1,
      packagesChanged: 1,
      packagesUnplanned: 0,
      configuration: 'restored',
      runtimePassed: true,
      layersAdded: null,
      sizeDeltaBytes: null,
    });
  });

  it('refuses anything but a verified execution job with both digests', () => {
    expect(() => buildImageComparison({ job: job({ mode: 'dry-run' }) })).toThrow(
      ImageComparisonError,
    );
    expect(() => buildImageComparison({ job: job({ patchedImageDigest: '' }) })).toThrow(
      /source and a patched digest/,
    );
  });

  it('keeps the frozen verification result apart from today’s scans', () => {
    const verified = dimensionOf(
      buildImageComparison({ job: job(), sourceReport, outputReport }),
      'vulnerabilities-verified',
    );
    expect(verified.rows.map((row) => [row.change, row.cve, row.severity])).toEqual([
      ['fixed', 'CVE-2026-0001', 'High'],
      ['remaining', 'CVE-2026-0002', 'Medium'],
    ]);
    expect(verified.summary).toMatchObject({ fixed: 1, remaining: 1 });
  });

  it('compares today’s full-image scans finding by finding', () => {
    const current = dimensionOf(
      buildImageComparison({ job: job(), sourceReport, outputReport }),
      'vulnerabilities-current',
    );
    expect(current.status).toBe(DIMENSION_STATUS.AVAILABLE);
    expect(current.summary).toMatchObject({
      fixed: 2,
      remaining: 1,
      new: 0,
      today: { source: 3, patched: 1 },
      atVerification: { source: 3, patched: 1 },
    });
    expect(current.attention).toEqual([]);
  });

  it('flags a finding that appears only in the patched image, critical or high as high attention', () => {
    const patched = report(OUTPUT, [
      ...outputReport.findings,
      { cve: 'CVE-2026-0099', package: 'curl', installed: '8.23.0-r0', severity: 'Critical' },
    ]);
    const comparison = buildImageComparison({ job: job(), sourceReport, outputReport: patched });
    const current = dimensionOf(comparison, 'vulnerabilities-current');
    expect(current.rows[0]).toMatchObject({
      change: 'new',
      cve: 'CVE-2026-0099',
      severity: 'Critical',
      patched: '8.23.0-r0',
    });
    expect(current.summary.newBySeverity.critical).toBe(1);
    expect(comparison.attention[0]).toMatchObject({
      level: 'high',
      code: 'new-in-patched',
      dimension: 'vulnerabilities-current',
    });
    // One more finding than at verification: published since then.
    expect(current.attention.map((point) => point.code)).toContain('found-since-verification');
  });

  it('is unavailable without a current scan of both digests (never compares another image)', () => {
    for (const [left, right] of [
      [null, outputReport],
      [sourceReport, null],
      [sourceReport, report(`sha256:${'c'.repeat(64)}`, [])],
    ]) {
      const current = dimensionOf(
        buildImageComparison({ job: job(), sourceReport: left, outputReport: right }),
        'vulnerabilities-current',
      );
      expect(current.status).toBe(DIMENSION_STATUS.UNAVAILABLE);
      expect(current.rows).toEqual([]);
    }
  });

  it('raises unplanned, removed, added and major package changes', () => {
    const changes = {
      summary: {
        unchanged: 60,
        changed: 2,
        added: 1,
        removed: 1,
        majorVersionChanges: 1,
        unplanned: 3,
      },
      changes: [
        {
          name: 'curl',
          arch: 'x86_64',
          from: '8.22.0-r0',
          to: '8.23.0-r0',
          change: 'changed',
          majorVersionChange: false,
          planned: true,
        },
        {
          name: 'openssl',
          arch: 'x86_64',
          from: '3.3.2-r0',
          to: '4.0.0-r0',
          change: 'changed',
          majorVersionChange: true,
          planned: false,
        },
        {
          name: 'libnew',
          arch: 'x86_64',
          from: '',
          to: '1.0-r0',
          change: 'added',
          majorVersionChange: false,
          planned: false,
        },
        {
          name: 'libgone',
          arch: 'x86_64',
          from: '2.0-r0',
          to: '',
          change: 'removed',
          majorVersionChange: false,
          planned: false,
        },
      ],
    };
    const comparison = buildImageComparison({
      job: job({ candidateTest: { ...job().candidateTest, packageChanges: changes } }),
    });
    const dimension = dimensionOf(comparison, 'packages');
    expect(dimension.rows.map((row) => row.change)).toEqual([
      'removed',
      'added',
      'changed',
      'changed',
    ]);
    expect(dimension.attention.map((point) => [point.level, point.code])).toEqual([
      ['high', 'unplanned-package-change'],
      ['high', 'package-removed'],
      ['warning', 'major-version-change'],
      ['warning', 'package-added'],
    ]);
  });

  it('says what is missing instead of guessing when an evidence source is absent', () => {
    const comparison = buildImageComparison({
      job: job({ candidateTest: undefined, verificationEvidence: {} }),
    });
    for (const id of [
      'packages',
      'runtime',
      'configuration',
      'layers',
      'vulnerabilities-current',
    ]) {
      const item = dimensionOf(comparison, id);
      expect(item.status).toBe(DIMENSION_STATUS.UNAVAILABLE);
      expect(item.note).not.toBe('');
    }
    expect(comparison.headline).toMatchObject({
      packagesChanged: null,
      runtimePassed: null,
      configuration: null,
    });
  });

  it('reports a failed candidate test and a withdrawal first', () => {
    const failing = {
      ...job().candidateTest,
      passed: false,
      checks: job().candidateTest.checks.map((check) =>
        check.id === 'startup' ? { ...check, status: 'fail', detail: 'exited 127' } : check,
      ),
    };
    const comparison = buildImageComparison({
      job: job({
        candidateTest: failing,
        publishWithdrawal: { reason: 'TLS breaks in html-hello-world' },
      }),
    });
    expect(comparison.attention.slice(0, 2).map((point) => point.code)).toEqual([
      'withdrawn',
      'candidate-test-failed',
    ]);
  });

  it('compares layers, size and configuration values once the worker reports image facts', () => {
    const L1 = `sha256:${'1'.repeat(64)}`;
    const L2 = `sha256:${'2'.repeat(64)}`;
    const PATCH = `sha256:${'3'.repeat(64)}`;
    const config = () => ({
      Cmd: ['nginx', '-g', 'daemon off;'],
      User: '',
      Env: ['PATH', 'NGINX_VERSION'],
    });
    const imageFacts = {
      source: { sizeBytes: 48_000_000, diffIds: [L1, L2], config: config() },
      candidate: { sizeBytes: 49_500_000, diffIds: [L1, L2, PATCH], config: config() },
    };
    const comparison = buildImageComparison({
      job: job({ candidateTest: { ...job().candidateTest, imageFacts } }),
    });
    const layers = dimensionOf(comparison, 'layers');
    expect(layers.status).toBe(DIMENSION_STATUS.AVAILABLE);
    expect(layers.summary).toMatchObject({
      sourceLayers: 2,
      patchedLayers: 3,
      added: 1,
      removed: 0,
      sourcePreserved: true,
      sourceBytes: 48_000_000,
      patchedBytes: 49_500_000,
      sizeDeltaBytes: 1_500_000,
    });
    expect(layers.rows.filter((row) => row.changed)).toEqual([
      { change: 'added', position: 3, digest: PATCH, changed: true },
    ]);
    expect(layers.attention).toEqual([]);
    expect(describeDimension(layers)).toBe(
      '2 → 3 layers (1 added, 0 removed); size 48.0 MB → 49.5 MB.',
    );
    expect(comparison.headline).toMatchObject({ layersAdded: 1, sizeDeltaBytes: 1_500_000 });
    const configuration = dimensionOf(comparison, 'configuration');
    // Restored by SSI after Copa dropped it: still listed under "Only changes".
    expect(configuration.rows.find((row) => row.field === 'Cmd')).toMatchObject({
      change: 'restored',
      changed: true,
    });
    expect(configuration.rows.find((row) => row.field === 'Env')).toMatchObject({
      source: '["PATH","NGINX_VERSION"]',
      changed: false,
    });
    expect(configuration.attention.map((point) => point.code)).toEqual(['config-restored']);
  });

  it('flags removed or reordered source layers', () => {
    const L1 = `sha256:${'1'.repeat(64)}`;
    const L2 = `sha256:${'2'.repeat(64)}`;
    const PATCH = `sha256:${'3'.repeat(64)}`;
    const facts = (candidateIds) => ({
      source: { sizeBytes: null, diffIds: [L1, L2], config: {} },
      candidate: { sizeBytes: null, diffIds: candidateIds, config: {} },
    });
    const codes = (candidateIds) => {
      const comparison = buildImageComparison({
        job: job({ candidateTest: { ...job().candidateTest, imageFacts: facts(candidateIds) } }),
      });
      return dimensionOf(comparison, 'layers').attention.map((point) => [point.level, point.code]);
    };
    expect(codes([L1, PATCH])).toEqual([['high', 'layer-removed']]);
    expect(codes([L2, L1, PATCH])).toEqual([['warning', 'layers-reordered']]);
    const unknownSize = buildImageComparison({
      job: job({ candidateTest: { ...job().candidateTest, imageFacts: facts([L1, L2, PATCH]) } }),
    });
    expect(describeDimension(dimensionOf(unknownSize, 'layers'))).toBe(
      '2 → 3 layers (1 added, 0 removed).',
    );
  });

  it('counts restored fields the same way with or without the worker-reported values', () => {
    const config = () => ({
      Cmd: ['nginx', '-g', 'daemon off;'],
      Entrypoint: ['/docker-entrypoint.sh'],
      User: '',
    });
    const facts = (candidateConfig) => ({
      source: { sizeBytes: null, diffIds: [], config: config() },
      candidate: { sizeBytes: null, diffIds: [], config: candidateConfig },
    });
    const restoredJob = (imageFacts) =>
      job({
        verificationEvidence: {
          ...job().verificationEvidence,
          configIntegrity: {
            status: 'restored',
            platform: 'linux/amd64',
            restoredFields: ['Cmd', 'Entrypoint'],
          },
        },
        candidateTest: { ...job().candidateTest, imageFacts },
      });
    const changesOf = (imageFacts) => {
      const item = dimensionOf(
        buildImageComparison({ job: restoredJob(imageFacts) }),
        'configuration',
      );
      return {
        rows: item.rows.filter((row) => row.changed).map((row) => [row.field, row.change]),
        codes: item.attention.map((point) => point.code),
      };
    };
    const restored = [
      ['Cmd', 'restored'],
      ['Entrypoint', 'restored'],
    ];
    expect(changesOf(undefined).rows).toEqual(restored);
    expect(changesOf(facts(config())).rows).toEqual(restored);
    expect(changesOf(facts(config())).codes).toEqual(['config-restored']);
    // Restored but still different from the source is drift, and a high-level point.
    const drift = changesOf(facts({ ...config(), Cmd: ['sh'] }));
    expect(drift.rows).toEqual([
      ['Cmd', 'changed'],
      ['Entrypoint', 'restored'],
    ]);
    expect(drift.codes).toEqual(['config-restored', 'config-changed']);
  });

  it('tolerates partial evidence records instead of failing the whole comparison', () => {
    const partial = {
      passed: true,
      platform: 'linux/amd64',
      packageChanges: { summary: { changed: 1, unplanned: 0 } },
    };
    const comparison = buildImageComparison({
      job: job({
        candidateTest: partial,
        verificationEvidence: { configIntegrity: { status: 'preserved' } },
      }),
      sourceReport,
      outputReport,
    });
    const packages = dimensionOf(comparison, 'packages');
    expect(packages.status).toBe(DIMENSION_STATUS.AVAILABLE);
    expect(packages.rows).toEqual([]);
    expect(packages.note).toMatch(/counts only/);
    expect(describeDimension(packages)).toBe('1 changed, 0 added, 0 removed; 0 not in the plan.');
    expect(dimensionOf(comparison, 'runtime').rows.map((row) => row.id)).toEqual(['startup-state']);
    expect(dimensionOf(comparison, 'configuration').summary.restoredFields).toEqual([]);
    expect(comparison.headline).toMatchObject({
      packagesChanged: 1,
      packagesUnplanned: 0,
      runtimePassed: true,
    });
  });
});

describe('configFieldRows', () => {
  it('marks every differing field and keeps unchanged ones', () => {
    expect(
      configFieldRows(
        { User: 'nginx', StopSignal: 'SIGQUIT' },
        { User: 'root', StopSignal: 'SIGQUIT' },
      ),
    ).toEqual([
      {
        change: 'unchanged',
        field: 'StopSignal',
        source: 'SIGQUIT',
        patched: 'SIGQUIT',
        changed: false,
      },
      { change: 'changed', field: 'User', source: 'nginx', patched: 'root', changed: true },
    ]);
  });
});

describe('dimensionCsv', () => {
  it('quotes every cell and defuses spreadsheet formulas', () => {
    const csv = dimensionCsv({
      columns: [
        { key: 'cve', label: 'Vulnerability' },
        { key: 'package', label: 'Package' },
      ],
      rows: [
        { cve: 'CVE-2026-0001', package: 'say "hi"' },
        { cve: '=HYPERLINK("http://x")', package: '@sum' },
      ],
    });
    expect(csv.split('\n')).toEqual([
      '"Vulnerability","Package"',
      '"CVE-2026-0001","say ""hi"""',
      `"'=HYPERLINK(""http://x"")","'@sum"`,
    ]);
  });
});

describe('describeDimension', () => {
  it('summarises each dimension in one line', () => {
    const comparison = buildImageComparison({ job: job(), sourceReport, outputReport });
    const lines = Object.fromEntries(
      comparison.dimensions.map((item) => [item.id, describeDimension(item)]),
    );
    expect(lines).toMatchObject({
      'vulnerabilities-verified': '1 fixed, 1 remaining (OS packages, at verification).',
      'vulnerabilities-current':
        '2 fixed, 1 remaining, 0 new in the patched image (full image, today).',
      packages: '1 changed, 0 added, 0 removed, 69 unchanged; 0 not in the plan.',
      configuration: 'Restored from the source and verified (Cmd, Entrypoint; linux/amd64).',
      runtime: 'Candidate test passed on linux/amd64.',
      layers:
        'Not available: No image facts in the candidate test result yet: run SSI - Candidate Test again for this job.',
      'supply-chain': 'Patched image carries signature, SBOM.',
    });
  });
});

describe('new findings and what the patch changed', () => {
  // RM-EXEC-0004 in production: the patch updated curl/libcurl/brotli-libs, while the patched
  // image's newer scan reported four libexpat CVEs the source scan did not know yet.
  const newer = report(OUTPUT, [
    { cve: 'CVE-2026-0002', package: 'busybox', installed: '1.37.0-r1', severity: 'Medium' },
    { cve: 'CVE-2026-1001', package: 'libexpat', installed: '2.9.0-r0', severity: 'High' },
    { cve: 'CVE-2026-1002', package: 'libexpat', installed: '2.9.0-r0', severity: 'Unknown' },
    { cve: 'CVE-2026-2001', package: 'curl', installed: '8.23.0-r0', severity: 'Critical' },
  ]);
  const boundTest = (overrides = {}) => ({
    ...job().candidateTest,
    candidateDigest: OUTPUT,
    ...overrides,
  });
  const compare = (candidateTest) =>
    buildImageComparison({ job: job({ candidateTest }), sourceReport, outputReport: newer });

  it('separates new findings in packages the patch did not change from those it updated', () => {
    const comparison = compare(boundTest());
    const current = comparison.dimensions.find((item) => item.id === 'vulnerabilities-current');
    expect(current.summary).toMatchObject({ new: 3, newInUnchangedPackages: 2 });
    expect(current.columns.at(-1)).toEqual({ key: 'packageChange', label: 'Package change' });
    expect(
      current.rows.filter((row) => row.change === 'new').map((row) => [row.cve, row.packageChange]),
    ).toEqual([
      ['CVE-2026-2001', 'Updated by the patch'],
      ['CVE-2026-1001', 'Not changed by the patch'],
      ['CVE-2026-1002', 'Not changed by the patch'],
    ]);
    expect(comparison.headline).toMatchObject({
      vulnerabilitiesNew: 1,
      vulnerabilitiesNewUnchangedPackages: 2,
    });
    const codes = Object.fromEntries(current.attention.map((point) => [point.code, point]));
    expect(codes['new-in-patched']).toMatchObject({
      level: 'high',
      message:
        '1 vulnerability finding(s) appear only in the patched image, in packages the patch updated (1 critical or high).',
    });
    expect(codes['new-in-unchanged-packages']).toMatchObject({ level: 'info' });
    expect(codes['new-in-unchanged-packages'].message).toContain(
      'packages the patch did not change (libexpat)',
    );
    expect(describeDimension(current)).toBe(
      '2 fixed, 1 remaining, 1 new from the patch and 2 in packages the patch did not change (full image, today).',
    );
  });

  it('raises no alarm when every new finding is in an unchanged package', () => {
    const scanDataOnly = report(
      OUTPUT,
      newer.findings.filter((finding) => finding.package !== 'curl'),
    );
    const comparison = buildImageComparison({
      job: job({ candidateTest: boundTest() }),
      sourceReport,
      outputReport: scanDataOnly,
    });
    expect(comparison.headline.vulnerabilitiesNew).toBe(0);
    expect(comparison.attention.map((point) => point.code)).not.toContain('new-in-patched');
    expect(comparison.attention.map((point) => point.code)).toContain('new-in-unchanged-packages');
  });

  it('treats every new finding as possibly from the patch without bound package evidence', () => {
    const otherDigest = compare(boundTest({ candidateDigest: `sha256:${'f'.repeat(64)}` }));
    const legacy = compare(
      boundTest({ packageChanges: { summary: { changed: 1, unplanned: 0 } } }),
    );
    for (const comparison of [otherDigest, legacy]) {
      const current = comparison.dimensions.find((item) => item.id === 'vulnerabilities-current');
      expect(current.summary.newInUnchangedPackages).toBeNull();
      expect(current.columns.map((column) => column.key)).not.toContain('packageChange');
      expect(comparison.headline).toMatchObject({
        vulnerabilitiesNew: 3,
        vulnerabilitiesNewUnchangedPackages: null,
      });
      expect(comparison.attention.find((point) => point.code === 'new-in-patched').message).toBe(
        '3 vulnerability finding(s) appear only in the patched image (2 critical or high).',
      );
    }
  });
});

describe('free comparison of two scanned images', () => {
  const scanned = (image, digest, findings, scannedAt = '2026-11-10 09:00') => ({
    id: image,
    image,
    digest,
    scanner: 'Trivy',
    scannedAt,
    findings,
  });
  const NEWER = `sha256:${'c'.repeat(64)}`;
  const base = scanned('ssi-images/onboarded/nginx:1.27-alpine', SOURCE, [
    {
      cve: 'CVE-2026-0001',
      package: 'curl',
      installed: '8.22.0-r0',
      fixed: '8.23.0-r0',
      severity: 'High',
    },
    { cve: 'CVE-2026-0002', package: 'busybox', installed: '1.37.0-r1', severity: 'Medium' },
  ]);
  const head = scanned('ssi-images/onboarded/nginx:1.29-alpine', NEWER, [
    { cve: 'CVE-2026-0002', package: 'busybox', installed: '1.37.0-r1', severity: 'Medium' },
    { cve: 'CVE-2026-0009', package: 'openssl', installed: '3.5.4-r0', severity: 'Critical' },
  ]);

  it('addresses a scanned image by repository and digest, never by its tag', () => {
    expect(scanReportReference(base)).toBe(`ssi-images/onboarded/nginx@${SOURCE}`);
    expect(
      scanReportReference(scanned(`ssi-images/onboarded/nginx@${SOURCE}`, SOURCE, [])),
    ).toBe(`ssi-images/onboarded/nginx@${SOURCE}`);
    expect(findScanReport([base, head], `ssi-images/onboarded/nginx@${NEWER}`)).toBe(head);
    // Same digest in another repository is another artifact.
    expect(findScanReport([base, head], `ssi-images/approved/nginx@${NEWER}`)).toBeNull();
    for (const malformed of [
      'ssi-images/onboarded/nginx:1.29-alpine',
      `nginx@sha256:abc`,
      '',
      '../x@' + NEWER.slice(0, 20),
    ]) {
      expect(() => findScanReport([base], malformed)).toThrow(ImageComparisonError);
    }
  });

  it('lists what is new, fixed and remaining in the compared image', () => {
    const diff = buildImageDiff({
      baseReport: base,
      headReport: head,
      generatedAt: '2026-11-11T10:00:00.000Z',
    });
    expect(diff).toMatchObject({
      contractVersion: IMAGE_COMPARISON_CONTRACT,
      kind: 'images',
      jobId: null,
      base: {
        role: 'base',
        reference: base.image,
        digest: SOURCE,
        immutableReference: `ssi-images/onboarded/nginx@${SOURCE}`,
      },
      head: { role: 'compared', reference: head.image, digest: NEWER },
      headline: {
        vulnerabilitiesFixed: 1,
        vulnerabilitiesRemaining: 1,
        vulnerabilitiesNew: 1,
        findingsBase: 2,
        findingsHead: 2,
        packagesChanged: null,
      },
    });
    const [vulnerabilities] = diff.dimensions;
    // Packages, layers and configuration wait for SSI - Image Inspection of both images.
    expect(diff.dimensions.map((item) => [item.id, item.status])).toEqual([
      ['vulnerabilities-current', 'available'],
      ['packages', 'unavailable'],
      ['layers', 'unavailable'],
      ['configuration', 'unavailable'],
    ]);
    expect(diff.dimensions[1].note).toBe(
      'Not inspected yet: the base image and the compared image. Run SSI - Image Inspection once per image; the image references are listed above.',
    );
    expect(diff.headline).toMatchObject({
      packageDifferences: null,
      sameOs: null,
      layersShared: null,
    });
    expect(diff.base).toMatchObject({ registryReference: '', inspectedAt: null });
    expect(vulnerabilities.summary).toMatchObject({
      fixed: 1,
      remaining: 1,
      new: 1,
      scanDaysApart: 0,
    });
    expect(vulnerabilities.rows.map((row) => [row.change, row.cve])).toEqual([
      ['new', 'CVE-2026-0009'],
      ['fixed', 'CVE-2026-0001'],
      ['remaining', 'CVE-2026-0002'],
    ]);
    expect(vulnerabilities.columns.map((column) => column.label)).toContain('Compared version');
    // The scanner's fix version is not what the compared image contains.
    expect(vulnerabilities.rows.find((row) => row.change === 'fixed')).toMatchObject({
      source: '8.22.0-r0',
      patched: '',
    });
    expect(diff.attention).toEqual([
      {
        level: 'high',
        code: 'new-in-compared',
        dimension: 'vulnerabilities-current',
        message:
          '1 vulnerability finding(s) appear only in the compared image (1 critical or high).',
      },
    ]);
  });

  it('warns when the two scans are far apart, since newer CVE data looks like a difference', () => {
    const old = { ...base, scannedAt: '2026-10-01 08:00' };
    const diff = buildImageDiff({ baseReport: old, headReport: head });
    expect(diff.dimensions[0].summary.scanDaysApart).toBe(40);
    expect(diff.attention.map((point) => [point.level, point.code])).toContainEqual([
      'info',
      'scans-apart',
    ]);
  });

  it('warns when two images share no finding, as different base images do', () => {
    const findings = (prefix, count) =>
      Array.from({ length: count }, (_, index) => ({
        cve: `CVE-2026-${prefix}${index}`,
        package: `${prefix}-pkg`,
        installed: '1',
        severity: 'Low',
      }));
    const alpine = scanned('ssi-images/onboarded/nginx:alpine', SOURCE, findings('a', 49));
    const debian = scanned(
      'ssi-images/onboarded/nginx:copa-poc-20260908-r1',
      NEWER,
      findings('d', 54),
    );
    const codes = (left, right) =>
      buildImageDiff({ baseReport: left, headReport: right }).attention.map((point) => point.code);
    expect(codes(alpine, debian)).toContain('no-common-findings');
    // Few findings sharing none is normal, and so is one shared finding.
    expect(codes({ ...alpine, findings: findings('a', 4) }, debian)).not.toContain(
      'no-common-findings',
    );
    expect(
      codes(alpine, { ...debian, findings: [...debian.findings, alpine.findings[0]] }),
    ).not.toContain('no-common-findings');
    // The remediation comparison never uses it: a complete fix shares nothing on purpose.
    const fullFix = buildImageComparison({
      job: job(),
      sourceReport: { ...alpine, digest: SOURCE },
      outputReport: { ...debian, digest: OUTPUT },
    });
    expect(fullFix.attention.map((point) => point.code)).not.toContain('no-common-findings');
  });

  it('compares packages, layers and configuration of two inspected images', () => {
    const L = (letter) => `sha256:${letter.repeat(64)}`;
    const inspection = (
      os,
      packages,
      diffIds,
      config,
      sizeBytes,
      generatedAt = '2026-11-11T11:00:00.000Z',
    ) => ({
      os,
      generatedAt,
      packages: packages.map(([name, version]) => ({ name, arch: 'x86_64', version })),
      facts: { sizeBytes, diffIds, config },
    });
    const baseInspection = inspection(
      'alpine 3.22.1',
      [
        ['curl', '8.22.0-r0'],
        ['musl', '1.2.5-r10'],
        ['zlib', '1.3.1-r2'],
        ['busybox', '1.37.0-r19'],
      ],
      [L('1'), L('2')],
      { Cmd: ['nginx'], Env: ['PATH', 'NGINX_VERSION'], User: '' },
      48_000_000,
    );
    const headInspection = inspection(
      'alpine 3.22.2',
      [
        ['curl', '8.23.0-r0'],
        ['musl', '1.2.5-r10'],
        ['zlib', '2.0.0-r0'],
        ['libidn2', '2.3.7-r0'],
      ],
      [L('1'), L('2'), L('3')],
      { Cmd: ['nginx'], Env: ['PATH', 'NGINX_VERSION', 'NJS_VERSION'], User: '' },
      49_500_000,
    );
    const diff = buildImageDiff({
      baseReport: base,
      headReport: head,
      baseInspection,
      headInspection,
      registryHost: 'Registry.example.com',
    });
    const [, packages, layers, configuration] = diff.dimensions;

    expect(packages.status).toBe('available');
    expect(
      packages.rows.map((row) => [
        row.change,
        row.name,
        row.source,
        row.patched,
        row.majorVersionChange,
      ]),
    ).toEqual([
      ['removed', 'busybox', '1.37.0-r19', '', ''],
      ['added', 'libidn2', '', '2.3.7-r0', ''],
      ['changed', 'curl', '8.22.0-r0', '8.23.0-r0', ''],
      ['changed', 'zlib', '1.3.1-r2', '2.0.0-r0', 'Yes'],
    ]);
    expect(packages.summary).toMatchObject({
      unchanged: 1,
      changed: 2,
      added: 1,
      removed: 1,
      differences: 4,
      sameOs: true,
    });
    expect(layers.summary).toMatchObject({
      baseLayers: 2,
      comparedLayers: 3,
      sharedBaseLayers: 2,
      added: 1,
      sizeDeltaBytes: 1_500_000,
    });
    expect(configuration.rows.filter((row) => row.changed).map((row) => row.field)).toEqual([
      'Env',
    ]);
    expect(diff.headline).toMatchObject({
      packageDifferences: 4,
      sameOs: true,
      layersShared: 2,
      layersAdded: 1,
      sizeDeltaBytes: 1_500_000,
    });
    expect(diff.base).toMatchObject({
      registryReference: `registry.example.com/ssi-images/onboarded/nginx@${SOURCE}`,
      inspectedAt: '2026-11-11T11:00:00.000Z',
    });
    expect(diff.attention.map((point) => point.code)).not.toContain('different-os');
  });

  it('tells new findings in same-version packages from real differences, once both images are inspected', () => {
    // Production, 2026-11-11: nginx:alpine vs its patched build. libexpat 2.9.0-r0 is in both
    // images; only the patched image's newer scan knew its CVEs.
    const alpineBase = {
      ...base,
      findings: [
        { cve: 'CVE-2026-0001', package: 'curl', installed: '8.22.0-r0', severity: 'High' },
      ],
    };
    const patched = {
      ...head,
      findings: [
        { cve: 'CVE-2026-1001', package: 'libexpat', installed: '2.9.0-r0', severity: 'High' },
        { cve: 'CVE-2026-1002', package: 'libexpat', installed: '2.9.0-r0', severity: 'Unknown' },
        { cve: 'CVE-2026-2001', package: 'curl', installed: '8.23.0-r0', severity: 'Critical' },
        { cve: 'CVE-2026-3001', package: 'nginx-module-njs', installed: '0.9.1', severity: 'High' },
      ],
    };
    const inspected = (packages) => ({
      os: 'alpine 3.22.2',
      generatedAt: '2026-11-11T12:31:00.000Z',
      packages: packages.map(([name, version, arch = 'x86_64']) => ({ name, arch, version })),
      facts: { sizeBytes: null, diffIds: [], config: {} },
    });
    const baseInspection = inspected([
      ['curl', '8.22.0-r0'],
      ['libexpat', '2.9.0-r0'],
      ['musl', '1.2.5-r10'],
    ]);
    const headInspection = inspected([
      ['curl', '8.23.0-r0'],
      ['libexpat', '2.9.0-r0'],
      ['musl', '1.2.5-r10'],
    ]);
    const diff = buildImageDiff({
      baseReport: alpineBase,
      headReport: patched,
      baseInspection,
      headInspection,
    });
    const [vulnerabilities] = diff.dimensions;

    expect(vulnerabilities.summary).toMatchObject({ new: 4, newInUnchangedPackages: 2 });
    expect(vulnerabilities.columns.at(-1)).toEqual({
      key: 'packageChange',
      label: 'Package version',
    });
    expect(
      vulnerabilities.rows
        .filter((row) => row.change === 'new')
        .map((row) => [row.cve, row.packageChange]),
    ).toEqual([
      ['CVE-2026-2001', 'Different in the compared image'],
      ['CVE-2026-1001', 'Same version in both images'],
      ['CVE-2026-3001', 'Not in the OS package inventory'],
      ['CVE-2026-1002', 'Same version in both images'],
    ]);
    expect(diff.headline).toMatchObject({
      vulnerabilitiesNew: 2,
      vulnerabilitiesNewUnchangedPackages: 2,
    });
    const byCode = Object.fromEntries(diff.attention.map((point) => [point.code, point]));
    // curl differs and the njs module is not an OS package: both still count, and stay high.
    expect(byCode['new-in-compared']).toMatchObject({
      level: 'high',
      message: '2 vulnerability finding(s) appear only in the compared image (2 critical or high).',
    });
    expect(byCode['new-in-unchanged-packages']).toMatchObject({ level: 'info' });
    expect(byCode['new-in-unchanged-packages'].message).toContain(
      'same version in both images (libexpat)',
    );
    expect(byCode['new-in-unchanged-packages'].message).toContain('rescan the base image');
  });

  it('counts a package as the same only if every architecture has the same version', () => {
    const finding = [
      { cve: 'CVE-2026-1001', package: 'libexpat', installed: '2.9.0-r0', severity: 'High' },
    ];
    const inspected = (packages) => ({
      os: 'debian 12.12',
      generatedAt: '2026-11-11T12:31:00.000Z',
      packages: packages.map(([name, version, arch]) => ({ name, arch, version })),
      facts: { sizeBytes: null, diffIds: [], config: {} },
    });
    const labelOf = (baseInspection, headInspection) =>
      buildImageDiff({
        baseReport: { ...base, findings: [] },
        headReport: { ...head, findings: finding },
        baseInspection,
        headInspection,
      }).dimensions[0].rows[0].packageChange;
    const both = inspected([
      ['libexpat', '2.9.0-r0', 'amd64'],
      ['libexpat', '2.9.0-r0', 'i386'],
    ]);
    expect(labelOf(both, both)).toBe('Same version in both images');
    expect(
      labelOf(
        both,
        inspected([
          ['libexpat', '2.9.0-r0', 'amd64'],
          ['libexpat', '2.9.1-r0', 'i386'],
        ]),
      ),
    ).toBe('Different in the compared image');
    expect(labelOf(inspected([['libexpat', '2.9.0-r0', 'amd64']]), both)).toBe(
      'Different in the compared image',
    );
    // Without both inspections there is no package evidence: every new finding counts.
    const oneSide = buildImageDiff({
      baseReport: { ...base, findings: [] },
      headReport: { ...head, findings: finding },
      headInspection: both,
    });
    expect(oneSide.dimensions[0].summary.newInUnchangedPackages).toBeNull();
    expect(oneSide.dimensions[0].rows[0]).not.toHaveProperty('packageChange');
    expect(oneSide.headline.vulnerabilitiesNew).toBe(1);
  });

  it('says so plainly when the inspections show different operating systems', () => {
    const findings = (prefix) =>
      Array.from({ length: 6 }, (_, index) => ({
        cve: `CVE-2026-${prefix}${index}`,
        package: `${prefix}-pkg`,
        installed: '1',
        severity: 'Low',
      }));
    const alpine = { ...base, findings: findings('a') };
    const debian = { ...head, findings: findings('d') };
    const inspection = (os, layer) => ({
      os,
      generatedAt: '2026-11-11T11:00:00.000Z',
      packages: [
        { name: os.startsWith('alpine') ? 'musl' : 'libc6', arch: 'x86_64', version: '1' },
      ],
      facts: { sizeBytes: null, diffIds: [`sha256:${layer.repeat(64)}`], config: {} },
    });
    const diff = buildImageDiff({
      baseReport: alpine,
      headReport: debian,
      baseInspection: inspection('alpine 3.22.2', '1'),
      headInspection: inspection('debian 12.12', '9'),
    });
    const codes = diff.attention.map((point) => [point.level, point.code]);
    expect(codes).toContainEqual(['warning', 'different-os']);
    expect(codes).toContainEqual(['info', 'no-shared-layers']);
    // The measured fact replaces the guess.
    expect(codes.map(([, code]) => code)).not.toContain('no-common-findings');
    expect(diff.headline.sameOs).toBe(false);
    expect(diff.attention.find((point) => point.code === 'different-os').message).toContain(
      'alpine 3.22.2 and debian 12.12',
    );
  });

  it('refuses the same image content and images without a digest', () => {
    const sameContent = {
      ...head,
      image: 'ssi-images/approved/nginx:verified-r1',
      digest: SOURCE,
    };
    expect(() => buildImageDiff({ baseReport: base, headReport: sameContent })).toThrow(
      /same image content/,
    );
    expect(() => buildImageDiff({ baseReport: base, headReport: { ...head, digest: '' } })).toThrow(
      ImageComparisonError,
    );
  });
});
