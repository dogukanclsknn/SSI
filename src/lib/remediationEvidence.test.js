import { describe, expect, it } from 'vitest';
import {
  createVerifiedRemediationJob,
  RemediationEvidenceValidationError,
} from './remediationEvidence.js';

const sourceDigest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const outputDigest = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const canonicalDigest = 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

const dryRunJob = {
  id: 'RM-DRY-0001',
  mode: 'dry-run',
  status: 'Planned',
  image: 'harbor.example.com/team/app:source',
  sourceDigest,
  scanReportId: 'team/app:source',
  scanner: 'Trivy',
  os: 'alpine 3.7.1',
  scope: 'os-packages-only',
  engineVersion: 'v0.14.2',
  canonicalReport: {
    contentDigest: canonicalDigest,
    findingCount: 2,
  },
  plannedFixes: [
    { cve: 'CVE-1', package: 'curl', from: '1.0', to: '1.1', severity: 'Critical', cvss: 9.8 },
    { cve: 'CVE-2', package: 'openssl', from: '2.0', to: '2.1', severity: 'High', cvss: 8.1 },
  ],
  packageUpdates: [],
};

const copaOutputDigest = 'sha256:9999999999999999999999999999999999999999999999999999999999999999';

// Worker proof that the Copa output lost its runtime config and the pipeline restored it.
function configIntegrity(overrides = {}) {
  return {
    contractVersion: 'ssi.image-config-integrity/v1',
    status: 'restored',
    verified: true,
    platform: 'linux/amd64',
    restoredFields: ['Cmd', 'Entrypoint', 'ExposedPorts', 'StopSignal'],
    layersPreserved: true,
    sourceConfigDigest: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    copaOutputDigest,
    copaConfigDigest: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    outputDigest,
    outputConfigDigest: 'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    runtimeConfigDigest: 'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    ...overrides,
  };
}

function remediationEvidence(overrides = {}) {
  return {
    contractVersion: 'ssi.copa-remediation-poc/v1alpha1',
    mode: 'approved-poc-execution',
    generatedAt: '2026-07-21T14:29:37.653Z',
    source: {
      immutableReference: `harbor.example.com/team/app@${sourceDigest}`,
      digest: sourceDigest,
    },
    canonicalInput: {
      contentDigest: canonicalDigest,
      trivyVersion: '0.70.0',
      scope: 'os-packages-only',
      findings: 2,
    },
    output: {
      tagReference: 'harbor.example.com/team/app:copa-poc-r1',
      immutableReference: `harbor.example.com/team/app@${outputDigest}`,
      digest: outputDigest,
      approvedPublishAttempted: false,
    },
    engine: {
      name: 'Copacetic BuildKit frontend',
      version: '0.14.2',
      packageScope: 'os',
    },
    verification: {
      scanner: 'Trivy',
      reScanPatchedDigest: true,
      before: { findings: 2, severity: { critical: 1, high: 1, medium: 0, low: 0, unknown: 0 } },
      after: { findings: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } },
      fixed: [
        { cve: 'CVE-1', package: 'curl', fixedVersion: '1.1' },
        { cve: 'CVE-2', package: 'openssl', fixedVersion: '2.1' },
      ],
      remaining: [],
      passed: true,
    },
    configIntegrity: configIntegrity(),
    result: {
      status: 'verified-poc-output',
      patchAttempted: true,
      registryWriteAttempted: true,
      verificationScanAttempted: true,
      approvedPublishAttempted: false,
    },
    ...overrides,
  };
}

describe('createVerifiedRemediationJob', () => {
  it('creates a separate verified execution job while keeping central publish blocked', () => {
    const job = createVerifiedRemediationJob({
      id: 'RM-EXEC-0001',
      dryRunJob,
      evidence: remediationEvidence(),
      acceptedAt: '2026-07-21T14:31:00.000Z',
      evidenceDigest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      fullImageComparison: { status: 'available', reducedBy: 64 },
    });

    expect(job).toMatchObject({
      id: 'RM-EXEC-0001',
      parentJobId: 'RM-DRY-0001',
      mode: 'execution',
      status: 'Verified',
      lifecycleState: 'verified',
      patchedImageDigest: outputDigest,
      verificationStatus: 'Passed',
      publishGate: { allowed: false, status: 'Blocked', approvedPublishAttempted: false },
      fullImageComparison: { status: 'available', reducedBy: 64 },
    });
    expect(job.fixed).toEqual([
      expect.objectContaining({ cve: 'CVE-1', from: '1.0', to: '1.1', severity: 'Critical' }),
      expect.objectContaining({ cve: 'CVE-2', from: '2.0', to: '2.1', severity: 'High' }),
    ]);
    expect(job.remaining).toEqual([]);
    expect(job.after).toEqual({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
  });

  it('rejects evidence for a different immutable source digest', () => {
    const differentDigest = 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    const evidence = remediationEvidence({
      source: {
        digest: differentDigest,
        immutableReference: `harbor.example.com/team/app@${differentDigest}`,
      },
    });

    expect(() => createVerifiedRemediationJob({ id: 'RM-EXEC-0002', dryRunJob, evidence })).toThrow(
      RemediationEvidenceValidationError,
    );
  });

  it('rejects evidence that claims an approved publish or inconsistent verification totals', () => {
    const evidence = remediationEvidence();
    evidence.result.approvedPublishAttempted = true;
    evidence.verification.after.findings = 1;

    expect(() => createVerifiedRemediationJob({ id: 'RM-EXEC-0003', dryRunJob, evidence })).toThrow(
      /after|publish/i,
    );
  });
});

describe('createVerifiedRemediationJob — image configuration integrity', () => {
  const accept = (evidence) => createVerifiedRemediationJob({ id: 'RM-EXEC-0004', dryRunJob, evidence });

  it('stores the restored-configuration proof and records it in the job log', () => {
    const job = accept(remediationEvidence());

    expect(job.verificationEvidence.configIntegrity).toEqual(configIntegrity());
    expect(job.logs).toContain(
      'Image configuration restored from the source (Cmd, Entrypoint, ExposedPorts, StopSignal) and verified on linux/amd64.',
    );
  });

  it('accepts a Copa output that preserved the configuration unchanged', () => {
    const preserved = configIntegrity({
      status: 'preserved',
      restoredFields: [],
      copaOutputDigest: outputDigest,
      outputConfigDigest: configIntegrity().copaConfigDigest,
    });
    const job = accept(remediationEvidence({ configIntegrity: preserved }));

    expect(job.verificationEvidence.configIntegrity.status).toBe('preserved');
    expect(job.logs).toContain('Image configuration preserved from the source and verified on linux/amd64.');
  });

  it('rejects evidence from a worker without the configuration integrity gate', () => {
    const evidence = remediationEvidence();
    delete evidence.configIntegrity;

    expect(() => accept(evidence)).toThrow(/missing the image configuration integrity proof/);
  });

  it.each([
    ['an unverified result', { verified: false }, /must be verified/],
    ['an unknown status', { status: 'skipped' }, /preserved or restored/],
    ['changed layers', { layersPreserved: false }, /no layer changed/],
    ['another output digest', { outputDigest: copaOutputDigest }, /not bound to the remediation output digest/],
    ['a restore without fields', { restoredFields: [] }, /list the restored fields/],
    ['a restore that kept the Copa digest', { copaOutputDigest: outputDigest }, /new output digest/],
    ['an invalid field name', { restoredFields: ['Cmd; rm -rf'] }, /invalid field name/],
    ['an invalid platform', { platform: 'linux' }, /platform is invalid/],
    ['an unknown contract', { contractVersion: 'v0' }, /Unsupported image configuration integrity contract/],
    ['a short digest', { runtimeConfigDigest: 'sha256:abc' }, /runtimeConfigDigest must be a sha256 digest/],
  ])('rejects %s', (_label, overrides, message) => {
    expect(() => accept(remediationEvidence({ configIntegrity: configIntegrity(overrides) }))).toThrow(message);
  });

  it('rejects a preserved claim whose output differs from the Copa output', () => {
    const preserved = configIntegrity({ status: 'preserved', restoredFields: [] });

    expect(() => accept(remediationEvidence({ configIntegrity: preserved }))).toThrow(/keep the Copa output unchanged/);
  });
});
