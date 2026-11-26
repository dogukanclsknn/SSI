import { describe, expect, it } from 'vitest';
import { createDryRunRemediationJob, replanDryRunFromCanonicalReport } from './remediation.js';
import {
  buildExecutionReadiness,
  buildWorkerHandoffManifest,
  buildWorkerDispatchPayload,
  createExecutionJobFromDryRun,
  REMEDIATION_LIFECYCLE_STATES,
  transitionRemediationJob,
} from './remediationLifecycle.js';

const report = {
  id: 'registry.example.com/payment-api:1.2.3',
  image: 'registry.example.com/payment-api:1.2.3',
  digest: 'sha256:8fbb1d1fd3d75d4d73d8b5d5d6d5f97b3d1f8e8b',
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
  ],
};

function createDryRunJob() {
  return createDryRunRemediationJob({
    id: 'RM-DRY-0001',
    report,
    createdAt: '2026-07-17T10:00:00.000Z',
  });
}

function createCanonicalDryRunJob() {
  const dryRunJob = createDryRunJob();

  return replanDryRunFromCanonicalReport({
    job: dryRunJob,
    acceptedAt: '2026-07-17T10:00:30.000Z',
    canonicalReport: {
      normalizedReport: report,
      receipt: {
        reportId: 'CTR-4c2d1a8f7b30',
        contentDigest: 'sha256:4c2d1a8f7b30d467e87eab1250e77bf9e5d5945d0c4869ec3f0c6d341f07f6b4',
        sourceDigest: report.digest,
        artifactName: report.image,
        generatedAt: '2026-07-17T10:00:20.000Z',
        trivyVersion: '0.70.0',
        schemaVersion: 2,
        scope: 'os-packages-only',
        resultClasses: ['os-pkgs'],
        findingCount: report.findings.length,
        os: report.os,
      },
    },
  });
}

describe('remediation lifecycle', () => {
  it('keeps a Dry Run plan separate from a queued execution job', () => {
    const dryRunJob = createCanonicalDryRunJob();
    const executionJob = createExecutionJobFromDryRun({
      id: 'RM-EXEC-0001',
      dryRunJob,
      createdAt: '2026-07-17T10:01:00.000Z',
    });

    expect(dryRunJob).toMatchObject({
      mode: 'dry-run',
      lifecycleState: REMEDIATION_LIFECYCLE_STATES.PLANNED,
      execution: 'not-run',
    });
    expect(executionJob).toMatchObject({
      mode: 'execution',
      parentJobId: 'RM-DRY-0001',
      lifecycleState: REMEDIATION_LIFECYCLE_STATES.QUEUED,
      status: 'Queued',
      execution: 'queued',
      fixed: [],
      patchedImageDigest: '',
    });
  });

  it('only permits the explicit execution lifecycle transitions', () => {
    const queued = createExecutionJobFromDryRun({ id: 'RM-EXEC-0001', dryRunJob: createCanonicalDryRunJob() });
    const running = transitionRemediationJob(queued, REMEDIATION_LIFECYCLE_STATES.RUNNING, {
      at: '2026-07-17T10:02:00.000Z',
    });
    const patched = transitionRemediationJob(running, REMEDIATION_LIFECYCLE_STATES.PATCHED);
    const rescanning = transitionRemediationJob(patched, REMEDIATION_LIFECYCLE_STATES.RESCANNING);
    const verified = transitionRemediationJob(rescanning, REMEDIATION_LIFECYCLE_STATES.VERIFIED, {
      at: '2026-07-17T10:05:00.000Z',
    });

    expect(verified).toMatchObject({
      lifecycleState: REMEDIATION_LIFECYCLE_STATES.VERIFIED,
      status: 'Verified',
      execution: 'completed',
      verificationStatus: 'Passed',
      verifiedAt: '2026-07-17T10:05:00.000Z',
    });
    expect(verified.lifecycleEvents).toHaveLength(5);
    expect(() => transitionRemediationJob(queued, REMEDIATION_LIFECYCLE_STATES.VERIFIED)).toThrow(
      'Invalid remediation lifecycle transition',
    );
  });
});

describe('isolated worker contract', () => {
  it('reports blockers instead of allowing a web container to dispatch work', () => {
    const readiness = buildExecutionReadiness(createDryRunJob());

    expect(readiness).toMatchObject({
      workerConfigured: false,
      dispatchAllowed: false,
      lifecycleState: REMEDIATION_LIFECYCLE_STATES.PLANNED,
    });
    expect(readiness.blockers).toContain('Isolated remediation worker');
    expect(readiness.requirements.find((item) => item.id === 'immutable-source-digest')).toMatchObject({
      met: true,
    });
  });

  it('lists only conditions that can be met, and allows dispatch once SSI can start the worker', () => {
    const job = createCanonicalDryRunJob();
    expect(buildExecutionReadiness(job).requirements.map((item) => item.id)).toEqual([
      'eligible-os-package-plan',
      'immutable-source-digest',
      'canonical-trivy-report',
      'credential-free-worker-handoff',
      'isolated-worker',
    ]);

    const manual = buildExecutionReadiness(job);
    expect(manual).toMatchObject({ ready: false, dispatchAllowed: false, workerConfigured: false });
    expect(manual.blockers).toEqual(['Isolated remediation worker']);

    const automated = buildExecutionReadiness(job, { workerConfigured: true });
    expect(automated).toMatchObject({ ready: true, dispatchAllowed: true, workerConfigured: true, blockers: [] });
    expect(automated.requirements.at(-1).detail).toMatch(/SSI starts the isolated Copa worker/);

    // A configured worker never makes an unprepared job dispatchable.
    const unprepared = buildExecutionReadiness(createDryRunJob(), { workerConfigured: true });
    expect(unprepared.dispatchAllowed).toBe(false);
    expect(unprepared.blockers).not.toContain('Isolated remediation worker');
  });

  it('exports a credential-free, prepare-only worker handoff for a canonical Dry Run', () => {
    const handoff = buildWorkerHandoffManifest(createCanonicalDryRunJob());

    expect(handoff).toMatchObject({
      contractVersion: 'ssi.remediation-worker/v1alpha1',
      kind: 'RemediationHandoffManifest',
      spec: {
        executionMode: 'prepare-only',
        source: {
          digest: report.digest,
          immutableReference: `registry.example.com/payment-api@${report.digest}`,
        },
        canonicalInput: {
          sourceDigest: report.digest,
          rawReportEmbedded: false,
        },
        output: {
          sourceMutation: 'forbidden',
          registryWrite: 'worker-runtime-only',
          publishAllowed: false,
        },
      },
      safeguards: {
        webContainerDispatch: false,
        dockerSocketInWebContainer: false,
        registryCredentialsEmbedded: false,
      },
    });
    expect(JSON.stringify(handoff)).not.toContain('HARBOR_ROBOT_SECRET');
  });

  it('requires a canonical report before an execution job or worker payload can be created', () => {
    expect(() => createExecutionJobFromDryRun({ id: 'RM-EXEC-0001', dryRunJob: createDryRunJob() })).toThrow(
      'validated canonical OS-only Trivy report',
    );
  });

  it('rejects a canonical receipt without an immutable content digest', () => {
    const incomplete = createCanonicalDryRunJob();
    incomplete.canonicalReport.contentDigest = '';

    expect(() => buildWorkerHandoffManifest(incomplete)).toThrow('validated canonical OS-only Trivy report');
  });

  it('builds a credential-free worker payload only for a queued canonical execution job', () => {
    const executionJob = createExecutionJobFromDryRun({ id: 'RM-EXEC-0001', dryRunJob: createCanonicalDryRunJob() });
    const payload = buildWorkerDispatchPayload(executionJob);

    expect(payload).toMatchObject({
      contractVersion: 'ssi.remediation-worker/v1alpha1',
      source: {
        digest: report.digest,
        immutableReference: `registry.example.com/payment-api@${report.digest}`,
      },
      scanner: {
        tool: 'trivy',
        scope: 'os-packages-only',
        command: 'trivy image --pkg-types os --ignore-unfixed --format json',
      },
      canonicalInput: {
        sourceDigest: report.digest,
        rawReportEmbedded: false,
      },
      verification: {
        reScanPatchedDigest: true,
        blockPublishUntilVerified: true,
      },
      credentialDelivery: {
        includedInPayload: false,
      },
    });
    expect(JSON.stringify(payload)).not.toContain('HARBOR_ROBOT_SECRET');
  });
});
