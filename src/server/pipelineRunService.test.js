import { describe, expect, it } from 'vitest';
import { AzureDevOpsError } from '../lib/azureDevOps.js';
import { createDryRunRemediationJob } from '../lib/remediation.js';
import { ALL_TENANTS } from '../lib/tenancy.js';
import { MemoryRemediationStore } from './remediationStore.js';
import { createPipelineRunService } from './pipelineRunService.js';

const SOURCE = `sha256:${'a'.repeat(64)}`;
const scope = ALL_TENANTS;
const config = { pipelines: { canonicalScan: 4417, copaRemediation: 4422, candidateTest: 4636 } };

function job() {
  const created = createDryRunRemediationJob({
    id: 'RM-DRY-0004',
    report: {
      id: 'ssi-images/onboarded/nginx:1.27',
      image: 'ssi-images/onboarded/nginx:1.27',
      digest: SOURCE,
      os: 'alpine 3.20',
      scanner: 'Trivy',
      findings: [
        {
          cve: 'CVE-1',
          package: 'p',
          installed: '1',
          fixed: '2',
          severity: 'High',
          class: 'os-pkgs',
          type: 'alpine',
        },
      ],
    },
    createdAt: '2026-11-16T08:00:00.000Z',
  });
  return { ...created, tenantId: 'default' };
}

function fakeAzureDevOps({ enabled = true, runState = 'inProgress', getRunError = null } = {}) {
  const calls = [];
  let nextId = 900;
  return {
    calls,
    enabled,
    async runPipeline(role, parameters) {
      calls.push({ type: 'run', role, parameters });
      nextId += 1;
      return {
        id: nextId,
        name: `r${nextId}`,
        state: 'inProgress',
        result: null,
        webUrl: 'https://example-org.visualstudio.com/SecureImages/_build/results?buildId=1',
      };
    },
    async getRun(role, runId) {
      calls.push({ type: 'get', role, runId });
      if (getRunError) throw getRunError;
      return { id: runId, state: runState, result: runState === 'completed' ? 'succeeded' : null };
    },
  };
}

async function setup(options) {
  const store = new MemoryRemediationStore();
  await store.createJob(
    job(),
    {
      eventType: 'seed',
      action: 'seed',
      resourceType: 'remediation-job',
      resourceId: 'RM-DRY-0004',
      summary: 'seed',
    },
    scope,
  );
  const azureDevOps = fakeAzureDevOps(options);
  const service = createPipelineRunService({
    azureDevOps,
    config,
    harborProject: 'ssi-images',
    store,
    now: () => new Date('2026-11-16T09:00:00Z'),
  });
  const audit = (values) => ({
    ...values,
    actorId: 'alex',
    outcome: 'success',
    severity: 'info',
  });
  const start = (extra = {}) =>
    service.start({
      jobId: 'RM-DRY-0004',
      action: 'canonical-scan',
      actorId: 'alex',
      scope,
      audit,
      ...extra,
    });
  return { store, azureDevOps, service, start };
}

describe('createPipelineRunService', () => {
  it('starts the run, stores it on the job with the parameters and audits who started it', async () => {
    const { store, azureDevOps, start } = await setup();
    const result = await start();
    expect(azureDevOps.calls).toEqual([
      {
        type: 'run',
        role: 'canonicalScan',
        parameters: {
          sourceRepository: 'onboarded/nginx',
          sourceDigest: SOURCE,
          remediationJobId: 'RM-DRY-0004',
          deliverToSsi: true,
        },
      },
    ]);
    expect(result.run).toMatchObject({
      action: 'canonical-scan',
      pipelineId: 4417,
      runId: 901,
      requestedBy: 'alex',
    });
    const stored = await store.getJob('RM-DRY-0004', scope);
    expect(stored.pipelineRuns[0].runId).toBe(901);
    const [event] = await store.listAuditEvents({ limit: 1 }, scope);
    expect(event).toMatchObject({
      eventType: 'remediation.pipeline-run.started',
      resourceId: 'RM-DRY-0004',
    });
  });

  it('refuses a second run of the same pipeline while Azure DevOps still reports the first in progress', async () => {
    const { azureDevOps, start } = await setup();
    await start();
    await expect(start()).rejects.toMatchObject({
      statusCode: 409,
      message: expect.stringMatching(/still in progress/),
    });
    expect(azureDevOps.calls.filter((call) => call.type === 'run')).toHaveLength(1);
  });

  it('starts again once the previous run has finished, and records the finished state', async () => {
    const { store, azureDevOps, start } = await setup();
    await start();
    azureDevOps.getRun = async (role, runId) => ({
      id: runId,
      state: 'completed',
      result: 'succeeded',
    });
    await start();
    const stored = await store.getJob('RM-DRY-0004', scope);
    expect(stored.pipelineRuns.map((run) => [run.runId, run.state])).toEqual([
      [902, 'inProgress'],
      [901, 'completed'],
    ]);
  });

  it('does not start when the previous run cannot be checked', async () => {
    const { start, azureDevOps } = await setup();
    await start();
    azureDevOps.getRun = async () => {
      throw new AzureDevOpsError('down', { code: 'ado_unreachable' });
    };
    await expect(start()).rejects.toMatchObject({
      statusCode: 409,
      message: expect.stringMatching(/could not be checked/),
    });
  });

  it('starts nothing when the job is not visible, automation is off or the action is unknown', async () => {
    const { start, azureDevOps } = await setup();
    await expect(start({ jobId: 'RM-DRY-9999' })).resolves.toBeNull();
    await expect(start({ action: 'drop-table' })).rejects.toMatchObject({ statusCode: 422 });
    const off = await setup({ enabled: false });
    await expect(off.start()).rejects.toMatchObject({ statusCode: 503 });
    expect(azureDevOps.calls).toHaveLength(0);
  });

  it('shows live state without writing, and marks runs it could not check', async () => {
    const { store, service, start, azureDevOps } = await setup();
    await start();
    azureDevOps.getRun = async (role, runId) => ({
      id: runId,
      state: 'completed',
      result: 'failed',
    });
    const view = await service.view(await store.getJob('RM-DRY-0004', scope), scope);
    expect(view.runs[0]).toMatchObject({ state: 'completed', result: 'failed' });
    expect((await store.getJob('RM-DRY-0004', scope)).pipelineRuns[0].state).toBe('inProgress');
    azureDevOps.getRun = async () => {
      throw new AzureDevOpsError('down', { code: 'ado_unreachable' });
    };
    const stale = await service.view(await store.getJob('RM-DRY-0004', scope), scope);
    expect(stale.runs[0].refreshError).toMatch(/could not be asked/);
  });

  it('reports the verified result that closes a Dry Run for Copa', async () => {
    const { store, service } = await setup();
    await store.createJob(
      {
        id: 'RM-EXEC-0005',
        mode: 'execution',
        parentJobId: 'RM-DRY-0004',
        lifecycleState: 'verified',
        status: 'Verified',
        tenantId: 'default',
      },
      {
        eventType: 'seed',
        action: 'seed',
        resourceType: 'remediation-job',
        resourceId: 'RM-EXEC-0005',
        summary: 'seed',
      },
      scope,
    );
    const view = await service.view(await store.getJob('RM-DRY-0004', scope), scope);
    for (const action of ['copa-prepare', 'copa-execute']) {
      expect(view.actions.find((item) => item.action === action)).toMatchObject({
        available: false,
        reason: expect.stringMatching(/RM-EXEC-0005/),
      });
    }
  });
});

describe('pipeline runs of onboarding, publish requests and scanned images', () => {
  const DIGEST = `sha256:${'b'.repeat(64)}`;
  const API = 'http://10.0.0.10:5021/api/v1';
  const seedAudit = (resourceId) => ({
    eventType: 'seed',
    action: 'seed',
    resourceType: 'seed',
    resourceId,
    summary: 'seed',
  });
  const fullConfig = {
    workerApiBaseUrl: API,
    pipelines: {
      onboardImport: 4503,
      controlledPublish: 4441,
      supplyChainSign: 4522,
      imageInspection: 4657,
    },
  };

  async function setupRecords() {
    const store = new MemoryRemediationStore();
    await store.createJob(
      {
        id: 'RM-EXEC-0005',
        mode: 'execution',
        lifecycleState: 'verified',
        sourceDigest: SOURCE,
        tenantId: 'default',
      },
      seedAudit('RM-EXEC-0005'),
      scope,
    );
    await store.createOnboardingRequest(
      {
        id: 'ONB-0009',
        status: 'Requested',
        target: { tagReference: 'harbor/ssi-images/onboarded/redis:7' },
        tenantId: 'default',
      },
      seedAudit('ONB-0009'),
      scope,
    );
    await store.createPublishRequest(
      {
        id: 'PUB-0011',
        jobId: 'RM-EXEC-0005',
        status: 'Approved',
        source: { digest: DIGEST },
        target: {
          project: 'ssi-images',
          repository: 'approved/nginx',
          tag: 'r1',
          tagReference: 'h/ssi-images/approved/nginx:r1',
        },
        tenantId: 'default',
      },
      seedAudit('PUB-0011'),
      scope,
    );
    const azureDevOps = fakeAzureDevOps();
    const service = createPipelineRunService({
      azureDevOps,
      config: fullConfig,
      harborProject: 'ssi-images',
      registryHost: 'registry.example.com',
      store,
      now: () => new Date('2026-11-17T09:00:00Z'),
    });
    const audit = (values) => ({
      ...values,
      actorId: 'approver',
      outcome: 'success',
      severity: 'info',
    });
    return { store, azureDevOps, service, audit };
  }

  it('checks an onboarding request, keeps the run on the request and refuses a parallel run', async () => {
    const { store, azureDevOps, service, audit } = await setupRecords();
    const started = await service.startOnboarding({
      requestId: 'ONB-0009',
      action: 'onboard-check',
      actorId: 'op',
      scope,
      audit,
    });
    expect(started.run).toMatchObject({ action: 'onboard-check', pipelineId: 4503 });
    expect(azureDevOps.calls[0].parameters).toMatchObject({
      onboardingRequestId: 'ONB-0009',
      executeImport: false,
    });
    expect((await store.getOnboardingRequest('ONB-0009', scope)).pipelineRuns).toHaveLength(1);
    await expect(
      service.startOnboarding({
        requestId: 'ONB-0009',
        action: 'onboard-import',
        actorId: 'op',
        scope,
        audit,
      }),
    ).rejects.toMatchObject({
      statusCode: 409,
      message: expect.stringMatching(/still in progress/),
    });
    await expect(
      service.startOnboarding({
        requestId: 'ONB-9999',
        action: 'onboard-check',
        actorId: 'op',
        scope,
        audit,
      }),
    ).resolves.toBeNull();
  });

  it('publishes an approved request under the job and request locks, and keeps its row version', async () => {
    const { store, azureDevOps, service, audit } = await setupRecords();
    const result = await service.startPublish({
      requestId: 'PUB-0011',
      action: 'publish-check',
      actorId: 'approver',
      scope,
      audit,
    });
    expect(result.run.action).toBe('publish-check');
    expect(azureDevOps.calls[0]).toMatchObject({
      role: 'controlledPublish',
      parameters: { publishRequestId: 'PUB-0011', executePublish: false },
    });
    const stored = await store.getPublishRequest('PUB-0011', scope);
    expect(stored.pipelineRuns[0].runId).toBe(901);
    expect(stored.rowVersion).toBe(2);
    const view = await service.viewPublish(stored, await store.getJob('RM-EXEC-0005', scope));
    expect(view.actions.find((item) => item.action === 'publish-execute')).toMatchObject({
      available: false,
      confirm: true,
    });
  });

  it('inspects a scanned image once at a time and keeps the runs in their own store', async () => {
    const { store, azureDevOps, service, audit } = await setupRecords();
    const reference = `ssi-images/onboarded/nginx@${DIGEST}`;
    const result = await service.startImage({
      reference,
      action: 'image-inspection',
      actorId: 'op',
      audit,
      tenantId: 'default',
    });
    expect(result.run.action).toBe('image-inspection');
    expect(azureDevOps.calls[0].parameters).toEqual({
      imageReference: `registry.example.com/${reference}`,
      deliverToSsi: true,
    });
    expect(await store.listResourceRuns('image', reference)).toHaveLength(1);
    await expect(
      service.startImage({
        reference,
        action: 'image-inspection',
        actorId: 'op',
        audit,
        tenantId: 'default',
      }),
    ).rejects.toMatchObject({ statusCode: 409 });
    const view = await service.viewImage(reference);
    expect(view.actions[0]).toMatchObject({ action: 'image-inspection', available: false });
  });
});
