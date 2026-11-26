import { describe, expect, it } from 'vitest';
import { createDryRunRemediationJob, replanDryRunFromCanonicalReport } from './remediation.js';
import {
  copaOutputReferenceOf,
  copaOutputRepository,
  createRunRecord,
  harborRepositoryPath,
  MAX_STORED_RUNS,
  PipelineRunError,
  pipelineRunsView,
  planPipelineRun,
  refreshedRun,
  verifiedExecutionOf,
  withRun,
} from './pipelineRuns.js';

const SOURCE = `sha256:${'a'.repeat(64)}`;
const CONTENT = `sha256:${'c'.repeat(64)}`;
const IMAGE = 'ssi-images/onboarded/nginx:1.27-alpine';
const options = {
  harborProject: 'ssi-images',
  pipelines: { canonicalScan: 4417, copaRemediation: 4422, candidateTest: 4636 },
  now: Date.parse('2026-11-16T09:00:00Z'),
};

const report = {
  id: IMAGE,
  image: IMAGE,
  digest: SOURCE,
  os: 'alpine 3.20',
  scanner: 'Trivy',
  findings: [
    {
      cve: 'CVE-2026-0001',
      package: 'libexpat',
      installed: '2.6.0-r0',
      fixed: '2.6.4-r0',
      severity: 'High',
      cvss: 7.5,
      class: 'os-pkgs',
      type: 'alpine',
    },
  ],
};

function dryRun() {
  return createDryRunRemediationJob({
    id: 'RM-DRY-0004',
    report,
    createdAt: '2026-11-16T08:00:00.000Z',
  });
}

function canonicalDryRun() {
  return replanDryRunFromCanonicalReport({
    job: dryRun(),
    acceptedAt: '2026-11-16T08:10:00.000Z',
    canonicalReport: {
      normalizedReport: report,
      receipt: {
        reportId: 'CTR-1',
        contentDigest: CONTENT,
        sourceDigest: SOURCE,
        artifactName: IMAGE,
        generatedAt: '2026-11-16T08:05:00.000Z',
        trivyVersion: '0.70.0',
        schemaVersion: 2,
        scope: 'os-packages-only',
        resultClasses: ['os-pkgs'],
        findingCount: 1,
        os: report.os,
      },
    },
  });
}

const run = (action, state, result, parameters, runId = 100) => ({
  action,
  role: action === 'canonical-scan' ? 'canonicalScan' : 'copaRemediation',
  runId,
  state,
  result,
  parameters,
});

const verifiedExecution = {
  id: 'RM-EXEC-0007',
  mode: 'execution',
  lifecycleState: 'verified',
  image: IMAGE,
  sourceDigest: SOURCE,
  patchedImageTag:
    'registry.example.com/ssi-images/onboarded/nginx:copa-poc-20261116-r1',
  patchedImageDigest: `sha256:${'b'.repeat(64)}`,
  verificationEvidence: {
    sourceReference: `registry.example.com/ssi-images/onboarded/nginx@${SOURCE}`,
  },
};

const expectRefused = (fn, pattern) => {
  let caught;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(PipelineRunError);
  expect(caught.message).toMatch(pattern);
};

describe('harborRepositoryPath', () => {
  it('takes the repository path inside the worker project, with or without the registry host', () => {
    expect(harborRepositoryPath(IMAGE, 'ssi-images')).toBe('onboarded/nginx');
    expect(
      harborRepositoryPath(
        `registry.example.com/ssi-images/onboarded/nginx@${SOURCE}`,
        'ssi-images',
      ),
    ).toBe('onboarded/nginx');
  });

  it('refuses images from another project', () => {
    expectRefused(
      () => harborRepositoryPath('other-project/nginx:1', 'ssi-images'),
      /Harbor project/,
    );
    expectRefused(() => harborRepositoryPath('nginx:1', 'ssi-images'), /Harbor project/);
  });
});

describe('planPipelineRun', () => {
  it('starts the canonical scan with the repository, the full source digest and delivery back to the job', () => {
    expect(planPipelineRun(dryRun(), 'canonical-scan', options)).toEqual({
      action: 'canonical-scan',
      role: 'canonicalScan',
      templateParameters: {
        sourceRepository: 'onboarded/nginx',
        sourceDigest: SOURCE,
        remediationJobId: 'RM-DRY-0004',
        deliverToSsi: true,
      },
    });
  });

  it('does not patch a plan again once it has a verified result', () => {
    const prepared = run('copa-prepare', 'completed', 'succeeded', {
      sourceDigest: SOURCE,
      canonicalReceiptContentDigest: CONTENT,
      canonicalBuildId: '1',
    });
    const job = { ...canonicalDryRun(), pipelineRuns: [prepared] };
    const verified = { ...options, verifiedExecutionId: 'RM-EXEC-0005' };
    expectRefused(
      () => planPipelineRun(job, 'copa-execute', verified),
      /RM-EXEC-0005.*new Dry Run/,
    );
    expectRefused(() => planPipelineRun(job, 'copa-prepare', verified), /verified result/);
    expect(planPipelineRun(job, 'canonical-scan', verified).action).toBe('canonical-scan');
    const view = pipelineRunsView(job, { enabled: true, ...verified });
    expect(view.actions.find((item) => item.action === 'copa-execute')).toMatchObject({
      available: false,
    });
  });

  it('finds only a verified, not withdrawn result of the same Dry Run', () => {
    const child = {
      id: 'RM-EXEC-0005',
      mode: 'execution',
      parentJobId: 'RM-DRY-0004',
      lifecycleState: 'verified',
    };
    const dry = dryRun();
    expect(verifiedExecutionOf(dry, [child])).toBe('RM-EXEC-0005');
    expect(verifiedExecutionOf(dry, [{ ...child, publishWithdrawal: { at: 'x' } }])).toBe('');
    expect(verifiedExecutionOf(dry, [{ ...child, parentJobId: 'RM-DRY-0009' }])).toBe('');
    expect(verifiedExecutionOf(child, [child])).toBe('');
  });

  it('runs the canonical scan on a Dry Run blocked by the Harbor scan, which it is there to unblock', () => {
    const blocked = { ...dryRun(), status: 'Blocked', lifecycleState: 'blocked', plannedFixes: [] };
    expect(planPipelineRun(blocked, 'canonical-scan', options).templateParameters).toMatchObject({
      sourceRepository: 'onboarded/nginx',
      sourceDigest: SOURCE,
    });
    expectRefused(() => planPipelineRun(blocked, 'copa-prepare', options), /canonical Trivy JSON/);
    const view = pipelineRunsView(blocked, { enabled: true, ...options });
    expect(view.actions.map((item) => [item.action, item.available])).toEqual([
      ['canonical-scan', true],
      ['copa-prepare', false],
      ['copa-execute', false],
    ]);
  });

  it('keeps Copa off a Dry Run whose canonical report has nothing to fix', () => {
    const blocked = { ...canonicalDryRun(), status: 'Blocked', lifecycleState: 'blocked' };
    expectRefused(
      () => planPipelineRun(blocked, 'copa-prepare', { ...options, canonicalBuildId: '5' }),
      /planned Dry Run/,
    );
  });

  it('keeps the runs when the canonical report is uploaded, so Copa finds the scan that produced it', () => {
    const scan = run('canonical-scan', 'completed', 'succeeded', { sourceDigest: SOURCE }, 876849);
    const replanned = replanDryRunFromCanonicalReport({
      job: { ...dryRun(), pipelineRuns: [scan] },
      acceptedAt: '2026-11-16T08:10:00.000Z',
      canonicalReport: canonicalDryRun().canonicalReport && {
        normalizedReport: report,
        receipt: { ...canonicalDryRun().canonicalReport },
      },
    });
    expect(replanned.pipelineRuns).toEqual([scan]);
    expect(
      planPipelineRun(replanned, 'copa-prepare', options).templateParameters.canonicalBuildId,
    ).toBe('876849');
  });

  it('needs the canonical report before Copa', () => {
    expectRefused(() => planPipelineRun(dryRun(), 'copa-prepare', options), /canonical Trivy JSON/);
  });

  it('runs the Copa input check with the canonical scan SSI started, never executing', () => {
    const job = {
      ...canonicalDryRun(),
      pipelineRuns: [
        run('canonical-scan', 'completed', 'succeeded', { sourceDigest: SOURCE }, 881234),
      ],
    };
    const plan = planPipelineRun(job, 'copa-prepare', options);
    expect(plan.templateParameters).toEqual({
      sourceRepository: 'onboarded/nginx',
      sourceDigest: SOURCE,
      remediationJobId: 'RM-DRY-0004',
      canonicalPipelineDefinitionId: '4417',
      canonicalBuildId: '881234',
      canonicalReceiptContentDigest: CONTENT,
      outputRepository: 'onboarded/nginx',
      outputTag: 'copa-poc-20261116-1.27-alpine-rm-dry-0004-r1',
      executeRemediation: false,
    });
  });

  it('needs a succeeded canonical scan or a Build ID given by the person', () => {
    const failedScan = {
      ...canonicalDryRun(),
      pipelineRuns: [run('canonical-scan', 'completed', 'failed', { sourceDigest: SOURCE })],
    };
    expectRefused(() => planPipelineRun(failedScan, 'copa-prepare', options), /enter its Build ID/);
    expect(
      planPipelineRun(failedScan, 'copa-prepare', { ...options, canonicalBuildId: '774757' })
        .templateParameters.canonicalBuildId,
    ).toBe('774757');
    expectRefused(
      () => planPipelineRun(failedScan, 'copa-prepare', { ...options, canonicalBuildId: '77x' }),
      /positive number/,
    );
  });

  it('patches only after a succeeded input check, with exactly that canonical input', () => {
    const base = canonicalDryRun();
    expectRefused(() => planPipelineRun(base, 'copa-execute', options), /input check/);
    const prepared = run('copa-prepare', 'completed', 'succeeded', {
      sourceDigest: SOURCE,
      canonicalReceiptContentDigest: CONTENT,
      canonicalBuildId: '774757',
    });
    const plan = planPipelineRun({ ...base, pipelineRuns: [prepared] }, 'copa-execute', options);
    expect(plan.templateParameters).toMatchObject({
      canonicalBuildId: '774757',
      executeRemediation: true,
    });
    const stale = {
      ...prepared,
      parameters: {
        ...prepared.parameters,
        canonicalReceiptContentDigest: `sha256:${'d'.repeat(64)}`,
      },
    };
    expectRefused(
      () => planPipelineRun({ ...base, pipelineRuns: [stale] }, 'copa-execute', options),
      /input check/,
    );
  });

  it('numbers each patch attempt in the output tag', () => {
    const prepared = run('copa-prepare', 'completed', 'succeeded', {
      sourceDigest: SOURCE,
      canonicalReceiptContentDigest: CONTENT,
      canonicalBuildId: '1',
    });
    const job = {
      ...canonicalDryRun(),
      pipelineRuns: [run('copa-execute', 'completed', 'failed', {}), prepared],
    };
    expect(planPipelineRun(job, 'copa-execute', options).templateParameters.outputTag).toMatch(
      /-r2$/,
    );
  });

  it('needs the canonical scan pipeline ID for Copa', () => {
    const job = { ...canonicalDryRun(), pipelineRuns: [] };
    expectRefused(
      () =>
        planPipelineRun(job, 'copa-prepare', {
          ...options,
          pipelines: { copaRemediation: 4422 },
          canonicalBuildId: '5',
        }),
      /CANONICAL_SCAN/,
    );
  });

  it('runs the candidate test on a verified execution job with its three parameters', () => {
    expect(planPipelineRun(verifiedExecution, 'candidate-test', options)).toEqual({
      action: 'candidate-test',
      role: 'candidateTest',
      templateParameters: {
        remediationJobId: 'RM-EXEC-0007',
        sourceReference: `registry.example.com/ssi-images/onboarded/nginx@${SOURCE}`,
        candidateReference: `registry.example.com/ssi-images/onboarded/nginx@sha256:${'b'.repeat(64)}`,
        deliverToSsi: true,
      },
    });
  });

  it('refuses the wrong kind of job, a withdrawn image and unknown actions', () => {
    expectRefused(() => planPipelineRun(dryRun(), 'candidate-test', options), /verified RM-EXEC/);
    expectRefused(
      () => planPipelineRun(verifiedExecution, 'canonical-scan', options),
      /Dry Run job/,
    );
    expectRefused(
      () =>
        planPipelineRun(
          { ...verifiedExecution, publishWithdrawal: { at: 'x' } },
          'candidate-test',
          options,
        ),
      /withdrawn/,
    );
    expectRefused(() => planPipelineRun(dryRun(), 'delete-everything', options), /Unknown/);
  });
});

describe('run records', () => {
  const plan = planPipelineRun(dryRun(), 'canonical-scan', options);
  const record = createRunRecord({
    plan,
    pipelineId: 4417,
    run: {
      id: 9001,
      name: '20261116.1',
      state: 'inProgress',
      result: null,
      webUrl: 'https://example-org.visualstudio.com/x',
      finishedDate: null,
    },
    actor: 'alex',
    at: '2026-11-16T09:00:00Z',
  });

  it('keeps who started what, with which parameters', () => {
    expect(record).toMatchObject({
      action: 'canonical-scan',
      pipelineId: 4417,
      runId: 9001,
      requestedBy: 'alex',
      parameters: plan.templateParameters,
    });
  });

  it('keeps the newest runs first and bounded', () => {
    let job = dryRun();
    for (let index = 0; index < MAX_STORED_RUNS + 5; index += 1)
      job = withRun(job, { ...record, runId: index + 1 });
    expect(job.pipelineRuns).toHaveLength(MAX_STORED_RUNS);
    expect(job.pipelineRuns[0].runId).toBe(MAX_STORED_RUNS + 5);
  });

  it('applies a new state from Azure DevOps and leaves an unchanged run alone', () => {
    expect(refreshedRun(record, { state: 'inProgress', result: null }, 'later')).toBe(record);
    expect(
      refreshedRun(record, { state: 'completed', result: 'succeeded', finishedDate: 'f' }, 'later'),
    ).toMatchObject({
      state: 'completed',
      result: 'succeeded',
      finishedAt: 'f',
      updatedAt: 'later',
    });
  });
});

describe('pipelineRunsView', () => {
  it('lists the Dry Run actions with the reason each one cannot start', () => {
    const view = pipelineRunsView(dryRun(), { enabled: true, ...options });
    expect(view.actions.map((item) => [item.action, item.available])).toEqual([
      ['canonical-scan', true],
      ['copa-prepare', false],
      ['copa-execute', false],
    ]);
  });

  it('asks for a Build ID only when SSI has no succeeded canonical scan', () => {
    const view = pipelineRunsView(canonicalDryRun(), { enabled: true, ...options });
    expect(view.actions.find((item) => item.action === 'copa-prepare')).toMatchObject({
      available: true,
      needsBuildId: true,
    });
  });

  it('blocks a second run of the same pipeline while one is in progress', () => {
    const job = {
      ...dryRun(),
      pipelineRuns: [run('canonical-scan', 'inProgress', null, { sourceDigest: SOURCE })],
    };
    expect(pipelineRunsView(job, { enabled: true, ...options }).actions[0]).toMatchObject({
      available: false,
      reason: expect.stringMatching(/in progress/),
    });
  });

  it('shows the candidate test on an execution job and nothing when automation is off', () => {
    expect(pipelineRunsView(verifiedExecution, { enabled: true, ...options }).actions).toEqual([
      expect.objectContaining({ action: 'candidate-test', available: true }),
    ]);
    expect(
      pipelineRunsView(verifiedExecution, { enabled: false, ...options }).actions[0].reason,
    ).toMatch(/not configured/);
  });
});

describe('copaOutputReferenceOf', () => {
  const run = (action, parameters = {}) => ({ action, runId: 1, state: 'completed', parameters });

  it('names where the newest patch SSI started writes its candidate, or nothing before the first one', () => {
    expect(copaOutputReferenceOf({ pipelineRuns: [] })).toBe('');
    expect(copaOutputReferenceOf({ pipelineRuns: [run('canonical-scan'), run('copa-prepare')] })).toBe('');
    expect(
      copaOutputReferenceOf({
        pipelineRuns: [
          run('candidate-test'),
          run('copa-execute', { outputRepository: 'onboarded/nginx', outputTag: 'copa-poc-20261117-alpine-rm-dry-0007-r2' }),
          run('copa-execute', { outputRepository: 'onboarded/nginx', outputTag: 'copa-poc-20261116-alpine-rm-dry-0007-r1' }),
        ],
      }),
    ).toBe('onboarded/nginx:copa-poc-20261117-alpine-rm-dry-0007-r2');
  });
});

describe('copaOutputRepository', () => {
  it('keeps a quarantined image in place', () => {
    expect(copaOutputRepository('onboarded/nginx')).toBe('onboarded/nginx');
    expect(copaOutputRepository('onboarded/payments/redis')).toBe('onboarded/payments/redis');
  });

  it('sends the candidate of an approved image to the same path in quarantine', () => {
    expect(copaOutputRepository('approved/nginx')).toBe('onboarded/nginx');
    expect(copaOutputRepository('approved/payments/api')).toBe('onboarded/payments/api');
    expect(
      copaOutputRepository('catalog/nginx', { publishPrefix: 'catalog', quarantinePrefix: 'intake' }),
    ).toBe('intake/nginx');
    // Only the whole first segment counts: approved-old/ is not the approved catalog.
    expect(copaOutputRepository('approved-old/nginx')).toBe('approved-old/nginx');
  });

  it('refuses when no separate quarantine folder is configured', () => {
    expect(() => copaOutputRepository('approved/nginx', { quarantinePrefix: '' })).toThrow(PipelineRunError);
    expect(() => copaOutputRepository('approved/nginx', { quarantinePrefix: 'approved' })).toThrow(
      /No quarantine folder/,
    );
  });

  it('plans the Copa run of an approved image with its candidate in quarantine', () => {
    const job = {
      ...canonicalDryRun(),
      image: 'ssi-images/approved/nginx:verified-20261116-alpine-r1',
      pipelineRuns: [run('canonical-scan', 'completed', 'succeeded', { sourceDigest: SOURCE }, 881234)],
    };
    const { templateParameters } = planPipelineRun(job, 'copa-prepare', options);
    expect(templateParameters).toMatchObject({
      sourceRepository: 'approved/nginx',
      outputRepository: 'onboarded/nginx',
      executeRemediation: false,
    });
  });
});
