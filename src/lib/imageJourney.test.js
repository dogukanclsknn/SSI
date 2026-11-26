import { describe, expect, it } from 'vitest';
import { buildImageJourney, journeyCandidates } from './imageJourney.js';

const SOURCE = `sha256:${'a'.repeat(64)}`;
const OUTPUT = `sha256:${'b'.repeat(64)}`;
const CONTENT = `sha256:${'c'.repeat(64)}`;
const run = (action, state, result = null, parameters = {}) => ({
  action,
  runId: 1,
  runName: '20261117.1',
  state,
  result,
  parameters,
});

const dryRun = (extra = {}) => ({
  id: 'RM-DRY-0008',
  mode: 'dry-run',
  lifecycleState: 'planned',
  image: 'ssi-images/onboarded/nginx:alpine',
  sourceDigest: SOURCE,
  createdAt: '2026-11-16T15:14:35Z',
  plannedFixes: [{ cve: 'CVE-1' }],
  ...extra,
});
const scanned = (extra = {}) =>
  dryRun({
    canonicalReport: { contentDigest: CONTENT },
    pipelineRuns: [run('canonical-scan', 'completed', 'succeeded')],
    ...extra,
  });
const checked = () =>
  scanned({
    pipelineRuns: [
      run('copa-prepare', 'completed', 'succeeded', { canonicalReceiptContentDigest: CONTENT }),
    ],
  });
const execution = (extra = {}) => ({
  id: 'RM-EXEC-0006',
  mode: 'execution',
  parentJobId: 'RM-DRY-0008',
  lifecycleState: 'verified',
  sourceDigest: SOURCE,
  patchedImageDigest: OUTPUT,
  fixed: new Array(58).fill({}),
  ...extra,
});
const passedTest = { candidateTest: { candidateDigest: OUTPUT, passed: true } };
const accepted = {
  consumerAcceptance: {
    decisionsByActor: {
      'jordan.reed': {
        decision: 'accepted',
        decidedBy: 'jordan.reed',
        environment: 'payments-test',
        decidedAt: '2026-11-17T10:00:00Z',
        candidateDigest: OUTPUT,
      },
    },
  },
};

const statuses = (journey) =>
  Object.fromEntries(journey.steps.map((item) => [item.id, item.status]));

describe('buildImageJourney', () => {
  it('starts a new plan at the canonical scan and locks everything after it', () => {
    const journey = buildImageJourney({ dryRun: dryRun(), jobs: [dryRun()] });
    expect(statuses(journey)).toEqual({
      onboard: 'skipped',
      'canonical-scan': 'action',
      'copa-check': 'locked',
      patch: 'locked',
      'candidate-test': 'locked',
      acceptance: 'locked',
      approval: 'locked',
      publish: 'locked',
      sign: 'locked',
    });
    expect(journey.currentStepId).toBe('canonical-scan');
    expect(journey.progress).toEqual({ done: 1, total: 9 });
  });

  it('shows a running scan and a failed check that can be retried', () => {
    const running = dryRun({ pipelineRuns: [run('canonical-scan', 'inProgress')] });
    expect(buildImageJourney({ dryRun: running, jobs: [running] }).steps[1]).toMatchObject({
      status: 'running',
    });
    const failed = scanned({ pipelineRuns: [run('copa-prepare', 'completed', 'failed')] });
    expect(statuses(buildImageJourney({ dryRun: failed, jobs: [failed] }))['copa-check']).toBe(
      'failed',
    );
  });

  it('follows the plan to its verified result and the candidate test', () => {
    const plan = checked();
    const journey = buildImageJourney({ dryRun: plan, jobs: [plan, execution()] });
    expect(statuses(journey)).toMatchObject({
      'copa-check': 'done',
      patch: 'done',
      'candidate-test': 'action',
    });
    expect(journey.steps.find((item) => item.id === 'patch').summary).toMatch(/RM-EXEC-0006: 58/);
  });

  it('waits for a person at consumer acceptance and at publish approval', () => {
    const plan = checked();
    const tested = execution(passedTest);
    expect(statuses(buildImageJourney({ dryRun: plan, jobs: [plan, tested] })).acceptance).toBe(
      'waiting',
    );
    const done = execution({ ...passedTest, ...accepted });
    const request = {
      id: 'PUB-0015',
      jobId: done.id,
      status: 'ApprovalRequired',
      source: { digest: OUTPUT },
    };
    const journey = buildImageJourney({
      dryRun: plan,
      jobs: [plan, done],
      publishRequests: [request],
    });
    expect(statuses(journey)).toMatchObject({
      acceptance: 'done',
      approval: 'waiting',
      publish: 'locked',
    });
    expect(journey.currentStepId).toBe('approval');
  });

  it('asks for a publish request after acceptance and completes after publish and signing', () => {
    const plan = checked();
    const done = execution({ ...passedTest, ...accepted });
    expect(statuses(buildImageJourney({ dryRun: plan, jobs: [plan, done] })).approval).toBe(
      'action',
    );
    const published = {
      id: 'PUB-0015',
      jobId: done.id,
      status: 'Published',
      source: { digest: OUTPUT },
      target: { tagReference: 'harbor/ssi-images/approved/nginx:r1' },
    };
    const unsigned = buildImageJourney({
      dryRun: plan,
      jobs: [plan, done],
      publishRequests: [published],
    });
    expect(statuses(unsigned)).toMatchObject({ publish: 'done', sign: 'action' });
    const signed = execution({
      ...passedTest,
      ...accepted,
      supplyChain: { signature: true, sbom: true },
    });
    const journey = buildImageJourney({
      dryRun: plan,
      jobs: [plan, signed],
      publishRequests: [published],
    });
    expect(journey.complete).toBe(true);
    expect(journey.currentStepId).toBe('');
  });

  it('goes back to the patch after a withdrawal and blocks a plan with nothing to fix', () => {
    const plan = checked();
    const withdrawn = execution({ ...passedTest, ...accepted, publishWithdrawal: { at: 'x' } });
    const journey = buildImageJourney({ dryRun: plan, jobs: [plan, withdrawn] });
    expect(statuses(journey)).toMatchObject({
      patch: 'action',
      approval: 'locked',
      sign: 'locked',
    });
    expect(journey.steps.find((item) => item.id === 'patch').summary).toMatch(
      /RM-EXEC-0006 was withdrawn/,
    );
    const empty = scanned({ lifecycleState: 'blocked', plannedFixes: [] });
    expect(statuses(buildImageJourney({ dryRun: empty, jobs: [empty] }))['copa-check']).toBe(
      'blocked',
    );
  });

  it('links the onboarding request of the same repository', () => {
    const onboarding = {
      id: 'ONB-0010',
      status: 'Imported',
      target: {
        tagReference: 'registry.example.com/ssi-images/onboarded/nginx:alpine',
      },
    };
    const journey = buildImageJourney({
      dryRun: dryRun(),
      jobs: [dryRun()],
      onboardingRequests: [onboarding],
    });
    expect(journey.steps[0]).toMatchObject({ status: 'done', record: 'ONB-0010' });
  });

  it('only follows Dry Runs', () => {
    expect(buildImageJourney({ dryRun: execution() })).toBeNull();
    expect(
      journeyCandidates([
        execution(),
        dryRun(),
        dryRun({ id: 'RM-DRY-0009', createdAt: '2026-11-17T00:00:00Z' }),
      ]).map((job) => job.id),
    ).toEqual(['RM-DRY-0009', 'RM-DRY-0008']);
  });
});
