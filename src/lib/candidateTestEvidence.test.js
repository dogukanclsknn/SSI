import { describe, expect, it } from 'vitest';
import {
  applyCandidateTest,
  applyConsumerAcceptance,
  CandidateTestValidationError,
  consumerDecisionsFor,
  createConsumerAcceptance,
  validateCandidateTestEvidence,
} from './candidateTestEvidence.js';

const SOURCE_DIGEST = `sha256:${'a'.repeat(64)}`;
const OUTPUT_DIGEST = `sha256:${'b'.repeat(64)}`;
const REPOSITORY = 'registry.example.com/ssi-images/onboarded/nginx';
const NOW = Date.parse('2026-11-04T10:05:00.000Z');

function verifiedJob(overrides = {}) {
  return {
    id: 'RM-EXEC-0004',
    mode: 'execution',
    status: 'Verified',
    verificationStatus: 'Passed',
    sourceDigest: SOURCE_DIGEST,
    patchedImageDigest: OUTPUT_DIGEST,
    plannedFixes: [{ cve: 'CVE-1', package: 'curl' }],
    packageUpdates: [{ package: 'brotli-libs' }],
    verificationEvidence: { configIntegrity: { platform: 'linux/amd64' } },
    ...overrides,
  };
}

function evidence(overrides = {}) {
  return {
    contractVersion: 'ssi.candidate-test/v1',
    generatedAt: '2026-11-04T10:00:00.000Z',
    remediationJobId: 'RM-EXEC-0004',
    source: { immutableReference: `${REPOSITORY}@${SOURCE_DIGEST}`, digest: SOURCE_DIGEST },
    candidate: { immutableReference: `${REPOSITORY}@${OUTPUT_DIGEST}`, digest: OUTPUT_DIGEST },
    platform: 'linux/amd64',
    runner: { pipeline: 'SSI - Candidate Test', buildId: '901', agent: 'LinuxAgent1' },
    startup: {
      source: { state: 'running', exitCode: 0, oomKilled: false, restarting: false, health: 'none' },
      candidate: { state: 'running', exitCode: 0, oomKilled: false, restarting: false, health: 'none' },
    },
    checks: [
      { id: 'image-config', status: 'pass', detail: 'Runtime configuration is identical to the source.' },
      { id: 'startup', status: 'pass', detail: 'Candidate starts like the source.' },
      { id: 'healthcheck', status: 'not-applicable', detail: 'Neither image defines a HEALTHCHECK.' },
      { id: 'package-inventory', status: 'pass', detail: '2 changed.' },
    ],
    packageChanges: {
      summary: { unchanged: 10, changed: 2, added: 1, removed: 0, majorVersionChanges: 1 },
      changes: [
        { name: 'curl', arch: 'x86_64', from: '8.22.0-r0', to: '8.23.0-r0', change: 'changed', majorVersionChange: false },
        { name: 'libidn2', arch: 'x86_64', from: '', to: '2.3.7-r0', change: 'added', majorVersionChange: false },
        { name: 'zlib', arch: 'x86_64', from: '1.3.1-r2', to: '2.0.0-r0', change: 'changed', majorVersionChange: true },
      ],
    },
    passed: true,
    ...overrides,
  };
}

const LAYER_A = `sha256:${'1'.repeat(64)}`;
const LAYER_B = `sha256:${'2'.repeat(64)}`;
const PATCH_LAYER = `sha256:${'3'.repeat(64)}`;

function imageFacts() {
  const config = () => ({ Cmd: ['nginx', '-g', 'daemon off;'], Env: ['PATH', 'NGINX_VERSION'] });
  return {
    source: { sizeBytes: 48_000_000, diffIds: [LAYER_A, LAYER_B], config: config() },
    candidate: { sizeBytes: 49_500_000, diffIds: [LAYER_A, LAYER_B, PATCH_LAYER], config: config() },
  };
}

const validate = (value, job = verifiedJob()) =>
  validateCandidateTestEvidence(value, {
    job,
    evidenceDigest: `sha256:${'e'.repeat(64)}`,
    intake: { channel: 'worker', workerId: 'LinuxAgent1' },
    now: NOW,
  });

describe('validateCandidateTestEvidence', () => {
  it('accepts a bound result and marks package changes outside the remediation plan', () => {
    const record = validate(evidence());

    expect(record).toMatchObject({
      contractVersion: 'ssi.candidate-test/v1',
      passed: true,
      platform: 'linux/amd64',
      candidateDigest: OUTPUT_DIGEST,
      sourceDigest: SOURCE_DIGEST,
      intake: { channel: 'worker', workerId: 'LinuxAgent1' },
    });
    expect(record.packageChanges.summary).toEqual({
      unchanged: 10,
      changed: 2,
      added: 1,
      removed: 0,
      majorVersionChanges: 1,
      unplanned: 2,
    });
    expect(record.packageChanges.changes.map((item) => [item.name, item.planned])).toEqual([
      ['curl', true],
      ['libidn2', false],
      ['zlib', false],
    ]);
  });

  it('stores a failed result too, so SSI knows the candidate failed', () => {
    const failed = evidence({
      passed: false,
      checks: evidence().checks.map((check) => (check.id === 'startup' ? { ...check, status: 'fail' } : check)),
    });
    failed.startup.candidate = { state: 'exited', exitCode: 3, oomKilled: false, restarting: false, health: 'none' };
    expect(validate(failed).passed).toBe(false);
  });

  it('re-derives the startup and health verdicts from the reported container states', () => {
    const lyingStartup = evidence();
    lyingStartup.startup.candidate = { state: 'exited', exitCode: 1, oomKilled: true, restarting: false, health: 'none' };
    expect(() => validate(lyingStartup)).toThrow(/startup status does not match/);

    const lyingHealth = evidence();
    lyingHealth.startup.candidate.health = 'unhealthy';
    lyingHealth.startup.source.health = 'healthy';
    expect(() => validate(lyingHealth)).toThrow(/healthcheck status does not match/);

    const healthy = evidence({
      checks: evidence().checks.map((check) => (check.id === 'healthcheck' ? { ...check, status: 'pass' } : check)),
    });
    healthy.startup.source.health = 'healthy';
    healthy.startup.candidate.health = 'healthy';
    expect(validate(healthy).passed).toBe(true);
  });

  it.each([
    ['another job', { remediationJobId: 'RM-EXEC-0009' }, /another remediation job/],
    ['another candidate digest', { candidate: { immutableReference: `${REPOSITORY}@${SOURCE_DIGEST}`, digest: SOURCE_DIGEST } }, /not the verified output digest/],
    ['another source digest', { source: { immutableReference: `${REPOSITORY}@${OUTPUT_DIGEST}`, digest: OUTPUT_DIGEST } }, /not the source digest/],
    ['a reference not bound to the digest', { candidate: { immutableReference: `${REPOSITORY}:copa-poc`, digest: OUTPUT_DIGEST } }, /not bound/],
    ['another platform than the verified one', { platform: 'linux/arm64' }, /verified on linux\/amd64/],
    ['an unknown contract', { contractVersion: 'ssi.candidate-test/v0' }, /Unsupported candidate test contract/],
    ['a verdict that contradicts the checks', { passed: false }, /verdict does not match/],
    ['a missing check', { checks: evidence().checks.slice(0, 3) }, /exactly once/],
    ['a not-applicable startup check', { checks: evidence().checks.map((c) => (c.id === 'startup' ? { ...c, status: 'not-applicable' } : c)) }, /cannot be not-applicable/],
    ['a timestamp from the future', { generatedAt: '2026-11-04T11:00:00.000Z' }, /in the future/],
  ])('rejects %s', (_label, overrides, message) => {
    expect(() => validate(evidence(overrides))).toThrow(message);
  });

  it('re-derives the package check and summary instead of trusting the worker', () => {
    const removed = evidence();
    removed.packageChanges.changes.push({ name: 'busybox', arch: 'x86_64', from: '1.37.0-r1', to: '', change: 'removed', majorVersionChange: false });
    removed.packageChanges.summary.removed = 1;
    expect(() => validate(removed)).toThrow(/package-inventory status does not match/);

    const lyingSummary = evidence();
    lyingSummary.packageChanges.summary.majorVersionChanges = 0;
    expect(() => validate(lyingSummary)).toThrow(/summary.majorVersionChanges does not match/);
  });

  it('rejects control characters and only tests verified execution jobs', () => {
    const injected = evidence();
    injected.checks[0].detail = 'ok\u001b[31m';
    expect(() => validate(injected)).toThrow(/control characters/);
    expect(() => validate(evidence(), verifiedJob({ mode: 'dry-run' }))).toThrow(CandidateTestValidationError);
    expect(() => validate(evidence(), verifiedJob({ status: 'Failed' }))).toThrow(/Only a verified RM-EXEC job/);
  });

  it('stores image facts when present and still accepts results from older workers without them', () => {
    expect(validate(evidence())).not.toHaveProperty('imageFacts');
    const record = validate(evidence({ imageFacts: imageFacts() }));
    expect(record.imageFacts.candidate).toEqual({
      sizeBytes: 49_500_000,
      diffIds: [LAYER_A, LAYER_B, PATCH_LAYER],
      config: { Cmd: ['nginx', '-g', 'daemon off;'], Env: ['PATH', 'NGINX_VERSION'] },
    });
  });

  it('never accepts an environment variable value, from any channel', () => {
    const leaking = imageFacts();
    leaking.candidate.config.Env = ['PATH', 'API_TOKEN=s3cr3t'];
    leaking.source.config.Env = ['PATH', 'API_TOKEN=s3cr3t'];
    expect(() => validate(evidence({ imageFacts: leaking }))).toThrow(/names only; values are never accepted/);
  });

  it('rejects malformed facts and facts that contradict the image-config verdict', () => {
    const unknownField = imageFacts();
    unknownField.source.config.Hostname = 'build-box';
    expect(() => validate(evidence({ imageFacts: unknownField }))).toThrow(/unknown field: Hostname/);

    const badLayer = imageFacts();
    badLayer.candidate.diffIds = ['not-a-digest'];
    expect(() => validate(evidence({ imageFacts: badLayer }))).toThrow(/diffIds must be sha256 digests/);

    const badSize = imageFacts();
    badSize.source.sizeBytes = -1;
    expect(() => validate(evidence({ imageFacts: badSize }))).toThrow(/sizeBytes/);

    const drift = imageFacts();
    drift.candidate.config.Cmd = null;
    expect(() => validate(evidence({ imageFacts: drift }))).toThrow(/image-config status does not match/);
  });
});

describe('applyCandidateTest', () => {
  const record = (generatedAt, evidenceDigest, passed = true) => ({ generatedAt, evidenceDigest, passed, intake: { channel: 'worker' } });

  it('keeps an identical replay idempotent and records history for a newer result', () => {
    const first = applyCandidateTest(verifiedJob(), record('2026-11-04T10:00:00.000Z', 'sha256:1'));
    expect(first.changed).toBe(true);
    expect(applyCandidateTest(first.job, record('2026-11-04T10:00:00.000Z', 'sha256:1')).changed).toBe(false);

    const second = applyCandidateTest(first.job, record('2026-11-04T11:00:00.000Z', 'sha256:2', false));
    expect(second.job.candidateTest.passed).toBe(false);
    expect(second.job.candidateTestHistory).toEqual([
      { generatedAt: '2026-11-04T10:00:00.000Z', passed: true, evidenceDigest: 'sha256:1', channel: 'worker' },
    ]);
  });

  it('never lets a manual upload replace a signed worker result', () => {
    const signed = applyCandidateTest(verifiedJob(), record('2026-11-04T10:00:00.000Z', 'sha256:1', false)).job;
    const manual = { ...record('2026-11-04T11:00:00.000Z', 'sha256:2', true), intake: { channel: 'manual', actor: 'ops.user' } };
    expect(() => applyCandidateTest(signed, manual)).toThrow(/signed worker result is already recorded/);
    const firstManual = applyCandidateTest(verifiedJob(), manual).job;
    expect(applyCandidateTest(firstManual, record('2026-11-04T12:00:00.000Z', 'sha256:3')).job.candidateTest.intake.channel).toBe('worker');
  });

  it('never lets an older result replace a newer one (replay of an old pass)', () => {
    const newerFailure = applyCandidateTest(verifiedJob(), record('2026-11-04T11:00:00.000Z', 'sha256:2', false)).job;
    expect(() => applyCandidateTest(newerFailure, record('2026-11-04T10:00:00.000Z', 'sha256:1', true))).toThrow(
      /newer candidate test result is already recorded/,
    );
  });
});

describe('consumer acceptance', () => {
  const tested = () => verifiedJob({ candidateTest: { passed: true, candidateDigest: OUTPUT_DIGEST, evidenceDigest: 'sha256:9' } });
  const decide = (body, job = tested(), actorId = 'ayse.yilmaz') =>
    createConsumerAcceptance({ job, body, actorId, decidedAt: '2026-11-04T12:00:00.000Z' });

  it('records an acceptance bound to the candidate digest and the tested evidence', () => {
    expect(decide({ decision: 'accepted', environment: 'html-hello-world', note: 'Smoke test green.' })).toEqual({
      decision: 'accepted',
      environment: 'html-hello-world',
      note: 'Smoke test green.',
      decidedBy: 'ayse.yilmaz',
      decidedAt: '2026-11-04T12:00:00.000Z',
      candidateDigest: OUTPUT_DIGEST,
      candidateTestEvidenceDigest: 'sha256:9',
    });
  });

  it('accepts only after a passed automatic test, but always allows reporting an issue', () => {
    const untested = verifiedJob();
    expect(() => decide({ decision: 'accepted', environment: 'staging-api' }, untested)).toThrow(/must pass before/);
    expect(decide({ decision: 'issue-found', environment: 'staging-api', note: 'Service fails health probes.' }, untested).decision).toBe(
      'issue-found',
    );
  });

  it('validates the decision, environment, note and identity', () => {
    expect(() => decide({ decision: 'approved', environment: 'x-env' })).toThrow(/accepted or issue-found/);
    expect(() => decide({ decision: 'accepted', environment: 'ab' })).toThrow(/3–120 characters/);
    expect(() => decide({ decision: 'issue-found', environment: 'staging', note: 'bad' })).toThrow(/at least 10 characters/);
    expect(() => decide({ decision: 'accepted', environment: 'stag\u0000ing' })).toThrow(/control characters/);
    expect(() => decide({ decision: 'accepted', environment: 'staging' }, tested(), '')).toThrow(/trusted signed-in identity/);
    expect(decide({ decision: 'issue-found', environment: 'staging', note: 'Line one\nLine two of the report' }).note).toContain('\n');
  });

  it("keeps every person's latest decision, so one acceptance cannot hide another person's issue", () => {
    let job = tested();
    job = applyConsumerAcceptance(job, decide({ decision: 'issue-found', environment: 'staging', note: 'App crashes on start.' }, job, 'alice'));
    job = applyConsumerAcceptance(job, decide({ decision: 'accepted', environment: 'qa-env' }, job, 'bob'));
    expect(consumerDecisionsFor(job).map((item) => [item.decidedBy, item.decision])).toEqual([
      ['alice', 'issue-found'],
      ['bob', 'accepted'],
    ]);
    job = applyConsumerAcceptance(job, decide({ decision: 'accepted', environment: 'staging' }, job, 'Alice'));
    expect(consumerDecisionsFor(job).every((item) => item.decision === 'accepted')).toBe(true);
    expect(consumerDecisionsFor({ ...job, patchedImageDigest: SOURCE_DIGEST })).toEqual([]);
  });

  it('keeps the latest decision on top and a bounded history', () => {
    let job = tested();
    for (let index = 0; index < 55; index += 1) {
      job = applyConsumerAcceptance(job, decide({ decision: 'accepted', environment: `env-${index}` }, job));
    }
    expect(job.consumerAcceptance.environment).toBe('env-54');
    expect(job.consumerAcceptance.history).toHaveLength(50);
    expect(job.consumerAcceptance.history[0].environment).toBe('env-54');
  });
});

describe('withdrawn image', () => {
  it('accepts no new candidate test result or consumer decision', () => {
    const withdrawn = verifiedJob({
      candidateTest: { passed: true, candidateDigest: OUTPUT_DIGEST },
      publishWithdrawal: { digest: OUTPUT_DIGEST, withdrawnBy: 'sam.lee' },
    });
    expect(() => validate(evidence(), withdrawn)).toThrow(/withdrawn after publish/);
    expect(() =>
      createConsumerAcceptance({
        job: withdrawn,
        body: { decision: 'issue-found', environment: 'staging-api', note: 'Service fails health probes.' },
        actorId: 'ayse.yilmaz',
      }),
    ).toThrow(/withdrawn after publish/);
  });
});
