import { describe, expect, it } from 'vitest';
import {
  approvePublishRequest,
  assertPublishApprover,
  buildPublishPolicyConfig,
  buildPublishWorkerHandoff,
  evaluatePublishPolicy,
  publicPublishPolicyConfig,
  PublishPolicyValidationError,
} from './publishPolicy.js';

// İmzalı-oturum kimliğinin açık olduğu (header'a gerek olmayan) tipik prod env'i.
function sessionConfig(overrides = {}) {
  return buildPublishPolicyConfig({
    SSI_RBAC_ENFORCED: 'true',
    SSI_SESSION_SECRET: 'test-secret',
    SSI_TRUST_ACTOR_HEADER: 'false',
    PUBLISH_TARGET_REGISTRY: 'registry.example.com',
    PUBLISH_TARGET_PROJECT: 'ssi-images',
    PUBLISH_TARGET_REPOSITORY_PREFIX: 'approved',
    ...overrides,
  });
}

const DIGEST = `sha256:${'a'.repeat(64)}`;

function verifiedJob() {
  return {
    id: 'RM-EXEC-0001',
    mode: 'execution',
    status: 'Verified',
    verificationStatus: 'Passed',
    patchedImageDigest: DIGEST,
    patchedImageTag: 'registry.example.com/ssi-images/approved/onboarded-nginx:verified-1',
    verificationEvidence: {
      evidenceDigest: `sha256:${'b'.repeat(64)}`,
      outputDigest: DIGEST,
      configIntegrity: {
        status: 'restored',
        verified: true,
        platform: 'linux/amd64',
        restoredFields: ['Cmd', 'Entrypoint', 'ExposedPorts', 'StopSignal'],
        outputDigest: DIGEST,
      },
    },
    after: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    fullImageComparison: {
      status: 'available',
      output: { digest: DIGEST, severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } },
      scannedAt: '2026-09-08T00:00:00.000Z',
    },
    supplyChain: {},
    candidateTest: {
      passed: true,
      candidateDigest: DIGEST,
      platform: 'linux/amd64',
      checks: [],
      packageChanges: { summary: { changed: 3, unplanned: 1 } },
    },
    consumerAcceptance: {
      decision: 'accepted',
      environment: 'html-hello-world',
      note: '',
      decidedBy: 'consumer.tester',
      candidateDigest: DIGEST,
    },
  };
}

const target = {
  registry: 'registry.example.com',
  project: 'ssi-images',
  repository: 'approved/onboarded-nginx',
  tag: 'verified-1',
};

function evaluate(config, actorId = 'alex.morgan') {
  return evaluatePublishPolicy({ job: verifiedJob(), target, config, actorId, requestId: 'PUB-0001' });
}

describe('publish policy — trusted identity', () => {
  it('imzalı oturum (RBAC enforced + secret) güvenilir kimlik sağlar; header gerekmez', () => {
    const config = sessionConfig();
    expect(config.approval.trustedActorHeader).toBe(false);
    expect(config.approval.sessionIdentity).toBe(true);
    expect(config.approval.trustedIdentity).toBe(true);
    expect(publicPublishPolicyConfig(config).approval.configured).toBe(true);
  });

  it('dev login (demo identity picker) counts as a trusted identity source', () => {
    const config = buildPublishPolicyConfig({ SSI_DEV_LOGIN: 'true' });
    expect(config.approval.devLoginIdentity).toBe(true);
    expect(config.approval.trustedIdentity).toBe(true);
  });

  it('ne header ne oturum varsa güvenilir kimlik yok', () => {
    const config = buildPublishPolicyConfig({ SSI_TRUST_ACTOR_HEADER: 'false' });
    expect(config.approval.trustedIdentity).toBe(false);
    expect(publicPublishPolicyConfig(config).approval.configured).toBe(false);
  });

  it('doğrulanmış iş + oturum kimliği → tüm kontroller geçer, ApprovalRequired', () => {
    const result = evaluate(sessionConfig());
    const failed = result.decision.checks.filter((c) => c.status === 'fail');
    expect(failed).toEqual([]);
    expect(result.status).toBe('ApprovalRequired');
    expect(result.requestedBy).toBe('alex.morgan');
  });

  it('güvenilir kimlik yoksa approval-control-ready başarısız → Blocked', () => {
    const config = buildPublishPolicyConfig({ SSI_TRUST_ACTOR_HEADER: 'false' });
    const result = evaluate(config);
    expect(result.status).toBe('Blocked');
    expect(result.decision.failedCheckIds).toContain('approval-control-ready');
  });
});

describe('publish policy — rol tabanlı onay', () => {
  const approvalRequired = () => evaluate(sessionConfig());

  it('approver rolü onaylayabilir (allowlist gerekmez)', () => {
    const approved = approvePublishRequest(approvalRequired(), {
      actorId: 'sam.lee',
      actorRoles: ['approver'],
      reason: 'canonical scan temiz, publish uygun',
      config: sessionConfig(),
      currentJob: verifiedJob(),
    });
    expect(approved.status).toBe('Approved');
    expect(approved.approval.approvedBy).toBe('sam.lee');
  });

  it('two-person rule is on by default: the requester cannot approve their own request', () => {
    const config = sessionConfig();
    expect(config.approval.requireSeparateApprover).toBe(true);
    expect(() =>
      approvePublishRequest(approvalRequired(), {
        actorId: 'alex.morgan', // same as requestedBy
        actorRoles: ['admin'],
        reason: 'self approval attempt',
        config,
        currentJob: verifiedJob(),
      }),
    ).toThrow(/Separation of duties/);
  });

  it('an explicitly disabled two-person rule lets an admin approve their own request', () => {
    const config = sessionConfig({ SSI_PUBLISH_REQUIRE_SEPARATE_APPROVER: 'false' });
    const approved = approvePublishRequest(evaluate(config), {
      actorId: 'alex.morgan',
      actorRoles: ['admin'],
      reason: 'single-operator approval',
      config,
      currentJob: verifiedJob(),
    });
    expect(approved.status).toBe('Approved');
  });

  it('approver/admin olmayan rol reddedilir (403)', () => {
    expect(() =>
      approvePublishRequest(approvalRequired(), {
        actorId: 'operator.user',
        actorRoles: ['operator'],
        reason: 'yetkim yok ama deniyorum',
        config: sessionConfig(),
        currentJob: verifiedJob(),
      }),
    ).toThrow(PublishPolicyValidationError);
  });

  it('iki-kişi kuralı açıkken talep eden = onaylayan reddedilir', () => {
    const config = sessionConfig({ SSI_PUBLISH_REQUIRE_SEPARATE_APPROVER: 'true' });
    expect(() =>
      approvePublishRequest(evaluate(config), {
        actorId: 'alex.morgan',
        actorRoles: ['admin'],
        reason: 'kendi kendime onay denemesi',
        config,
        currentJob: verifiedJob(),
      }),
    ).toThrow(/Separation of duties/);
  });

  it('opsiyonel e-posta allowlist yolu da çalışır', () => {
    const config = sessionConfig({ SSI_PUBLISH_APPROVERS: 'ozel.onaylayan' });
    const approved = approvePublishRequest(evaluate(config), {
      actorId: 'ozel.onaylayan',
      actorRoles: [], // rol yok ama allowlist'te
      reason: 'allowlist üzerinden onay',
      config,
      currentJob: verifiedJob(),
    });
    expect(approved.status).toBe('Approved');
  });

  it('kısa gerekçe reddedilir', () => {
    expect(() =>
      approvePublishRequest(approvalRequired(), {
        actorId: 'sam.lee',
        actorRoles: ['approver'],
        reason: 'kısa',
        config: sessionConfig(),
        currentJob: verifiedJob(),
      }),
    ).toThrow(/at least 10/);
  });
});

describe('publish policy v1.1 — risk acceptance', () => {
  function criticalJob() {
    const job = verifiedJob();
    job.fullImageComparison.output.severity = { critical: 2, high: 1, medium: 0, low: 0, unknown: 0 };
    return job;
  }
  const adjustment = {
    status: 'applied',
    accepted: [
      { cve: 'CVE-2023-45853', package: 'zlib1g', severity: 'critical', exceptionId: 'EXC-0001' },
      { cve: 'CVE-2023-6879', package: 'libaom3', severity: 'critical', exceptionId: 'EXC-0002' },
    ],
    appliedExceptions: [
      { id: 'EXC-0001', cve: 'CVE-2023-45853', expiresAt: '2026-11-13T00:00:00.000Z', findings: 1 },
      { id: 'EXC-0002', cve: 'CVE-2023-6879', expiresAt: '2026-10-24T00:00:00.000Z', findings: 1 },
    ],
  };
  const run = (exceptionAdjustment) =>
    evaluatePublishPolicy({
      job: criticalJob(),
      target,
      config: sessionConfig(),
      actorId: 'alex.morgan',
      requestId: 'PUB-0002',
      exceptionAdjustment,
    });

  it('deducts accepted findings from the critical threshold and records the exceptions', () => {
    const result = run(adjustment);
    const critical = result.decision.checks.find((item) => item.id === 'critical-threshold');
    expect(critical).toMatchObject({
      status: 'pass',
      detail: '0 remaining (2 accepted by EXC-0001, EXC-0002); maximum allowed is 0.',
    });
    expect(result.decision.failedCheckIds).toEqual(['high-threshold']);
    expect(result.decision.remainingSeverity.critical).toBe(2);
    expect(result.decision.exceptions.appliedExceptions.map((item) => item.id)).toEqual(['EXC-0001', 'EXC-0002']);
    expect(result.contractVersion).toBe('ssi.publish-policy/v1.4');
  });

  it('leaves the thresholds unchanged when the adjustment is unavailable (fail-closed)', () => {
    const result = run({ status: 'unavailable', reason: 'The output scan report was not found.' });
    const critical = result.decision.checks.find((item) => item.id === 'critical-threshold');
    expect(critical.status).toBe('fail');
    expect(critical.detail).toMatch(/^2 remaining; maximum allowed is 0\. Risk acceptances were not applied/);
    expect(result.decision.exceptions.status).toBe('unavailable');
  });

  it('requires every applied exception to still be active at approval time', () => {
    const highFreeJob = criticalJob();
    highFreeJob.fullImageComparison.output.severity.high = 0;
    const request = evaluatePublishPolicy({
      job: highFreeJob,
      target,
      config: sessionConfig(),
      actorId: 'alex.morgan',
      requestId: 'PUB-0003',
      exceptionAdjustment: adjustment,
    });
    expect(request.status).toBe('ApprovalRequired');
    const approve = (activeExceptionIds) =>
      approvePublishRequest(request, {
        actorId: 'sam.lee',
        actorRoles: ['approver'],
        reason: 'Accepted risks reviewed',
        config: sessionConfig(),
        currentJob: verifiedJob(),
        activeExceptionIds,
      });
    expect(() => approve(['EXC-0001'])).toThrow(/EXC-0002 is no longer active/);
    expect(() => approve(undefined)).toThrow(/fail-closed/);
    expect(approve(['EXC-0001', 'EXC-0002']).status).toBe('Approved');
  });
});

describe('publish policy — evidence provenance', () => {
  const config = sessionConfig();
  const evaluateJob = (job) =>
    evaluatePublishPolicy({ job, target, config, actorId: 'alex.morgan', requestId: 'PUB-0009' });
  const detail = (result, id) => result.decision.checks.find((item) => item.id === id).detail;

  it('records how verification and supply-chain evidence entered SSI', () => {
    const job = {
      ...verifiedJob(),
      evidenceIntake: { channel: 'worker', workerId: 'LinuxAgent1', actor: 'remediation-worker:LinuxAgent1' },
      supplyChain: {
        signature: true,
        sbom: true,
        provenance: true,
        intake: { channel: 'manual', actor: 'alex.morgan' },
      },
    };
    const result = evaluateJob(job);
    expect(result.decision.evidenceIntake).toEqual({ verification: 'worker', supplyChain: 'manual' });
    expect(detail(result, 'verification-evidence')).toContain('Submitted by signed worker LinuxAgent1.');
    expect(detail(result, 'signature-requirement')).toContain('Uploaded manually by alex.morgan.');
  });

  it('marks evidence stored before provenance tracking as unrecorded, and absent evidence as none', () => {
    const legacy = evaluateJob({ ...verifiedJob(), supplyChain: { signature: true } });
    expect(legacy.decision.evidenceIntake).toEqual({ verification: 'unrecorded', supplyChain: 'unrecorded' });
    expect(evaluateJob(verifiedJob()).decision.evidenceIntake.supplyChain).toBe('none');
  });
});

describe('publish policy — image configuration integrity', () => {
  const evaluateJob = (job) =>
    evaluatePublishPolicy({ job, target, config: sessionConfig(), actorId: 'alex.morgan', requestId: 'PUB-0002' });
  const integrityCheck = (result) => result.decision.checks.find((item) => item.id === 'image-config-preserved');

  it('passes when the restored configuration is verified for the output digest', () => {
    const result = evaluateJob(verifiedJob());

    expect(result.status).toBe('ApprovalRequired');
    expect(integrityCheck(result)).toEqual({
      id: 'image-config-preserved',
      label: 'Image configuration preserved',
      status: 'pass',
      detail: 'Copa output lost Cmd, Entrypoint, ExposedPorts, StopSignal; restored from the source and verified on linux/amd64.',
    });
  });

  it('passes with a preserved configuration', () => {
    const job = verifiedJob();
    job.verificationEvidence.configIntegrity = { ...job.verificationEvidence.configIntegrity, status: 'preserved', restoredFields: [] };

    expect(integrityCheck(evaluateJob(job))).toMatchObject({
      status: 'pass',
      detail: 'Runtime configuration identical to the source on linux/amd64.',
    });
  });

  it('blocks a job verified before the integrity gate existed (fail-closed)', () => {
    const job = verifiedJob();
    delete job.verificationEvidence.configIntegrity;
    const result = evaluateJob(job);

    expect(result.status).toBe('Blocked');
    expect(result.decision.failedCheckIds).toEqual(['image-config-preserved']);
    expect(integrityCheck(result).detail).toBe(
      'No image configuration integrity proof. Run the Copa remediation again with the current worker.',
    );
  });

  it('blocks a proof that is bound to another digest or not verified', () => {
    const otherDigest = verifiedJob();
    otherDigest.verificationEvidence.configIntegrity.outputDigest = `sha256:${'c'.repeat(64)}`;
    const unverified = verifiedJob();
    unverified.verificationEvidence.configIntegrity.verified = false;

    for (const job of [otherDigest, unverified]) {
      const result = evaluateJob(job);
      expect(result.decision.failedCheckIds).toEqual(['image-config-preserved']);
      expect(integrityCheck(result).detail).toBe('Image configuration integrity proof is not verified for this output digest.');
    }
  });
});

describe('publish policy v1.3 — pre-release testing', () => {
  const evaluateJob = (job, config = sessionConfig(), actorId = 'alex.morgan') =>
    evaluatePublishPolicy({ job, target, config, actorId, requestId: 'PUB-0003' });
  const checkOf = (result, id) => result.decision.checks.find((item) => item.id === id);

  it('passes both checks for a tested and accepted candidate', () => {
    const result = evaluateJob(verifiedJob());

    expect(result.status).toBe('ApprovalRequired');
    expect(checkOf(result, 'candidate-smoke-test')).toMatchObject({
      label: 'Candidate smoke test passed',
      status: 'pass',
      detail: 'Candidate behaves like the source on linux/amd64 (3 package(s) changed, 1 unplanned).',
    });
    expect(checkOf(result, 'consumer-acceptance')).toMatchObject({
      status: 'pass',
      detail: 'Accepted by consumer.tester in html-hello-world.',
    });
  });

  it('requires consumer acceptance by default', () => {
    expect(buildPublishPolicyConfig({}).requirements.consumerAcceptance).toBe(true);
    expect(buildPublishPolicyConfig({ SSI_PUBLISH_REQUIRE_CONSUMER_ACCEPTANCE: 'false' }).requirements.consumerAcceptance).toBe(false);
  });

  it('blocks a job without a candidate test or with a failed one', () => {
    const untested = verifiedJob();
    delete untested.candidateTest;
    expect(evaluateJob(untested).decision.failedCheckIds).toEqual(['candidate-smoke-test']);
    expect(checkOf(evaluateJob(untested), 'candidate-smoke-test').detail).toBe(
      'No candidate test result. Run SSI - Candidate Test for this image.',
    );

    const failed = verifiedJob();
    failed.candidateTest = {
      ...failed.candidateTest,
      passed: false,
      checks: [
        { id: 'startup', status: 'fail' },
        { id: 'image-config', status: 'pass' },
      ],
    };
    expect(checkOf(evaluateJob(failed), 'candidate-smoke-test').detail).toBe('Candidate test failed: startup.');
  });

  it('does not accept a candidate test of another digest', () => {
    const job = verifiedJob();
    job.candidateTest.candidateDigest = `sha256:${'c'.repeat(64)}`;
    expect(checkOf(evaluateJob(job), 'candidate-smoke-test')).toMatchObject({
      status: 'fail',
      detail: 'The candidate test result is not bound to this output digest.',
    });
  });

  it('enforces the four-eyes rule: the requester cannot be the person who accepted', () => {
    const result = evaluateJob(verifiedJob(), sessionConfig(), 'Consumer.Tester');
    expect(result.decision.failedCheckIds).toEqual(['consumer-acceptance']);
    expect(checkOf(result, 'consumer-acceptance').detail).toBe(
      'The publish requester cannot accept their own candidate (four-eyes rule).',
    );
  });

  it('blocks a reported issue even when acceptance is not required', () => {
    const job = verifiedJob();
    job.consumerAcceptance = {
      ...job.consumerAcceptance,
      decision: 'issue-found',
      note: 'TLS handshake fails with the new openssl build.',
    };
    const config = sessionConfig({ SSI_PUBLISH_REQUIRE_CONSUMER_ACCEPTANCE: 'false' });
    expect(checkOf(evaluateJob(job, config), 'consumer-acceptance')).toMatchObject({
      status: 'fail',
      detail: 'Issue reported by consumer.tester in html-hello-world: TLS handshake fails with the new openssl build.',
    });

    const notRequired = verifiedJob();
    delete notRequired.consumerAcceptance;
    expect(checkOf(evaluateJob(notRequired, config), 'consumer-acceptance').status).toBe('pass');
  });

  it('re-checks the job state at approval time (fail-closed)', () => {
    const request = evaluateJob(verifiedJob());
    const approve = (currentJob) =>
      approvePublishRequest(request, {
        actorId: 'sam.lee',
        actorRoles: ['approver'],
        reason: 'candidate tested, publish is fine',
        config: sessionConfig(),
        currentJob,
      });

    expect(approve(verifiedJob()).status).toBe('Approved');

    const issueAfterRequest = verifiedJob();
    issueAfterRequest.consumerAcceptance.decision = 'issue-found';
    issueAfterRequest.consumerAcceptance.note = 'Container crashes under load in staging.';
    expect(() => approve(issueAfterRequest)).toThrow(/Consumer acceptance: Issue reported by consumer.tester/);
    expect(() => approve(issueAfterRequest)).toThrow(/Evaluate the publish request again\./);

    const retestFailed = verifiedJob();
    retestFailed.candidateTest.passed = false;
    expect(() => approve(retestFailed)).toThrow(/Candidate smoke test passed: Candidate test failed/);

    expect(() => approve(undefined)).toThrow(/could not be verified; approval is fail-closed/);
    const otherDigest = verifiedJob();
    otherDigest.patchedImageDigest = `sha256:${'d'.repeat(64)}`;
    expect(() => approve(otherDigest)).toThrow(/could not be verified/);
  });

  it('also blocks approval of a legacy request whose image has no configuration proof', () => {
    const request = evaluateJob(verifiedJob());
    const legacy = verifiedJob();
    delete legacy.verificationEvidence.configIntegrity;
    expect(() =>
      approvePublishRequest(request, {
        actorId: 'sam.lee',
        actorRoles: ['approver'],
        reason: 'legacy request from before v1.2',
        config: sessionConfig(),
        currentJob: legacy,
      }),
    ).toThrow(/Image configuration preserved: No image configuration integrity proof/);
  });
});

describe('publish policy v1.3 — consumer decisions per person', () => {
  const evaluateJob = (job, config = sessionConfig(), actorId = 'alex.morgan') =>
    evaluatePublishPolicy({ job, target, config, actorId, requestId: 'PUB-0004' });
  const acceptanceOf = (result) => result.decision.checks.find((item) => item.id === 'consumer-acceptance');
  const decision = (decidedBy, value, decidedAt, note = '') => ({
    decision: value,
    environment: `${decidedBy}-env`,
    note,
    decidedBy,
    decidedAt,
    candidateDigest: DIGEST,
  });
  const withDecisions = (...items) => {
    const job = verifiedJob();
    job.consumerAcceptance = {
      ...items.at(-1),
      decisionsByActor: Object.fromEntries(items.map((item) => [item.decidedBy.toLowerCase(), item])),
    };
    return job;
  };

  it("does not let a later acceptance by someone else clear another person's open issue", () => {
    const job = withDecisions(
      decision('alice', 'issue-found', '2026-11-04T10:00:00.000Z', 'App crashes on start.'),
      decision('bob', 'accepted', '2026-11-04T11:00:00.000Z'),
    );
    for (const config of [sessionConfig(), sessionConfig({ SSI_PUBLISH_REQUIRE_CONSUMER_ACCEPTANCE: 'false' })]) {
      expect(acceptanceOf(evaluateJob(job, config))).toMatchObject({
        status: 'fail',
        detail: 'Issue reported by alice in alice-env: App crashes on start.',
      });
    }
  });

  it('lets the reporter withdraw their own issue', () => {
    const job = withDecisions(decision('bob', 'accepted', '2026-11-04T11:00:00.000Z'), decision('alice', 'accepted', '2026-11-04T12:00:00.000Z'));
    expect(acceptanceOf(evaluateJob(job)).status).toBe('pass');
  });

  it('does not count an acceptance by the person who uploaded the test result manually', () => {
    const job = withDecisions(decision('ops.user', 'accepted', '2026-11-04T11:00:00.000Z'));
    job.candidateTest = { ...job.candidateTest, intake: { channel: 'manual', actor: 'Ops.User' } };
    expect(acceptanceOf(evaluateJob(job))).toMatchObject({
      status: 'fail',
      detail: 'The person who uploaded the candidate test result manually cannot accept it (four-eyes rule).',
    });
    const second = withDecisions(decision('ops.user', 'accepted', '2026-11-04T11:00:00.000Z'), decision('qa.lead', 'accepted', '2026-11-04T12:00:00.000Z'));
    second.candidateTest = job.candidateTest;
    expect(acceptanceOf(evaluateJob(second))).toMatchObject({ status: 'pass', detail: 'Accepted by qa.lead in qa.lead-env.' });
  });

  it('counts every open issue in the detail', () => {
    const job = withDecisions(
      decision('alice', 'issue-found', '2026-11-04T10:00:00.000Z', 'Crash.'),
      decision('carol', 'issue-found', '2026-11-04T12:00:00.000Z', 'Slow startup.'),
    );
    expect(acceptanceOf(evaluateJob(job)).detail).toBe('Issue reported by carol in carol-env: Slow startup. (+1 more open issue(s))');
  });
});

describe('publish worker handoff re-check', () => {
  const approved = () =>
    approvePublishRequest(
      evaluatePublishPolicy({ job: verifiedJob(), target, config: sessionConfig(), actorId: 'alex.morgan', requestId: 'PUB-0005' }),
      { actorId: 'sam.lee', actorRoles: ['approver'], reason: 'candidate accepted, publish', config: sessionConfig(), currentJob: verifiedJob() },
    );

  it('hands off an approved request whose image still passes its checks', () => {
    const handoff = buildPublishWorkerHandoff(approved(), '2026-11-04T12:00:00.000Z', { currentJob: verifiedJob(), config: sessionConfig() });
    expect(handoff.source.digest).toBe(DIGEST);
    expect(handoff.target.latestReference).toBe(`${target.registry}/${target.project}/${target.repository}:latest`);
  });

  it('stops the publish when an issue is reported after approval', () => {
    const job = verifiedJob();
    job.consumerAcceptance = { ...job.consumerAcceptance, decision: 'issue-found', decidedBy: 'late.tester', note: 'Found a regression after approval.' };
    expect(() => buildPublishWorkerHandoff(approved(), undefined, { currentJob: job, config: sessionConfig() })).toThrow(
      /Issue reported by late.tester/,
    );
    expect(() => buildPublishWorkerHandoff(approved(), undefined, { config: sessionConfig() })).toThrow(/publish is fail-closed/);
  });
});

describe('publish policy v1.4 — withdrawn images', () => {
  const withdrawnJob = (digest = DIGEST) => ({
    ...verifiedJob(),
    publishWithdrawal: {
      digest,
      withdrawnBy: 'sam.lee',
      withdrawnAt: '2026-11-09T10:00:00.000Z',
      reason: 'Consumer saw broken TLS after publish.',
      category: 'functional',
      requestIds: ['PUB-0012'],
    },
  });
  const evaluateJob = (job) =>
    evaluatePublishPolicy({ job, target, config: sessionConfig(), actorId: 'alex.morgan', requestId: 'PUB-0020' });
  const checkOf = (result, id) => result.decision.checks.find((item) => item.id === id);

  it('passes for an image without a withdrawal record', () => {
    expect(checkOf(evaluateJob(verifiedJob()), 'image-not-withdrawn')).toMatchObject({
      label: 'Image not withdrawn',
      status: 'pass',
    });
  });

  it('blocks a new request for a withdrawn digest and says who withdrew it and why', () => {
    const result = evaluateJob(withdrawnJob());
    expect(result.status).toBe('Blocked');
    expect(result.decision.failedCheckIds).toEqual(['image-not-withdrawn']);
    expect(checkOf(result, 'image-not-withdrawn').detail).toMatch(
      /^Withdrawn by sam.lee on 2026-11-09T10:00:00.000Z: Consumer saw broken TLS after publish\./,
    );
  });

  it('fails closed when the withdrawal record does not match the digest', () => {
    const result = evaluateJob(withdrawnJob(`sha256:${'f'.repeat(64)}`));
    expect(checkOf(result, 'image-not-withdrawn')).toMatchObject({
      status: 'fail',
      detail: 'A withdrawal is recorded for this job but its digest does not match; publish is fail-closed.',
    });
  });

  it('stops approval and the worker handoff of a pending request once the image is withdrawn', () => {
    const request = evaluateJob(verifiedJob());
    const decide = (currentJob) =>
      approvePublishRequest(request, {
        actorId: 'sam.lee',
        actorRoles: ['approver'],
        reason: 'candidate tested, publish is fine',
        config: sessionConfig(),
        currentJob,
      });
    expect(() => decide(withdrawnJob())).toThrow(/Image not withdrawn: Withdrawn by sam.lee/);

    const approved = decide(verifiedJob());
    expect(() => buildPublishWorkerHandoff(approved, undefined, { currentJob: withdrawnJob(), config: sessionConfig() })).toThrow(
      /Image not withdrawn/,
    );
  });
});

describe('assertPublishApprover', () => {
  it('accepts an approver or admin role and returns the normalized actor', () => {
    expect(assertPublishApprover(sessionConfig(), ' Sam.Lee ', ['approver'])).toBe('sam.lee');
    expect(assertPublishApprover(sessionConfig(), 'root', ['admin'])).toBe('root');
  });

  it('refuses operators, anonymous callers and an untrusted identity source', () => {
    expect(() => assertPublishApprover(sessionConfig(), 'op', ['operator'])).toThrow(/not an authorized publish approver/);
    expect(() => assertPublishApprover(sessionConfig(), '', ['approver'])).toThrow(/authenticated approver identity/);
    const untrusted = buildPublishPolicyConfig({ SSI_RBAC_ENFORCED: 'false' });
    expect(() => assertPublishApprover(untrusted, 'a', ['approver'])).toThrow(/fail-closed/);
  });

  it('accepts the optional e-mail allowlist without an approver role', () => {
    const config = sessionConfig({ SSI_PUBLISH_APPROVERS: 'sec.lead@corp.example' });
    expect(assertPublishApprover(config, 'sec.lead@corp.example', [])).toBe('sec.lead@corp.example');
  });
});
