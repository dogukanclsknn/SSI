import { consumerDecisionsFor } from './candidateTestEvidence.js';
import { buildExceptionPolicyConfig } from './policyExceptions.js';

// v1.1: approved risk acceptances (policy exceptions) are deducted from the Critical and
// High threshold checks. v1.2: the patched image must keep the source runtime configuration
// (image-config-preserved). v1.3: pre-release testing — the automatic candidate test must pass
// and a consumer team must accept the candidate (candidate-smoke-test, consumer-acceptance);
// these job-bound checks are evaluated again at approval time. v1.4: a withdrawn image can
// never be published again (image-not-withdrawn, also job-bound). Decisions keep the version
// they were evaluated with.
export const PUBLISH_POLICY_VERSION = 'ssi.publish-policy/v1.4';
export const PUBLISH_HANDOFF_VERSION = 'ssi.publish-handoff/v1';
export const PUBLISH_RECEIPT_VERSION = 'ssi.publish-receipt/v1';

const sha256Pattern = /^sha256:[a-f0-9]{64}$/i;
const repositoryPattern = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;
const tagPattern = /^[\w][\w.-]{0,127}$/;

export class PublishPolicyValidationError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'PublishPolicyValidationError';
    this.statusCode = statusCode;
  }
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function normalizeDigest(value) {
  return text(value).toLowerCase();
}

function booleanFromEnvironment(value, fallback = false) {
  if (value == null || text(value) === '') return fallback;
  return text(value).toLowerCase() === 'true';
}

function nonNegativeInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function splitApprovers(value) {
  return text(value)
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function normalizeRegistry(value) {
  return text(value).replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
}

function normalizeProject(value) {
  return text(value).replace(/^\/+|\/+$/g, '').toLowerCase();
}

function normalizeRepository(value) {
  return text(value).replace(/^\/+|\/+$/g, '').toLowerCase();
}

function check(id, label, passed, detail) {
  return { id, label, status: passed ? 'pass' : 'fail', detail };
}

function severityFromJob(job) {
  const severity = job?.fullImageComparison?.output?.severity || {};
  return {
    critical: nonNegativeInteger(severity.critical, 0),
    high: nonNegativeInteger(severity.high, 0),
    medium: nonNegativeInteger(severity.medium, 0),
    low: nonNegativeInteger(severity.low, 0),
    unknown: nonNegativeInteger(severity.unknown, 0),
  };
}

function validateTarget(target, config) {
  const registry = normalizeRegistry(target?.registry || config.target.registry);
  const project = normalizeProject(target?.project || config.target.project);
  const repository = normalizeRepository(target?.repository);
  const tag = text(target?.tag);

  if (!repositoryPattern.test(repository)) {
    throw new PublishPolicyValidationError('Target repository is invalid.');
  }
  if (!tagPattern.test(tag) || tag.toLowerCase() === 'latest') {
    throw new PublishPolicyValidationError('Target tag is invalid or uses the mutable latest tag.');
  }

  return {
    registry,
    project,
    repository,
    tag,
    tagReference: `${registry}/${project}/${repository}:${tag}`,
  };
}

export function buildPublishPolicyConfig(environment = {}) {
  const targetRegistry = normalizeRegistry(
    environment.PUBLISH_TARGET_REGISTRY || environment.HARBOR_URL || 'registry.example.com',
  );
  const targetProject = normalizeProject(
    environment.PUBLISH_TARGET_PROJECT || environment.HARBOR_PROJECT || 'ssi-images',
  );

  // A trusted identity can come from (see src/server/identity.js):
  //  - trustedActorHeader: an authenticating proxy (X-Forwarded-User/Groups).
  //  - sessionIdentity: RBAC enforced + a session secret → signed session cookie.
  //  - devLoginIdentity: the demo identity picker (SSI_DEV_LOGIN); not authentication.
  const trustedActorHeader = booleanFromEnvironment(environment.SSI_TRUST_ACTOR_HEADER, false);
  const sessionIdentity =
    booleanFromEnvironment(environment.SSI_RBAC_ENFORCED, true) && text(environment.SSI_SESSION_SECRET) !== '';
  const devLoginIdentity = booleanFromEnvironment(environment.SSI_DEV_LOGIN, false);

  return {
    version: text(environment.SSI_PUBLISH_POLICY_VERSION) || PUBLISH_POLICY_VERSION,
    thresholds: {
      maxCritical: nonNegativeInteger(environment.SSI_PUBLISH_MAX_CRITICAL, 0),
      maxHigh: nonNegativeInteger(environment.SSI_PUBLISH_MAX_HIGH, 0),
    },
    requirements: {
      sbom: booleanFromEnvironment(environment.SSI_PUBLISH_REQUIRE_SBOM, false),
      signature: booleanFromEnvironment(environment.SSI_PUBLISH_REQUIRE_SIGNATURE, false),
      provenance: booleanFromEnvironment(environment.SSI_PUBLISH_REQUIRE_PROVENANCE, false),
      // Pre-release consumer acceptance is on unless explicitly disabled (fail-closed default).
      consumerAcceptance: booleanFromEnvironment(environment.SSI_PUBLISH_REQUIRE_CONSUMER_ACCEPTANCE, true),
    },
    target: {
      registry: targetRegistry,
      project: targetProject,
      repositoryPrefix: normalizeRepository(environment.PUBLISH_TARGET_REPOSITORY_PREFIX || 'approved'),
    },
    approval: {
      required: true,
      trustedActorHeader,
      sessionIdentity,
      devLoginIdentity,
      trustedIdentity: trustedActorHeader || sessionIdentity || devLoginIdentity,
      // Onay yetkisi ROL tabanlı (RBAC ile bütünleşik): approver/admin onaylayabilir.
      // E-posta allowlist'i (SSI_PUBLISH_APPROVERS) opsiyonel EK bir yol olarak korunur.
      approverRoles: ['approver', 'admin'],
      approvers: splitApprovers(environment.SSI_PUBLISH_APPROVERS),
      // Two-person rule (separation of duties: requester ≠ approver). On by default;
      // SSI_PUBLISH_REQUIRE_SEPARATE_APPROVER=false disables it explicitly.
      requireSeparateApprover: booleanFromEnvironment(environment.SSI_PUBLISH_REQUIRE_SEPARATE_APPROVER, true),
    },
    riskAcceptance: buildExceptionPolicyConfig(environment),
  };
}

export function publicPublishPolicyConfig(config) {
  return {
    version: config.version,
    thresholds: { ...config.thresholds },
    requirements: { ...config.requirements },
    target: { ...config.target },
    approval: {
      required: true,
      trustedIdentityEnabled: config.approval.trustedIdentity,
      approverRoles: [...config.approval.approverRoles],
      approverCount: config.approval.approvers.length,
      requireSeparateApprover: config.approval.requireSeparateApprover,
      // Onay mekanizması hazır mı: güvenilir kimlik (imzalı oturum ya da güvenilir proxy).
      // Onaylayan kaynağı rol tabanlı olduğu için ayrıca allowlist şart değildir.
      configured: config.approval.trustedIdentity,
    },
    riskAcceptance: { ...config.riskAcceptance, appliesTo: [...config.riskAcceptance.appliesTo] },
  };
}

const severityCountKeys = ['critical', 'high', 'medium', 'low', 'unknown'];

// The server's exception adjustment for one evaluation. Only an "applied" adjustment
// changes counts; anything else leaves the thresholds exactly as before (fail-closed).
function normalizeExceptionAdjustment(adjustment) {
  const status = ['applied', 'unavailable'].includes(adjustment?.status) ? adjustment.status : 'none';
  const accepted = Array.isArray(adjustment?.accepted) && status === 'applied' ? adjustment.accepted : [];
  const appliedExceptions =
    Array.isArray(adjustment?.appliedExceptions) && status === 'applied' ? adjustment.appliedExceptions : [];
  const acceptedBySeverity = Object.fromEntries(severityCountKeys.map((key) => [key, 0]));
  const idsBySeverity = Object.fromEntries(severityCountKeys.map((key) => [key, new Set()]));
  for (const finding of accepted) {
    const key = severityCountKeys.includes(finding.severity) ? finding.severity : 'unknown';
    acceptedBySeverity[key] += 1;
    if (finding.exceptionId) idsBySeverity[key].add(finding.exceptionId);
  }
  return {
    status: appliedExceptions.length > 0 ? 'applied' : status === 'unavailable' ? 'unavailable' : 'none',
    reason: text(adjustment?.reason),
    acceptedBySeverity,
    idsBySeverity,
    appliedExceptions: appliedExceptions.map((item) => ({
      id: text(item.id),
      cve: text(item.cve),
      expiresAt: text(item.expiresAt),
      findings: nonNegativeInteger(item.findings, 0),
    })),
  };
}

function thresholdDetail(remaining, accepted, ids, maximum, adjustment) {
  const acceptedNote = accepted > 0 ? ` (${accepted} accepted by ${[...ids].join(', ')})` : '';
  // Only a failing threshold needs to say that risk acceptances could not be applied.
  const unavailableNote =
    adjustment.status === 'unavailable' && remaining > maximum
      ? ` Risk acceptances were not applied: ${adjustment.reason}`
      : '';
  return `${remaining} remaining${acceptedNote}; maximum allowed is ${maximum}.${unavailableNote}`;
}

// Evidence provenance (see server.js evidenceIntake): signed worker or manual upload.
export function evidenceIntakeNote(intake) {
  if (!intake || !intake.channel) return '';
  return intake.channel === 'worker'
    ? ` Submitted by signed worker ${text(intake.workerId) || 'unknown'}.`
    : ` Uploaded manually by ${text(intake.actor) || 'unknown'}.`;
}

// Image configuration integrity (src/lib/imageConfigIntegrity.js): the patched output must
// start and run like the source. Jobs verified before the integrity gate existed carry no
// proof and stay blocked (fail-closed); they must be remediated again.
function configIntegrityCheck(job, outputDigest) {
  const integrity = job.verificationEvidence?.configIntegrity;
  const passed =
    integrity?.verified === true &&
    ['preserved', 'restored'].includes(integrity.status) &&
    sha256Pattern.test(outputDigest) &&
    normalizeDigest(integrity.outputDigest) === outputDigest;

  let detail = 'No image configuration integrity proof. Run the Copa remediation again with the current worker.';
  if (passed && integrity.status === 'restored') {
    const fields = Array.isArray(integrity.restoredFields) ? integrity.restoredFields.join(', ') : '';
    detail = `Copa output lost ${fields || 'runtime fields'}; restored from the source and verified on ${text(integrity.platform)}.`;
  } else if (passed) {
    detail = `Runtime configuration identical to the source on ${text(integrity.platform)}.`;
  } else if (integrity) {
    detail = 'Image configuration integrity proof is not verified for this output digest.';
  }
  return check('image-config-preserved', 'Image configuration preserved', passed, detail);
}

// Automatic candidate test (src/lib/candidateTest.js) of this exact output digest.
function candidateTestCheck(job, outputDigest) {
  const result = job.candidateTest;
  const bound = Boolean(result) && sha256Pattern.test(outputDigest) && normalizeDigest(result.candidateDigest) === outputDigest;
  const passed = bound && result.passed === true;

  let detail = 'No candidate test result. Run SSI - Candidate Test for this image.';
  if (passed) {
    const summary = result.packageChanges?.summary || {};
    detail =
      `Candidate behaves like the source on ${text(result.platform)} ` +
      `(${summary.changed || 0} package(s) changed, ${summary.unplanned || 0} unplanned).`;
  } else if (bound) {
    const failed = (result.checks || []).filter((item) => item.status === 'fail').map((item) => item.id);
    detail = `Candidate test failed: ${failed.join(', ') || 'unknown check'}.`;
  } else if (result) {
    detail = 'The candidate test result is not bound to this output digest.';
  }
  return check('candidate-smoke-test', 'Candidate smoke test passed', passed, detail);
}

// Consumer team acceptance of the candidate, from every person's latest decision for this
// digest. Any open issue blocks, even when the requirement is off; only the person who
// reported an issue can withdraw it (by accepting). When required, someone must have
// accepted who is neither the publish requester nor the person who uploaded the candidate
// test result manually (four-eyes rule).
function consumerAcceptanceCheck(job, outputDigest, { required, requesterId }) {
  const fail = (detail) => check('consumer-acceptance', 'Consumer acceptance', false, detail);
  const pass = (detail) => check('consumer-acceptance', 'Consumer acceptance', true, detail);
  const newestFirst = (left, right) => text(right.decidedAt).localeCompare(text(left.decidedAt));
  const decisions = sha256Pattern.test(outputDigest) ? consumerDecisionsFor(job).sort(newestFirst) : [];

  const openIssues = decisions.filter((item) => item.decision === 'issue-found');
  if (openIssues.length > 0) {
    const [latest] = openIssues;
    const more = openIssues.length > 1 ? ` (+${openIssues.length - 1} more open issue(s))` : '';
    return fail(
      `Issue reported by ${text(latest.decidedBy)} in ${text(latest.environment)}: ${text(latest.note).slice(0, 200)}${more}`,
    );
  }
  if (!required) return pass('Not required by the active policy. Reported issues still block publish.');

  const accepted = decisions.filter((item) => item.decision === 'accepted');
  if (accepted.length === 0) return fail('No consumer team has accepted this candidate yet.');
  const requester = text(requesterId).toLowerCase();
  const manualUploader =
    job.candidateTest?.intake?.channel === 'manual' ? text(job.candidateTest.intake.actor).toLowerCase() : '';
  const eligible = accepted.filter((item) => {
    const decider = text(item.decidedBy).toLowerCase();
    return decider !== requester && decider !== manualUploader;
  });
  if (eligible.length > 0) {
    return pass(`Accepted by ${text(eligible[0].decidedBy)} in ${text(eligible[0].environment)}.`);
  }
  return fail(
    accepted.some((item) => text(item.decidedBy).toLowerCase() === requester)
      ? 'The publish requester cannot accept their own candidate (four-eyes rule).'
      : 'The person who uploaded the candidate test result manually cannot accept it (four-eyes rule).',
  );
}

// A withdrawn image stays withdrawn: the withdrawal is recorded on the job that produced the
// digest (src/lib/publishLifecycle.js) and blocks every request for it, new or pending.
// A record whose digest cannot be confirmed blocks as well (fail-closed).
function notWithdrawnCheck(job, outputDigest) {
  const withdrawal = job?.publishWithdrawal;
  if (!withdrawal) {
    return check('image-not-withdrawn', 'Image not withdrawn', true, 'No withdrawal is recorded for this image.');
  }
  const confirmed = normalizeDigest(withdrawal.digest) === outputDigest;
  return check(
    'image-not-withdrawn',
    'Image not withdrawn',
    false,
    confirmed
      ? `Withdrawn by ${text(withdrawal.withdrawnBy)} on ${text(withdrawal.withdrawnAt)}: ${text(withdrawal.reason).slice(0, 200)} Remediate the source again to publish a new image.`
      : 'A withdrawal is recorded for this job but its digest does not match; publish is fail-closed.',
  );
}

// Checks bound to the job's current state. Evaluated when the request is created and again
// when it is approved and handed to the worker, because evidence, consumer decisions and a
// withdrawal can change in between.
export function jobBoundChecks(job, { config, requesterId }) {
  const outputDigest = normalizeDigest(job?.patchedImageDigest);
  return [
    configIntegrityCheck(job, outputDigest),
    candidateTestCheck(job, outputDigest),
    consumerAcceptanceCheck(job, outputDigest, { required: config.requirements.consumerAcceptance, requesterId }),
    notWithdrawnCheck(job, outputDigest),
  ];
}

function requirementDetail({ required, attached, requirement, note }) {
  const attachedNote = attached ? ` Verified evidence attached.${note}` : '';
  return required ? `${requirement}${attachedNote}` : `Not required by the active policy.${attachedNote}`;
}

export function evaluatePublishPolicy({
  job,
  target,
  config,
  actorId,
  requestId,
  evaluatedAt,
  exceptionAdjustment,
}) {
  if (!job) throw new PublishPolicyValidationError('A verified remediation job is required.', 404);

  const normalizedTarget = validateTarget(target, config);
  const outputDigest = normalizeDigest(job.patchedImageDigest);
  const evidenceDigest = normalizeDigest(job.verificationEvidence?.evidenceDigest);
  const fullImage = job.fullImageComparison;
  const remainingSeverity = severityFromJob(job);
  const adjustment = normalizeExceptionAdjustment(exceptionAdjustment);
  const gatedSeverity = {
    critical: Math.max(remainingSeverity.critical - adjustment.acceptedBySeverity.critical, 0),
    high: Math.max(remainingSeverity.high - adjustment.acceptedBySeverity.high, 0),
  };
  const supplyChain = job.supplyChain || {};
  const supplyChainNote = evidenceIntakeNote(supplyChain.intake);
  const expectedPrefix = config.target.repositoryPrefix
    ? `${config.target.repositoryPrefix}/`
    : '';

  const checks = [
    check(
      'verified-remediation',
      'Verified remediation result',
      job.mode === 'execution' && job.status === 'Verified' && job.verificationStatus === 'Passed',
      'Only an accepted RM-EXEC verification result can enter the publish gate.',
    ),
    check(
      'immutable-output-digest',
      'Immutable output digest',
      sha256Pattern.test(outputDigest),
      outputDigest || 'The patched image digest is missing.',
    ),
    check(
      'verification-evidence',
      'Verification evidence binding',
      sha256Pattern.test(evidenceDigest) &&
        normalizeDigest(job.verificationEvidence?.outputDigest) === outputDigest,
      evidenceDigest ? `${evidenceDigest}.${evidenceIntakeNote(job.evidenceIntake)}` : 'Accepted verification evidence is missing.',
    ),
    check(
      'canonical-os-zero',
      'Canonical OS findings remediated',
      Number(job.after?.critical || 0) + Number(job.after?.high || 0) + Number(job.after?.medium || 0) + Number(job.after?.low || 0) + Number(job.after?.unknown || 0) === 0,
      `Canonical OS findings after remediation: ${job.remaining?.length || 0}.`,
    ),
    check(
      'full-image-rescan',
      'Full-image verification re-scan',
      fullImage?.status === 'available' && normalizeDigest(fullImage.output?.digest) === outputDigest,
      fullImage?.status === 'available'
        ? `Re-scan output digest: ${normalizeDigest(fullImage.output?.digest) || 'missing'}.`
        : fullImage?.reason || 'Full-image re-scan is unavailable.',
    ),
    ...jobBoundChecks(job, { config, requesterId: actorId }),
    check(
      'critical-threshold',
      'Critical severity threshold',
      gatedSeverity.critical <= config.thresholds.maxCritical,
      thresholdDetail(
        gatedSeverity.critical,
        adjustment.acceptedBySeverity.critical,
        adjustment.idsBySeverity.critical,
        config.thresholds.maxCritical,
        adjustment,
      ),
    ),
    check(
      'high-threshold',
      'High severity threshold',
      gatedSeverity.high <= config.thresholds.maxHigh,
      thresholdDetail(
        gatedSeverity.high,
        adjustment.acceptedBySeverity.high,
        adjustment.idsBySeverity.high,
        config.thresholds.maxHigh,
        adjustment,
      ),
    ),
    check(
      'target-boundary',
      'Approved registry boundary',
      normalizedTarget.registry === config.target.registry &&
        normalizedTarget.project === config.target.project &&
        (!expectedPrefix || normalizedTarget.repository.startsWith(expectedPrefix)),
      `Target must remain under ${config.target.registry}/${config.target.project}/${expectedPrefix || ''}.`,
    ),
    check(
      'approval-control-ready',
      'Trusted approval control',
      config.approval.trustedIdentity && Boolean(text(actorId)),
      config.approval.trustedIdentity
        ? 'A trusted requester identity is required.'
        : 'A trusted signed-session identity (or trusted actor propagation) must be configured.',
    ),
    check(
      'sbom-requirement',
      'SBOM requirement',
      !config.requirements.sbom || supplyChain.sbom === true,
      requirementDetail({
        required: config.requirements.sbom,
        attached: supplyChain.sbom === true,
        requirement: 'A verified SBOM is required.',
        note: supplyChainNote,
      }),
    ),
    check(
      'signature-requirement',
      'Signature requirement',
      !config.requirements.signature || supplyChain.signature === true,
      requirementDetail({
        required: config.requirements.signature,
        attached: supplyChain.signature === true,
        requirement: 'A verified image signature is required.',
        note: supplyChainNote,
      }),
    ),
    check(
      'provenance-requirement',
      'Provenance requirement',
      !config.requirements.provenance || supplyChain.provenance === true,
      requirementDetail({
        required: config.requirements.provenance,
        attached: supplyChain.provenance === true,
        requirement: 'Verified provenance is required.',
        note: supplyChainNote,
      }),
    ),
  ];

  const failedChecks = checks.filter((item) => item.status === 'fail');
  const decision = failedChecks.length > 0 ? 'Blocked' : 'ApprovalRequired';
  const timestamp = evaluatedAt || new Date().toISOString();

  return {
    id: requestId,
    contractVersion: PUBLISH_POLICY_VERSION,
    policyVersion: config.version,
    jobId: job.id,
    status: decision,
    requestedBy: text(actorId) || 'unknown',
    createdAt: timestamp,
    updatedAt: timestamp,
    source: {
      originalReference: text(job.image),
      tagReference: text(job.patchedImageTag),
      digest: outputDigest,
      immutableReference: `${text(job.patchedImageTag).replace(/:[^/:]+$/, '')}@${outputDigest}`,
      verificationEvidenceDigest: evidenceDigest,
      fullImageScannedAt: text(fullImage?.scannedAt),
    },
    target: normalizedTarget,
    decision: {
      status: decision,
      evaluatedAt: timestamp,
      checks,
      failedCheckIds: failedChecks.map((item) => item.id),
      remainingSeverity,
      thresholds: { ...config.thresholds },
      exceptions: {
        status: adjustment.status,
        reason: adjustment.reason,
        acceptedSeverity: { critical: adjustment.acceptedBySeverity.critical, high: adjustment.acceptedBySeverity.high },
        appliedExceptions: adjustment.appliedExceptions,
      },
      // How each piece of evidence entered SSI (worker | manual), for audit and review.
      evidenceIntake: {
        verification: text(job.evidenceIntake?.channel) || 'unrecorded',
        supplyChain: supplyChain.intake
          ? text(supplyChain.intake.channel)
          : Object.keys(supplyChain).length > 0
            ? 'unrecorded'
            : 'none',
      },
    },
    approval: null,
    publish: {
      status: 'NotStarted',
      receipt: null,
    },
  };
}

// Publish decisions (approve, reject, withdraw) need a trusted identity with publish
// authority: the approver/admin ROLE (primary) or the optional e-mail allowlist. Returns the
// normalized (lower-case) actor ID.
export function assertPublishApprover(config, actorId, actorRoles = []) {
  if (!config?.approval?.trustedIdentity) {
    throw new PublishPolicyValidationError('Trusted actor identity is not enabled; publish decisions are fail-closed.', 403);
  }
  const normalizedActor = text(actorId).toLowerCase();
  if (!normalizedActor) {
    throw new PublishPolicyValidationError('An authenticated approver identity is required.', 403);
  }
  const roles = (Array.isArray(actorRoles) ? actorRoles : []).map((role) => text(role).toLowerCase());
  const hasApproverRole = roles.some((role) => config.approval.approverRoles.includes(role));
  const inApproverAllowlist =
    config.approval.approvers.length > 0 && config.approval.approvers.includes(normalizedActor);
  if (!hasApproverRole && !inApproverAllowlist) {
    throw new PublishPolicyValidationError('The current actor is not an authorized publish approver.', 403);
  }
  return normalizedActor;
}

export function approvePublishRequest(
  request,
  { actorId, actorRoles = [], reason, config, approvedAt, activeExceptionIds, currentJob },
) {
  if (request?.status !== 'ApprovalRequired') {
    throw new PublishPolicyValidationError('Only an approval-required publish request can be approved.', 409);
  }
  const normalizedActor = assertPublishApprover(config, actorId, actorRoles);

  // Görevlerin ayrılığı (iki-kişi kuralı) yalnızca config açıkken zorlanır.
  if (
    config.approval.requireSeparateApprover &&
    normalizedActor === text(request.requestedBy).toLowerCase()
  ) {
    throw new PublishPolicyValidationError('Separation of duties requires a different requester and approver.', 403);
  }
  if (text(reason).length < 10) {
    throw new PublishPolicyValidationError('Approval reason must contain at least 10 characters.');
  }

  // A decision that relied on risk acceptances is only approvable while every one of them
  // is still active. Expired or revoked → re-evaluate (fail-closed).
  const appliedExceptions = request.decision?.exceptions?.appliedExceptions || [];
  if (appliedExceptions.length > 0) {
    if (!Array.isArray(activeExceptionIds)) {
      throw new PublishPolicyValidationError('Risk acceptances could not be verified; approval is fail-closed.', 503);
    }
    const inactive = appliedExceptions.filter((item) => !activeExceptionIds.includes(item.id)).map((item) => item.id);
    if (inactive.length > 0) {
      throw new PublishPolicyValidationError(
        `Risk acceptance ${inactive.join(', ')} is no longer active; evaluate the publish request again.`,
        409,
      );
    }
  }

  // The image may have changed state since the request was evaluated (a failed re-test, a
  // reported issue, ...). Re-check the job-bound checks against its current state.
  assertJobBoundChecks(request, currentJob, config, 'approval');

  const timestamp = approvedAt || new Date().toISOString();
  return {
    ...request,
    status: 'Approved',
    updatedAt: timestamp,
    approval: {
      approvedBy: text(actorId),
      reason: text(reason),
      approvedAt: timestamp,
      policyVersion: request.policyVersion,
    },
  };
}

// Fail-closed re-check of the job-bound checks for an existing request (at approval and at
// the publish worker handoff): an issue reported or a failed re-test after the request was
// evaluated must stop it.
function assertJobBoundChecks(request, currentJob, config, stage) {
  if (!currentJob || normalizeDigest(currentJob.patchedImageDigest) !== request.source?.digest) {
    throw new PublishPolicyValidationError(`The remediation job for this request could not be verified; ${stage} is fail-closed.`, 409);
  }
  const changed = jobBoundChecks(currentJob, { config, requesterId: request.requestedBy }).filter(
    (item) => item.status === 'fail',
  );
  if (changed.length > 0) {
    throw new PublishPolicyValidationError(
      `${changed.map((item) => `${item.label}: ${item.detail}`).join(' ')} Evaluate the publish request again.`,
      409,
    );
  }
}

export function buildPublishWorkerHandoff(request, generatedAt, { currentJob, config } = {}) {
  if (request?.status !== 'Approved' || !request.approval) {
    throw new PublishPolicyValidationError('Publish worker handoff requires an approved request.', 409);
  }
  if (!config) throw new PublishPolicyValidationError('Publish policy configuration is required for the handoff.', 500);
  assertJobBoundChecks(request, currentJob, config, 'publish');

  return {
    contractVersion: PUBLISH_HANDOFF_VERSION,
    requestId: request.id,
    generatedAt: generatedAt || new Date().toISOString(),
    policy: {
      version: request.policyVersion,
      decision: 'Approved',
      approvedBy: request.approval.approvedBy,
      approvedAt: request.approval.approvedAt,
    },
    source: {
      immutableReference: request.source.immutableReference,
      digest: request.source.digest,
      verificationEvidenceDigest: request.source.verificationEvidenceDigest,
    },
    target: { ...request.target, latestReference: publishLatestReference(request.target) },
    constraints: {
      credentialMaterialIncluded: false,
      overwriteExistingTag: false,
      preserveManifestDigest: true,
      verifyTargetDigest: true,
    },
  };
}

// A worker that did not get the answer to its receipt (timeout, network) sends the same
// receipt again. When the request already records exactly that registry write, the retry is
// answered with the stored request instead of a conflict, so the worker run does not fail
// after a successful publish. Anything that differs is not a replay and gets the normal
// validation (and its 409).
export function isPublishReceiptReplay(request, receipt) {
  const recorded = request?.publish?.status === 'Published' ? request.publish.receipt : null;
  if (!recorded || !['Published', 'Withdrawn'].includes(request.status)) return false;
  return (
    receipt?.contractVersion === PUBLISH_RECEIPT_VERSION &&
    text(receipt.requestId) === request.id &&
    receipt.status === 'published' &&
    receipt.verified === true &&
    text(receipt.latestReference) === text(recorded.latestReference) &&
    normalizeDigest(receipt.latestDigest) === normalizeDigest(recorded.latestDigest) &&
    normalizeDigest(receipt.sourceDigest) === request.source.digest &&
    normalizeDigest(receipt.targetDigest) === recorded.targetDigest &&
    text(receipt.targetReference).toLowerCase() === text(recorded.targetReference).toLowerCase()
  );
}

export function acceptPublishReceipt(request, receipt, acceptedAt) {
  if (request?.status !== 'Approved') {
    throw new PublishPolicyValidationError('A publish receipt can only complete an approved request.', 409);
  }
  if (receipt?.contractVersion !== PUBLISH_RECEIPT_VERSION) {
    throw new PublishPolicyValidationError('Unsupported publish receipt contract.');
  }
  if (text(receipt.requestId) !== request.id) {
    throw new PublishPolicyValidationError('Publish receipt request ID does not match.');
  }
  if (normalizeDigest(receipt.sourceDigest) !== request.source.digest) {
    throw new PublishPolicyValidationError('Publish receipt source digest does not match the approved request.');
  }
  if (normalizeDigest(receipt.targetDigest) !== request.source.digest) {
    throw new PublishPolicyValidationError('Published target digest does not preserve the approved manifest digest.');
  }
  if (text(receipt.targetReference).toLowerCase() !== request.target.tagReference.toLowerCase()) {
    throw new PublishPolicyValidationError('Publish receipt target reference does not match the approved request.');
  }
  if (receipt.status !== 'published' || receipt.verified !== true) {
    throw new PublishPolicyValidationError('Publish receipt must confirm a verified registry write.');
  }
  if (receipt.latestReference != null || receipt.latestDigest != null) {
    if (receipt.latestReference !== publishLatestReference(request.target) ||
        normalizeDigest(receipt.latestDigest) !== request.source.digest) {
      throw new PublishPolicyValidationError('Latest alias must reference the approved repository and digest.');
    }
  }

  const timestamp = acceptedAt || new Date().toISOString();
  return {
    ...request,
    status: 'Published',
    updatedAt: timestamp,
    publish: {
      status: 'Published',
      receipt: {
        contractVersion: receipt.contractVersion,
        targetReference: request.target.tagReference,
        targetDigest: request.source.digest,
        ...(receipt.latestReference ? {
          latestReference: receipt.latestReference,
          latestDigest: request.source.digest,
        } : {}),
        workerId: text(receipt.workerId),
        publishedAt: text(receipt.publishedAt) || timestamp,
        acceptedAt: timestamp,
      },
    },
  };
}

// A moving consumption address; the versioned publication remains immutable.
function publishLatestReference(target) {
  return `${target.registry}/${target.project}/${target.repository}:latest`;
}
