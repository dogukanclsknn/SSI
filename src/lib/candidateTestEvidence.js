// Server-side intake of the pre-release test stage for a verified remediation (RM-EXEC) job:
//   1. the candidate test worker's ssi.candidate-test/v1 result (see candidateTest.js), and
//   2. the consumer team's acceptance: "tested in our environment" or "issue found".
//
// Both are bound to the job's immutable output digest. SSI never trusts the worker's own
// verdict: it re-derives the startup, health and package checks and `passed` from the
// reported observations, and it marks package changes that are not part of the remediation
// plan ("unplanned"). Pure functions, no I/O; server.js persists the result atomically and
// writes the audit trail.

import {
  CANDIDATE_TEST_CHECK_IDS,
  CANDIDATE_TEST_CHECK_STATUSES,
  CANDIDATE_TEST_CONTRACT_VERSION,
  deriveCandidateTestPassed,
  MAX_ENV_NAMES,
  MAX_IMAGE_LAYERS,
  MAX_PACKAGE_CHANGES,
  PACKAGE_CHANGE_TYPES,
  packageInventoryStatus,
  RUNTIME_CONFIG_FIELDS,
  startupCheck,
} from './candidateTest.js';
import { canonicalJson } from './imageConfigIntegrity.js';

export const CONSUMER_ACCEPTANCE_DECISIONS = Object.freeze(['accepted', 'issue-found']);
const MAX_ACCEPTANCE_HISTORY = 50;
// Distinct people whose latest decision is kept for the policy (see decisionsByActor).
const MAX_DECIDERS = 200;
const MAX_CANDIDATE_TEST_HISTORY = 20;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const MAX_RUNTIME_CONFIG_BYTES = 64 * 1024;
const MAX_ENV_NAME_LENGTH = 256;

const sha256Pattern = /^sha256:[a-f0-9]{64}$/;
const platformPattern = /^[a-z0-9]+\/[a-z0-9_]+(?:\/[a-z0-9]+)?$/;
const immutableReferencePattern = /^[a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/;

// True when the text has no control characters (line breaks are allowed in notes only).
function hasOnlyPrintable(value, { multiline }) {
  for (const character of value) {
    const code = character.codePointAt(0);
    const lineBreak = code === 10 || code === 13;
    if ((code < 32 && !(multiline && lineBreak)) || code === 127) return false;
  }
  return true;
}

export class CandidateTestValidationError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'CandidateTestValidationError';
    this.statusCode = statusCode;
  }
}

function assertValid(condition, message, statusCode) {
  if (!condition) throw new CandidateTestValidationError(message, statusCode);
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value, label, { max, required = false, multiline = false }) {
  const normalized = text(value);
  assertValid(!required || normalized.length > 0, `${label} is required.`);
  assertValid(normalized.length <= max, `${label} must be at most ${max} characters.`);
  assertValid(hasOnlyPrintable(normalized, { multiline }), `${label} contains control characters.`);
  return normalized;
}

function nonNegativeInteger(value, label) {
  assertValid(Number.isInteger(value) && value >= 0, `${label} must be a non-negative integer.`);
  return value;
}

function integer(value, label) {
  assertValid(Number.isInteger(value), `${label} must be an integer.`);
  return value;
}

function isoTimestamp(value, label, now) {
  const normalized = text(value);
  const time = Date.parse(normalized);
  assertValid(normalized && Number.isFinite(time), `${label} must be an ISO-8601 timestamp.`);
  assertValid(time <= now + MAX_FUTURE_SKEW_MS, `${label} is in the future.`);
  return new Date(time).toISOString();
}

function outputDigestOf(job) {
  return text(job?.patchedImageDigest).toLowerCase();
}

export function assertTestableJob(job) {
  assertValid(job, 'Remediation job not found.', 404);
  assertValid(
    job.mode === 'execution' && job.status === 'Verified' && job.verificationStatus === 'Passed',
    'Only a verified RM-EXEC job can be tested before release.',
    409,
  );
  assertValid(sha256Pattern.test(outputDigestOf(job)), 'The verified job has no immutable output digest.', 409);
  // A withdrawn image is final (src/lib/publishLifecycle.js): no new test results or decisions.
  assertValid(!job.publishWithdrawal, 'This image was withdrawn after publish; remediate the source again.', 409);
}

// Package names the remediation plan was allowed to change.
function plannedPackageNames(job) {
  const names = new Set();
  for (const list of [job.plannedFixes, job.packageUpdates, job.fixed]) {
    for (const item of Array.isArray(list) ? list : []) {
      const name = text(item?.package || item?.name).toLowerCase();
      if (name) names.add(name);
    }
  }
  return names;
}

function validateChecks(checks) {
  assertValid(Array.isArray(checks) && checks.length === CANDIDATE_TEST_CHECK_IDS.length, 'checks must list every candidate test check exactly once.');
  const normalized = checks.map((check) => {
    assertValid(isPlainObject(check), 'Each check must be an object.');
    assertValid(CANDIDATE_TEST_CHECK_IDS.includes(check.id), `Unknown candidate test check: ${text(check.id) || 'missing'}.`);
    assertValid(CANDIDATE_TEST_CHECK_STATUSES.includes(check.status), `Check ${check.id} has an invalid status.`);
    assertValid(check.status !== 'not-applicable' || check.id === 'healthcheck', `Check ${check.id} cannot be not-applicable.`);
    return { id: check.id, status: check.status, detail: boundedText(check.detail, `Check ${check.id} detail`, { max: 500 }) };
  });
  assertValid(new Set(normalized.map((check) => check.id)).size === CANDIDATE_TEST_CHECK_IDS.length, 'checks contains a duplicate check.');
  // Report the checks in the contract order, whatever order the worker used.
  return CANDIDATE_TEST_CHECK_IDS.map((id) => normalized.find((check) => check.id === id));
}

function validatePackageChanges(value, plannedNames) {
  assertValid(isPlainObject(value) && isPlainObject(value.summary), 'packageChanges with a summary is required.');
  assertValid(Array.isArray(value.changes) && value.changes.length <= MAX_PACKAGE_CHANGES, `packageChanges.changes must be an array of at most ${MAX_PACKAGE_CHANGES} entries.`);

  const changes = value.changes.map((item) => {
    assertValid(isPlainObject(item), 'Each package change must be an object.');
    assertValid(PACKAGE_CHANGE_TYPES.includes(item.change), 'A package change has an invalid change type.');
    const name = boundedText(item.name, 'Package name', { max: 200, required: true });
    const from = boundedText(item.from, `Package ${name} previous version`, { max: 200, required: item.change !== 'added' });
    const to = boundedText(item.to, `Package ${name} new version`, { max: 200, required: item.change !== 'removed' });
    assertValid(item.change !== 'added' || from === '', `Added package ${name} cannot have a previous version.`);
    assertValid(item.change !== 'removed' || to === '', `Removed package ${name} cannot have a new version.`);
    assertValid(typeof item.majorVersionChange === 'boolean', `Package ${name} majorVersionChange must be a boolean.`);
    return {
      name,
      arch: boundedText(item.arch, `Package ${name} architecture`, { max: 64 }),
      from,
      to,
      change: item.change,
      majorVersionChange: item.change === 'changed' && item.majorVersionChange,
      planned: plannedNames.has(name.toLowerCase()),
    };
  });

  const count = (predicate) => changes.filter(predicate).length;
  const summary = {
    unchanged: nonNegativeInteger(value.summary.unchanged, 'packageChanges.summary.unchanged'),
    changed: count((item) => item.change === 'changed'),
    added: count((item) => item.change === 'added'),
    removed: count((item) => item.change === 'removed'),
    majorVersionChanges: count((item) => item.majorVersionChange),
    unplanned: count((item) => !item.planned),
  };
  for (const key of ['changed', 'added', 'removed', 'majorVersionChanges']) {
    assertValid(value.summary[key] === summary[key], `packageChanges.summary.${key} does not match the listed changes.`);
  }
  return { summary, changes };
}

function validateStartup(value, label) {
  assertValid(isPlainObject(value), `${label} is required.`);
  return {
    state: boundedText(value.state, `${label} state`, { max: 32, required: true }),
    exitCode: value.exitCode === null ? null : integer(value.exitCode, `${label} exitCode`),
    oomKilled: value.oomKilled === true,
    restarting: value.restarting === true,
    health: boundedText(value.health, `${label} health`, { max: 32, required: true }),
  };
}

// Runtime configuration as reported for the comparison. Env must hold variable names only:
// a value is refused, so no channel (worker or manual upload) can store one in SSI.
function validateRuntimeConfig(value, label) {
  assertValid(isPlainObject(value), `${label} must be an object.`);
  for (const key of Object.keys(value)) {
    assertValid(RUNTIME_CONFIG_FIELDS.includes(key), `${label} has an unknown field: ${key.slice(0, 64)}.`);
  }
  if ('Env' in value && value.Env !== null) {
    assertValid(Array.isArray(value.Env) && value.Env.length <= MAX_ENV_NAMES, `${label}.Env must be an array of at most ${MAX_ENV_NAMES} names.`);
    for (const name of value.Env) {
      assertValid(
        typeof name === 'string' && name.length > 0 && name.length <= MAX_ENV_NAME_LENGTH,
        `${label}.Env must list variable names of 1-${MAX_ENV_NAME_LENGTH} characters.`,
      );
      assertValid(!name.includes('='), `${label}.Env must list variable names only; values are never accepted.`);
      assertValid(hasOnlyPrintable(name, { multiline: false }), `${label}.Env contains control characters.`);
    }
  }
  // TextEncoder, not Buffer: this module is also bundled for the browser.
  assertValid(new TextEncoder().encode(canonicalJson(value)).length <= MAX_RUNTIME_CONFIG_BYTES, `${label} exceeds ${MAX_RUNTIME_CONFIG_BYTES / 1024} KiB.`);
  return value;
}

// Also used by the image inspection intake (src/lib/imageInspection.js).
export function validateImageSide(value, label) {
  assertValid(isPlainObject(value), `${label} is required.`);
  assertValid(
    value.sizeBytes === null || (Number.isSafeInteger(value.sizeBytes) && value.sizeBytes >= 0),
    `${label}.sizeBytes must be a non-negative integer or null.`,
  );
  assertValid(Array.isArray(value.diffIds) && value.diffIds.length <= MAX_IMAGE_LAYERS, `${label}.diffIds must be an array of at most ${MAX_IMAGE_LAYERS} layers.`);
  const diffIds = value.diffIds.map((item) => text(item).toLowerCase());
  assertValid(diffIds.every((item) => sha256Pattern.test(item)), `${label}.diffIds must be sha256 digests.`);
  return { sizeBytes: value.sizeBytes, diffIds, config: validateRuntimeConfig(value.config, `${label}.config`) };
}

// Optional (workers before the comparison feature do not send it). The facts must agree with
// the image-config verdict: configurations that differ even by Env names cannot "pass".
function validateImageFacts(value, imageConfigStatus) {
  if (value === undefined || value === null) return null;
  assertValid(isPlainObject(value), 'imageFacts must be an object.');
  const facts = {
    source: validateImageSide(value.source, 'imageFacts.source'),
    candidate: validateImageSide(value.candidate, 'imageFacts.candidate'),
  };
  assertValid(
    imageConfigStatus === 'fail' || canonicalJson(facts.source.config) === canonicalJson(facts.candidate.config),
    'The image-config status does not match the reported runtime configurations.',
  );
  return facts;
}

// The health verdict SSI expects from the reported health results. Whether an image defines
// a HEALTHCHECK is not part of the evidence, so not-applicable is only consistent when
// neither container reported a health state.
function expectedHealthStatus(reported, { source, candidate }) {
  const unset = (health) => health === 'none';
  if (reported === 'not-applicable') return unset(source.health) && unset(candidate.health) ? 'not-applicable' : 'fail';
  const settled = (health) => !['starting', 'none'].includes(health);
  return settled(source.health) && settled(candidate.health) && source.health === candidate.health ? 'pass' : 'fail';
}

// Validates an ssi.candidate-test/v1 result for `job` and returns the record SSI stores.
export function validateCandidateTestEvidence(evidence, { job, evidenceDigest, intake, now = Date.now() }) {
  assertTestableJob(job);
  assertValid(isPlainObject(evidence), 'Candidate test evidence must be a JSON object.');
  assertValid(
    evidence.contractVersion === CANDIDATE_TEST_CONTRACT_VERSION,
    `Unsupported candidate test contract: ${text(evidence.contractVersion) || 'missing'}.`,
  );
  assertValid(text(evidence.remediationJobId) === job.id, 'Candidate test evidence belongs to another remediation job.');

  const outputDigest = outputDigestOf(job);
  const sourceDigest = text(evidence.source?.digest).toLowerCase();
  const candidateDigest = text(evidence.candidate?.digest).toLowerCase();
  const sourceReference = text(evidence.source?.immutableReference);
  const candidateReference = text(evidence.candidate?.immutableReference);
  assertValid(candidateDigest === outputDigest, 'The tested candidate is not the verified output digest of this job.');
  assertValid(sourceDigest === text(job.sourceDigest).toLowerCase(), 'The tested source is not the source digest of this job.');
  assertValid(immutableReferencePattern.test(sourceReference) && sourceReference.endsWith(`@${sourceDigest}`), 'The source reference is not bound to the source digest.');
  assertValid(immutableReferencePattern.test(candidateReference) && candidateReference.endsWith(`@${candidateDigest}`), 'The candidate reference is not bound to the candidate digest.');

  const platform = text(evidence.platform);
  assertValid(platformPattern.test(platform), 'Candidate test platform is invalid.');
  const verifiedPlatform = text(job.verificationEvidence?.configIntegrity?.platform);
  assertValid(!verifiedPlatform || verifiedPlatform === platform, `The candidate was tested on ${platform}, but it was verified on ${verifiedPlatform}.`);

  const checks = validateChecks(evidence.checks);
  const packageChanges = validatePackageChanges(evidence.packageChanges, plannedPackageNames(job));
  const statusOf = (id) => checks.find((check) => check.id === id).status;
  assertValid(statusOf('package-inventory') === packageInventoryStatus(packageChanges.summary), 'The package-inventory status does not match the reported package changes.');
  const startup = {
    source: validateStartup(evidence.startup?.source, 'startup.source'),
    candidate: validateStartup(evidence.startup?.candidate, 'startup.candidate'),
  };
  assertValid(statusOf('startup') === startupCheck(startup.source, startup.candidate).status, 'The startup status does not match the reported container states.');
  assertValid(statusOf('healthcheck') === expectedHealthStatus(statusOf('healthcheck'), startup), 'The healthcheck status does not match the reported health results.');
  const imageFacts = validateImageFacts(evidence.imageFacts, statusOf('image-config'));
  const passed = deriveCandidateTestPassed(checks);
  assertValid(evidence.passed === passed, 'The reported candidate test verdict does not match its checks.');

  return {
    contractVersion: CANDIDATE_TEST_CONTRACT_VERSION,
    generatedAt: isoTimestamp(evidence.generatedAt, 'generatedAt', now),
    evidenceDigest,
    passed,
    platform,
    sourceDigest,
    sourceReference,
    candidateDigest,
    candidateReference,
    runner: {
      pipeline: boundedText(evidence.runner?.pipeline, 'runner.pipeline', { max: 200 }),
      buildId: boundedText(evidence.runner?.buildId, 'runner.buildId', { max: 64 }),
      agent: boundedText(evidence.runner?.agent, 'runner.agent', { max: 128 }),
    },
    startup,
    checks,
    packageChanges,
    ...(imageFacts ? { imageFacts } : {}),
    intake,
  };
}

// Attaches a validated result. A replay of the same body is idempotent; an older result can
// never replace a newer one (an old "passed" must not hide a later "failed").
export function applyCandidateTest(job, record) {
  const current = job.candidateTest;
  if (current?.evidenceDigest && current.evidenceDigest === record.evidenceDigest) {
    return { job, changed: false };
  }
  assertValid(
    !current || Date.parse(record.generatedAt) > Date.parse(current.generatedAt),
    'A newer candidate test result is already recorded for this job.',
    409,
  );
  // A signed worker result is authoritative: an uploaded file cannot replace it.
  assertValid(
    !(current?.intake?.channel === 'worker' && record.intake?.channel !== 'worker'),
    'A signed worker result is already recorded. Run the SSI - Candidate Test pipeline again instead of uploading a file.',
    409,
  );
  const previous = current
    ? [
        {
          generatedAt: current.generatedAt,
          passed: current.passed,
          evidenceDigest: current.evidenceDigest,
          channel: current.intake?.channel || '',
        },
      ]
    : [];
  return {
    job: {
      ...job,
      candidateTest: record,
      candidateTestHistory: [...previous, ...(job.candidateTestHistory || [])].slice(0, MAX_CANDIDATE_TEST_HISTORY),
    },
    changed: true,
  };
}

// Records a consumer team's decision on the candidate. "accepted" requires a passed
// automatic test for the same digest; "issue-found" is always allowed and blocks publish.
export function createConsumerAcceptance({ job, body, actorId, decidedAt = new Date().toISOString() }) {
  assertTestableJob(job);
  const actor = text(actorId);
  assertValid(actor, 'A trusted signed-in identity is required to record a consumer decision.', 403);
  assertValid(isPlainObject(body), 'The consumer decision must be a JSON object.');
  assertValid(CONSUMER_ACCEPTANCE_DECISIONS.includes(body.decision), 'decision must be accepted or issue-found.');

  const environment = boundedText(body.environment, 'environment', { max: 120, required: true });
  assertValid(environment.length >= 3, 'environment must name the project or environment where the image was tried (3–120 characters).');
  const note = boundedText(body.note, 'note', { max: 1000, multiline: true, required: body.decision === 'issue-found' });
  assertValid(body.decision !== 'issue-found' || note.length >= 10, 'Describe the issue in at least 10 characters.');

  const outputDigest = outputDigestOf(job);
  if (body.decision === 'accepted') {
    assertValid(
      job.candidateTest?.passed === true && text(job.candidateTest.candidateDigest).toLowerCase() === outputDigest,
      'The automatic candidate test must pass before the image can be accepted.',
      409,
    );
  }

  return {
    decision: body.decision,
    environment,
    note,
    decidedBy: actor,
    decidedAt,
    candidateDigest: outputDigest,
    candidateTestEvidenceDigest: text(job.candidateTest?.evidenceDigest),
  };
}

// Each person's latest decision is kept separately (decisionsByActor), so one person's
// "accepted" never hides another person's open issue; a reporter withdraws their own issue
// by recording "accepted" themselves. The top-level fields show the latest decision and
// `history` is the bounded display log.
export function applyConsumerAcceptance(job, decision) {
  const previous = job.consumerAcceptance || {};
  const history = [decision, ...(previous.history || [])].slice(0, MAX_ACCEPTANCE_HISTORY);
  const key = decision.decidedBy.toLowerCase();
  const decisionsByActor = { ...(previous.decisionsByActor || {}) };
  delete decisionsByActor[key];
  const actors = Object.keys(decisionsByActor);
  assertValid(actors.length < MAX_DECIDERS, `At most ${MAX_DECIDERS} people can record decisions for one candidate.`, 409);
  decisionsByActor[key] = decision;
  return { ...job, consumerAcceptance: { ...decision, history, decisionsByActor } };
}

// Latest decision of every person for this output digest. Older records without
// decisionsByActor fall back to their single latest decision.
export function consumerDecisionsFor(job) {
  const outputDigest = outputDigestOf(job);
  const acceptance = job?.consumerAcceptance;
  if (!acceptance) return [];
  const decisions = acceptance.decisionsByActor ? Object.values(acceptance.decisionsByActor) : [acceptance];
  return decisions.filter((item) => text(item?.candidateDigest).toLowerCase() === outputDigest);
}
